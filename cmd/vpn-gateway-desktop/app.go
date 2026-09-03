//go:build desktop

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"

	"github.com/vpn-gateway/vpn-gateway/internal/client"
	"github.com/vpn-gateway/vpn-gateway/internal/client/helper"
	"github.com/vpn-gateway/vpn-gateway/internal/client/ui"
	"github.com/vpn-gateway/vpn-gateway/internal/version"
)

// pollInterval is how often the tray refreshes. The window streams its own
// updates; the menu bar only needs to be roughly current, and a tray that
// polls hard is a laptop that runs warm.
const pollInterval = 3 * time.Second

// serviceCheckInterval is how often the background service is looked for.
//
// Answering runs launchctl, so it is not asked on every menu bar refresh: a
// service is installed or removed by hand perhaps twice in the life of a
// machine, and spawning two processes every few seconds to notice is the kind
// of thing that shows up as battery. A service that stops answering shortens
// this to the next tick, which is the case that actually needs to be quick.
const serviceCheckInterval = 15 * time.Second

// Window geometry. The interface is a dense table, so it wants width more
// than height, and it stays usable well below this.
const (
	windowWidth  = 920
	windowHeight = 620
	windowMinW   = 680
	windowMinH   = 440
)

// run builds the application and blocks until it quits.
func run(configPath, lang string) error {
	t := translator(lang)
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	session := client.NewSession(configPath, log)

	// The interface listens on a port of its own choosing, so two copies of
	// this and a headless client can coexist rather than one refusing to
	// start because another holds a fixed port.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("could not open a local port for the interface: %w", err)
	}
	token, err := ui.NewToken()
	if err != nil {
		return err
	}

	server := ui.New(session, configPath, token, log)
	// The window belongs to this application, so the interface in it leaves
	// moving it alone: this is the side that can check a service answers
	// before pointing anything at it. Said before it serves a request, which
	// is the last moment nothing is reading it.
	server.Managed()
	link := fmt.Sprintf("http://%s/?token=%s", listener.Addr().String(), token)
	if err := ui.ServeOn(listener, server.Handler(), log); err != nil {
		return err
	}
	// Printed for anyone who started this from a terminal, or who would
	// rather use a browser than the window. Nobody sees it when it is opened
	// from a launcher, which is why nothing depends on it.
	fmt.Println("interface:", link)

	// Published so the background service can find its way back here. A
	// service cannot install over its own executable or stop itself while
	// serving the page that asked it to, and this is the process that
	// outlives both, so its interface is where that work is sent.
	appLink := ui.AppLinkPath(configPath)
	if err := ui.WriteLink(appLink, listener.Addr().String(), token, ""); err != nil {
		log.Warn("could not record this application's interface link", "path", appLink, "error", err)
	}
	// A link left behind by an application that has quit points at nothing,
	// which is the error page this exists to prevent.
	defer os.Remove(appLink)

	var sv *supervisor
	app := application.New(application.Options{
		Name:        t("title"),
		Description: t("description"),
		Icon:        appIcon(256),
		SingleInstance: &application.SingleInstanceOptions{
			UniqueID: "com.vpn-gateway.desktop",
			OnSecondInstanceLaunch: func(data application.SecondInstanceData) {
				if sv != nil && sv.window != nil {
					showWindow(sv.window)
				}
			},
		},
		Mac: application.MacOptions{
			// A menu bar tool: no Dock icon, and closing the window leaves it
			// running rather than quitting.
			ActivationPolicy: application.ActivationPolicyAccessory,
			ApplicationShouldTerminateAfterLastWindowClosed: false,
		},
		LogLevel: slog.LevelWarn,
		OnShutdown: func() {
			os.Remove(appLink)
			// Disconnecting tears down the interface and the routes pointing
			// at it; leaving them behind would take the machine offline.
			session.Close()
		},
	})

	app.SetIcon(appIcon(256))

	// Which engine is in charge is decided here, not chosen: the background
	// service either exists or it does not, and it can be installed or removed
	// from somewhere this application never hears about.
	sv = &supervisor{
		configPath: absPath(configPath),
		session:    session,
		local:      &localEngine{session: session, link: link},
		srv:        server,
		log:        log,
	}
	sv.current = sv.local

	// If the background service is already running, point window at it directly from the start
	initialURL := link
	if svcLink := sv.serviceLink(); svcLink != "" {
		if svcEngine, err := newServiceEngine(svcLink); err == nil {
			pingCtx, pingCancel := context.WithTimeout(context.Background(), 1*time.Second)
			if err := svcEngine.Ping(pingCtx); err == nil {
				initialURL = svcLink
				sv.current = svcEngine
			}
			pingCancel()
		}
	}

	sv.pointed, sv.want = initialURL, initialURL

	window := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Name:      "console",
		Title:     t("title"),
		URL:       initialURL,
		Width:     windowWidth,
		Height:    windowHeight,
		MinWidth:  windowMinW,
		MinHeight: windowMinH,
		Hidden:    true,
	})
	sv.window = window

	// On close, hide to system tray instead of destroying the window so the
	// session keeps running and can be reopened from the tray.
	window.RegisterHook(events.Common.WindowClosing, func(e *application.WindowEvent) {
		e.Cancel()
		window.Hide()
		hideDockIcon()
	})

	tray := app.SystemTray.New()
	setTrayIcon(tray, client.PhaseSetup, false)
	tray.SetTooltip(t("tip.setup"))

	menu := application.NewMenu()
	title := menu.Add(t("title") + " — " + version.Full())
	title.SetEnabled(false)
	menu.AddSeparator()

	status := menu.Add(t("status.setup"))
	status.SetEnabled(false)

	menu.AddSeparator()
	connect := menu.Add(t("connect"))
	connect.OnClick(func(*application.Context) { sv.toggle() })
	menu.Add(t("open")).OnClick(func(*application.Context) { showWindow(window) })
	menu.Add(t("quit")).OnClick(func(*application.Context) { app.Quit() })

	tray.SetMenu(menu)
	tray.OnClick(func() { showWindow(window) })

	// Anything that touches the tray is dispatched to the main thread, and
	// that dispatch does not exist until the application is running. Starting
	// the refresh from here keeps the first update from racing it.
	app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
		// A service installed on an earlier run is already in charge, so the
		// window opens on its interface rather than on this one.
		_ = sv.engine()
		sv.settle()
		showWindow(window)
		go refresh(sv, t, tray, status, connect, menu)
	})

	return app.Run()
}

// supervisor decides which engine is in charge and tells the window when that
// changes.
type supervisor struct {
	configPath string
	session    *client.Session
	local      *localEngine
	// srv is this application's own interface. It is asked whether it is in
	// the middle of installing or removing the service before the window is
	// moved, because moving it then would reload the page doing the work.
	srv *ui.Server
	log *slog.Logger

	// window is where the interface is displayed. Before the window of an
	// application is running this only changes the address it will open at,
	// which is the same answer arriving earlier.
	window *application.WebviewWindow

	mu      sync.Mutex
	current engine
	checked time.Time
	// want is where the window belongs, and pointed is where it was last
	// sent. They differ only while something is in the way: setting the same
	// address again reloads a page that is already right, and setting a new
	// one during an install would take the page running it away.
	want    string
	pointed string
}

// engine returns the engine in charge, handing over first if that has changed.
func (sv *supervisor) engine() engine {
	sv.mu.Lock()
	checkInterval := serviceCheckInterval
	if sv.current == engine(sv.local) {
		checkInterval = pollInterval
	}
	if time.Since(sv.checked) < checkInterval {
		cur := sv.current
		sv.mu.Unlock()
		return cur
	}
	sv.checked = time.Now()
	sv.mu.Unlock()

	// Asking runs launchctl/sc.exe, so it happens outside the lock.
	link := sv.serviceLink()

	if link == "" {
		sv.mu.Lock()
		defer sv.mu.Unlock()
		if sv.current != engine(sv.local) {
			// The service is gone. It owned the configuration file while it
			// ran, so the session reads it again before taking over.
			sv.log.Info("the background service is no longer running; using the engine in this application")
			sv.session.Reload()
			sv.point(sv.local.Link())
			sv.current = sv.local
		}
		return sv.current
	}

	sv.mu.Lock()
	if cur, ok := sv.current.(*serviceEngine); ok && cur.Link() == link {
		sv.mu.Unlock()
		return cur
	}
	sv.mu.Unlock()

	svc, err := newServiceEngine(link)
	if err != nil {
		sv.log.Error("could not attach to the background service", "error", err)
		sv.mu.Lock()
		cur := sv.current
		sv.mu.Unlock()
		return cur
	}

	// Wait up to 3 seconds for the newly started background service HTTP endpoint
	// to be ready and responding before navigating the window and handing over.
	ready := false
	for i := 0; i < 15; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
		err := svc.Ping(ctx)
		cancel()
		if err == nil {
			ready = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !ready {
		sv.log.Warn("background service was started but HTTP endpoint is not responding yet, will retry")
		sv.recheck()
		sv.mu.Lock()
		cur := sv.current
		sv.mu.Unlock()
		return cur
	}

	sv.mu.Lock()
	defer sv.mu.Unlock()
	// Handing over means letting go first: two engines would fight over the
	// same routing table.
	if err := sv.session.Disconnect(); err != nil {
		sv.log.Error("could not stop the engine in this application", "error", err)
	}
	sv.log.Info("attached to the background service")
	sv.point(link)
	sv.current = svc
	return svc
}

// pathsEqual checks if two filesystem paths refer to the same location,
// accounting for case-insensitivity on Windows and slash canonicalization.
func pathsEqual(p1, p2 string) bool {
	if p1 == "" || p2 == "" {
		return false
	}
	a := filepath.Clean(absPath(p1))
	b := filepath.Clean(absPath(p2))
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// serviceLink is where the background service serves its interface, empty when
// there is none to attach to.
func (sv *supervisor) serviceLink() string {
	st := helper.Inspect(helper.Options{ConfigPath: sv.configPath})
	if !st.Installed || !st.Running {
		return ""
	}
	// A service running some other configuration belongs to somebody else.
	// Attaching to it would show tunnels that have nothing to do with what
	// this application is configured with.
	if st.ConfigPath != "" && !pathsEqual(st.ConfigPath, sv.configPath) {
		return ""
	}

	link, err := ui.ReadLink(sv.linkPath())
	if err == nil && link != "" {
		return link
	}

	// Fallback if link file is missing: construct link from token
	listen := sv.session.Settings().UI.Listen
	if listen == "" {
		listen = "127.0.0.1:8645"
	}
	stateDir := sv.session.Settings().UI.StateDir
	if stateDir == "" {
		stateDir = filepath.Dir(sv.configPath)
	}
	if tok, tokErr := ui.ReadToken(stateDir); tokErr == nil && tok != "" {
		return fmt.Sprintf("http://%s/?token=%s", listen, tok)
	}
	return ""
}

// linkPath is where the service was told to publish its link.
func (sv *supervisor) linkPath() string {
	if p := sv.session.Settings().UI.LinkFile; p != "" {
		return p
	}
	return ui.ServiceLinkPath(sv.configPath)
}

// point records where the window belongs. It is called while the lock is
// held and does not move anything itself: whether the move can happen now is
// settle's question.
func (sv *supervisor) point(url string) {
	sv.want = url
}

// settle moves the window to where it belongs, when it can. It is called on
// the refresh tick rather than at the moment of the decision, so a move that
// had to wait happens as soon as whatever it was waiting for is over.
func (sv *supervisor) settle() {
	sv.mu.Lock()
	want, pointed := sv.want, sv.pointed
	sv.mu.Unlock()
	if want == "" || want == pointed {
		return
	}
	// The page in the window is installing or removing the service. It has to
	// survive to say how that went, and a page that is reloaded says nothing.
	if sv.srv.Busy() {
		return
	}
	sv.mu.Lock()
	sv.pointed = want
	sv.mu.Unlock()
	sv.window.SetURL(want)
}

// recheck makes the next call look for the service again. It is what an
// engine that has stopped answering asks for: either the service is gone and
// this application takes over, or it is back and nothing changes.
func (sv *supervisor) recheck() {
	sv.mu.Lock()
	sv.checked = time.Time{}
	sv.mu.Unlock()
}

func (sv *supervisor) toggle() {
	e := sv.engine()
	if err := e.Toggle(context.Background()); err != nil {
		sv.log.Error("could not change the connection", "error", err)
	}
}

// absPath is best-effort: a path that cannot be resolved is compared as given,
// which is still right whenever both sides were written the same way.
func absPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

// setTrayIcon gives the tray the one icon it will show.
//
// Never both kinds. macOS keeps the template flag once anything has set it, so
// a tray told about a colour icon after a template one goes on drawing every
// icon it is given as a stencil -- which is how a connected client kept the
// same outline as a stopped one.
func setTrayIcon(tray *application.SystemTray, phase client.Phase, healthy bool) {
	icon, template := trayIcon(phase, healthy)
	if template {
		tray.SetTemplateIcon(icon)
		return
	}
	tray.SetIcon(icon)
}

func showWindow(w *application.WebviewWindow) {
	showDockIcon()
	w.Show()
	w.Focus()
}

func refresh(sv *supervisor, t func(string, ...any) string,
	tray *application.SystemTray, status, connect *application.MenuItem,
	menu *application.Menu) {

	for {
		snap := sv.engine().Snapshot()
		if snap.Unreachable {
			sv.recheck()
		}
		sv.settle()
		v := buildView(snap, t)

		status.SetLabel(v.Status)
		connect.SetLabel(v.Action)
		connect.SetEnabled(v.CanToggle)
		setTrayIcon(tray, snap.Phase, v.Healthy)
		tray.SetTooltip(v.Tooltip)

		// The menu is rebuilt from its items, so it has to be told they moved.
		menu.Update()

		time.Sleep(pollInterval)
	}
}

// view is what the menu should show. It is worked out separately from the
// menu itself so the decisions can be checked without a menu bar.
type view struct {
	Healthy   bool
	CanToggle bool
	Status    string
	Action    string
	Tooltip   string
}

func buildView(st snapshot, t func(string, ...any) string) view {
	v := view{Action: t("connect")}

	// The service is in charge and not answering. Nothing here can fix that,
	// and offering a connect button that goes nowhere would be worse than
	// saying so.
	if st.Unreachable {
		v.Status = t("status.unreachable")
		v.Tooltip = t("tip.unreachable")
		return v
	}

	switch st.Phase {
	case client.PhaseSetup:
		v.Status = t("status.setup")
		v.Tooltip = t("tip.setup")
		return v
	case client.PhaseConnecting:
		v.Status = t("status.connecting")
		v.Tooltip = t("tip.connecting")
		return v
	case client.PhaseFailed:
		v.Status = t("status.failed")
		v.Tooltip = t("tip.failed")
		v.CanToggle = true
		return v
	case client.PhaseIdle:
		v.Status = t("status.idle", st.TunnelCount)
		v.Tooltip = t("tip.idle")
		v.CanToggle = true
		return v
	}

	// Connected: the tunnels themselves decide what this looks like.
	v.CanToggle = true
	v.Action = t("disconnect")

	if len(st.Tunnels) == 0 {
		v.Status = t("status.connected")
		v.Tooltip = t("tip.connected")
		v.Healthy = true
		return v
	}

	up := 0
	for _, tn := range st.Tunnels {
		if tn.Up {
			up++
		}
	}
	v.Status = t("status.up", up, len(st.Tunnels))
	v.Tooltip = t("tip.ok", up, len(st.Tunnels))
	// A tunnel that is not carrying traffic has to show in the menu bar.
	// Otherwise the one moment someone needs to look is the one moment it
	// looks fine.
	v.Healthy = (up > 0 && up == len(st.Tunnels)) || len(st.Tunnels) == 0
	return v
}
