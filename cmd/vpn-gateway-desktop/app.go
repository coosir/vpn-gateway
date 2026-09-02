//go:build desktop

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
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
	link := fmt.Sprintf("http://%s/?token=%s", listener.Addr().String(), token)
	if err := ui.ServeOn(listener, server.Handler(), log); err != nil {
		return err
	}
	// Printed for anyone who started this from a terminal, or who would
	// rather use a browser than the window. Nobody sees it when it is opened
	// from a launcher, which is why nothing depends on it.
	fmt.Println("interface:", link)

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
		log:        log,
	}
	sv.current = sv.local

	// If the background service is already running, point window at it directly from the start
	initialURL := link
	if svcLink := sv.serviceLink(); svcLink != "" {
		initialURL = svcLink
		if svcEngine, err := newServiceEngine(svcLink); err == nil {
			sv.current = svcEngine
		}
	}

	window := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Name:      "console",
		Title:     t("title"),
		URL:       initialURL,
		Width:     windowWidth,
		Height:    windowHeight,
		MinWidth:  windowMinW,
		MinHeight: windowMinH,
		Hidden:    false,
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
	tray.SetIcon(statusIcon(client.PhaseSetup, false))
	tray.SetTemplateIcon(degradedIcon())
	tray.SetTooltip(t("tip.setup"))

	menu := application.NewMenu()
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
		showWindow(window)
		go refresh(sv, t, tray, status, connect, menu)
	})

	return app.Run()
}

// supervisor keeps one engine in charge and the window pointed at it.
//
// It is consulted on the menu bar's own timer rather than driven by an event.
// Nothing tells an application that a launchd daemon was installed or removed,
// and someone doing either from a terminal should not have to reopen this to
// see the difference.
type supervisor struct {
	configPath string
	session    *client.Session
	local      *localEngine
	log        *slog.Logger

	// window is pointed at whichever interface is in charge. Before the
	// application is running this only changes the address it will open at,
	// which is the same answer arriving earlier.
	window *application.WebviewWindow

	mu      sync.Mutex
	current engine
	checked time.Time
}

// engine returns the engine in charge, handing over first if that has changed.
func (sv *supervisor) engine() engine {
	sv.mu.Lock()
	if time.Since(sv.checked) < serviceCheckInterval {
		cur := sv.current
		sv.mu.Unlock()
		return cur
	}
	sv.mu.Unlock()

	// Asking runs launchctl, so it happens outside the lock.
	link := sv.serviceLink()

	sv.mu.Lock()
	defer sv.mu.Unlock()
	sv.checked = time.Now()

	if link == "" {
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

	if cur, ok := sv.current.(*serviceEngine); ok && cur.Link() == link {
		return cur
	}
	svc, err := newServiceEngine(link)
	if err != nil {
		sv.log.Error("could not attach to the background service", "error", err)
		return sv.current
	}
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
	if st.ConfigPath != "" && absPath(st.ConfigPath) != sv.configPath {
		return ""
	}
	// An outdated service is running an older binary from a previous version of the app.
	// Do not attach to it; run the local engine/UI so the user sees the latest UI and can update.
	if st.InstalledVersion != "" && st.InstalledVersion != version.Full() {
		sv.log.Warn("background service is running an older version, staying on local interface",
			"service_version", st.InstalledVersion, "app_version", version.Full())
		return ""
	}
	link, err := ui.ReadLink(sv.linkPath())
	if err != nil {
		return ""
	}
	return link
}

// linkPath is where the service was told to publish its link.
func (sv *supervisor) linkPath() string {
	if p := sv.session.Settings().UI.LinkFile; p != "" {
		return p
	}
	return ui.ServiceLinkPath(sv.configPath)
}

// point moves the window. It is safe from any goroutine: the webview
// dispatches to the main thread itself, and before there is a webview it only
// records the address the window will open at.
func (sv *supervisor) point(url string) {
	sv.window.SetURL(url)
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
		v := buildView(snap, t)

		status.SetLabel(v.Status)
		connect.SetLabel(v.Action)
		connect.SetEnabled(v.CanToggle)
		tray.SetIcon(statusIcon(snap.Phase, v.Healthy))
		if v.Healthy {
			tray.SetTemplateIcon(connectedIcon())
		} else {
			tray.SetTemplateIcon(degradedIcon())
		}
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
		v.Status = t("status.idle", st.TunnelCount)
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
	v.Healthy = up == len(st.Tunnels)
	return v
}
