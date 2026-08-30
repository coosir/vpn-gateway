//go:build desktop

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sort"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"

	"github.com/vpn-gateway/vpn-gateway/internal/client"
	"github.com/vpn-gateway/vpn-gateway/internal/client/ui"
)

// pollInterval is how often the tray refreshes. The window streams its own
// updates; the menu bar only needs to be roughly current, and a tray that
// polls hard is a laptop that runs warm.
const pollInterval = 3 * time.Second

// maxTunnelItems bounds the menu. Past this the list stops being something
// anyone reads at a glance, and the window shows all of them anyway.
const maxTunnelItems = 12

// Window geometry. The interface is a dense table, so it wants width more
// than height, and it stays usable well below this.
const (
	windowWidth  = 1100
	windowHeight = 720
	windowMinW   = 720
	windowMinH   = 460
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

	app := application.New(application.Options{
		Name:        t("title"),
		Description: t("description"),
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

	// Created hidden and reused. Rebuilding it on every open would reload the
	// interface and lose whatever was being typed into it.
	window := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Name:      "console",
		Title:     t("title"),
		URL:       link,
		Width:     windowWidth,
		Height:    windowHeight,
		MinWidth:  windowMinW,
		MinHeight: windowMinH,
		Hidden:    true,
	})

	tray := app.SystemTray.New()
	tray.SetTemplateIcon(degradedIcon())
	tray.SetTooltip(t("tip.setup"))

	menu := application.NewMenu()
	status := menu.Add(t("status.setup"))
	status.SetEnabled(false)

	menu.AddSeparator()
	items := make([]*application.MenuItem, maxTunnelItems)
	for i := range items {
		items[i] = menu.Add("")
		items[i].SetEnabled(false)
		items[i].SetHidden(true)
	}

	menu.AddSeparator()
	connect := menu.Add(t("connect"))
	connect.OnClick(func(*application.Context) { toggle(session, log) })
	menu.Add(t("open")).OnClick(func(*application.Context) { showWindow(window) })
	menu.Add(t("quit")).OnClick(func(*application.Context) { app.Quit() })

	tray.SetMenu(menu)
	tray.OnClick(func() { showWindow(window) })

	// Anything that touches the tray is dispatched to the main thread, and
	// that dispatch does not exist until the application is running. Starting
	// the refresh from here keeps the first update from racing it.
	app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
		// Nothing is configured yet, so the window is the whole point of
		// opening this. Show it rather than leaving a menu bar icon someone
		// has to discover.
		if session.Status().Phase == client.PhaseSetup {
			showWindow(window)
		}
		go refresh(session, t, tray, status, connect, items, menu)
	})

	return app.Run()
}

func toggle(session *client.Session, log *slog.Logger) {
	if session.Status().Phase == client.PhaseConnected {
		if err := session.Disconnect(); err != nil {
			log.Error("could not disconnect", "error", err)
		}
		return
	}
	if err := session.Connect(context.Background()); err != nil {
		log.Error("could not connect", "error", err)
	}
}

func showWindow(w *application.WebviewWindow) {
	w.Show()
	w.Focus()
}

func refresh(session *client.Session, t func(string, ...any) string,
	tray *application.SystemTray, status, connect *application.MenuItem,
	items []*application.MenuItem, menu *application.Menu) {

	for {
		v := buildView(session, t)

		status.SetLabel(v.Status)
		connect.SetLabel(v.Action)
		connect.SetEnabled(v.CanToggle)
		if v.Healthy {
			tray.SetTemplateIcon(connectedIcon())
		} else {
			tray.SetTemplateIcon(degradedIcon())
		}
		tray.SetTooltip(v.Tooltip)

		for i, it := range items {
			if i >= len(v.Lines) {
				it.SetHidden(true)
				continue
			}
			it.SetLabel(v.Lines[i])
			it.SetHidden(false)
		}
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
	Lines     []string
}

func buildView(session *client.Session, t func(string, ...any) string) view {
	st := session.Status()

	v := view{Action: t("connect")}
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

	c := session.Client()
	if c == nil {
		v.Status = t("status.idle", st.TunnelCount)
		return v
	}
	tunnels := c.Tunnels()
	sort.Slice(tunnels, func(i, j int) bool { return tunnels[i].Name < tunnels[j].Name })

	up := 0
	for _, tn := range tunnels {
		if tn.Up {
			up++
		}
	}
	v.Status = t("status.up", up, len(tunnels))
	v.Tooltip = t("tip.ok", up, len(tunnels))
	// A tunnel that is not carrying traffic has to show in the menu bar.
	// Otherwise the one moment someone needs to look is the one moment it
	// looks fine.
	v.Healthy = len(tunnels) > 0 && up == len(tunnels)

	for _, tn := range tunnels {
		state := t("tunnel.down")
		if tn.Up {
			state = t("tunnel.up")
		}
		v.Lines = append(v.Lines, fmt.Sprintf("%s  ·  %s", tn.Name, state))
	}
	return v
}
