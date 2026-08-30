//go:build desktop

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
)

// pollInterval is how often the tray asks the client what it is doing. The
// interface itself streams updates; the menu bar only needs to be roughly
// current, and a tray that polls hard is a laptop that runs warm.
const pollInterval = 5 * time.Second

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

type tunnelView struct {
	Name string `json:"name"`
	Up   bool   `json:"up"`
}

type trayState struct {
	Tunnels []tunnelView `json:"tunnels"`
	Prompts []struct {
		Tunnel string `json:"tunnel"`
	} `json:"prompts"`
}

// run builds the application and blocks until it quits.
//
// Anything that goes wrong before the tray exists is reported in a dialog and
// not on standard error. Opening this from a launcher passes no arguments and
// shows no terminal, so a message printed to stderr is a message nobody ever
// sees: the application would simply appear not to start.
func run(explicit, configPath, lang string) error {
	t := translator(lang)

	app := application.New(application.Options{
		Name:        t("title"),
		Description: t("description"),
		// A tray tool should be silent unless something is wrong. At the
		// default level the framework announces its build and platform on
		// every start, which is noise in a menu bar application's log.
		LogLevel: slog.LevelWarn,
		Mac: application.MacOptions{
			// A menu bar tool, not a windowed application: no Dock icon, and
			// closing the window leaves the tray running rather than quitting.
			ActivationPolicy: application.ActivationPolicyAccessory,
			ApplicationShouldTerminateAfterLastWindowClosed: false,
		},
	})

	// Not finding a link at all is the only thing worth refusing to start
	// for. A client that is merely down is the case the tray exists to show,
	// so it starts anyway and says so until the client comes back.
	link, err := findLink(explicit, configPath)
	if err != nil {
		fail(app, t, err)
		return nil
	}
	base, token, err := splitLink(link)
	if err != nil {
		fail(app, t, err)
		return nil
	}

	if reachable := checkLink(link); reachable != nil {
		// Remembering a link that has never worked would make every later
		// launch fail the same way with no clue as to why, so it is only
		// recorded once it has answered.
		if explicit != "" {
			// It was just typed, so say what is wrong with it rather than
			// leaving the tray to sit there reporting nothing.
			warn(app, t, reachable)
		}
	} else if remembered := rememberLink(link); remembered != nil {
		// Not fatal: the link works, it just will not be there next time.
		fmt.Fprintln(os.Stderr, "vpn-gateway-desktop: could not remember the link:", remembered)
	}

	// Created hidden and reused. Rebuilding the window on every open would
	// reload the interface and lose whatever was being typed into it.
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
	tray.SetTooltip(t("tip.gone"))

	menu := application.NewMenu()
	status := menu.Add(t("status.gone"))
	status.SetEnabled(false)

	menu.AddSeparator()
	items := make([]*application.MenuItem, maxTunnelItems)
	for i := range items {
		items[i] = menu.Add("")
		items[i].SetEnabled(false)
		items[i].SetHidden(true)
	}

	menu.AddSeparator()
	menu.Add(t("open")).OnClick(func(*application.Context) { showWindow(window) })
	menu.Add(t("quit")).OnClick(func(*application.Context) { app.Quit() })

	tray.SetMenu(menu)
	// Clicking the icon itself opens the console, which is what a person
	// reaches for far more often than the menu.
	tray.OnClick(func() { showWindow(window) })

	// Anything that touches the tray or a dialog is dispatched to the main
	// thread, and that dispatch does not exist until the application is
	// running. Starting the poll loop from here rather than before Run keeps
	// the first update from racing the thing it updates.
	app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
		go poll(base, token, t, tray, status, items, menu)
	})

	return app.Run()
}

// fail shows why the application cannot start and quits when it is dismissed.
//
// The dialog is raised from the started event rather than straight away: it
// has to be shown on the main thread, and there is no main thread to dispatch
// to until the application is running.
func fail(app *application.App, t func(string, ...any) string, cause error) {
	// Also to standard error, for anyone who did start this from a terminal.
	fmt.Fprintln(os.Stderr, "vpn-gateway-desktop:", cause)

	app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
		dialog := app.Dialog.Error()
		dialog.SetTitle(t("fail.title"))
		dialog.SetMessage(cause.Error())
		dialog.Show()
		app.Quit()
	})
	app.Run()
}

// warn reports a problem without stopping: the tray is still worth having.
func warn(app *application.App, t func(string, ...any) string, cause error) {
	fmt.Fprintln(os.Stderr, "vpn-gateway-desktop:", cause)
	app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
		dialog := app.Dialog.Warning()
		dialog.SetTitle(t("warn.title"))
		dialog.SetMessage(cause.Error())
		dialog.Show()
	})
}

func showWindow(w *application.WebviewWindow) {
	w.Show()
	w.Focus()
}

func poll(base, token string, t func(string, ...any) string,
	tray *application.SystemTray, status *application.MenuItem,
	items []*application.MenuItem, menu *application.Menu) {

	c := &http.Client{Timeout: 4 * time.Second}
	for {
		st, err := fetchState(c, base, token)
		if err != nil {
			tray.SetTemplateIcon(degradedIcon())
			tray.SetTooltip(t("tip.gone"))
			status.SetLabel(t("status.gone"))
			for _, it := range items {
				it.SetHidden(true)
			}
		} else {
			apply(buildView(st, t), t, tray, status, items)
		}
		// The menu is rebuilt from its items, so it has to be told they moved.
		menu.Update()
		time.Sleep(pollInterval)
	}
}

// view is what the menu should show. It is worked out separately from the
// menu itself so the decisions can be checked without a menu bar.
type view struct {
	Healthy bool
	Up      int
	Total   int
	Status  string
	Lines   []string
}

func buildView(st *trayState, t func(string, ...any) string) view {
	waiting := map[string]bool{}
	for _, p := range st.Prompts {
		waiting[p.Tunnel] = true
	}

	tunnels := append([]tunnelView(nil), st.Tunnels...)
	sort.Slice(tunnels, func(i, j int) bool { return tunnels[i].Name < tunnels[j].Name })

	up := 0
	for _, tn := range tunnels {
		if tn.Up {
			up++
		}
	}

	v := view{Up: up, Total: len(tunnels)}
	if len(tunnels) == 0 {
		v.Status = t("status.none")
	} else {
		v.Status = t("status.up", up, len(tunnels))
	}

	// A tunnel waiting for a code is not carrying traffic, and the icon has
	// to say so. Otherwise the one moment someone needs to look at this is
	// the one moment it looks fine.
	v.Healthy = len(tunnels) > 0 && up == len(tunnels) && len(waiting) == 0

	for _, tn := range tunnels {
		state := t("tunnel.down")
		if waiting[tn.Name] {
			state = t("auth.waiting")
		} else if tn.Up {
			state = t("tunnel.up")
		}
		v.Lines = append(v.Lines, fmt.Sprintf("%s  ·  %s", tn.Name, state))
	}
	return v
}

func apply(v view, t func(string, ...any) string,
	tray *application.SystemTray, status *application.MenuItem, items []*application.MenuItem) {

	status.SetLabel(v.Status)
	if v.Healthy {
		tray.SetTemplateIcon(connectedIcon())
	} else {
		tray.SetTemplateIcon(degradedIcon())
	}
	tray.SetTooltip(t("tip.ok", v.Up, v.Total))

	for i, it := range items {
		if i >= len(v.Lines) {
			it.SetHidden(true)
			continue
		}
		it.SetLabel(v.Lines[i])
		it.SetHidden(false)
	}
}

func fetchState(c *http.Client, base, token string) (*trayState, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, base+"/api/state", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the client answered %d", resp.StatusCode)
	}
	var st trayState
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return nil, err
	}
	return &st, nil
}

// splitLink separates the address from the token, so the token travels in a
// header rather than in every request line.
func splitLink(link string) (base, token string, err error) {
	u, err := url.Parse(link)
	if err != nil {
		return "", "", fmt.Errorf("%q is not a URL: %w", link, err)
	}
	token = u.Query().Get("token")
	if token == "" {
		return "", "", fmt.Errorf("%q carries no token; use the link the client printed", link)
	}
	u.RawQuery = ""
	return strings.TrimRight(u.String(), "/"), token, nil
}
