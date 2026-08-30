//go:build desktop

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"fyne.io/systray"
)

// pollInterval is how often the tray asks the client what it is doing. The
// interface itself streams updates; the menu bar only needs to be roughly
// current, and a tray that polls hard is a laptop that runs warm.
const pollInterval = 5 * time.Second

// maxTunnelItems bounds the menu. Past this the list stops being something
// anyone reads at a glance, and the console shows all of them anyway.
const maxTunnelItems = 12

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

func runTray(link, lang string) {
	t := translator(lang)

	base, token, err := splitLink(link)
	if err != nil {
		fmt.Fprintln(os.Stderr, "vpn-gateway-desktop:", err)
		os.Exit(1)
	}

	systray.Run(func() {
		systray.SetTemplateIcon(degradedIcon(), degradedIcon())
		systray.SetTooltip(t("tip.gone"))

		status := systray.AddMenuItem(t("status.gone"), "")
		status.Disable()

		systray.AddSeparator()
		tunnelItems := make([]*systray.MenuItem, maxTunnelItems)
		for i := range tunnelItems {
			tunnelItems[i] = systray.AddMenuItem("", "")
			tunnelItems[i].Disable()
			tunnelItems[i].Hide()
		}

		systray.AddSeparator()
		open := systray.AddMenuItem(t("open"), "")
		quit := systray.AddMenuItem(t("quit"), "")

		go func() {
			for {
				select {
				case <-open.ClickedCh:
					openWindow(link)
				case <-quit.ClickedCh:
					systray.Quit()
					return
				}
			}
		}()

		go pollLoop(base, token, t, status, tunnelItems)
	}, func() {})
}

func pollLoop(base, token string, t func(string, ...any) string, status *systray.MenuItem, items []*systray.MenuItem) {
	client := &http.Client{Timeout: 4 * time.Second}
	for {
		st, err := fetchState(client, base, token)
		if err != nil {
			systray.SetTemplateIcon(degradedIcon(), degradedIcon())
			systray.SetTooltip(t("tip.gone"))
			status.SetTitle(t("status.gone"))
			for _, it := range items {
				it.Hide()
			}
		} else {
			applyState(st, t, status, items)
		}
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

func applyState(st *trayState, t func(string, ...any) string, status *systray.MenuItem, items []*systray.MenuItem) {
	v := buildView(st, t)

	status.SetTitle(v.Status)
	if v.Healthy {
		systray.SetTemplateIcon(connectedIcon(), connectedIcon())
	} else {
		systray.SetTemplateIcon(degradedIcon(), degradedIcon())
	}
	systray.SetTooltip(t("tip.ok", v.Up, v.Total))

	for i, it := range items {
		if i >= len(v.Lines) {
			it.Hide()
			continue
		}
		it.SetTitle(v.Lines[i])
		it.Show()
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

// openWindow re-executes this binary in window mode. A tray and a webview
// each want the process's main run loop, so they cannot share one; a second
// process is what lets both exist, and it also means closing the window
// leaves the tray alone.
func openWindow(link string) {
	cmd := exec.Command(selfPath(), "-window", link)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "vpn-gateway-desktop: could not open the console:", err)
		return
	}
	// Reap it so a session of opening and closing does not leave zombies.
	go cmd.Wait()
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
