//go:build desktop

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/client"
	"github.com/vpn-gateway/vpn-gateway/internal/client/ui"
)

// An engine is whatever is currently doing the routing. There are two, and
// which one is in charge is not this application's choice: a background
// service exists or it does not.
//
// When it does, this application must not run an engine of its own. Two of
// them would fight over the same routing table and write the same
// configuration file, and the person watching would have no way to tell which
// one they were looking at. So the application hands over: the window shows
// the service's interface and the menu bar reports the service's tunnels.
type engine interface {
	// Link is where the window should point.
	Link() string
	// Snapshot is what the menu bar shows.
	Snapshot() snapshot
	// Toggle connects or disconnects, whichever the current state calls for.
	Toggle(ctx context.Context) error
}

// snapshot is the little of a client's state that fits in a menu.
type snapshot struct {
	Phase       client.Phase
	TunnelCount int
	Tunnels     []tunnelLine
	// Attached means a background service is in charge.
	Attached bool
	// Unreachable means the service is in charge and not answering. It is its
	// own state rather than an error: the routing is still up, and saying
	// nothing would show a healthy menu bar over a client nobody can reach.
	Unreachable bool
}

type tunnelLine struct {
	Name string
	Up   bool
	// Wanted is whether the tunnel was asked to dial at all. One that was not
	// is stopped on purpose -- disabled on the server, or stopped by hand --
	// and counting it as a tunnel that ought to be up turns every deliberate
	// choice into a warning nobody can clear.
	Wanted bool
}

// --- the engine inside this process --------------------------------------

type localEngine struct {
	session *client.Session
	link    string
}

func (e *localEngine) Link() string { return e.link }

func (e *localEngine) Snapshot() snapshot { return sessionSnapshot(e.session) }

func (e *localEngine) Toggle(ctx context.Context) error {
	if e.session.Status().Phase == client.PhaseConnected {
		return e.session.Disconnect()
	}
	return e.session.Connect(ctx)
}

func sessionSnapshot(s *client.Session) snapshot {
	st := s.Status()
	snap := snapshot{Phase: st.Phase, TunnelCount: st.TunnelCount}
	if c := s.Client(); c != nil {
		for _, t := range c.Tunnels() {
			snap.Tunnels = append(snap.Tunnels, tunnelLine{Name: t.Name, Up: t.Up, Wanted: t.Wanted})
		}
	}
	sortTunnels(snap.Tunnels)
	return snap
}

// --- the engine inside the background service -----------------------------

// serviceEngine drives a client running as a launchd daemon over the same
// interface a browser would use. There is no second protocol for this: the
// interface the service already serves is the whole API.
type serviceEngine struct {
	link  string
	base  string
	token string
	http  *http.Client
}

// newServiceEngine reads a link the service published and prepares to talk to
// it. The link carries the token, which is why the file it comes from is
// written for one named user and nobody else.
func newServiceEngine(link string) (*serviceEngine, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("the service published an unreadable link: %w", err)
	}
	token := u.Query().Get("token")
	if token == "" || u.Host == "" {
		return nil, fmt.Errorf("the service published a link with no token: %s", link)
	}
	return &serviceEngine{
		link:  link,
		base:  u.Scheme + "://" + u.Host,
		token: token,
		// Short: this runs on the menu bar's timer, and a service that is
		// slow to answer is a service to report as unreachable, not one to
		// wait for.
		http: &http.Client{Timeout: 3 * time.Second},
	}, nil
}

func (e *serviceEngine) Link() string { return e.link }

func (e *serviceEngine) Snapshot() snapshot {
	var st ui.State
	if err := e.call(context.Background(), http.MethodGet, "/api/state", &st); err != nil {
		return snapshot{Attached: true, Unreachable: true}
	}
	snap := snapshot{
		Phase:       st.Session.Phase,
		TunnelCount: st.Session.TunnelCount,
		Attached:    true,
	}
	for _, t := range st.Tunnels {
		snap.Tunnels = append(snap.Tunnels, tunnelLine{Name: t.Name, Up: t.Up, Wanted: t.Wanted})
	}
	sortTunnels(snap.Tunnels)
	return snap
}

func (e *serviceEngine) Ping(ctx context.Context) error {
	var st ui.State
	return e.call(ctx, http.MethodGet, "/api/state", &st)
}

func (e *serviceEngine) Toggle(ctx context.Context) error {
	path := "/api/connect"
	if e.Snapshot().Phase == client.PhaseConnected {
		path = "/api/disconnect"
	}
	return e.call(ctx, http.MethodPost, path, nil)
}

func (e *serviceEngine) call(ctx context.Context, method, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, e.base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+e.token)
	resp, err := e.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the service answered %s", resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func sortTunnels(lines []tunnelLine) {
	sort.Slice(lines, func(i, j int) bool { return strings.Compare(lines[i].Name, lines[j].Name) < 0 })
}
