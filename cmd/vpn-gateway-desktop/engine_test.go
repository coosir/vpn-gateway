//go:build desktop

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/vpn-gateway/vpn-gateway/internal/client"
	"github.com/vpn-gateway/vpn-gateway/internal/client/ui"
)

// fakeService stands in for a client running as a background service.
type fakeService struct {
	mu       sync.Mutex
	state    ui.State
	token    string
	posted   []string
	unauthed int
}

func (f *fakeService) handler() http.Handler {
	mux := http.NewServeMux()
	guard := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+f.token {
				f.mu.Lock()
				f.unauthed++
				f.mu.Unlock()
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}
	mux.HandleFunc("GET /api/state", guard(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		json.NewEncoder(w).Encode(f.state)
	}))
	for _, p := range []string{"/api/connect", "/api/disconnect"} {
		path := p
		mux.HandleFunc("POST "+path, guard(func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			f.posted = append(f.posted, path)
			f.mu.Unlock()
			w.WriteHeader(http.StatusOK)
		}))
	}
	return mux
}

func testService(t *testing.T, state ui.State) (*fakeService, *serviceEngine) {
	t.Helper()
	f := &fakeService{state: state, token: "tok123"}
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)

	e, err := newServiceEngine(srv.URL + "/?token=" + f.token)
	if err != nil {
		t.Fatal(err)
	}
	return f, e
}

func TestAttachedMenuShowsTheServicesTunnels(t *testing.T) {
	_, e := testService(t, ui.State{
		Session: client.SessionStatus{Phase: client.PhaseConnected, TunnelCount: 2},
		Tunnels: []ui.TunnelView{{Name: "office", Up: true}, {Name: "lab", Up: false}},
	})

	snap := e.Snapshot()
	if !snap.Attached || snap.Unreachable {
		t.Fatalf("snapshot = %+v", snap)
	}
	// Sorted, so the menu does not reorder itself between refreshes.
	if len(snap.Tunnels) != 2 || snap.Tunnels[0].Name != "lab" {
		t.Fatalf("tunnels = %+v", snap.Tunnels)
	}

	v := buildView(snap, translator("en"))
	if !strings.Contains(v.Status, "1/2") {
		t.Errorf("status = %q", v.Status)
	}
	if v.Healthy {
		t.Error("a tunnel that is down was shown as healthy")
	}
	if v.Action != "Disconnect" {
		t.Errorf("action = %q", v.Action)
	}
}

func TestAttachedMenuSaysWhenTheServiceStopsAnswering(t *testing.T) {
	// The routing is still up and nothing here can change that, so the menu
	// says so rather than offering a button that goes nowhere.
	f := &fakeService{token: "tok"}
	srv := httptest.NewServer(f.handler())
	e, err := newServiceEngine(srv.URL + "/?token=tok")
	if err != nil {
		t.Fatal(err)
	}
	srv.Close()

	snap := e.Snapshot()
	if !snap.Unreachable {
		t.Fatalf("a service that is not answering reported %+v", snap)
	}
	v := buildView(snap, translator("en"))
	if !strings.Contains(v.Status, "not answering") {
		t.Errorf("status = %q", v.Status)
	}
	if v.CanToggle {
		t.Error("connecting was offered against a service that cannot be reached")
	}
}

func TestToggleDrivesTheService(t *testing.T) {
	f, e := testService(t, ui.State{Session: client.SessionStatus{Phase: client.PhaseIdle}})
	if err := e.Toggle(context.Background()); err != nil {
		t.Fatal(err)
	}

	f.mu.Lock()
	f.state.Session.Phase = client.PhaseConnected
	f.mu.Unlock()
	if err := e.Toggle(context.Background()); err != nil {
		t.Fatal(err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	want := []string{"/api/connect", "/api/disconnect"}
	if len(f.posted) != 2 || f.posted[0] != want[0] || f.posted[1] != want[1] {
		t.Errorf("the service was asked for %v, want %v", f.posted, want)
	}
	if f.unauthed != 0 {
		t.Errorf("%d requests reached the service without the token", f.unauthed)
	}
}

func TestALinkWithoutATokenIsRefused(t *testing.T) {
	// Attaching without one would mean every request coming back 401 and a
	// menu bar that says the service is unreachable while it is running fine.
	if _, err := newServiceEngine("http://127.0.0.1:8645/"); err == nil {
		t.Error("a link carrying no token was accepted")
	}
	if _, err := newServiceEngine("://nonsense"); err == nil {
		t.Error("an unparseable link was accepted")
	}
}
