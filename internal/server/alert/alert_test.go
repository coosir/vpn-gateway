package alert

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/server/tunnel"
	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

func newTestWatcher(manual ...string) (*Watcher, *time.Time) {
	m := map[string]bool{}
	for _, n := range manual {
		m[n] = true
	}
	w := New(Options{Grace: 3 * time.Minute, Label: "home", Manual: m})
	now := time.Date(2026, 9, 24, 3, 0, 0, 0, time.UTC)
	w.now = func() time.Time { return now }
	return w, &now
}

func snap(name string, wanted bool, state contract.State, reachable bool) tunnel.Snapshot {
	return tunnel.Snapshot{
		Name: name, Wanted: wanted, Reachable: reachable,
		Status: contract.Status{State: state},
	}
}

func drain(w *Watcher) []message {
	var out []message
	for {
		select {
		case m := <-w.send:
			out = append(out, m)
		default:
			return out
		}
	}
}

func TestManualStandDownAlertsAtOnce(t *testing.T) {
	w, _ := newTestWatcher("hk")
	w.observe(tunnel.Event{Tunnel: snap("hk", true, contract.StateUp, true)})
	s := snap("hk", false, contract.StateDown, false)
	s.LastError = "session expired"
	w.observe(tunnel.Event{Tunnel: s, StoodDown: true})

	got := drain(w)
	if len(got) != 1 || got[0].title != "[home] hk 离线" || !strings.Contains(got[0].body, "session expired") {
		t.Fatalf("got %+v", got)
	}

	// A person dials it again: one recovery.
	w.observe(tunnel.Event{Tunnel: snap("hk", true, contract.StateUp, true)})
	if got := drain(w); len(got) != 1 || got[0].title != "[home] hk 已恢复" {
		t.Fatalf("got %+v", got)
	}
}

func TestStopIsNotAnAlert(t *testing.T) {
	w, now := newTestWatcher()
	w.observe(tunnel.Event{Tunnel: snap("a", true, contract.StateUp, true)})
	w.observe(tunnel.Event{Tunnel: snap("a", false, contract.StateDown, false)})
	*now = now.Add(time.Hour)
	w.check()
	if got := drain(w); len(got) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestAutoReconnectWithinGraceIsQuiet(t *testing.T) {
	w, now := newTestWatcher()
	w.observe(tunnel.Event{Tunnel: snap("a", true, contract.StateUp, true)})
	w.observe(tunnel.Event{At: *now, Tunnel: snap("a", true, contract.StateConnecting, true)})
	*now = now.Add(time.Minute)
	w.check()
	w.observe(tunnel.Event{Tunnel: snap("a", true, contract.StateUp, true)})
	*now = now.Add(time.Hour)
	w.check()
	if got := drain(w); len(got) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestAutoReconnectFailingAlertsOnceAfterGrace(t *testing.T) {
	w, now := newTestWatcher()
	w.observe(tunnel.Event{Tunnel: snap("a", true, contract.StateUp, true)})
	w.observe(tunnel.Event{At: *now, Tunnel: snap("a", true, contract.StateConnecting, true)})
	s := snap("a", true, contract.StateError, true)
	s.LastError = "login refused"
	w.observe(tunnel.Event{At: now.Add(30 * time.Second), Tunnel: s})

	*now = now.Add(2 * time.Minute)
	w.check()
	if got := drain(w); len(got) != 0 {
		t.Fatalf("alerted inside the grace period: %+v", got)
	}
	*now = now.Add(2 * time.Minute)
	w.check()
	w.check()
	got := drain(w)
	if len(got) != 1 || got[0].title != "[home] a 离线" || !strings.Contains(got[0].body, "login refused") {
		t.Fatalf("got %+v", got)
	}
	w.observe(tunnel.Event{Tunnel: snap("a", true, contract.StateUp, true)})
	if got := drain(w); len(got) != 1 || !strings.Contains(got[0].title, "已恢复") {
		t.Fatalf("got %+v", got)
	}
}

func TestAutostartThatNeverComesUpAlerts(t *testing.T) {
	w, now := newTestWatcher()
	// The state a wanted tunnel starts in, before any poll.
	w.observe(tunnel.Event{At: *now, Tunnel: snap("a", true, contract.StateDown, false)})
	*now = now.Add(5 * time.Minute)
	w.check()
	if got := drain(w); len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
}

func TestManualDiallingIsNotTimed(t *testing.T) {
	w, now := newTestWatcher("hk")
	w.observe(tunnel.Event{At: *now, Tunnel: snap("hk", true, contract.StateAuthRequired, true)})
	*now = now.Add(time.Hour)
	w.check()
	if got := drain(w); len(got) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestDisabledIsIgnored(t *testing.T) {
	w, now := newTestWatcher()
	s := snap("a", true, contract.StateDown, false)
	s.Disabled = true
	w.observe(tunnel.Event{At: *now, Tunnel: s})
	*now = now.Add(time.Hour)
	w.check()
	if got := drain(w); len(got) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestBarkPostsJSON(t *testing.T) {
	var got map[string]string
	var path, query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, query = r.URL.Path, r.URL.RawQuery
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"code":200}`))
	}))
	defer srv.Close()

	b := Bark{URL: srv.URL + "/devicekey?sound=alarm"}
	if err := b.Notify(context.Background(), "a 离线", "reason / with slash"); err != nil {
		t.Fatal(err)
	}
	if path != "/devicekey" || query != "sound=alarm" {
		t.Fatalf("path %q query %q", path, query)
	}
	if got["title"] != "a 离线" || got["body"] != "reason / with slash" || got["group"] != "vpn-gateway" {
		t.Fatalf("payload %+v", got)
	}
}

func TestBarkReportsFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad key", http.StatusBadRequest)
	}))
	defer srv.Close()
	if err := (Bark{URL: srv.URL}).Notify(context.Background(), "t", "b"); err == nil {
		t.Fatal("want an error")
	}
}
