package tunnel

import (
	"sync"
	"testing"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/server"
	"github.com/vpn-gateway/vpn-gateway/internal/server/proxy"
	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

// recordingSink is a listener that remembers what it was told.
type recordingSink struct {
	mu      sync.Mutex
	set     map[string]proxy.Route
	removed []string
}

func (r *recordingSink) SetRoute(rt proxy.Route) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.set == nil {
		r.set = map[string]proxy.Route{}
	}
	r.set[rt.Name] = rt
	return nil
}

func (r *recordingSink) RemoveRoute(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.set, name)
	r.removed = append(r.removed, name)
}

func (r *recordingSink) route(name string) (proxy.Route, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rt, ok := r.set[name]
	return rt, ok
}

// TestTunnelsChangeWhileTheServerRuns is the admin page's promise: a tunnel
// added is supervised and routed at once, one edited is replaced in place, and
// one removed is gone from both -- without a restart.
func TestTunnelsChangeWhileTheServerRuns(t *testing.T) {
	m := managerIn(t, t.TempDir(), &fakeEngine{},
		server.TunnelConfig{Name: "lan", Provider: "direct"})
	sink := &recordingSink{}
	m.SetRouteSink(sink)
	events, release := m.Subscribe()
	defer release()
	runManager(t, m)

	// Added: a direct tunnel is up as soon as it exists.
	if err := m.Put(server.TunnelConfig{Name: "office", Provider: "direct"}); err != nil {
		t.Fatal(err)
	}
	if rt, ok := sink.route("office"); !ok || !rt.Direct {
		t.Fatalf("listener route for an added tunnel = %+v, %v", rt, ok)
	}
	waitFor(t, 5*time.Second, func() bool { return stateOf(m, "office") == contract.StateUp })

	// Edited: now an upstream trojan node, routed there.
	if err := m.Put(server.TunnelConfig{Name: "office", Provider: "trojan", Server: "hk.example:8443", Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	rt, _ := sink.route("office")
	if rt.TrojanOutbound == nil || rt.TrojanOutbound.Server != "hk.example" || rt.TrojanOutbound.ServerPort != 8443 {
		t.Fatalf("listener route for an edited tunnel = %+v", rt)
	}
	if got, _ := m.Config("office"); got.Provider != "trojan" {
		t.Errorf("configuration after the edit names provider %q", got.Provider)
	}
	if n := len(m.Snapshots()); n != 2 {
		t.Errorf("%d tunnels after an edit, want 2", n)
	}

	// Disabled: out of the listener, kept in the list.
	if err := m.Put(server.TunnelConfig{Name: "office", Provider: "direct", Disabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, ok := sink.route("office"); ok {
		t.Error("a disabled tunnel is still in the listener")
	}

	// Removed.
	if err := m.Remove("office"); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Lookup("office"); ok {
		t.Error("a removed tunnel is still managed")
	}
	if err := m.Remove("office"); err == nil {
		t.Error("removing a tunnel twice did not fail")
	}
	sawRemoved := false
	for !sawRemoved {
		select {
		case ev := <-events:
			sawRemoved = ev.Removed && ev.Tunnel.Name == "office"
		case <-time.After(5 * time.Second):
			t.Fatal("no event said the tunnel was removed")
		}
	}

	// The tunnel nobody touched carried on.
	if stateOf(m, "lan") != contract.StateUp {
		t.Errorf("untouched tunnel is %s", stateOf(m, "lan"))
	}
}

func stateOf(m *Manager, name string) contract.State {
	t, ok := m.Lookup(name)
	if !ok {
		return ""
	}
	return t.Snapshot().Status.State
}
