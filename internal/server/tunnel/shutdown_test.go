package tunnel

import (
	"context"
	"log/slog"
	"testing"

	"github.com/vpn-gateway/vpn-gateway/internal/server"
)

// A restart is the usual reason this process exits, and the VPN client lives
// inside the container: stopping it ends the session and what comes back is a
// fresh authentication against a corporate gateway, not the tunnel that was
// there a second ago.
func TestShutdownLeavesContainersDialled(t *testing.T) {
	engine := &countingEngine{fakeEngine: fakeEngine{present: true}, exists: true, running: true}
	m := managerFor(t, engine, oneTunnel())

	m.Shutdown(context.Background())

	if _, _, stops, removes := engine.counts(); stops != 0 || removes != 0 {
		t.Errorf("shutdown touched the container: stops=%d removes=%d", stops, removes)
	}
	if !engine.running {
		t.Error("the container is no longer running")
	}
}

// The next start has to recognise what it left behind, or leaving it running
// would only mean an orphan beside a second container.
func TestAStillRunningContainerIsAdoptedNotRecreated(t *testing.T) {
	engine := &countingEngine{fakeEngine: fakeEngine{present: true}}
	m := managerFor(t, engine, oneTunnel())
	tun := m.tunnels[0]

	// First run: creates and starts.
	if err := tun.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	creates, starts, _, _ := engine.counts()
	if creates != 1 || starts != 1 {
		t.Fatalf("first reconcile: creates=%d starts=%d, want 1 and 1", creates, starts)
	}

	// Shutdown leaves it alone, and the next server start reconciles again
	// against the same configuration.
	m.Shutdown(context.Background())
	if err := tun.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	creates, starts, stops, removes := engine.counts()
	if creates != 1 || starts != 1 {
		t.Errorf("the running container was replaced: creates=%d starts=%d, want 1 and 1", creates, starts)
	}
	if stops != 0 || removes != 0 {
		t.Errorf("the running container was disturbed: stops=%d removes=%d", stops, removes)
	}
}

// An operator who wants a stopped server to leave nothing dialled says so.
func TestStopContainersOnExitTakesThemDown(t *testing.T) {
	engine := &countingEngine{fakeEngine: fakeEngine{present: true}, exists: true, running: true}
	cfg := serverConfigFor(t, oneTunnel())
	cfg.StopContainersOnExit = true
	m, err := NewManager(cfg, engine, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}

	m.Shutdown(context.Background())

	if _, _, stops, _ := engine.counts(); stops != 1 {
		t.Errorf("stops = %d, want 1", stops)
	}
}

// A tunnel with no container of its own has nothing to stop either way.
func TestShutdownSkipsContainerlessTunnels(t *testing.T) {
	engine := &countingEngine{fakeEngine: fakeEngine{present: true}}
	cfg := serverConfigFor(t, server.TunnelConfig{Name: "server-lan", Provider: "direct"})
	cfg.StopContainersOnExit = true
	m, err := NewManager(cfg, engine, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}

	m.Shutdown(context.Background())

	if _, _, stops, _ := engine.counts(); stops != 0 {
		t.Errorf("stops = %d, want 0", stops)
	}
}
