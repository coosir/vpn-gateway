package tunnel

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/server"
	"github.com/vpn-gateway/vpn-gateway/internal/server/runtime"
	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

// managerIn is managerFor with the state directory named, so a second manager
// can be built over what the first one left behind -- which is what a server
// restart is.
func managerIn(t *testing.T, dir string, engine runtime.Engine, cfgs ...server.TunnelConfig) *Manager {
	t.Helper()
	m, err := NewManager(&server.Config{StateDir: dir, PullPolicy: "never", Tunnels: cfgs}, engine, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// runManager supervises until the test ends, and waits for the supervisor to
// actually be gone: it writes into the state directory, and the temporary one
// is removed the moment the test returns.
func runManager(t *testing.T, m *Manager) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("the supervisor did not stop")
		}
	})
}

func wantedOf(t *testing.T, m *Manager, name string) bool {
	t.Helper()
	for _, s := range m.Snapshots() {
		if s.Name == name {
			return s.Wanted
		}
	}
	t.Fatalf("no tunnel named %q", name)
	return false
}

// A gateway that wants an SMS code cannot be dialled while nobody is watching.
// Restoring the wish is how an ordinary tunnel comes back after a restart, and
// is exactly what must not happen here: the server would authenticate, be
// asked for a code, and park at auth_required until somebody noticed.
func TestAManualTunnelDoesNotComeBackByItself(t *testing.T) {
	dir := t.TempDir()
	manual := server.TunnelConfig{
		Name: "yanfeng", Provider: "mock", Image: "coosir/vg-mock:latest",
		DataPort: 21000, ControlPort: 21001, Manual: true,
	}
	ordinary := server.TunnelConfig{
		Name: "office", Provider: "mock", Image: "coosir/vg-mock:latest",
		DataPort: 21002, ControlPort: 21003,
	}

	first := managerIn(t, dir, &fakeEngine{present: true}, manual, ordinary)
	if err := first.Start("yanfeng"); err != nil {
		t.Fatal(err)
	}
	if err := first.Start("office"); err != nil {
		t.Fatal(err)
	}
	if !wantedOf(t, first, "yanfeng") || !wantedOf(t, first, "office") {
		t.Fatal("starting a tunnel did not make it wanted")
	}

	// The server restarts.
	second := managerIn(t, dir, &fakeEngine{present: true}, manual, ordinary)
	if wantedOf(t, second, "yanfeng") {
		t.Error("a manual tunnel dialled again after a restart")
	}
	if !wantedOf(t, second, "office") {
		t.Error("an ordinary tunnel did not come back after a restart")
	}

	// And it still starts when a person asks.
	if err := second.Start("yanfeng"); err != nil {
		t.Fatal(err)
	}
	if !wantedOf(t, second, "yanfeng") {
		t.Error("a manual tunnel could not be started by hand")
	}
}

// parkedAgent stands in for a container whose VPN client has given up: the
// control plane answers, and what it reports is a tunnel that is no longer up.
func parkedAgent(t *testing.T, state contract.State, reason string) int {
	t.Helper()
	var mu sync.Mutex
	up := true

	mux := http.NewServeMux()
	mux.HandleFunc(contract.PathStatus, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		s := contract.Status{State: contract.StateUp}
		if !up {
			s = contract.Status{State: state, Error: reason}
		}
		mu.Unlock()
		json.NewEncoder(w).Encode(s)
	})
	mux.HandleFunc(contract.PathNetwork, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(contract.Network{})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// The server dials 127.0.0.1 at the tunnel's control port, so the port it
	// was given has to be the one this is listening on.
	_, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	// Up at first, then parked: the tunnel has to get up before losing it
	// means anything.
	go func() {
		time.Sleep(100 * time.Millisecond)
		mu.Lock()
		up = false
		mu.Unlock()
	}()
	return port
}

// Once a manual tunnel stops being up it has to wait to be asked again rather
// than being redialled: the next attempt raises a question only a person can
// answer, so a person has to be the one who starts it.
func TestAManualTunnelStandsDownWhenItStopsBeingUp(t *testing.T) {
	port := parkedAgent(t, contract.StateError, "gateway refused the session")
	cfg := server.TunnelConfig{
		Name: "yanfeng", Provider: "mock", Image: "coosir/vg-mock:latest",
		DataPort: port + 1000, ControlPort: port, Manual: true,
	}
	m := managerIn(t, t.TempDir(), &fakeEngine{present: true}, cfg)

	runManager(t, m)

	if err := m.Start("yanfeng"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 20*time.Second, func() bool { return !wantedOf(t, m, "yanfeng") })

	// Why it is down has to survive standing down, or whoever comes back to
	// it is shown a tunnel that looks merely switched off.
	var snap Snapshot
	for _, s := range m.Snapshots() {
		if s.Name == "yanfeng" {
			snap = s
		}
	}
	if snap.LastError == "" {
		t.Error("standing down threw away the reason the tunnel is not up")
	}

	// And it can be started again by hand.
	if err := m.Start("yanfeng"); err != nil {
		t.Fatal(err)
	}
	if !wantedOf(t, m, "yanfeng") {
		t.Error("a manual tunnel that stood down could not be started again")
	}
}

// An ordinary tunnel keeps the behaviour it had: it is the server's job to
// hold it up.
func TestAnOrdinaryTunnelKeepsDialling(t *testing.T) {
	port := parkedAgent(t, contract.StateError, "link lost")
	cfg := server.TunnelConfig{
		Name: "office", Provider: "mock", Image: "coosir/vg-mock:latest",
		DataPort: port + 1000, ControlPort: port,
	}
	m := managerIn(t, t.TempDir(), &fakeEngine{present: true}, cfg)

	runManager(t, m)

	if err := m.Start("office"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(6 * time.Second)
	if !wantedOf(t, m, "office") {
		t.Error("an ordinary tunnel stopped wanting to dial on its own")
	}
}
