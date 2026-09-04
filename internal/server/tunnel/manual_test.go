package tunnel

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
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

// fakeAgent stands in for the control plane inside a tunnel's container.
type fakeAgent struct {
	mu    sync.Mutex
	state contract.State
	err   string
	port  int
}

func newFakeAgent(t *testing.T, state contract.State) *fakeAgent {
	t.Helper()
	a := &fakeAgent{state: state}

	mux := http.NewServeMux()
	mux.HandleFunc(contract.PathStatus, func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		s := contract.Status{State: a.state, Error: a.err}
		a.mu.Unlock()
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
	if a.port, err = strconv.Atoi(portStr); err != nil {
		t.Fatal(err)
	}
	return a
}

// standingContainer leaves the engine holding a running container built from
// this tunnel's current configuration, so reconcile adopts it rather than
// deciding the configuration changed and rebuilding it.
func standingContainer(t *testing.T, m *Manager, engine *countingEngine, name string) {
	t.Helper()
	tun, ok := m.Lookup(name)
	if !ok {
		t.Fatalf("no tunnel named %q", name)
	}
	hash, err := tun.writeEnvFile()
	if err != nil {
		t.Fatal(err)
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	engine.exists, engine.running = true, true
	engine.labels = map[string]string{runtime.LabelConfigHash: hash}
}

func (a *fakeAgent) park(state contract.State, reason string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.state, a.err = state, reason
}

// parkedAgent reports up at first and then gives up, which is what a session
// dropping looks like from outside the container.
func parkedAgent(t *testing.T, state contract.State, reason string) int {
	t.Helper()
	a := newFakeAgent(t, contract.StateUp)
	go func() {
		time.Sleep(100 * time.Millisecond)
		a.park(state, reason)
	}()
	return a.port
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

// The code somebody typed bought a session, and restarting this server must
// not spend it again.
//
// A manual tunnel starts down, and taking that to mean "stop whatever is
// running" tears down a live session on every upgrade -- which on a gateway
// that wants an SMS code is the most expensive thing this server can do.
// What is up is adopted instead.
func TestARestartAdoptsAManualTunnelThatIsStillUp(t *testing.T) {
	agent := newFakeAgent(t, contract.StateUp)
	cfg := server.TunnelConfig{
		Name: "yanfeng", Provider: "mock", Image: "coosir/vg-openconnect:latest",
		DataPort: agent.port + 1000, ControlPort: agent.port, Manual: true,
	}
	engine := &countingEngine{fakeEngine: fakeEngine{present: true}}
	m := managerIn(t, t.TempDir(), engine, cfg)
	// The container survived the restart, built from this very configuration,
	// which is what an upgrade without stop_containers_on_exit leaves behind.
	standingContainer(t, m, engine, "yanfeng")

	if wantedOf(t, m, "yanfeng") {
		t.Fatal("a manual tunnel came back wanted before anything looked at the container")
	}
	runManager(t, m)

	waitFor(t, 20*time.Second, func() bool { return wantedOf(t, m, "yanfeng") })

	time.Sleep(time.Second)
	if _, _, stops, removes := engine.counts(); stops != 0 || removes != 0 {
		t.Errorf("the live session was torn down: %d stops, %d removes", stops, removes)
	}
}

// The same restart with nothing left running must not start dialling: there
// is no session to keep, and dialling is what needs a person.
func TestARestartDoesNotReviveAManualTunnelThatGaveUp(t *testing.T) {
	agent := newFakeAgent(t, contract.StateError)
	agent.park(contract.StateError, "gateway refused the session")
	cfg := server.TunnelConfig{
		Name: "yanfeng", Provider: "mock", Image: "coosir/vg-openconnect:latest",
		DataPort: agent.port + 1000, ControlPort: agent.port, Manual: true,
	}
	engine := &countingEngine{fakeEngine: fakeEngine{present: true}}
	m := managerIn(t, t.TempDir(), engine, cfg)
	standingContainer(t, m, engine, "yanfeng")
	runManager(t, m)

	time.Sleep(6 * time.Second)
	if wantedOf(t, m, "yanfeng") {
		t.Error("a manual tunnel whose agent had given up was adopted anyway")
	}
}

// The agent decides for itself whether to redial, so the setting has to reach
// it. Enforcing manual only on this side leaves the container redialling on
// its own, which is the half of the problem nobody can see from here.
func TestManualTravelsToTheAgent(t *testing.T) {
	for _, tc := range []struct {
		name   string
		manual bool
		want   string
	}{
		{"manual", true, "true"},
		{"ordinary", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := server.TunnelConfig{
				Name: "yanfeng", Provider: "mock", Image: "coosir/vg-openconnect:latest",
				DataPort: 21000, ControlPort: 21001, Manual: tc.manual,
			}
			dir := t.TempDir()
			m := managerIn(t, dir, &fakeEngine{present: true}, cfg)
			tun, ok := m.Lookup("yanfeng")
			if !ok {
				t.Fatal("no tunnel")
			}
			if _, err := tun.writeEnvFile(); err != nil {
				t.Fatal(err)
			}
			// What reaches the container, not what this side believes.
			body, err := os.ReadFile(tun.cfg.EnvFilePath(dir))
			if err != nil {
				t.Fatal(err)
			}
			var extra map[string]string
			for _, line := range strings.Split(string(body), "\n") {
				if raw, ok := strings.CutPrefix(line, "VG_EXTRA_JSON="); ok {
					if err := json.Unmarshal([]byte(raw), &extra); err != nil {
						t.Fatal(err)
					}
				}
			}
			if got := extra["manual"]; got != tc.want {
				t.Errorf("the agent is told manual=%q, want %q", got, tc.want)
			}
		})
	}
}
