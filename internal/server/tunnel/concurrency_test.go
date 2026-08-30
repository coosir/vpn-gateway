package tunnel

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/server"
	"github.com/vpn-gateway/vpn-gateway/internal/server/runtime"
)

// countingEngine records how often a container is actually created and
// started, which is what a duplicate request would show up as.
type countingEngine struct {
	fakeEngine
	mu      sync.Mutex
	creates int
	starts  int
	stops   int
	removes int
	running bool
	exists  bool
	// labels are what a real engine records at create time and reports back.
	// Without them every reconcile would see a container built from a
	// different configuration and recreate it.
	labels map[string]string
}

func (c *countingEngine) Inspect(ctx context.Context, name string) (runtime.Status, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return runtime.Status{
		Exists:     c.exists,
		Running:    c.running,
		ConfigHash: c.labels[runtime.LabelConfigHash],
	}, nil
}

func (c *countingEngine) Create(ctx context.Context, spec runtime.Spec) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.creates++
	c.exists = true
	c.labels = spec.Labels
	return nil
}

func (c *countingEngine) Start(ctx context.Context, name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.starts++
	c.running = true
	return nil
}

func (c *countingEngine) Stop(ctx context.Context, name string, grace int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stops++
	c.running = false
	return nil
}

func (c *countingEngine) Remove(ctx context.Context, name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removes++
	c.running = false
	c.exists = false
	c.labels = nil
	return nil
}

func (c *countingEngine) counts() (creates, starts, stops, removes int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.creates, c.starts, c.stops, c.removes
}

func serverConfigFor(t *testing.T, cfgs ...server.TunnelConfig) *server.Config {
	t.Helper()
	return &server.Config{StateDir: t.TempDir(), PullPolicy: "never", Tunnels: cfgs}
}

func managerFor(t *testing.T, engine runtime.Engine, cfgs ...server.TunnelConfig) *Manager {
	t.Helper()
	cfg := serverConfigFor(t, cfgs...)
	logger := slog.New(slog.DiscardHandler)
	if os.Getenv("VG_TEST_LOG") != "" {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	m, err := NewManager(cfg, engine, logger)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func oneTunnel() server.TunnelConfig {
	return server.TunnelConfig{
		Name: "office", Provider: "mock", Image: "coosir/vg-mock:latest",
		DataPort: 21000, ControlPort: 21001,
	}
}

// TestConcurrentStartsDialOnce is the question a second client pressing the
// same button asks. Every dial is a full authentication against a corporate
// gateway, so two clients agreeing that a tunnel should be up must not become
// two logins.
func TestConcurrentStartsDialOnce(t *testing.T) {
	engine := &countingEngine{fakeEngine: fakeEngine{present: true}}
	m := managerFor(t, engine, oneTunnel())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)

	// Twenty clients, all convinced they are the one turning it on.
	var wg sync.WaitGroup
	var accepted atomic.Int32
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := m.Start("office"); err == nil {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()

	// Every caller is told yes: asking for a state it is already in is not an
	// error, it is agreement.
	if accepted.Load() != 20 {
		t.Errorf("%d of 20 callers were refused", 20-accepted.Load())
	}

	waitFor(t, 5*time.Second, func() bool {
		_, starts, _, _ := engine.counts()
		return starts >= 1
	})
	time.Sleep(500 * time.Millisecond)

	creates, starts, _, removes := engine.counts()
	if starts != 1 {
		t.Errorf("the container was started %d times, want once", starts)
	}
	if creates > 1 {
		t.Errorf("the container was created %d times, want at most once", creates)
	}
	if removes != 0 {
		t.Errorf("the container was removed %d times while being asked to start", removes)
	}
}

// TestStartingAnAlreadyRunningTunnelChangesNothing covers the ordinary case:
// pressing connect on something already connected.
func TestStartingAnAlreadyRunningTunnelChangesNothing(t *testing.T) {
	engine := &countingEngine{fakeEngine: fakeEngine{present: true}}
	m := managerFor(t, engine, oneTunnel())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)

	if err := m.Start("office"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, func() bool {
		_, starts, _, _ := engine.counts()
		return starts == 1
	})

	before := countsOf(engine)
	for range 5 {
		if err := m.Start("office"); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(1500 * time.Millisecond)

	if after := countsOf(engine); after != before {
		t.Errorf("pressing connect on a running tunnel changed the container: %+v then %+v", before, after)
	}
}

// TestStopIsAlsoIdempotent: the same question the other way round.
func TestStopIsAlsoIdempotent(t *testing.T) {
	engine := &countingEngine{fakeEngine: fakeEngine{present: true}}
	m := managerFor(t, engine, oneTunnel())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)

	m.Start("office")
	waitFor(t, 5*time.Second, func() bool {
		_, starts, _, _ := engine.counts()
		return starts == 1
	})

	for range 5 {
		if err := m.Stop("office"); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, 5*time.Second, func() bool {
		_, _, stops, _ := engine.counts()
		return stops >= 1
	})
	time.Sleep(500 * time.Millisecond)

	if _, _, stops, _ := engine.counts(); stops != 1 {
		t.Errorf("the container was stopped %d times, want once", stops)
	}
}

// TestStartingAnUnknownOrDisabledTunnelIsRefused makes sure the guard is not
// simply accepting everything.
func TestStartingAnUnknownOrDisabledTunnelIsRefused(t *testing.T) {
	disabled := oneTunnel()
	disabled.Name = "off"
	disabled.Disabled = true
	m := managerFor(t, &countingEngine{}, oneTunnel(), disabled)

	if err := m.Start("nosuch"); err == nil {
		t.Error("starting a tunnel that does not exist was accepted")
	}
	if err := m.Start("off"); err == nil {
		t.Error("starting a disabled tunnel was accepted")
	}
}

type engineCounts struct{ creates, starts, stops, removes int }

func countsOf(e *countingEngine) engineCounts {
	c, s, st, r := e.counts()
	return engineCounts{c, s, st, r}
}

func waitFor(t *testing.T, within time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition never held")
}
