package tunnel

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/server"
	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

type fakeProber struct {
	mu      sync.Mutex
	err     error
	calls   int
	traffic time.Time
}

func (f *fakeProber) Probe(context.Context, string, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.err
}

func (f *fakeProber) LastTraffic(string) time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.traffic
}

func (f *fakeProber) set(err error, traffic time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err, f.traffic = err, traffic
}

func probedManager(t *testing.T, tc server.TunnelConfig) (*Manager, *Tunnel, *fakeProber) {
	t.Helper()
	cfg := &server.Config{
		StateDir: t.TempDir(),
		Probe:    server.ProbeConfig{Interval: 5 * time.Minute, URL: server.DefaultProbeURL},
		Tunnels:  []server.TunnelConfig{tc},
	}
	m, err := NewManager(cfg, nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeProber{}
	m.SetProber(p)
	return m, m.Tunnels()[0], p
}

var trojanNode = server.TunnelConfig{Name: "node", Provider: "trojan", Server: "node.test:443", Password: "x"}

func TestAProbedTunnelIsNotUpUntilSomethingComesBack(t *testing.T) {
	_, tr, _ := probedManager(t, trojanNode)
	if got := tr.Snapshot().Status.State; got != contract.StateConnecting {
		t.Fatalf("state before any probe = %q, want connecting", got)
	}
	fails := 0
	if next := tr.checkPath(context.Background(), &fails); next != 5*time.Minute {
		t.Errorf("next check in %s, want the interval", next)
	}
	if got := tr.Snapshot().Status.State; got != contract.StateUp {
		t.Fatalf("state after a good probe = %q, want up", got)
	}
}

func TestOneFailedProbeIsABlipTwoAreAnOutage(t *testing.T) {
	_, tr, p := probedManager(t, trojanNode)
	ctx := context.Background()
	fails := 0
	tr.checkPath(ctx, &fails)

	p.set(errors.New("i/o timeout"), time.Time{})
	if next := tr.checkPath(ctx, &fails); next != probeRetry {
		t.Errorf("after one failure next check in %s, want %s", next, probeRetry)
	}
	if got := tr.Snapshot().Status.State; got != contract.StateUp {
		t.Fatalf("one failure took it to %q", got)
	}
	if next := tr.checkPath(ctx, &fails); next != probeWhileDown {
		t.Errorf("while down next check in %s, want %s", next, probeWhileDown)
	}
	s := tr.Snapshot()
	if s.Status.State != contract.StateError || s.LastError != "i/o timeout" {
		t.Fatalf("after two failures: state %q error %q", s.Status.State, s.LastError)
	}

	p.set(nil, time.Time{})
	tr.checkPath(ctx, &fails)
	if s := tr.Snapshot(); s.Status.State != contract.StateUp || s.LastError != "" {
		t.Fatalf("after recovering: state %q error %q", s.Status.State, s.LastError)
	}
}

func TestRecentTrafficStandsInForAProbe(t *testing.T) {
	_, tr, p := probedManager(t, trojanNode)
	ctx := context.Background()
	fails := 0
	tr.checkPath(ctx, &fails)

	p.set(errors.New("would fail"), time.Now())
	tr.checkPath(ctx, &fails)
	if p.calls != 1 {
		t.Errorf("probed %d times with traffic flowing, want only the first", p.calls)
	}
	if got := tr.Snapshot().Status.State; got != contract.StateUp {
		t.Fatalf("state %q", got)
	}
}

// Data coming back through a node that refuses us is its cover website, so
// it must not be what brings a tunnel back.
func TestTrafficDoesNotRecoverATunnelThatIsDown(t *testing.T) {
	_, tr, p := probedManager(t, trojanNode)
	ctx := context.Background()
	fails := 0
	p.set(errors.New("refused"), time.Time{})
	tr.checkPath(ctx, &fails)
	tr.checkPath(ctx, &fails)

	p.set(errors.New("refused"), time.Now())
	tr.checkPath(ctx, &fails)
	if got := tr.Snapshot().Status.State; got != contract.StateError {
		t.Fatalf("state %q, want error", got)
	}
}

func TestProbeTargets(t *testing.T) {
	cases := []struct {
		tc   server.TunnelConfig
		want string
	}{
		{trojanNode, server.DefaultProbeURL},
		{server.TunnelConfig{Name: "n", Provider: "trojan", ProbeURL: "http://10.0.0.1/"}, "http://10.0.0.1/"},
		{server.TunnelConfig{Name: "n", Provider: "trojan", ProbeURL: server.ProbeOff}, ""},
		{server.TunnelConfig{Name: "n", Provider: "direct"}, ""},
		{server.TunnelConfig{Name: "n", Provider: "direct", ProbeURL: "http://192.168.2.1/"}, "http://192.168.2.1/"},
		{server.TunnelConfig{Name: "n", Provider: "mock", Image: "i"}, ""},
	}
	for _, c := range cases {
		if got := c.tc.ProbeTarget(server.DefaultProbeURL); got != c.want {
			t.Errorf("%s/%q: got %q, want %q", c.tc.Provider, c.tc.ProbeURL, got, c.want)
		}
	}
}

func TestStoppingAProbedTunnelTakesItDown(t *testing.T) {
	m, tr, _ := probedManager(t, trojanNode)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()

	waitFor(t, 5*time.Second, func() bool { return tr.Snapshot().Status.State == contract.StateUp })
	if err := m.Stop("node"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, func() bool {
		s := tr.Snapshot()
		return !s.Wanted && s.Status.State == contract.StateDown
	})
	cancel()
	<-done
}
