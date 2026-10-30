package client

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/server/clientcfg"
)

// connectFor stands in for building and starting the routing engine, which
// needs a server to log in to and an interface to bring up. What these tests
// are about is when the attempt is made, not what it produces.
func (s *Session) connectFor(t *testing.T, attempt func(context.Context) error) {
	t.Helper()
	s.newEngine = func(ctx context.Context, _ *Config, _ *clientcfg.Bundle, _ *slog.Logger) (*Client, error) {
		return nil, attempt(ctx)
	}
}

// engineWithoutGateway stands in for an engine that starts, but whose
// gateway does: attempt decides how signing in to the gateway goes.
func (s *Session) engineWithoutGateway(t *testing.T, attempt func(context.Context) error) {
	t.Helper()
	s.newEngine = func(ctx context.Context, _ *Config, bundle *clientcfg.Bundle, log *slog.Logger) (*Client, error) {
		if bundle != nil {
			if err := attempt(ctx); err != nil {
				return nil, &GatewayError{err}
			}
		}
		return &Client{log: log, selected: map[string]string{}}, nil
	}
	s.attach = func(ctx context.Context, _ *Client, _ *clientcfg.Bundle) error {
		if err := attempt(ctx); err != nil {
			return &GatewayError{err}
		}
		return errors.New("attached for real") // never reached in these tests
	}
}

func awaitGateway(t *testing.T, s *Session, want GatewayPhase, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) && s.Status().Gateway.Phase != want {
		time.Sleep(50 * time.Millisecond)
	}
	if got := s.Status().Gateway.Phase; got != want {
		t.Fatalf("gateway phase = %q, want %q", got, want)
	}
}

// A gateway server that cannot be reached is no reason to stop proxying
// everything else: the engine starts without the gateway, and the gateway is
// retried on its own.
func TestAGatewayThatCannotSignInDoesNotStopTheEngine(t *testing.T) {
	s, _ := newSession(t)
	if err := s.ImportBundle([]byte(bundleJSON)); err != nil {
		t.Fatal(err)
	}
	var attempts atomic.Int32
	s.engineWithoutGateway(t, func(context.Context) error {
		attempts.Add(1)
		return errors.New("dial tcp: connection refused")
	})
	t.Cleanup(func() { s.Disconnect() })

	if err := s.Connect(context.Background()); err != nil {
		t.Fatalf("connect failed with the gateway down: %v", err)
	}
	if st := s.Status(); st.Phase != PhaseConnected {
		t.Fatalf("phase = %q, want connected", st.Phase)
	}

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) && attempts.Load() < 3 {
		time.Sleep(50 * time.Millisecond)
	}
	if got := attempts.Load(); got < 3 {
		t.Errorf("tried the gateway %d times, want it to keep trying", got)
	}
	if st := s.Status(); st.Phase != PhaseConnected || st.Gateway.Phase != GatewayConnecting {
		t.Errorf("phase = %q, gateway = %q while retrying; want connected and connecting", st.Phase, st.Gateway.Phase)
	}
}

// A password the server does not accept will not start working however many
// times it is sent, and every attempt is one more against an account that may
// lock.
func TestRefusedCredentialsStopTheRetrying(t *testing.T) {
	s, _ := newSession(t)
	if err := s.ImportBundle([]byte(bundleJSON)); err != nil {
		t.Fatal(err)
	}
	var attempts atomic.Int32
	s.engineWithoutGateway(t, func(context.Context) error {
		attempts.Add(1)
		return ErrBadCredentials
	})
	t.Cleanup(func() { s.Disconnect() })

	if err := s.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	awaitGateway(t, s, GatewayFailed, time.Second)

	time.Sleep(4 * time.Second)
	if got := attempts.Load(); got != 1 {
		t.Errorf("sent the refused password %d times, want once", got)
	}
	if st := s.Status(); st.Phase != PhaseConnected {
		t.Errorf("phase = %q, want the engine still connected", st.Phase)
	}
}

// Switching the gateway off has to end the argument, and leave the rest of
// the engine running.
func TestSwitchingTheGatewayOffStopsTheRetrying(t *testing.T) {
	s, _ := newSession(t)
	if err := s.ImportBundle([]byte(bundleJSON)); err != nil {
		t.Fatal(err)
	}
	var attempts atomic.Int32
	s.engineWithoutGateway(t, func(context.Context) error {
		attempts.Add(1)
		return errors.New("dial tcp: connection refused")
	})
	t.Cleanup(func() { s.Disconnect() })

	if err := s.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGatewayEnabled(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	settled := attempts.Load()

	time.Sleep(4 * time.Second)
	if got := attempts.Load(); got != settled {
		t.Errorf("kept trying after the gateway was switched off: %d then %d", settled, got)
	}
	st := s.Status()
	if st.Phase != PhaseConnected || st.Gateway.Phase != GatewayOff {
		t.Errorf("phase = %q, gateway = %q; want connected and off", st.Phase, st.Gateway.Phase)
	}
	if !s.Settings().GatewayDisabled {
		t.Error("the switch was not remembered")
	}
}

// Pressing disconnect ends the gateway's retrying along with everything else.
func TestDisconnectingStopsTheRetrying(t *testing.T) {
	s, _ := newSession(t)
	if err := s.ImportBundle([]byte(bundleJSON)); err != nil {
		t.Fatal(err)
	}
	var attempts atomic.Int32
	s.engineWithoutGateway(t, func(context.Context) error {
		attempts.Add(1)
		return errors.New("dial tcp: connection refused")
	})

	if err := s.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.Disconnect(); err != nil {
		t.Fatal(err)
	}
	settled := attempts.Load()

	time.Sleep(4 * time.Second)
	if got := attempts.Load(); got != settled {
		t.Errorf("kept trying after disconnect: %d then %d", settled, got)
	}
	if st := s.Status(); st.Gateway.Phase != GatewayIdle {
		t.Errorf("gateway = %q after disconnect, want idle", st.Gateway.Phase)
	}
}

// Switching the gateway on with nothing running is the one-click connect: it
// brings the engine up.
func TestSwitchingTheGatewayOnConnects(t *testing.T) {
	s, _ := newSession(t)
	if err := s.ImportBundle([]byte(bundleJSON)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGatewayEnabled(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	var withGateway atomic.Bool
	s.newEngine = func(_ context.Context, _ *Config, bundle *clientcfg.Bundle, log *slog.Logger) (*Client, error) {
		withGateway.Store(bundle != nil)
		return &Client{log: log, selected: map[string]string{}}, nil
	}
	t.Cleanup(func() { s.Disconnect() })

	if err := s.SetGatewayEnabled(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if st := s.Status(); st.Phase != PhaseConnected {
		t.Fatalf("phase = %q, want connected", st.Phase)
	}
	if !withGateway.Load() {
		t.Error("the engine was built without the gateway")
	}
}

// Two callers can want a connection at the same time -- a person pressing
// connect, and the gateway switch. Only one engine may be built: two of them
// fight over the same interface and routing table.
func TestOnlyOneEngineIsEverBuilt(t *testing.T) {
	s, _ := newSession(t)
	if err := s.ImportBundle([]byte(bundleJSON)); err != nil {
		t.Fatal(err)
	}

	var inFlight, peak atomic.Int32
	s.connectFor(t, func(ctx context.Context) error {
		n := inFlight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(300 * time.Millisecond)
		inFlight.Add(-1)
		return errors.New("dial tcp: connection refused")
	})

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.Connect(context.Background())
		}()
	}
	wg.Wait()

	if got := peak.Load(); got > 1 {
		t.Errorf("%d engines were being built at once, want at most 1", got)
	}
}

// Without a username or password there is nothing to retry with until
// somebody fills them in.
func TestMissingCredentialsAreNotRetried(t *testing.T) {
	s, _ := newSession(t)
	if err := s.ImportBundle([]byte(bundleJSON)); err != nil {
		t.Fatal(err)
	}
	var attempts atomic.Int32
	s.engineWithoutGateway(t, func(context.Context) error {
		attempts.Add(1)
		return ErrNoCredentials
	})
	t.Cleanup(func() { s.Disconnect() })

	if err := s.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	awaitGateway(t, s, GatewayFailed, time.Second)
	time.Sleep(3 * time.Second)
	if got := attempts.Load(); got != 1 {
		t.Errorf("tried %d times with no credentials, want once", got)
	}
}
