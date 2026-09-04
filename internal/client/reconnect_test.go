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

// A server that restarted forgot every session it issued, so the client's
// token stops being one it knows. That is not a failure to sit in: logging in
// again fixes it, and nobody should have to notice and press connect.
func TestALostSessionIsBroughtBack(t *testing.T) {
	s, _ := newSession(t)
	if err := s.ImportBundle([]byte(bundleJSON)); err != nil {
		t.Fatal(err)
	}

	var attempts atomic.Int32
	s.connectFor(t, func(context.Context) error {
		attempts.Add(1)
		return errors.New("dial tcp: connection refused")
	})

	s.retryConnect(errors.New("the server no longer knows this session"))
	t.Cleanup(func() {
		s.mu.Lock()
		s.endRetry()
		s.mu.Unlock()
	})

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) && attempts.Load() < 2 {
		time.Sleep(50 * time.Millisecond)
	}
	if got := attempts.Load(); got < 2 {
		t.Errorf("tried %d times to come back, want it to keep trying", got)
	}
	if st := s.Status(); st.Phase != PhaseConnecting {
		t.Errorf("phase = %q while reconnecting, want connecting", st.Phase)
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
	s.connectFor(t, func(context.Context) error {
		attempts.Add(1)
		return ErrBadCredentials
	})

	s.retryConnect(errors.New("the server no longer knows this session"))
	t.Cleanup(func() {
		s.mu.Lock()
		s.endRetry()
		s.mu.Unlock()
	})

	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) && s.Status().Phase != PhaseFailed {
		time.Sleep(50 * time.Millisecond)
	}
	if st := s.Status(); st.Phase != PhaseFailed {
		t.Fatalf("phase = %q, want failed once the credentials were refused", st.Phase)
	}

	time.Sleep(4 * time.Second)
	if got := attempts.Load(); got != 1 {
		t.Errorf("sent the refused password %d times, want once", got)
	}
}

// Pressing disconnect has to end the argument.
func TestDisconnectingStopsTheRetrying(t *testing.T) {
	s, _ := newSession(t)
	if err := s.ImportBundle([]byte(bundleJSON)); err != nil {
		t.Fatal(err)
	}

	var attempts atomic.Int32
	s.connectFor(t, func(context.Context) error {
		attempts.Add(1)
		return errors.New("dial tcp: connection refused")
	})

	s.retryConnect(errors.New("the server no longer knows this session"))
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) && attempts.Load() < 1 {
		time.Sleep(50 * time.Millisecond)
	}

	if err := s.Disconnect(); err != nil {
		t.Fatal(err)
	}
	settled := attempts.Load()

	time.Sleep(4 * time.Second)
	if got := attempts.Load(); got != settled {
		t.Errorf("kept trying after disconnect: %d then %d", settled, got)
	}
}

// Two callers can now want a connection at the same time -- a person pressing
// connect, and the loop bringing a dropped one back. Only one engine may be
// built: two of them fight over the same interface and routing table.
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
