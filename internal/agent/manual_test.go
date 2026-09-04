package agent

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

// diedProvider comes up, carries traffic for a moment, and then loses the
// session. It is what a rejected cookie or an expired session looks like from
// out here: the tunnel was working, and now it is not.
type diedProvider struct{ runs atomic.Int32 }

func (p *diedProvider) Capabilities() []string { return []string{contract.CapTCP} }

func (p *diedProvider) Run(ctx context.Context, cfg Config, rep Reporter) error {
	p.runs.Add(1)
	rep.SetState(contract.StateUp, nil)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(100 * time.Millisecond):
	}
	return errors.New("Cookie was rejected by server; exiting.")
}

func (p *diedProvider) Dial(context.Context, string, string) (net.Conn, error) {
	return nil, errNotDialable
}
func (p *diedProvider) Answer(contract.AuthAnswer) error { return nil }

func manualAgent(p Provider, manual bool) *Agent {
	return &Agent{
		cfg:         Config{Provider: "died"},
		provider:    p,
		log:         slog.New(slog.DiscardHandler),
		maxAttempts: 3,
		manual:      manual,
		state:       contract.StateConnecting,
		since:       time.Now(),
		subs:        map[int]chan contract.Event{},
		redial:      make(chan struct{}, 1),
	}
}

// A session that dies is normally redialled at once, and for a gateway that
// wants a code off somebody's phone that is a login nobody asked for and a
// question raised to an empty room. Keeping the server from asking is only
// half of it: this is the agent inside the container deciding on its own.
func TestAManualTunnelDoesNotRedialWhenTheSessionDies(t *testing.T) {
	p := &diedProvider{}
	a := manualAgent(p, true)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	go a.Supervise(ctx)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && p.runs.Load() < 1 {
		time.Sleep(20 * time.Millisecond)
	}
	if p.runs.Load() != 1 {
		t.Fatalf("dialled %d times before the session died, want 1", p.runs.Load())
	}

	// Well past the retry backoff, which is where an ordinary tunnel would
	// have dialled again.
	time.Sleep(5 * time.Second)
	if got := p.runs.Load(); got != 1 {
		t.Errorf("dialled %d times without being asked, want 1", got)
	}
	if st := a.Status(); st.State == contract.StateUp {
		t.Errorf("state = %q, want anything but up", st.State)
	}
}

// Parked is not finished: the person with the phone says when.
func TestAManualTunnelDialsAgainWhenAsked(t *testing.T) {
	p := &diedProvider{}
	a := manualAgent(p, true)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	go a.Supervise(ctx)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && p.runs.Load() < 1 {
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(2 * time.Second) // let it settle into waiting

	a.Reconnect()
	deadline = time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) && p.runs.Load() < 2 {
		time.Sleep(20 * time.Millisecond)
	}
	if got := p.runs.Load(); got < 2 {
		t.Errorf("dialled %d times after being asked to reconnect, want 2", got)
	}
}

// An ordinary tunnel keeps the behaviour it had: losing a session is
// something the server is expected to fix by itself.
func TestAnOrdinaryTunnelRedialsWhenTheSessionDies(t *testing.T) {
	p := &diedProvider{}
	a := manualAgent(p, false)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	go a.Supervise(ctx)

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && p.runs.Load() < 2 {
		time.Sleep(20 * time.Millisecond)
	}
	if got := p.runs.Load(); got < 2 {
		t.Errorf("dialled %d times after losing a session, want it to redial", got)
	}
}
