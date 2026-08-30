package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

// Retry backoff bounds for redialing a failed tunnel. The agent reconnects
// in-process first because that is far cheaper than the server recreating the
// container, and it can preserve a provider's authenticated session.
const (
	retryMin = 2 * time.Second
	retryMax = 60 * time.Second
)

// DefaultMaxAttempts is how many times a tunnel dials before giving up and
// waiting to be told to try again.
//
// Every attempt is a full authentication against a corporate gateway, and
// enough failures in a row is what locks an account. Retrying forever turns a
// gateway that is refusing us into a machine that keeps knocking, so the
// default is small: enough to ride out a network blip, not enough to look
// like anything else.
const DefaultMaxAttempts = 3

// Agent owns the state of one tunnel: it supervises the Provider, tracks
// uptime and traffic, and serves the control plane. It is the only writer of
// contract.Status.
type Agent struct {
	cfg      Config
	provider Provider
	log      *slog.Logger
	// secret authenticates both planes. Empty disables authentication, which
	// is only appropriate for local development.
	secret string
	// maxAttempts bounds how many times a failing tunnel dials before it
	// waits to be told to try again.
	maxAttempts int

	mu          sync.RWMutex
	state       contract.State
	since       time.Time
	connectedAt *time.Time
	lastErr     error
	network     contract.Network
	challenge   *contract.Challenge

	tx, rx      atomic.Uint64
	activeConns atomic.Int64
	totalConns  atomic.Uint64

	subsMu sync.Mutex
	subs   map[int]chan contract.Event
	nextID int

	// redial fires when something asks for an immediate reconnect.
	redial chan struct{}
}

// NewAgent builds an agent for cfg using the provider registered under
// cfg.Provider.
func NewAgent(cfg Config, log *slog.Logger) (*Agent, error) {
	p, err := New(cfg.Provider)
	if err != nil {
		return nil, err
	}
	attempts := cfg.Int("max_attempts", DefaultMaxAttempts)
	if attempts < 1 {
		attempts = 1
	}
	return &Agent{
		cfg:         cfg,
		provider:    p,
		log:         log,
		secret:      cfg.Secret,
		maxAttempts: attempts,
		state:       contract.StateConnecting,
		since:       time.Now(),
		subs:        map[int]chan contract.Event{},
		redial:      make(chan struct{}, 1),
	}, nil
}

// Capabilities reports what the underlying provider supports.
func (a *Agent) Capabilities() []string { return a.provider.Capabilities() }

// Status renders the current contract status.
func (a *Agent) Status() contract.Status {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.statusLocked()
}

func (a *Agent) statusLocked() contract.Status {
	s := contract.Status{
		Contract:     contract.Version,
		Provider:     a.cfg.Provider,
		State:        a.state,
		Since:        a.since,
		ConnectedAt:  a.connectedAt,
		Capabilities: a.provider.Capabilities(),
		Traffic: contract.Traffic{
			TxBytes:     a.tx.Load(),
			RxBytes:     a.rx.Load(),
			ActiveConns: int(a.activeConns.Load()),
			TotalConns:  a.totalConns.Load(),
		},
	}
	// Uptime is the current connection's duration, so it resets on every
	// reconnect even though ConnectedAt is also updated.
	if a.state == contract.StateUp && a.connectedAt != nil {
		s.UptimeSeconds = int64(time.Since(*a.connectedAt).Seconds())
	}
	if a.lastErr != nil {
		s.Error = a.lastErr.Error()
	}
	return s
}

// Network returns the routes and DNS pushed by the VPN.
func (a *Agent) Network() contract.Network {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.network
}

// Challenge returns the pending interactive prompt, or nil.
func (a *Agent) Challenge() *contract.Challenge {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.challenge
}

// Answer forwards a challenge response to the provider and clears the pending
// challenge on success.
func (a *Agent) Answer(ans contract.AuthAnswer) error {
	a.mu.RLock()
	ch := a.challenge
	a.mu.RUnlock()
	if ch == nil {
		return errors.New("no challenge is pending")
	}
	if ans.ID != ch.ID {
		return fmt.Errorf("challenge %q is no longer pending", ans.ID)
	}
	if err := a.provider.Answer(ans); err != nil {
		return err
	}
	a.SetChallenge(nil)
	return nil
}

// Reconnect asks the supervisor to tear down and redial immediately.
func (a *Agent) Reconnect() {
	select {
	case a.redial <- struct{}{}:
	default: // a redial is already queued
	}
}

// Dial opens a connection through the tunnel. It refuses while the tunnel is
// not up, so callers get a clear error instead of a stalled connection.
func (a *Agent) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	a.mu.RLock()
	state := a.state
	a.mu.RUnlock()
	if state != contract.StateUp {
		return nil, fmt.Errorf("tunnel is %s, not up", state)
	}
	return a.provider.Dial(ctx, network, addr)
}

// --- Reporter -------------------------------------------------------------

// SetState records a provider state transition and publishes it.
func (a *Agent) SetState(s contract.State, err error) {
	a.mu.Lock()
	if a.state == s && errors.Is(err, a.lastErr) {
		a.mu.Unlock()
		return
	}
	a.state = s
	a.since = time.Now()
	a.lastErr = err
	if s == contract.StateUp {
		now := a.since
		a.connectedAt = &now
	}
	status := a.statusLocked()
	a.mu.Unlock()

	if err != nil {
		a.log.Warn("state change", "state", s, "error", err)
	} else {
		a.log.Info("state change", "state", s)
	}
	a.publish(contract.Event{Type: contract.EventStatus, At: time.Now(), Status: &status})
}

// SetNetwork publishes the routes and DNS the VPN pushed.
func (a *Agent) SetNetwork(n contract.Network) {
	a.mu.Lock()
	a.network = n
	a.mu.Unlock()
	a.log.Info("network pushed", "routes", n.Routes, "dns", n.DNS, "mtu", n.MTU)
	a.publish(contract.Event{Type: contract.EventNetwork, At: time.Now(), Network: &n})
}

// SetChallenge raises or clears an interactive authentication prompt.
func (a *Agent) SetChallenge(ch *contract.Challenge) {
	a.mu.Lock()
	a.challenge = ch
	a.mu.Unlock()
	if ch == nil {
		return
	}
	a.log.Info("auth challenge", "type", ch.Type, "prompt", ch.Prompt)
	a.publish(contract.Event{Type: contract.EventChallenge, At: time.Now(), Challenge: ch})
}

// Log emits a line to the container log and the event stream.
func (a *Agent) Log(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	a.log.Info(msg)
	a.publish(contract.Event{Type: contract.EventLog, At: time.Now(), Log: msg})
}

// --- traffic accounting ---------------------------------------------------

func (a *Agent) connOpened()   { a.activeConns.Add(1); a.totalConns.Add(1) }
func (a *Agent) connClosed()   { a.activeConns.Add(-1) }
func (a *Agent) addTx(n int64) { a.tx.Add(uint64(n)) }
func (a *Agent) addRx(n int64) { a.rx.Add(uint64(n)) }

// --- event fan-out --------------------------------------------------------

// Subscribe returns a channel of events and a function to release it. The
// channel is buffered; a subscriber that falls behind drops events rather
// than stalling the agent.
func (a *Agent) Subscribe() (<-chan contract.Event, func()) {
	ch := make(chan contract.Event, 32)
	a.subsMu.Lock()
	id := a.nextID
	a.nextID++
	a.subs[id] = ch
	a.subsMu.Unlock()

	return ch, func() {
		a.subsMu.Lock()
		if c, ok := a.subs[id]; ok {
			delete(a.subs, id)
			close(c)
		}
		a.subsMu.Unlock()
	}
}

func (a *Agent) publish(ev contract.Event) {
	a.subsMu.Lock()
	defer a.subsMu.Unlock()
	for _, ch := range a.subs {
		select {
		case ch <- ev:
		default: // slow subscriber, drop
		}
	}
}

// --- supervisor -----------------------------------------------------------

// Supervise runs the provider until ctx is cancelled.
//
// A failed dial is retried with backoff, but only a few times: see
// DefaultMaxAttempts. After that the tunnel parks in error and waits to be
// told to try again, rather than knocking at a gateway that is refusing it.
func (a *Agent) Supervise(ctx context.Context) {
	backoff := retryMin
	attempts := 0
	for {
		attempts++
		runCtx, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- a.provider.Run(runCtx, a.cfg, a) }()

		var err error
		select {
		case <-ctx.Done():
			cancel()
			<-done
			return
		case <-a.redial:
			a.Log("reconnect requested")
			cancel()
			<-done
			backoff = retryMin
			attempts = 0
			continue
		case err = <-done:
			cancel()
		}

		switch {
		case ctx.Err() != nil:
			return
		case err == nil:
			a.SetState(contract.StateDown, nil)
			a.log.Info("provider exited cleanly, not redialing")
			return
		case errors.Is(err, ErrPermanent):
			a.SetState(contract.StateError, err)
			a.log.Error("permanent failure, not redialing", "error", err)
			// Parked rather than returned: an explicit reconnect can still
			// revive this once whatever was wrong has been dealt with.
			if !a.waitForRedial(ctx) {
				return
			}
			backoff, attempts = retryMin, 0
			continue
		}

		a.SetState(contract.StateError, err)

		if attempts >= a.maxAttempts {
			a.log.Warn("giving up after repeated failures; waiting to be told to try again",
				"attempts", attempts, "error", err)
			a.Log("gave up after %d attempts; reconnect to try again", attempts)
			if !a.waitForRedial(ctx) {
				return
			}
			backoff, attempts = retryMin, 0
			continue
		}

		wait := jitter(backoff)
		a.Log("redialing in %s (attempt %d of %d)", wait.Round(time.Second), attempts+1, a.maxAttempts)
		select {
		case <-ctx.Done():
			return
		case <-a.redial:
			backoff, attempts = retryMin, 0
		case <-time.After(wait):
			backoff = min(backoff*2, retryMax)
		}
	}
}

// waitForRedial blocks until someone asks for another attempt, reporting
// false when the agent is shutting down instead.
func (a *Agent) waitForRedial(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	case <-a.redial:
		a.Log("reconnect requested")
		return true
	}
}

// jitter spreads reconnects so several tunnels failing together do not
// stampede the same VPN gateway.
func jitter(d time.Duration) time.Duration {
	return d/2 + time.Duration(rand.Int63n(int64(d/2)+1))
}
