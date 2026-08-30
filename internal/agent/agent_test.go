package agent

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

// scriptedProvider returns a queue of results from Run, one per call, so a
// test can drive the supervisor's retry behaviour.
type scriptedProvider struct {
	results []error
	calls   atomic.Int32
}

func (p *scriptedProvider) Capabilities() []string { return []string{contract.CapTCP} }
func (p *scriptedProvider) Run(ctx context.Context, cfg Config, rep Reporter) error {
	n := int(p.calls.Add(1)) - 1
	if n < len(p.results) {
		return p.results[n]
	}
	rep.SetState(contract.StateUp, nil)
	<-ctx.Done()
	return nil
}
func (p *scriptedProvider) Dial(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not dialable")
}
func (p *scriptedProvider) Answer(contract.AuthAnswer) error { return nil }

func newTestAgent(t *testing.T, p Provider) *Agent {
	t.Helper()
	return &Agent{
		cfg:         Config{Provider: "test"},
		provider:    p,
		log:         slog.New(slog.DiscardHandler),
		maxAttempts: DefaultMaxAttempts,
		state:       contract.StateConnecting,
		since:       time.Now(),
		subs:        map[int]chan contract.Event{},
		redial:      make(chan struct{}, 1),
	}
}

func TestUptimeTracksTheCurrentConnection(t *testing.T) {
	a := newTestAgent(t, &scriptedProvider{})

	if got := a.Status().UptimeSeconds; got != 0 {
		t.Errorf("uptime before connecting = %d, want 0", got)
	}

	a.SetState(contract.StateUp, nil)
	s := a.Status()
	if s.ConnectedAt == nil {
		t.Fatal("ConnectedAt was not set on the transition to up")
	}
	first := *s.ConnectedAt

	// Dropping out of "up" must stop the clock but keep the last connection
	// time, so a UI can still show when the tunnel was last working.
	a.SetState(contract.StateError, errors.New("link lost"))
	s = a.Status()
	if s.UptimeSeconds != 0 {
		t.Errorf("uptime while down = %d, want 0", s.UptimeSeconds)
	}
	if s.ConnectedAt == nil || !s.ConnectedAt.Equal(first) {
		t.Error("ConnectedAt was cleared when the tunnel went down")
	}
	if s.Error != "link lost" {
		t.Errorf("Error = %q, want %q", s.Error, "link lost")
	}

	// Reconnecting restarts the clock.
	time.Sleep(10 * time.Millisecond)
	a.SetState(contract.StateUp, nil)
	if s := a.Status(); s.ConnectedAt.Equal(first) {
		t.Error("ConnectedAt was not refreshed on reconnect")
	}
}

func TestSuperviseStopsDiallingOnAPermanentFailure(t *testing.T) {
	// A rejected password must not become a login loop against a corporate
	// gateway, which is how accounts get locked. The supervisor stays alive
	// so a corrected password can be tried without recreating the container,
	// but it must not dial again on its own.
	p := &scriptedProvider{results: []error{Permanent(errors.New("bad password"))}}
	a := newTestAgent(t, p)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Supervise(ctx)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && a.Status().State != contract.StateError {
		time.Sleep(20 * time.Millisecond)
	}
	if st := a.Status(); st.State != contract.StateError {
		t.Fatalf("state = %q, want %q", st.State, contract.StateError)
	}

	// Left alone for well past any backoff, it must not have tried again.
	time.Sleep(3 * time.Second)
	if n := p.calls.Load(); n != 1 {
		t.Errorf("dialled %d times after a permanent failure, want 1", n)
	}
}

func TestSuperviseRetriesTransientFailures(t *testing.T) {
	p := &scriptedProvider{results: []error{errors.New("network unreachable")}}
	a := newTestAgent(t, p)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Supervise(ctx)

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if a.Status().State == contract.StateUp {
			if n := p.calls.Load(); n < 2 {
				t.Errorf("provider ran %d times, want at least 2", n)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("tunnel never recovered; state is %q", a.Status().State)
}

func TestAnswerRejectsStaleChallengeID(t *testing.T) {
	a := newTestAgent(t, &scriptedProvider{})
	a.SetChallenge(&contract.Challenge{ID: "current", Type: contract.ChallengeSMS})

	if err := a.Answer(contract.AuthAnswer{ID: "stale", Value: "123456"}); err == nil {
		t.Fatal("a stale challenge id was accepted")
	}
	if err := a.Answer(contract.AuthAnswer{ID: "current", Value: "123456"}); err != nil {
		t.Fatalf("the current challenge id was rejected: %v", err)
	}
	if a.Challenge() != nil {
		t.Error("the challenge was not cleared after being answered")
	}
}

func TestControlPlaneRequiresTheSecret(t *testing.T) {
	a := newTestAgent(t, &scriptedProvider{})
	a.secret = "s3cret"
	srv := httptest.NewServer(a.ControlHandler())
	defer srv.Close()

	tests := []struct {
		name   string
		header string
		want   int
	}{
		{"missing", "", http.StatusUnauthorized},
		{"wrong", "Bearer nope", http.StatusUnauthorized},
		{"not a bearer token", "s3cret", http.StatusUnauthorized},
		{"correct", "Bearer s3cret", http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, srv.URL+contract.PathStatus, nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}
}

func TestClientRoundTripsStatusAndNetwork(t *testing.T) {
	a := newTestAgent(t, &scriptedProvider{})
	a.secret = "s3cret"
	a.SetState(contract.StateUp, nil)
	a.SetNetwork(contract.Network{Routes: []string{"10.20.0.0/16"}, DNS: []string{"10.20.0.53"}, MTU: 1400})

	srv := httptest.NewServer(a.ControlHandler())
	defer srv.Close()

	c := contract.NewClient("placeholder", "s3cret")
	c.BaseURL = srv.URL

	st, err := c.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.State != contract.StateUp || st.Contract != contract.Version {
		t.Errorf("unexpected status: %+v", st)
	}

	n, err := c.Network(context.Background())
	if err != nil {
		t.Fatalf("Network: %v", err)
	}
	if len(n.Routes) != 1 || n.Routes[0] != "10.20.0.0/16" || n.MTU != 1400 {
		t.Errorf("unexpected network: %+v", n)
	}
}

func TestConfigExtraAccessors(t *testing.T) {
	cfg := Config{Extra: map[string]string{"port": "8443", "flag": "true", "blank": ""}}
	if got := cfg.Str("port", "443"); got != "8443" {
		t.Errorf("Str(port) = %q, want 8443", got)
	}
	if got := cfg.Str("blank", "443"); got != "443" {
		t.Errorf("an empty value must fall back to the default, got %q", got)
	}
	if got := cfg.Str("absent", "443"); got != "443" {
		t.Errorf("Str(absent) = %q, want 443", got)
	}
	if !cfg.Bool("flag", false) {
		t.Error("Bool(flag) = false, want true")
	}
	if !cfg.Bool("absent", true) {
		t.Error("Bool(absent) did not fall back to the default")
	}
}

func TestApplyNetworkOverridesWins(t *testing.T) {
	// An operator's explicit answer must replace a provider's guess, not
	// merge with it: a wrong auto-detected route needs to be correctable.
	cfg := Config{Extra: map[string]string{
		"routes": "172.16.0.0/12, 10.1.0.0/16",
		"dns":    "172.16.0.53",
		"mtu":    "1350",
	}}
	got := ApplyNetworkOverrides(cfg, contract.Network{
		Routes: []string{"192.168.0.0/16"},
		DNS:    []string{"8.8.8.8"},
		MTU:    1400,
	})
	if len(got.Routes) != 2 || got.Routes[0] != "172.16.0.0/12" || got.Routes[1] != "10.1.0.0/16" {
		t.Errorf("routes = %v", got.Routes)
	}
	if len(got.DNS) != 1 || got.DNS[0] != "172.16.0.53" {
		t.Errorf("dns = %v", got.DNS)
	}
	if got.MTU != 1350 {
		t.Errorf("mtu = %d, want 1350", got.MTU)
	}
}
