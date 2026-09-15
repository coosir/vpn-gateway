package agent

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

// dialRecorder is a provider that counts what the keepalive asks for and
// answers with a connection to a real listener, so a probe that succeeds
// closes something real.
type dialRecorder struct {
	ln     net.Listener
	dials  atomic.Int32
	addrs  chan string
	failed bool
}

func newDialRecorder(t *testing.T, failed bool) *dialRecorder {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return &dialRecorder{ln: ln, addrs: make(chan string, 8), failed: failed}
}

func (p *dialRecorder) Capabilities() []string                              { return []string{contract.CapTCP} }
func (p *dialRecorder) Run(ctx context.Context, _ Config, _ Reporter) error { <-ctx.Done(); return nil }
func (p *dialRecorder) Answer(contract.AuthAnswer) error                    { return nil }
func (p *dialRecorder) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	p.dials.Add(1)
	select {
	case p.addrs <- addr:
	default:
	}
	if p.failed {
		return nil, errors.New("no route to host")
	}
	var d net.Dialer
	return d.DialContext(ctx, network, p.ln.Addr().String())
}

func TestKeepaliveProbesOnlyWhileTheTunnelIsUp(t *testing.T) {
	p := newDialRecorder(t, false)
	a := newTestAgent(t, p)
	a.SetNetwork(contract.Network{DNS: []string{"10.20.0.53"}})

	var st keepaliveState
	// Connecting, error, down: a tunnel that is not carrying traffic has
	// nothing to keep alive, and dialling through it would only fail.
	for _, state := range []contract.State{contract.StateConnecting, contract.StateError, contract.StateDown} {
		a.SetState(state, nil)
		a.keepaliveRound(context.Background(), &st, time.Second)
	}
	if n := p.dials.Load(); n != 0 {
		t.Fatalf("probed %d times while the tunnel was not up, want 0", n)
	}

	a.SetState(contract.StateUp, nil)
	a.keepaliveRound(context.Background(), &st, time.Second)
	if n := p.dials.Load(); n != 1 {
		t.Fatalf("probed %d times while up, want 1", n)
	}
	select {
	case addr := <-p.addrs:
		if addr != "10.20.0.53:53" {
			t.Errorf("probed %q, want the pushed resolver on 53", addr)
		}
	default:
		t.Fatal("no address was probed")
	}
}

func TestKeepaliveLeavesABusyTunnelAlone(t *testing.T) {
	// A tunnel carrying real traffic has already told the gateway somebody is
	// there; a probe on top of that is pure noise against a corporate
	// network.
	p := newDialRecorder(t, false)
	a := newTestAgent(t, p)
	a.SetNetwork(contract.Network{DNS: []string{"10.20.0.53"}})
	a.SetState(contract.StateUp, nil)

	var st keepaliveState
	a.addRx(4096)
	a.keepaliveRound(context.Background(), &st, time.Second)
	if n := p.dials.Load(); n != 0 {
		t.Fatalf("probed %d times after traffic moved, want 0", n)
	}

	// Nothing moved since, so the next round is the one that has to speak up.
	a.keepaliveRound(context.Background(), &st, time.Second)
	if n := p.dials.Load(); n != 1 {
		t.Fatalf("probed %d times on an idle tunnel, want 1", n)
	}
}

func TestKeepaliveNeedsSomewhereToProbe(t *testing.T) {
	// A provider that pushed no resolvers and named no target has nothing to
	// dial; it must say so rather than dial nowhere.
	p := newDialRecorder(t, false)
	a := newTestAgent(t, p)
	a.SetState(contract.StateUp, nil)

	var st keepaliveState
	a.keepaliveRound(context.Background(), &st, time.Second)
	if n := p.dials.Load(); n != 0 {
		t.Fatalf("probed %d times with no target, want 0", n)
	}
	if !st.mentioned {
		t.Error("the missing target was not reported")
	}
}

func TestKeepaliveTriesEveryTargetBeforeGivingUp(t *testing.T) {
	p := newDialRecorder(t, true)
	a := newTestAgent(t, p)
	a.cfg.Extra = map[string]string{"keepalive_target": "10.20.0.53, intranet.corp:443"}
	a.SetState(contract.StateUp, nil)

	var st keepaliveState
	a.keepaliveRound(context.Background(), &st, time.Second)
	if n := p.dials.Load(); n != 2 {
		t.Fatalf("tried %d targets, want both", n)
	}
	if !st.failing {
		t.Error("a round where nothing answered was not recorded as failing")
	}
}

func TestKeepaliveTargets(t *testing.T) {
	tests := []struct {
		name  string
		extra map[string]string
		dns   []string
		want  []string
	}{
		{
			name: "the pushed resolvers by default",
			dns:  []string{"10.20.0.53", "10.20.0.54"},
			want: []string{"10.20.0.53:53", "10.20.0.54:53"},
		},
		{
			name:  "a named target wins over them",
			extra: map[string]string{"keepalive_target": "app.corp:8080"},
			dns:   []string{"10.20.0.53"},
			want:  []string{"app.corp:8080"},
		},
		{
			name:  "a named target without a port answers on 53",
			extra: map[string]string{"keepalive_target": "10.20.0.53"},
			want:  []string{"10.20.0.53:53"},
		},
		{
			name: "an IPv6 resolver is bracketed",
			dns:  []string{"fd00::53"},
			want: []string{"[fd00::53]:53"},
		},
		{
			name: "nothing pushed, nothing to probe",
			want: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newTestAgent(t, &dialRecorder{})
			a.cfg.Extra = tt.extra
			a.SetNetwork(contract.Network{DNS: tt.dns})
			got := a.keepaliveTargets()
			if len(got) != len(tt.want) {
				t.Fatalf("targets = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("target %d = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestCfgDuration(t *testing.T) {
	// Both spellings are in use: durations in provider settings, bare seconds
	// in the server's own configuration.
	tests := []struct {
		value string
		want  time.Duration
	}{
		{"", time.Minute},
		{"90s", 90 * time.Second},
		{"5m", 5 * time.Minute},
		{"120", 2 * time.Minute},
		{"nonsense", time.Minute},
		{"0", time.Minute},
		{"-30s", time.Minute},
	}
	for _, tt := range tests {
		cfg := Config{Extra: map[string]string{"keepalive_interval": tt.value}}
		if got := cfgDuration(cfg, "keepalive_interval", time.Minute); got != tt.want {
			t.Errorf("cfgDuration(%q) = %s, want %s", tt.value, got, tt.want)
		}
	}
}
