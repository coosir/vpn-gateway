package agent

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/vpn-gateway/vpn-gateway/internal/addrmap"
	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

// mappedDialRecorder remembers where the agent asked it to dial.
type mappedDialRecorder struct {
	scriptedProvider
	dialled atomic.Value
}

func (p *mappedDialRecorder) Dial(_ context.Context, _, addr string) (net.Conn, error) {
	p.dialled.Store(addr)
	return nil, errors.New("recorded")
}

func TestTheAgentDialsAndAnnouncesThroughTheMap(t *testing.T) {
	p := &mappedDialRecorder{}
	a := newTestAgent(t, p)
	m, err := addrmap.Parse("10.211.12.0/24=10.11.12.0/24")
	if err != nil {
		t.Fatal(err)
	}
	a.addrMap = m
	a.SetState(contract.StateUp, nil)

	a.Dial(context.Background(), "tcp", "10.211.12.2:3389")
	if got, _ := p.dialled.Load().(string); got != "10.11.12.2:3389" {
		t.Errorf("the provider was asked to dial %q", got)
	}

	// Whatever a provider reports, the client hears the virtual range.
	a.SetNetwork(contract.Network{Routes: []string{"10.11.12.0/24", "10.20.0.0/16"}})
	got := a.Network().Routes
	if !slices.Equal(got, []string{"10.211.12.0/24", "10.20.0.0/16"}) {
		t.Errorf("routes announced: %v", got)
	}
}

func TestAnAgentWithABadMapDoesNotStart(t *testing.T) {
	registerOnce.Do(func() { Register("addrmap-test", func() Provider { return &scriptedProvider{} }) })
	_, err := NewAgent(Config{Provider: "addrmap-test", Extra: map[string]string{"map": "10.211.12.0/24=10.11.0.0/16"}},
		slog.New(slog.DiscardHandler))
	if err == nil || !strings.Contains(err.Error(), "extra.map") {
		t.Errorf("NewAgent with a mismatched map: %v", err)
	}
}

var registerOnce sync.Once
