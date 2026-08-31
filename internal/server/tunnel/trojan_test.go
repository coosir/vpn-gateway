package tunnel

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/server"
	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

func TestTrojanTunnelManager(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := &server.Config{
		StateDir: dir,
		Runtime:  "auto",
		Tunnels: []server.TunnelConfig{
			{
				Name:        "hk-node",
				Provider:    "trojan",
				Server:      "hk.example.com:443",
				SNI:         "hk.example.com",
				Password:    "secretpass",
				Insecure:    true,
				Extra: map[string]string{
					"domains": "google.com,github.com",
					"routes":  "1.1.1.1/32",
					"dns":     "8.8.8.8",
				},
			},
		},
	}

	m, err := NewManager(cfg, nil, log)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	if len(m.Tunnels()) != 1 {
		t.Fatalf("len(tunnels) = %d, want 1", len(m.Tunnels()))
	}

	tr := m.Tunnels()[0]
	if !tr.cfg.IsTrojan() {
		t.Errorf("tr.cfg.IsTrojan() = false, want true")
	}

	snap := tr.Snapshot()
	if snap.Status.State != contract.StateUp {
		t.Errorf("state = %q, want up", snap.Status.State)
	}
	if !snap.Reachable || !snap.ContainerUp {
		t.Errorf("reachable/containerUp = %v/%v, want true/true", snap.Reachable, snap.ContainerUp)
	}
	if len(snap.Network.SearchDomains) != 2 || snap.Network.SearchDomains[0] != "google.com" {
		t.Errorf("search_domains = %+v, want [google.com, github.com]", snap.Network.SearchDomains)
	}
	if len(snap.Network.Routes) != 1 || snap.Network.Routes[0] != "1.1.1.1/32" {
		t.Errorf("routes = %+v, want [1.1.1.1/32]", snap.Network.Routes)
	}

	route := tr.Route()
	if route.TrojanOutbound == nil {
		t.Fatal("route.TrojanOutbound is nil")
	}
	if route.TrojanOutbound.Server != "hk.example.com" || route.TrojanOutbound.ServerPort != 443 {
		t.Errorf("TrojanOutbound server = %s:%d, want hk.example.com:443", route.TrojanOutbound.Server, route.TrojanOutbound.ServerPort)
	}
	if route.TrojanOutbound.Password != "secretpass" || route.TrojanOutbound.ServerName != "hk.example.com" || !route.TrojanOutbound.Insecure {
		t.Errorf("TrojanOutbound fields = %+v", route.TrojanOutbound)
	}

	// Test supervisor loop starts and cancels cleanly
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	m.Run(ctx)
}
