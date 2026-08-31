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

func TestDirectTunnel(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := &server.Config{
		StateDir: dir,
		Runtime:  "auto",
		Tunnels: []server.TunnelConfig{
			{
				Name:     "lan",
				Provider: "direct",
				Extra: map[string]string{
					"routes":         "192.168.1.0/24, 10.0.0.0/8",
					"dns":            "192.168.1.1",
					"search_domains": "lan.corp",
				},
			},
		},
	}

	engine := &countingEngine{}
	mgr, err := NewManager(cfg, engine, log)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	routes := mgr.Routes()
	if len(routes) != 1 {
		t.Fatalf("len(routes) = %d, want 1", len(routes))
	}
	if !routes[0].Direct {
		t.Errorf("routes[0].Direct = false, want true")
	}
	if routes[0].Name != "lan" {
		t.Errorf("routes[0].Name = %q, want lan", routes[0].Name)
	}

	snaps := mgr.Snapshots()
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	s := snaps[0]
	if s.Status.State != contract.StateUp {
		t.Errorf("state = %q, want up", s.Status.State)
	}
	if len(s.Network.Routes) != 2 || s.Network.Routes[0] != "192.168.1.0/24" || s.Network.Routes[1] != "10.0.0.0/8" {
		t.Errorf("routes = %+v, want [192.168.1.0/24, 10.0.0.0/8]", s.Network.Routes)
	}
	if len(s.Network.DNS) != 1 || s.Network.DNS[0] != "192.168.1.1" {
		t.Errorf("dns = %+v, want [192.168.1.1]", s.Network.DNS)
	}
	if len(s.Network.SearchDomains) != 1 || s.Network.SearchDomains[0] != "lan.corp" {
		t.Errorf("search_domains = %+v, want [lan.corp]", s.Network.SearchDomains)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go mgr.Run(ctx)

	time.Sleep(50 * time.Millisecond)

	// Direct tunnel should not invoke container engine creates or starts
	if engine.creates != 0 || engine.starts != 0 {
		t.Errorf("engine created %d or started %d containers for direct tunnel", engine.creates, engine.starts)
	}

	// Stop direct tunnel
	if err := mgr.Stop("lan"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	s = mgr.Snapshots()[0]
	if s.Status.State != contract.StateDown {
		t.Errorf("after stop, state = %q, want down", s.Status.State)
	}

	// Start direct tunnel again
	if err := mgr.Start("lan"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	s = mgr.Snapshots()[0]
	if s.Status.State != contract.StateUp {
		t.Errorf("after start, state = %q, want up", s.Status.State)
	}
}
