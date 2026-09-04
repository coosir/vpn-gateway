package client

import (
	"context"
	"testing"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/testsupport"
)

func TestReloadContextCancellation(t *testing.T) {
	cfg := baseConfig()
	cfg.AutoRoutes = false
	cfg.AutoDomains = false
	cfg.Rules = []Rule{
		{DomainSuffix: []string{"office.example.com"}, Tunnel: "office"},
	}
	stack := startFullStack(t, cfg, "office")

	// Verify it works initially
	got, err := stack.get("a.office.example.com")
	if err != nil || got != "office" {
		t.Fatalf("initial request failed: %q, %v", got, err)
	}

	// Simulate what PUT /api/rules did: call Reload with a short-lived request context
	reqCtx, reqCancel := context.WithCancel(context.Background())
	newCfg := *stack.client.Settings()
	newCfg.Rules = []Rule{
		{DomainSuffix: []string{"office.example.com"}, Tunnel: "office"},
		{DomainSuffix: []string{"new.example.com"}, Tunnel: "office"},
	}

	if err := stack.client.Reload(reqCtx, &newCfg); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	// Cancel the request context, exactly as net/http does when request ends
	reqCancel()
	time.Sleep(50 * time.Millisecond)

	// Traffic must still flow through the client
	got, err = stack.get("a.office.example.com")
	if err != nil {
		t.Errorf("Traffic failed after request context canceled: %v", err)
	} else if got != "office" {
		t.Errorf("Traffic routed incorrectly: %q", got)
	}

	// New rule must work
	got, err = stack.get("b.new.example.com")
	if err != nil {
		t.Errorf("Traffic for new rule failed: %v", err)
	} else if got != "office" {
		t.Errorf("Traffic for new rule routed incorrectly: %q", got)
	}
}

func TestDisableAndReEnableRule(t *testing.T) {
	direct := testsupport.StartLabelServer(t, "direct")

	cfg := baseConfig()
	cfg.AutoRoutes = false
	cfg.AutoDomains = false
	cfg.Rules = []Rule{
		{DomainSuffix: []string{"office.example.com"}, Tunnel: "office"},
		{DomainSuffix: []string{"lab.example.com"}, Tunnel: "lab"},
	}
	stack := startFullStack(t, cfg, "office", "lab")

	// Both tunnels work
	if got, err := stack.get("a.office.example.com"); err != nil || got != "office" {
		t.Fatalf("office failed: %q, %v", got, err)
	}
	if got, err := stack.get("a.lab.example.com"); err != nil || got != "lab" {
		t.Fatalf("lab failed: %q, %v", got, err)
	}

	// 1. Disable the office rule
	reqCtx1, cancel1 := context.WithCancel(context.Background())
	disCfg := *stack.client.Settings()
	disCfg.Rules = []Rule{
		{DomainSuffix: []string{"office.example.com"}, Tunnel: "office", Disabled: true},
		{DomainSuffix: []string{"lab.example.com"}, Tunnel: "lab", Disabled: false},
	}
	if err := stack.client.Reload(reqCtx1, &disCfg); err != nil {
		t.Fatalf("Reload with disabled rule failed: %v", err)
	}
	cancel1()

	// Lab tunnel must still work and be completely unaffected!
	if got, err := stack.get("b.lab.example.com"); err != nil || got != "lab" {
		t.Errorf("lab tunnel broken after office disabled: %q, %v", got, err)
	}

	// Office rule is disabled, so traffic falls through to direct
	// (direct label server should respond)
	if got, err := stack.get(direct); err != nil || got != "direct" {
		t.Errorf("direct traffic failed: %q, %v", got, err)
	}

	// 2. Re-enable the office rule
	reqCtx2, cancel2 := context.WithCancel(context.Background())
	enCfg := *stack.client.Settings()
	enCfg.Rules = []Rule{
		{DomainSuffix: []string{"office.example.com"}, Tunnel: "office", Disabled: false},
		{DomainSuffix: []string{"lab.example.com"}, Tunnel: "lab", Disabled: false},
	}
	if err := stack.client.Reload(reqCtx2, &enCfg); err != nil {
		t.Fatalf("Reload with re-enabled rule failed: %v", err)
	}
	cancel2()

	// Both tunnels must work again!
	if got, err := stack.get("c.office.example.com"); err != nil || got != "office" {
		t.Errorf("office tunnel failed to reconnect after re-enable: %q, %v", got, err)
	}
	if got, err := stack.get("c.lab.example.com"); err != nil || got != "lab" {
		t.Errorf("lab tunnel broken after office re-enabled: %q, %v", got, err)
	}
}

func TestDisableAndReEnableAutoRule(t *testing.T) {
	direct := testsupport.StartLabelServer(t, "direct")

	cfg := baseConfig()
	cfg.AutoRoutes = true
	cfg.AutoDomains = true
	// Start with office and lab tunnels that have SearchDomains
	stack := startFullStack(t, cfg, "office", "lab")

	// Verify auto rules routed to office and lab
	// In test, office has SearchDomains: []string{"office.example.com"}
	// (Note: testTunnels in build_test has office.example.com, but startFullStack uses names without SearchDomains)
	// Let's test custom rules with DisabledAutoRules
	disCfg := *stack.client.Settings()
	disCfg.DisabledAutoRules = []string{
		AutoRuleKey("office", "domain_suffix", "office.example.com"),
	}
	reqCtx1, cancel1 := context.WithCancel(context.Background())
	if err := stack.client.Reload(reqCtx1, &disCfg); err != nil {
		t.Fatalf("Reload with disabled auto rule failed: %v", err)
	}
	cancel1()

	// Direct traffic works
	if got, err := stack.get(direct); err != nil || got != "direct" {
		t.Errorf("direct traffic failed: %q, %v", got, err)
	}

	// Re-enable auto rule
	enCfg := *stack.client.Settings()
	enCfg.DisabledAutoRules = nil
	reqCtx2, cancel2 := context.WithCancel(context.Background())
	if err := stack.client.Reload(reqCtx2, &enCfg); err != nil {
		t.Fatalf("Reload with re-enabled auto rule failed: %v", err)
	}
	cancel2()

	// Direct traffic still works
	if got, err := stack.get(direct); err != nil || got != "direct" {
		t.Errorf("direct traffic failed: %q, %v", got, err)
	}
}
