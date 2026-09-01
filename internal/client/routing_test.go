package client

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
	"golang.org/x/net/proxy"

	"github.com/vpn-gateway/vpn-gateway/internal/server/certs"
	"github.com/vpn-gateway/vpn-gateway/internal/server/clientcfg"
	sproxy "github.com/vpn-gateway/vpn-gateway/internal/server/proxy"
	"github.com/vpn-gateway/vpn-gateway/internal/testsupport"
	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

// TestGeneratedConfigIsAcceptedBySingBox is the cheapest guard against the
// generator drifting from what sing-box actually parses. Every field here is
// hand-written JSON, so a renamed or restructured option would otherwise only
// show up at runtime.
func TestGeneratedConfigIsAcceptedBySingBox(t *testing.T) {
	cfg := baseConfig()
	cfg.TUN = TUNConfig{Enabled: true, Address: "172.19.0.1/30", MTU: 1400, AutoRoute: true, Stack: "system"}
	cfg.Rules = []Rule{
		{DomainSuffix: []string{"corp.example.com"}, Tunnel: "office"},
		{IPCIDR: []string{"10.10.5.0/24"}, Tunnel: "lab"},
		{Domain: []string{"ads.example.com"}, Tunnel: TargetBlock},
		{DomainKeyword: []string{"gitlab"}, Tunnel: "lab"},
		{Port: []int{22}, Tunnel: TargetDirect},
	}

	raw, err := BuildConfig(cfg, testBundle(), testTunnels())
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}

	ctx := registryContext(context.Background())
	var parsed option.Options
	if err := singjson.UnmarshalContext(ctx, raw, &parsed); err != nil {
		t.Fatalf("sing-box rejected the generated configuration: %v\n\n%s", err, raw)
	}
	if len(parsed.Inbounds) != 2 {
		t.Errorf("got %d inbounds, want tun and proxy", len(parsed.Inbounds))
	}
	// direct, block, and a trojan plus a selector per tunnel.
	if want := 2 + 2*len(testTunnels()); len(parsed.Outbounds) != want {
		t.Errorf("got %d outbounds, want %d", len(parsed.Outbounds), want)
	}
}

// fullStack wires a real server -- trojan listener in front of one stand-in
// container per tunnel, plus a control API -- to a real client in proxy mode.
type fullStack struct {
	clientProxy string
	backends    map[string]*testsupport.LabelledSOCKS
	client      *Client
	setUp       func(name string, up bool)
	t           *testing.T
}

// setFailed marks a tunnel down and applies the change the way the watch loop
// would, without waiting for a poll interval.
func (f *fullStack) setFailed(name string) {
	f.t.Helper()
	f.setUp(name, false)
	f.resync()
}

// setRecovered is the reverse.
func (f *fullStack) setRecovered(name string) {
	f.t.Helper()
	f.setUp(name, true)
	f.resync()
}

func (f *fullStack) resync() {
	f.t.Helper()
	refreshed, err := f.client.fetch(context.Background())
	if err != nil {
		f.t.Fatal(err)
	}
	f.client.applySelection(refreshed)
}

func startFullStack(t *testing.T, cfg *Config, names ...string) *fullStack {
	t.Helper()

	mat, err := certs.EnsureSelfSigned(filepath.Join(t.TempDir(), "tls"), "vpn.test")
	if err != nil {
		t.Fatal(err)
	}

	// One stand-in container per tunnel.
	backends := map[string]*testsupport.LabelledSOCKS{}
	serverOpts := sproxy.Options{
		Listen:     "127.0.0.1:" + strconv.Itoa(testsupport.FreePort(t)),
		ServerName: "vpn.test",
		CertPath:   mat.CertPath,
		KeyPath:    mat.KeyPath,
		LogLevel:   "error",
	}
	for _, name := range names {
		b := testsupport.StartLabelledSOCKS(t, name, "vpngw", "socks-"+name)
		backends[name] = b
		host, port := b.HostPort()
		serverOpts.Routes = append(serverOpts.Routes, sproxy.Route{
			Name: name, TrojanPassword: "trojan-" + name,
			DataHost: host, DataPort: port,
			SOCKSUser: "vpngw", SOCKSPassword: "socks-" + name,
		})
	}

	srv, err := sproxy.New(context.Background(), serverOpts, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	testsupport.WaitForPort(t, serverOpts.Listen)

	// A control API standing in for the real server's, so tunnel state can be
	// flipped from the test.
	var mu sync.Mutex
	up := map[string]bool{}
	for _, n := range names {
		up[n] = true
	}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/login" || r.URL.Path == "/api/v1/login" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"ok": true, "token": "test-token"})
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		snaps := make([]Snapshot, 0, len(names))
		for _, n := range names {
			state := contract.StateUp
			if !up[n] {
				state = contract.StateError
			}
			snaps = append(snaps, Snapshot{
				Name: n, Reachable: true, TrojanPassword: "trojan-" + n,
				Status:  contract.Status{State: state},
				Network: contract.Network{Routes: []string{"10.10.0.0/16"}, UDP: false},
			})
		}
		json.NewEncoder(w).Encode(snaps)
	}))
	t.Cleanup(api.Close)

	bundle := &clientcfg.Bundle{
		Version: 1,
		Server: clientcfg.ServerRef{
			Address:        serverOpts.Listen,
			ServerName:     "vpn.test",
			APIURL:         api.URL,
			CertificatePEM: mat.CertPEM,
		},
		APIToken: "test-token",
	}
	for _, n := range names {
		bundle.Tunnels = append(bundle.Tunnels, clientcfg.Tunnel{Name: n, Password: "trojan-" + n})
	}

	proxyPort := testsupport.FreePort(t)
	cfg.Proxy = ProxyConfig{Enabled: true, Listen: "127.0.0.1:" + strconv.Itoa(proxyPort)}
	cfg.Bundle = "unused"
	cfg.applyDefaults()

	c, err := New(context.Background(), cfg, bundle, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("build client: %v", err)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatalf("start client: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	clientProxy := "127.0.0.1:" + strconv.Itoa(proxyPort)
	testsupport.WaitForPort(t, clientProxy)

	return &fullStack{
		clientProxy: clientProxy,
		backends:    backends,
		client:      c,
		t:           t,
		setUp: func(name string, state bool) {
			mu.Lock()
			up[name] = state
			mu.Unlock()
		},
	}
}

// get sends a request for host through the client and reports which tunnel
// answered, or "direct" when the client sent it out normally.
func (f *fullStack) get(host string) (string, error) {
	d, err := proxy.SOCKS5("tcp", f.clientProxy, nil, proxy.Direct)
	if err != nil {
		return "", err
	}
	cd := d.(proxy.ContextDialer)
	client := &http.Client{
		Transport: &http.Transport{DialContext: cd.DialContext},
		Timeout:   15 * time.Second,
	}
	resp, err := client.Get("http://" + host + "/")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	return string(body), err
}

// TestTrafficReachesTheTunnelItsRuleSelects is the Phase 2 acceptance: a
// domain covered by a rule goes through that tunnel, and everything else does
// not.
func TestTrafficReachesTheTunnelItsRuleSelects(t *testing.T) {
	direct := testsupport.StartLabelServer(t, "direct")

	cfg := baseConfig()
	cfg.AutoRoutes = false
	cfg.AutoDomains = false
	cfg.Rules = []Rule{
		{DomainSuffix: []string{"office.example.com"}, Tunnel: "office"},
		{DomainSuffix: []string{"lab.example.com"}, Tunnel: "lab"},
	}
	stack := startFullStack(t, cfg, "office", "lab")

	got, err := stack.get("intranet.office.example.com")
	if err != nil {
		t.Fatalf("office request: %v", err)
	}
	if got != "office" {
		t.Errorf("office.example.com was carried by %q, want office", got)
	}

	got, err = stack.get("wiki.lab.example.com")
	if err != nil {
		t.Fatalf("lab request: %v", err)
	}
	if got != "lab" {
		t.Errorf("lab.example.com was carried by %q, want lab", got)
	}

	// A name no rule mentions must not enter a tunnel.
	got, err = stack.get(direct)
	if err != nil {
		t.Fatalf("direct request: %v", err)
	}
	if got != "direct" {
		t.Errorf("unmatched traffic was carried by %q, want direct", got)
	}

	if n := stack.backends["office"].Conns(); n != 1 {
		t.Errorf("the office tunnel carried %d connections, want 1", n)
	}
	if n := stack.backends["lab"].Conns(); n != 1 {
		t.Errorf("the lab tunnel carried %d connections, want 1", n)
	}
}

// TestTunnelFailureFallsBackWithoutDisturbingOthers checks the isolation the
// design promises: one tunnel going down must not interrupt another, and must
// not require a restart.
//
// Success is measured by what reaches each stand-in container rather than by
// what the failed request returns: once traffic leaves the tunnel it goes to
// the real network, which has no such host.
func TestTunnelFailureFallsBackWithoutDisturbingOthers(t *testing.T) {
	cfg := baseConfig()
	cfg.AutoRoutes = false
	cfg.AutoDomains = false
	cfg.OnFailure = TargetDirect
	cfg.Rules = []Rule{
		{DomainSuffix: []string{"office.example.com"}, Tunnel: "office"},
		{DomainSuffix: []string{"lab.example.com"}, Tunnel: "lab"},
	}
	stack := startFullStack(t, cfg, "office", "lab")

	if got, err := stack.get("a.office.example.com"); err != nil || got != "office" {
		t.Fatalf("baseline office request returned %q, %v", got, err)
	}
	if n := stack.backends["office"].Conns(); n != 1 {
		t.Fatalf("baseline: office carried %d connections, want 1", n)
	}

	// The office tunnel drops.
	stack.setFailed("office")

	stack.get("b.office.example.com") // expected to fail: it now leaves the tunnel
	if n := stack.backends["office"].Conns(); n != 1 {
		t.Errorf("traffic still entered the failed tunnel: %d connections, want 1", n)
	}

	// The lab tunnel is untouched, and was never restarted.
	if got, err := stack.get("c.lab.example.com"); err != nil || got != "lab" {
		t.Errorf("the lab tunnel was disturbed by the office failure: %q, %v", got, err)
	}

	// And office recovers without a restart.
	stack.setRecovered("office")
	if got, err := stack.get("d.office.example.com"); err != nil || got != "office" {
		t.Errorf("the office tunnel did not recover: %q, %v", got, err)
	}
	if n := stack.backends["office"].Conns(); n != 2 {
		t.Errorf("after recovery office carried %d connections, want 2", n)
	}
}

// TestOnFailureBlockRefusesInsteadOfLeaking checks the other failure policy:
// with on_failure set to block, traffic for a dead tunnel is refused rather
// than sent out the machine's normal connection, where it would leave the
// network it was meant to stay inside.
func TestOnFailureBlockRefusesInsteadOfLeaking(t *testing.T) {
	cfg := baseConfig()
	cfg.AutoRoutes = false
	cfg.AutoDomains = false
	cfg.OnFailure = TargetBlock
	cfg.Rules = []Rule{{DomainSuffix: []string{"office.example.com"}, Tunnel: "office"}}
	stack := startFullStack(t, cfg, "office")

	if got, err := stack.get("a.office.example.com"); err != nil || got != "office" {
		t.Fatalf("baseline office request returned %q, %v", got, err)
	}

	stack.setFailed("office")
	if got, err := stack.get("b.office.example.com"); err == nil {
		t.Errorf("traffic for a failed tunnel was carried by %q instead of being refused", got)
	}
	if n := stack.backends["office"].Conns(); n != 1 {
		t.Errorf("office carried %d connections, want 1", n)
	}
}

// TestBlockedTrafficIsRefused checks that a blocking rule actually refuses.
func TestBlockedTrafficIsRefused(t *testing.T) {
	cfg := baseConfig()
	cfg.AutoRoutes = false
	cfg.AutoDomains = false
	cfg.Rules = []Rule{
		{DomainSuffix: []string{"blocked.example.com"}, Tunnel: TargetBlock},
		{DomainSuffix: []string{"office.example.com"}, Tunnel: "office"},
	}
	stack := startFullStack(t, cfg, "office")

	if got, err := stack.get("x.blocked.example.com"); err == nil {
		t.Errorf("blocked traffic was carried by %q", got)
	}
	if got, err := stack.get("y.office.example.com"); err != nil || got != "office" {
		t.Errorf("blocking one name broke the office tunnel: %q, %v", got, err)
	}
}
