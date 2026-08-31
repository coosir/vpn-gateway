package client

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vpn-gateway/vpn-gateway/internal/server/clientcfg"
)

func testBundle() *clientcfg.Bundle {
	return &clientcfg.Bundle{
		Version: 1,
		Server: clientcfg.ServerRef{
			Address:        "vpn.home.test:443",
			ServerName:     "vpn.home.test",
			APIURL:         "http://vpn.home.test:8642",
			CertificatePEM: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",
		},
		APIToken: "token",
		Tunnels: []clientcfg.Tunnel{
			{Name: "office", Password: "pw-office"},
			{Name: "lab", Password: "pw-lab"},
		},
	}
}

func testTunnels() []TunnelState {
	return []TunnelState{
		{
			Name: "office", Password: "pw-office", Up: true,
			Routes: []string{"10.10.0.0/16"}, DNS: []string{"10.10.0.53"},
			SearchDomains: []string{"office.example.com"}, UDP: false,
		},
		{
			Name: "lab", Password: "pw-lab", Up: true,
			Routes: []string{"172.20.0.0/16"}, DNS: []string{"172.20.0.53"},
			SearchDomains: []string{"lab.example.com"}, UDP: true,
		},
	}
}

func baseConfig() *Config {
	c := &Config{
		Bundle:      "/dev/null",
		Auth:        AuthConfig{Username: "testuser", Password: "testpassword"},
		Proxy:       ProxyConfig{Enabled: true, Listen: "127.0.0.1:1080"},
		AutoRoutes:  true,
		AutoDomains: true,
	}
	c.applyDefaults()
	return c
}

// build renders the configuration and decodes it for inspection.
func build(t *testing.T, cfg *Config, tunnels []TunnelState) map[string]any {
	t.Helper()
	raw, err := BuildConfig(cfg, testBundle(), tunnels)
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("generated configuration is not valid JSON: %v", err)
	}
	return out
}

func routeRules(t *testing.T, cfg map[string]any) []map[string]any {
	t.Helper()
	route, ok := cfg["route"].(map[string]any)
	if !ok {
		t.Fatal("no route section")
	}
	raw, _ := route["rules"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		out = append(out, r.(map[string]any))
	}
	return out
}

func dnsSection(t *testing.T, cfg map[string]any) map[string]any {
	t.Helper()
	d, ok := cfg["dns"].(map[string]any)
	if !ok {
		t.Fatal("no dns section")
	}
	return d
}

func TestSniffAndDNSHijackComeFirst(t *testing.T) {
	// Traffic arriving on TUN is only an address until it is sniffed, so a
	// domain rule placed before sniffing could never match.
	cfg := baseConfig()
	cfg.Rules = []Rule{{DomainSuffix: []string{"corp.example.com"}, Tunnel: "office"}}
	rules := routeRules(t, build(t, cfg, testTunnels()))

	if len(rules) < 2 {
		t.Fatalf("expected at least two leading rules, got %d", len(rules))
	}
	if rules[0]["action"] != "sniff" {
		t.Errorf("first rule is %v, want the sniff action", rules[0])
	}
	if rules[1]["action"] != "hijack-dns" {
		t.Errorf("second rule is %v, want the hijack-dns action", rules[1])
	}
}

func TestExplicitRulesPrecedeDerivedOnes(t *testing.T) {
	// A tunnel claims 10.10.0.0/16, but the operator wants one subnet of it
	// to go elsewhere. The explicit rule has to win.
	cfg := baseConfig()
	cfg.Rules = []Rule{{IPCIDR: []string{"10.10.5.0/24"}, Tunnel: "lab"}}
	rules := routeRules(t, build(t, cfg, testTunnels()))

	var explicitAt, derivedAt = -1, -1
	for i, r := range rules {
		cidrs, _ := r["ip_cidr"].([]any)
		if len(cidrs) == 1 && cidrs[0] == "10.10.5.0/24" {
			explicitAt = i
		}
		if len(cidrs) == 1 && cidrs[0] == "10.10.0.0/16" {
			derivedAt = i
		}
	}
	if explicitAt < 0 {
		t.Fatal("the explicit rule is missing")
	}
	if derivedAt < 0 {
		t.Fatal("the derived route rule is missing")
	}
	if explicitAt > derivedAt {
		t.Errorf("the explicit rule is at %d, after the derived rule at %d", explicitAt, derivedAt)
	}
}

func TestRulesTargetSelectorsNotTunnelsDirectly(t *testing.T) {
	// Rules point at the selector so a tunnel going down is handled by
	// switching it, without restarting and disturbing other tunnels.
	cfg := baseConfig()
	cfg.Rules = []Rule{{DomainSuffix: []string{"corp.example.com"}, Tunnel: "office"}}
	rules := routeRules(t, build(t, cfg, testTunnels()))

	found := false
	for _, r := range rules {
		if ob, ok := r["outbound"].(string); ok && strings.HasPrefix(ob, tunnelPrefix) {
			t.Errorf("a rule points straight at %q instead of its selector", ob)
		}
		if r["outbound"] == routePrefix+"office" {
			found = true
		}
	}
	if !found {
		t.Error("no rule targets the office selector")
	}
}

func TestDNSFollowsRouting(t *testing.T) {
	// An intranet name resolves only through the VPN's own resolver, which is
	// reachable only through that tunnel. Routing the traffic without also
	// routing the lookup leaves internal names failing while everything looks
	// configured correctly.
	cfg := baseConfig()
	cfg.Rules = []Rule{{DomainSuffix: []string{"corp.example.com"}, Tunnel: "office"}}
	dns := dnsSection(t, build(t, cfg, testTunnels()))

	rawRules, _ := dns["rules"].([]any)
	matched := false
	for _, r := range rawRules {
		rule := r.(map[string]any)
		suffixes, _ := rule["domain_suffix"].([]any)
		if len(suffixes) == 1 && suffixes[0] == "corp.example.com" {
			if rule["server"] != dnsPrefix+"office" {
				t.Errorf("corp.example.com resolves via %v, want the office resolver", rule["server"])
			}
			matched = true
		}
	}
	if !matched {
		t.Error("the routing rule for corp.example.com has no matching DNS rule")
	}
}

func TestTunnelResolverUsesTCPWithoutUDPSupport(t *testing.T) {
	// The container data plane only carries datagrams when it says so; an
	// unqualified UDP query would silently time out.
	dns := dnsSection(t, build(t, baseConfig(), testTunnels()))
	servers, _ := dns["servers"].([]any)

	byTag := map[string]map[string]any{}
	for _, s := range servers {
		srv := s.(map[string]any)
		byTag[srv["tag"].(string)] = srv
	}

	office, ok := byTag[dnsPrefix+"office"]
	if !ok {
		t.Fatal("the office resolver is missing")
	}
	if office["type"] != "tcp" {
		t.Errorf("office resolver type is %v, want tcp (the tunnel reports udp=false)", office["type"])
	}
	if office["detour"] != routePrefix+"office" {
		t.Errorf("office resolver detour is %v, want its selector so it follows the tunnel down", office["detour"])
	}

	lab, ok := byTag[dnsPrefix+"lab"]
	if !ok {
		t.Fatal("the lab resolver is missing")
	}
	if lab["type"] != "udp" {
		t.Errorf("lab resolver type is %v, want udp (the tunnel reports udp=true)", lab["type"])
	}
}

func TestSelectorDefaultsToFallbackWhenTunnelIsDown(t *testing.T) {
	tunnels := testTunnels()
	tunnels[0].Up = false

	for _, tc := range []struct{ onFailure, want string }{
		{TargetDirect, tagDirect},
		{TargetBlock, tagBlock},
	} {
		t.Run(tc.onFailure, func(t *testing.T) {
			cfg := baseConfig()
			cfg.OnFailure = tc.onFailure
			out := build(t, cfg, tunnels)

			raw, _ := out["outbounds"].([]any)
			for _, o := range raw {
				ob := o.(map[string]any)
				if ob["tag"] != routePrefix+"office" {
					continue
				}
				if ob["default"] != tc.want {
					t.Errorf("selector default is %v, want %v", ob["default"], tc.want)
				}
				members, _ := ob["outbounds"].([]any)
				if len(members) != 2 || members[0] != tunnelPrefix+"office" || members[1] != tc.want {
					t.Errorf("selector members are %v, want [%s %s]", members, tunnelPrefix+"office", tc.want)
				}
				return
			}
			t.Fatal("the office selector is missing")
		})
	}
}

func TestUnknownTunnelInRuleIsRejected(t *testing.T) {
	// Dropping the rule silently would send intranet traffic to the internet.
	cfg := baseConfig()
	cfg.Rules = []Rule{{DomainSuffix: []string{"x.example.com"}, Tunnel: "typo"}}
	if _, err := BuildConfig(cfg, testBundle(), testTunnels()); err == nil {
		t.Fatal("a rule naming an unknown tunnel was accepted")
	} else if !strings.Contains(err.Error(), "typo") {
		t.Errorf("the error does not name the offending tunnel: %v", err)
	}
}

func TestBlockTargetUsesRejectAction(t *testing.T) {
	cfg := baseConfig()
	cfg.Rules = []Rule{{Domain: []string{"ads.example.com"}, Tunnel: TargetBlock}}
	for _, r := range routeRules(t, build(t, cfg, testTunnels())) {
		domains, _ := r["domain"].([]any)
		if len(domains) == 1 && domains[0] == "ads.example.com" {
			if r["action"] != "reject" {
				t.Errorf("blocked rule action is %v, want reject", r["action"])
			}
			return
		}
	}
	t.Fatal("the blocking rule is missing")
}

func TestAutoDerivationCanBeTurnedOff(t *testing.T) {
	cfg := baseConfig()
	cfg.AutoRoutes = false
	cfg.AutoDomains = false
	rules := routeRules(t, build(t, cfg, testTunnels()))

	// Only the two leading action rules should remain.
	if len(rules) != 2 {
		t.Errorf("got %d rules with derivation off, want only sniff and hijack-dns", len(rules))
	}
	dnsRules, ok := dnsSection(t, build(t, cfg, testTunnels()))["rules"].([]any)
	if !ok {
		t.Fatal("dns.rules is not a list; a nil slice would marshal to null")
	}
	if len(dnsRules) != 0 {
		t.Error("DNS rules were derived even though auto_domains is off")
	}
}

func TestAutoDetectInterfaceIsOn(t *testing.T) {
	// Without it the connection to the server itself is captured by our own
	// routes and loops back into the tunnel.
	out := build(t, baseConfig(), testTunnels())
	route := out["route"].(map[string]any)
	if route["auto_detect_interface"] != true {
		t.Error("auto_detect_interface is not enabled; the server connection would loop back")
	}
}

func TestServerCertificateIsPinnedNotIgnored(t *testing.T) {
	out := build(t, baseConfig(), testTunnels())
	raw, _ := out["outbounds"].([]any)
	for _, o := range raw {
		ob := o.(map[string]any)
		if ob["type"] != "trojan" {
			continue
		}
		tls, ok := ob["tls"].(map[string]any)
		if !ok {
			t.Fatal("the trojan outbound has no TLS settings")
		}
		if tls["insecure"] == true {
			t.Fatal("certificate verification is disabled; any certificate would be accepted")
		}
		if _, ok := tls["certificate"]; !ok {
			t.Error("the server certificate is not pinned")
		}
		return
	}
	t.Fatal("no trojan outbound was generated")
}

func TestDefaultResolverHasNoDetour(t *testing.T) {
	// sing-box refuses "detour to an empty direct outbound", so the default
	// resolver must carry no detour at all.
	dns := dnsSection(t, build(t, baseConfig(), testTunnels()))
	for _, s := range dns["servers"].([]any) {
		srv := s.(map[string]any)
		if srv["tag"] != tagDNSDefault {
			continue
		}
		if _, ok := srv["detour"]; ok {
			t.Errorf("the default resolver has a detour: %v", srv["detour"])
		}
		return
	}
	t.Fatal("the default resolver is missing")
}

func TestParseDNSURLOmitsEmptyDetour(t *testing.T) {
	got, err := parseDNSURL("https://1.1.1.1/dns-query", "t", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["detour"]; ok {
		t.Error("an empty detour was still written to the config")
	}
}

func TestParseDNSURL(t *testing.T) {
	tests := []struct {
		in      string
		want    map[string]any
		wantErr bool
	}{
		{in: "local", want: map[string]any{"type": "local", "tag": "t"}},
		{in: "udp://192.168.1.1", want: map[string]any{"type": "udp", "server": "192.168.1.1", "tag": "t", "detour": "d"}},
		// sing-box rejects an explicit detour to the bare direct outbound,
		// so an empty detour must be left out entirely.
		{in: "tcp://10.0.0.1:5353", want: map[string]any{"type": "tcp", "server": "10.0.0.1", "server_port": 5353, "tag": "t", "detour": "d"}},
		{in: "tls://1.1.1.1", want: map[string]any{"type": "tls", "server": "1.1.1.1", "tag": "t", "detour": "d"}},
		{in: "https://1.1.1.1/dns-query", want: map[string]any{"type": "https", "server": "1.1.1.1", "path": "/dns-query", "tag": "t", "detour": "d"}},
		{in: "ftp://1.1.1.1", wantErr: true},
		{in: "https://", wantErr: true},
	}
	for _, tc := range tests {
		got, err := parseDNSURL(tc.in, "t", "d")
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseDNSURL(%q) succeeded, want an error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseDNSURL(%q): %v", tc.in, err)
			continue
		}
		for k, want := range tc.want {
			if got[k] != want {
				t.Errorf("parseDNSURL(%q)[%q] = %v, want %v", tc.in, k, got[k], want)
			}
		}
	}
}

func TestDisabledRuleIsSkipped(t *testing.T) {
	cfg := baseConfig()
	cfg.Rules = []Rule{
		{DomainSuffix: []string{"enabled.example.com"}, Tunnel: "office", Disabled: false},
		{DomainSuffix: []string{"disabled.example.com"}, Tunnel: "office", Disabled: true},
	}
	rules := routeRules(t, build(t, cfg, testTunnels()))

	for _, r := range rules {
		if suffixes, ok := r["domain_suffix"].([]any); ok {
			for _, s := range suffixes {
				if s == "disabled.example.com" {
					t.Errorf("disabled rule %s was included in route rules", s)
				}
			}
		}
	}
}

func TestAutoRulesGeneratedAndDisabled(t *testing.T) {
	cfg := baseConfig()
	cfg.AutoRoutes = true
	cfg.AutoDomains = true
	cfg.DisabledAutoRules = []string{
		AutoRuleKey("office", "ip_cidr", "10.10.0.0/16"),
		AutoRuleKey("lab", "domain_suffix", "lab.example.com"),
	}

	auto := AutoRules(cfg, testTunnels())
	if len(auto) != 4 {
		t.Fatalf("len(AutoRules) = %d, want 4", len(auto))
	}

	for _, r := range auto {
		if !r.Auto {
			t.Errorf("auto rule %+v does not have Auto=true", r)
		}
		if len(r.IPCIDR) > 0 && r.IPCIDR[0] == "10.10.0.0/16" && !r.Disabled {
			t.Error("office 10.10.0.0/16 auto rule should be disabled")
		}
		if len(r.DomainSuffix) > 0 && r.DomainSuffix[0] == "lab.example.com" && !r.Disabled {
			t.Error("lab.example.com auto rule should be disabled")
		}
	}

	// Verify route rules exclude disabled auto rules
	built := routeRules(t, build(t, cfg, testTunnels()))
	for _, r := range built {
		if cidrs, ok := r["ip_cidr"].([]any); ok {
			for _, c := range cidrs {
				if c == "10.10.0.0/16" {
					t.Error("disabled auto route 10.10.0.0/16 was included in sing-box route rules")
				}
			}
		}
	}
}

func TestUserRulesPrecedeAutoRules(t *testing.T) {
	cfg := baseConfig()
	cfg.Rules = []Rule{
		{DomainSuffix: []string{"custom.example.com"}, Tunnel: "office"},
	}
	auto := AutoRules(cfg, testTunnels())
	all := append(cfg.Rules, auto...)

	if all[0].Auto {
		t.Error("user rule should come first, not auto rule")
	}
	if !all[len(all)-1].Auto {
		t.Error("auto rule should be at the bottom")
	}
}
