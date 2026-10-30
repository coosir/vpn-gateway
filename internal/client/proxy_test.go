package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
)

// buildWithout renders the configuration with the gateway left out.
func buildWithout(t *testing.T, cfg *Config) map[string]any {
	t.Helper()
	raw, err := BuildConfig(cfg, nil, nil)
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func outboundOf(r map[string]any) string {
	if r["action"] == "reject" {
		return tagBlock
	}
	s, _ := r["outbound"].(string)
	return s
}

func proxyConfig() *Config {
	cfg := baseConfig()
	cfg.Mode = ModeRule
	cfg.CustomNodes = []CustomNode{
		{ID: "hk", Name: "HK", Type: NodeTrojan, Server: "hk.example.com", Port: 443, Password: "p"},
		{ID: "jp", Name: "JP", Type: NodeShadowsocks, Server: "jp.example.com", Port: 8388, Method: "aes-128-gcm", Password: "p"},
	}
	return cfg
}

// The gateway's rules win over the proxy rules: intranet traffic must never
// leave through a proxy node, however broad a proxy rule is written.
func TestGatewayRulesPrecedeProxyRules(t *testing.T) {
	cfg := proxyConfig()
	cfg.Rules = []Rule{{DomainSuffix: []string{"corp.example.com"}, Tunnel: "office"}}
	cfg.ProxyRules = []Rule{{DomainSuffix: []string{"example.com"}, Outbound: TargetProxy}}

	rules := routeRules(t, build(t, cfg, testTunnels()))
	var order []string
	for _, r := range rules {
		if out := outboundOf(r); out != "" {
			order = append(order, out)
		}
	}
	gateway, proxy := -1, -1
	for i, out := range order {
		if strings.HasPrefix(out, routePrefix) && gateway < 0 {
			gateway = i
		}
		if out == tagProxy {
			proxy = i
		}
	}
	if gateway < 0 || proxy < 0 || gateway > proxy {
		t.Errorf("rule order %v: every gateway rule must come before the proxy rules", order)
	}
	// Derived tunnel rules are gateway rules too.
	last := 0
	for i, out := range order {
		if strings.HasPrefix(out, routePrefix) {
			last = i
		}
	}
	if last > proxy {
		t.Errorf("rule order %v: a derived tunnel rule comes after a proxy rule", order)
	}
}

// With the gateway switched off none of it is in the engine: no tunnels, none
// of its rules -- not even a rule naming a tunnel that does not exist now.
func TestTheGatewayLeavesNothingBehindWhenOff(t *testing.T) {
	cfg := proxyConfig()
	cfg.Rules = []Rule{{DomainSuffix: []string{"corp.example.com"}, Tunnel: "office"}}
	built := buildWithout(t, cfg)
	for _, r := range routeRules(t, built) {
		if strings.HasPrefix(outboundOf(r), routePrefix) {
			t.Errorf("a gateway rule survived with the gateway off: %v", r)
		}
	}
	for _, o := range built["outbounds"].([]any) {
		if tag := o.(map[string]any)["tag"].(string); strings.HasPrefix(tag, tunnelPrefix) || strings.HasPrefix(tag, routePrefix) {
			t.Errorf("tunnel outbound %s survived with the gateway off", tag)
		}
	}
}

func TestModesDecideWhatIsLeft(t *testing.T) {
	cfg := proxyConfig()
	cfg.ProxyRules = []Rule{{DomainSuffix: []string{"google.com"}, Outbound: TargetProxy}}

	cases := []struct {
		mode       string
		final      string
		proxyRules bool
	}{
		{ModeRule, tagDirect, true},
		{ModeGlobal, tagProxy, false},
		{ModeDirect, tagDirect, false},
	}
	for _, c := range cases {
		cfg.Mode = c.mode
		built := buildWithout(t, cfg)
		if got := built["route"].(map[string]any)["final"]; got != c.final {
			t.Errorf("%s mode: final = %v, want %v", c.mode, got, c.final)
		}
		found := false
		for _, r := range routeRules(t, built) {
			if outboundOf(r) == tagProxy {
				found = true
			}
		}
		if found != c.proxyRules {
			t.Errorf("%s mode: proxy rules present = %t, want %t", c.mode, found, c.proxyRules)
		}
	}
}

// Names sent through a node are looked up through it; a direct rule earlier
// in the list keeps its names on the local resolver.
func TestProxiedNamesResolveRemotely(t *testing.T) {
	cfg := proxyConfig()
	cfg.ProxyRules = []Rule{
		{DomainSuffix: []string{"baidu.com"}, Outbound: TargetDirect},
		{DomainSuffix: []string{"google.com"}, Outbound: "node-hk"},
		{IPCIDR: []string{"8.8.8.0/24"}, Outbound: TargetProxy},
	}
	dns := dnsSection(t, buildWithout(t, cfg))
	var servers []string
	for _, s := range dns["servers"].([]any) {
		servers = append(servers, s.(map[string]any)["tag"].(string))
	}
	if !strings.Contains(strings.Join(servers, ","), tagDNSRemote) {
		t.Fatalf("no remote resolver among %v", servers)
	}
	rules := dns["rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("dns rules = %v, want one per name rule and none for the address rule", rules)
	}
	if got := rules[0].(map[string]any)["server"]; got != tagDNSDefault {
		t.Errorf("direct rule resolves through %v, want the default resolver", got)
	}
	if got := rules[1].(map[string]any)["server"]; got != tagDNSRemote {
		t.Errorf("proxied rule resolves through %v, want the remote resolver", got)
	}

	cfg.Mode = ModeGlobal
	if got := dnsSection(t, buildWithout(t, cfg))["final"]; got != tagDNSRemote {
		t.Errorf("global mode resolves unclaimed names through %v, want remote", got)
	}
}

// With no node there is nothing to resolve through, and a public resolver
// dialled directly is exactly what is blocked where a proxy is needed.
func TestNoRemoteResolverWithoutNodes(t *testing.T) {
	cfg := baseConfig()
	cfg.Mode = ModeGlobal
	for _, s := range dnsSection(t, buildWithout(t, cfg))["servers"].([]any) {
		if s.(map[string]any)["tag"] == tagDNSRemote {
			t.Error("a remote resolver was configured with no node to reach it through")
		}
	}
}

// A rule naming a rule set that has not been downloaded is left out rather
// than allowed to stop the engine; once the file is there it is used.
func TestRuleSetsAreUsedOnceDownloaded(t *testing.T) {
	cfg := proxyConfig()
	cfg.RuleSetDir = t.TempDir()
	cfg.ProxyRules = []Rule{
		{GeoSite: []string{"cn"}, Outbound: TargetDirect},
		{GeoIP: []string{"cn"}, Outbound: TargetDirect},
	}
	for _, r := range routeRules(t, buildWithout(t, cfg)) {
		if _, ok := r["rule_set"]; ok {
			t.Fatalf("a rule using a missing rule set was compiled: %v", r)
		}
	}

	if err := os.WriteFile(filepath.Join(cfg.RuleSetDir, "geosite-cn.srs"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	built := buildWithout(t, cfg)
	var used []string
	for _, r := range routeRules(t, built) {
		if sets, ok := r["rule_set"].([]any); ok {
			for _, s := range sets {
				used = append(used, s.(string))
			}
		}
	}
	if strings.Join(used, ",") != "geosite-cn" {
		t.Errorf("rules use %v, want only the downloaded geosite-cn", used)
	}
	defs := built["route"].(map[string]any)["rule_set"].([]any)
	if len(defs) != 1 || defs[0].(map[string]any)["type"] != "local" {
		t.Errorf("rule set definitions = %v, want one local file", defs)
	}
}

func TestNeededRuleSetsFollowTheMode(t *testing.T) {
	cfg := proxyConfig()
	cfg.ProxyRules = []Rule{{GeoSite: []string{"cn"}, Outbound: TargetDirect}}
	if got := neededRuleSets(cfg, false); len(got) != 1 || got[0] != "geosite-cn" {
		t.Errorf("rule mode needs %v, want geosite-cn", got)
	}
	cfg.Mode = ModeGlobal
	if got := neededRuleSets(cfg, false); len(got) != 0 {
		t.Errorf("global mode needs %v, want nothing: proxy rules are not consulted", got)
	}
}

// A rule naming a node a subscription update dropped goes through the proxy
// group instead of breaking the engine.
func TestARuleForAVanishedNodeFallsBackToTheGroup(t *testing.T) {
	cfg := proxyConfig()
	cfg.ProxyRules = []Rule{{DomainSuffix: []string{"x.com"}, Outbound: "node-gone"}}
	for _, r := range routeRules(t, buildWithout(t, cfg)) {
		if _, ok := r["domain_suffix"]; ok && outboundOf(r) != tagProxy {
			t.Errorf("rule for a vanished node goes to %q, want the proxy group", outboundOf(r))
		}
	}
}

// Rules that pointed at the proxy group used to be written among the gateway's
// rules. They are moved to where they are matched now.
func TestOldProxyRulesMoveOutOfTheGatewaysRules(t *testing.T) {
	path := writeClientConfig(t, `proxy: {enabled: true}
selected_node: hk
rules:
  - domain_suffix: [corp.example.com]
    tunnel: office
  - domain_suffix: [google.com]
    tunnel: proxy
  - domain_suffix: [youtube.com]
    tunnel: node-hk
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Rules) != 1 || cfg.Rules[0].Tunnel != "office" {
		t.Errorf("gateway rules = %+v, want only the office rule", cfg.Rules)
	}
	if len(cfg.ProxyRules) != 2 || cfg.ProxyRules[0].Outbound != TargetProxy || cfg.ProxyRules[1].Outbound != "node-hk" {
		t.Errorf("proxy rules = %+v", cfg.ProxyRules)
	}
	if cfg.SelectedNode != "node-hk" {
		t.Errorf("selected node = %q, want it written as a tag", cfg.SelectedNode)
	}
}

// A file written before the switch existed has a bundle and no opinion: it
// keeps the gateway it was written for.
func TestAnOldFileKeepsItsGateway(t *testing.T) {
	path := writeClientConfig(t, "bundle: /etc/vpn-gateway/client.json\nproxy: {enabled: true}\n")
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.GatewayWanted() {
		t.Error("an existing gateway configuration was switched off by the upgrade")
	}
	if cfg.EffectiveMode() != ModeRule {
		t.Errorf("mode = %q, want rule", cfg.EffectiveMode())
	}
}

func TestABundleIsNoLongerRequired(t *testing.T) {
	path := writeClientConfig(t, "proxy: {enabled: true}\n")
	if _, err := LoadConfig(path); err != nil {
		t.Errorf("a configuration without a bundle was refused: %v", err)
	}
}

func TestProxyRulesAreValidated(t *testing.T) {
	cases := map[string]Rule{
		"no outbound":     {DomainSuffix: []string{"x.com"}},
		"unknown target":  {DomainSuffix: []string{"x.com"}, Outbound: "office"},
		"no matcher":      {Outbound: TargetProxy},
		"path in geosite": {GeoSite: []string{"../etc"}, Outbound: TargetProxy},
		"bad cidr":        {IPCIDR: []string{"10.0.0.0/99"}, Outbound: TargetProxy},
	}
	for name, r := range cases {
		cfg := baseConfig()
		cfg.ProxyRules = []Rule{r}
		if cfg.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Every protocol a node can be is one sing-box accepts, in this build.
func TestEveryNodeTypeIsAcceptedBySingBox(t *testing.T) {
	cfg := baseConfig()
	cfg.CustomNodes = []CustomNode{
		{ID: "a", Name: "trojan-ws", Type: NodeTrojan, Server: "a.example", Port: 443, Password: "p", Transport: "ws", Path: "/ws", Host: "cdn.example"},
		{ID: "b", Name: "vmess-grpc", Type: NodeVMess, Server: "b.example", Port: 443, UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", TLS: true, Transport: "grpc", ServiceName: "svc"},
		{ID: "c", Name: "vless-vision", Type: NodeVLESS, Server: "c.example", Port: 443, UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Flow: "xtls-rprx-vision", TLS: true},
		{ID: "d", Name: "ss-obfs", Type: NodeShadowsocks, Server: "d.example", Port: 8388, Method: "chacha20-ietf-poly1305", Password: "p", Plugin: "obfs-local", PluginOpts: "obfs=http;obfs-host=x.com"},
		{ID: "e", Name: "ss-2022", Type: NodeShadowsocks, Server: "e.example", Port: 8388, Method: "2022-blake3-aes-128-gcm", Password: "AAAAAAAAAAAAAAAAAAAAAA=="},
		{ID: "f", Name: "anytls", Type: NodeAnyTLS, Server: "f.example", Port: 443, Password: "p"},
		{ID: "g", Name: "socks", Type: NodeSOCKS, Server: "g.example", Port: 1080, Username: "u", Password: "p"},
		{ID: "h", Name: "http", Type: NodeHTTP, Server: "h.example", Port: 8080, TLS: true},
		{ID: "i", Name: "hy2", Type: NodeHysteria2, Server: "i.example", Port: 443, Password: "p", Obfs: "salamander", ObfsPassword: "o"},
		{ID: "j", Name: "tuic", Type: NodeTUIC, Server: "j.example", Port: 443, UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Password: "p", CongestionControl: "bbr"},
		{ID: "k", Name: "vless-reality", Type: NodeVLESS, Server: "k.example", Port: 443, UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", RealityPublicKey: "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0", RealityShortID: "0123"},
	}
	raw, err := BuildConfig(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := registryContext(context.Background())
	var parsed option.Options
	if err := singjson.UnmarshalContext(ctx, raw, &parsed); err != nil {
		t.Fatalf("sing-box rejected the configuration: %v\n%s", err, raw)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: parsed})
	if err != nil {
		t.Fatalf("sing-box could not build it: %v\n%s", err, raw)
	}
	instance.Close()

	// What this build cannot dial is left out, not fatal.
	var want int
	for _, n := range cfg.CustomNodes {
		if n.Unsupported() == "" {
			want++
		}
	}
	got := 0
	for _, o := range parsed.Outbounds {
		if strings.HasPrefix(o.Tag, nodePrefix) {
			got++
		}
	}
	if got != want {
		t.Errorf("%d node outbounds, want %d (the ones this build supports)", got, want)
	}
}

func TestShareLinksParse(t *testing.T) {
	vmessJSON := `{"v":"2","ps":"VM 1","add":"vm.example","port":"443","id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":0,"net":"ws","path":"/ray","host":"cdn.example","tls":"tls","sni":"vm.example"}`
	ssUser := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:secret"))
	ssLegacy := base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:pw@ss2.example:8389"))

	cases := []struct {
		link  string
		check func(n *CustomNode) bool
	}{
		{"vmess://" + base64.StdEncoding.EncodeToString([]byte(vmessJSON)), func(n *CustomNode) bool {
			return n.Type == NodeVMess && n.Name == "VM 1" && n.Port == 443 && n.Transport == "ws" && n.Path == "/ray" && n.Host == "cdn.example" && n.TLS
		}},
		{"vless://b831381d-6324-4d53-ad4f-8cda48b30811@vl.example:443?security=reality&pbk=KEY&sid=ab&fp=chrome&flow=xtls-rprx-vision&sni=www.apple.com#VL", func(n *CustomNode) bool {
			return n.Type == NodeVLESS && n.RealityPublicKey == "KEY" && n.RealityShortID == "ab" && n.Flow == "xtls-rprx-vision" && n.SNI == "www.apple.com" && n.Name == "VL"
		}},
		{"ss://" + ssUser + "@ss.example:8388?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dx.com#SS%201", func(n *CustomNode) bool {
			return n.Type == NodeShadowsocks && n.Method == "aes-256-gcm" && n.Password == "secret" && n.Plugin == "obfs-local" && n.PluginOpts == "obfs=http;obfs-host=x.com" && n.Name == "SS 1"
		}},
		{"ss://" + ssLegacy + "#Old", func(n *CustomNode) bool {
			return n.Server == "ss2.example" && n.Port == 8389 && n.Method == "aes-128-gcm" && n.Password == "pw"
		}},
		{"ss://2022-blake3-aes-128-gcm:a%2Bb%3D@ss3.example:443#2022", func(n *CustomNode) bool {
			return n.Method == "2022-blake3-aes-128-gcm" && n.Password == "a+b="
		}},
		{"hy2://pass@hy.example:443,20000-30000?obfs=salamander&obfs-password=o&insecure=1&sni=hy.example#HY", func(n *CustomNode) bool {
			return n.Type == NodeHysteria2 && n.Port == 443 && n.Password == "pass" && n.Obfs == "salamander" && n.AllowInsecure
		}},
		{"tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pw@tu.example:443?congestion_control=bbr&alpn=h3#TU", func(n *CustomNode) bool {
			return n.Type == NodeTUIC && n.Password == "pw" && n.CongestionControl == "bbr" && len(n.ALPN) == 1
		}},
		{"anytls://pw@any.example:443?sni=any.example#AT", func(n *CustomNode) bool {
			return n.Type == NodeAnyTLS && n.Password == "pw" && n.SNI == "any.example"
		}},
		{"socks://dXNlcjpwYXNz@so.example:1080#SO", func(n *CustomNode) bool {
			return n.Type == NodeSOCKS && n.Username == "user" && n.Password == "pass"
		}},
	}
	for _, c := range cases {
		n, err := ParseNodeURL(c.link)
		if err != nil {
			t.Errorf("%s: %v", c.link, err)
			continue
		}
		if n.ID == "" || !c.check(n) {
			t.Errorf("%s parsed as %+v", c.link, n)
		}
	}
}

func TestClashSubscriptionParses(t *testing.T) {
	doc := `
proxies:
  - {name: "ss", type: ss, server: a.example, port: "8388", cipher: aes-128-gcm, password: p, plugin: obfs, plugin-opts: {mode: tls, host: x.com}}
  - name: vmess
    type: vmess
    server: b.example
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: auto
    tls: true
    network: ws
    ws-opts: {path: /ray, headers: {Host: cdn.example}}
  - name: vless
    type: vless
    server: c.example
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    flow: xtls-rprx-vision
    reality-opts: {public-key: KEY, short-id: ab}
  - {name: hy2, type: hysteria2, server: d.example, port: 443, password: p, up: "50 Mbps", down: 200}
  - {name: unknown, type: wireguard, server: e.example, port: 51820}
`
	nodes, err := ParseSubscription([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 4 {
		t.Fatalf("got %d nodes, want 4 (the unknown type skipped)", len(nodes))
	}
	if nodes[0].Port != 8388 || nodes[0].PluginOpts != "obfs=tls;obfs-host=x.com" {
		t.Errorf("ss = %+v", nodes[0])
	}
	if nodes[1].Transport != "ws" || nodes[1].Host != "cdn.example" || !nodes[1].TLS {
		t.Errorf("vmess = %+v", nodes[1])
	}
	if nodes[2].RealityPublicKey != "KEY" || !nodes[2].TLS {
		t.Errorf("vless = %+v", nodes[2])
	}
	if nodes[3].UpMbps != 50 || nodes[3].DownMbps != 200 {
		t.Errorf("hy2 = %+v", nodes[3])
	}
}

func TestAnUpdatedSubscriptionKeepsNodeIDs(t *testing.T) {
	old := []CustomNode{{ID: "keep", Name: "HK 01"}, {ID: "gone", Name: "US 01"}}
	fresh := []CustomNode{{ID: "new1", Name: "HK 01"}, {ID: "new2", Name: "JP 01"}}
	KeepIDs(fresh, old)
	if fresh[0].ID != "keep" || fresh[1].ID != "new2" {
		t.Errorf("ids = %s, %s; want keep, new2", fresh[0].ID, fresh[1].ID)
	}
}

func TestSubscriptionUserinfoIsRead(t *testing.T) {
	u := parseUserinfo("upload=100; download=2048; total=1073741824; expire=1767225600")
	if u == nil || u.Download != 2048 || u.Total != 1073741824 || u.Expire != 1767225600 {
		t.Errorf("usage = %+v", u)
	}
	if parseUserinfo("") != nil {
		t.Error("an absent header produced usage")
	}
}
