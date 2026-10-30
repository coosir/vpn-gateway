package client

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/vpn-gateway/vpn-gateway/internal/server/clientcfg"
)

// Outbound and DNS server tags in the generated configuration.
const (
	tagDirect  = "direct"
	tagBlock   = "block"
	tagProxy   = "proxy"
	tagTUNIn   = "tun-in"
	tagProxyIn = "proxy-in"

	// tunnelPrefix tags the trojan outbound that actually reaches a tunnel.
	tunnelPrefix = "tunnel-"
	// routePrefix tags the selector in front of it. Rules point at the
	// selector, never at the tunnel, so a tunnel going down is handled by
	// switching the selector rather than rewriting and restarting everything.
	routePrefix = "route-"
	// dnsPrefix tags a tunnel's own resolver.
	dnsPrefix = "dns-"

	tagDNSDefault = "dns-default"
	tagDNSRemote  = "dns-remote"
	// tagAuto is the group that follows the fastest node.
	tagAuto = "auto"
)

// TunnelState is what the client knows about one tunnel: its credentials from
// the bundle and its live state from the control API.
type TunnelState struct {
	Name     string
	Password string

	// Up reports whether the server says the tunnel is carrying traffic.
	Up bool
	// Wanted reports whether the tunnel has been asked to dial. One that has
	// not is stopped on purpose rather than broken, and its rules fall back
	// the same way a failed one's do.
	Wanted bool

	// Routes, DNS and SearchDomains are what the VPN pushed, relayed by the
	// server. They become implicit rules.
	Routes        []string
	DNS           []string
	SearchDomains []string
	// UDP reports whether the tunnel's data plane can carry datagrams. When
	// false its resolver must be queried over TCP.
	UDP bool
}

// RouteTag is the outbound a rule targeting this tunnel should use.
func (t TunnelState) RouteTag() string { return routePrefix + t.Name }

// DNSTag is this tunnel's resolver tag, empty when it pushed no resolver.
func (t TunnelState) DNSTag() string {
	if len(t.DNS) == 0 {
		return ""
	}
	return dnsPrefix + t.Name
}

// BuildConfig renders the sing-box configuration for this client.
//
// The configuration is generated as JSON rather than assembled from sing-box's
// option structs: JSON is the interface upstream documents, and a generated
// file can be dumped verbatim when a routing decision needs explaining.
//
// A nil bundle leaves the enterprise gateway out entirely: no tunnels, none
// of its rules. What remains is an ordinary proxy client.
func BuildConfig(cfg *Config, bundle *clientcfg.Bundle, tunnels []TunnelState) ([]byte, error) {
	gateway := bundle != nil
	if !gateway {
		tunnels = nil
	}
	byName := make(map[string]TunnelState, len(tunnels))
	for _, t := range tunnels {
		byName[t.Name] = t
	}
	if gateway {
		if err := validateRuleTargets(cfg.Rules, byName); err != nil {
			return nil, err
		}
	}

	nodes := usableNodes(cfg)
	outbounds, err := buildOutbounds(cfg, bundle, tunnels, nodes)
	if err != nil {
		return nil, err
	}
	inbounds, err := buildInbounds(cfg)
	if err != nil {
		return nil, err
	}
	remote := hasRemoteDNS(cfg, nodes)
	dnsServers, err := buildDNSServers(cfg, tunnels, remote)
	if err != nil {
		return nil, err
	}

	sets := &ruleSets{cfg: cfg, used: map[string]bool{}}
	routeRules := buildRouteRules(cfg, gateway, tunnels, byName, nodes, sets)
	dnsRules := buildDNSRules(cfg, tunnels, byName, sets, remote)

	finalOutbound, finalDNS := tagDirect, tagDNSDefault
	if cfg.EffectiveMode() == ModeGlobal {
		finalOutbound = tagProxy
		if remote {
			finalDNS = tagDNSRemote
		}
	}

	route := map[string]any{
		"rules": routeRules,
		// Outbounds need to resolve their own server names, and must do
		// so outside the tunnels they are dialing.
		"default_domain_resolver": map[string]any{"server": tagDNSDefault},
		"final":                   finalOutbound,
		// Without this the connection to the vpn-gateway server would be
		// captured by our own TUN routes and loop back into itself.
		"auto_detect_interface": true,
	}
	if defs := sets.definitions(); len(defs) > 0 {
		route["rule_set"] = defs
	}
	if name := cfg.TUN.OutboundInterface; name != "" {
		// A named adapter instead of whichever holds the default route,
		// which another program's virtual adapter may have taken. sing-box
		// ignores default_interface while auto-detection is on.
		route["auto_detect_interface"] = false
		route["default_interface"] = name
	}

	out := map[string]any{
		"log": map[string]any{"level": cfg.LogLevel, "timestamp": true},
		"dns": map[string]any{
			"servers":  dnsServers,
			"rules":    dnsRules,
			"final":    finalDNS,
			"strategy": cfg.DNS.Strategy,
		},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route":     route,
	}
	return json.MarshalIndent(out, "", "  ")
}

// usableNodes is every node this build can dial. A node it cannot -- a
// protocol left out of the build, an entry with no address -- is skipped
// rather than allowed to stop the engine from starting.
func usableNodes(cfg *Config) []CustomNode {
	var out []CustomNode
	for _, n := range cfg.AllNodes() {
		if n.Unsupported() == "" {
			out = append(out, n)
		}
	}
	return out
}

// hasRemoteDNS reports whether names leaving through a proxy should be
// resolved through it. With no node to go through there is nothing to gain,
// and a public resolver dialed directly is exactly what is unreachable where
// a proxy is needed.
func hasRemoteDNS(cfg *Config, nodes []CustomNode) bool {
	return len(nodes) > 0 && cfg.DNS.Remote != "" && cfg.DNS.Remote != "local"
}

// selectedOutbound is what the proxy group points at to begin with.
func selectedOutbound(cfg *Config, nodes []CustomNode) string {
	if len(nodes) == 0 {
		return tagDirect
	}
	switch sel := cfg.SelectedNode; {
	case sel == TargetDirect:
		return tagDirect
	case IsNodeTarget(sel):
		for _, n := range nodes {
			if n.OutboundTag() == sel {
				return sel
			}
		}
	}
	// Nothing chosen, or a node a subscription update has since dropped.
	return tagAuto
}

func validateRuleTargets(rules []Rule, byName map[string]TunnelState) error {
	var unknown []string
	for _, r := range rules {
		if r.Disabled {
			continue
		}
		switch r.Tunnel {
		case TargetDirect, TargetBlock:
			continue
		}
		if _, ok := byName[r.Tunnel]; ok {
			continue
		}
		unknown = append(unknown, r.Tunnel)
	}
	if len(unknown) > 0 {
		// Silently dropping the rule would send intranet traffic to the
		// internet, so a typo has to be loud.
		return fmt.Errorf("gateway rules reference unknown tunnels: %s", strings.Join(dedupe(unknown), ", "))
	}
	return nil
}

func buildInbounds(cfg *Config) ([]map[string]any, error) {
	var inbounds []map[string]any

	if cfg.TUN.Enabled {
		tun := map[string]any{
			"type":         "tun",
			"tag":          tagTUNIn,
			"address":      []string{cfg.TUN.Address},
			"mtu":          cfg.TUN.MTU,
			"auto_route":   cfg.TUN.AutoRoute,
			"strict_route": cfg.TUN.StrictRoute,
			"stack":        cfg.TUN.EffectiveStack(),
		}
		if cfg.TUN.Name != "" {
			tun["interface_name"] = cfg.TUN.Name
		}
		inbounds = append(inbounds, tun)
	}

	if cfg.Proxy.Enabled {
		host, portStr, err := net.SplitHostPort(cfg.Proxy.Listen)
		if err != nil {
			return nil, fmt.Errorf("proxy.listen: %q is not a host:port address: %w", cfg.Proxy.Listen, err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("proxy.listen: %q has no valid port", cfg.Proxy.Listen)
		}
		if host == "" {
			host = "127.0.0.1"
		}
		// "mixed" serves SOCKS5 and HTTP on one port, so a browser and a
		// shell can share it.
		inbounds = append(inbounds, map[string]any{
			"type": "mixed", "tag": tagProxyIn,
			"listen": host, "listen_port": port,
		})
	}
	return inbounds, nil
}

func buildOutbounds(cfg *Config, bundle *clientcfg.Bundle, tunnels []TunnelState, nodes []CustomNode) ([]map[string]any, error) {
	outbounds := []map[string]any{
		{"type": "direct", "tag": tagDirect},
		{"type": "block", "tag": tagBlock},
	}

	if bundle != nil && len(tunnels) > 0 {
		host, port, err := net.SplitHostPort(bundle.Server.Address)
		if err != nil {
			return nil, fmt.Errorf("bundle server address %q is not host:port: %w", bundle.Server.Address, err)
		}
		portNum, err := strconv.Atoi(port)
		if err != nil {
			return nil, fmt.Errorf("bundle server address %q has no valid port", bundle.Server.Address)
		}

		tls := map[string]any{"enabled": true, "server_name": bundle.Server.ServerName}
		if pem := bundle.Server.CertificatePEM; pem != "" {
			// Trust exactly the server's certificate. Turning verification off
			// instead would accept any certificate at all.
			tls["certificate"] = strings.Split(strings.TrimSpace(pem), "\n")
		}

		fallback := tagDirect
		if cfg.OnFailure == TargetBlock {
			fallback = tagBlock
		}

		for _, t := range tunnels {
			outbounds = append(outbounds, map[string]any{
				"type": "trojan", "tag": tunnelPrefix + t.Name,
				"server": host, "server_port": portNum,
				"password": t.Password,
				"tls":      tls,
			})
			// The selector is what rules target. Switching it when a tunnel goes
			// down leaves every other tunnel's connections untouched, which
			// restarting the whole client would not.
			current := tunnelPrefix + t.Name
			if !t.Up {
				current = fallback
			}
			outbounds = append(outbounds, map[string]any{
				"type": "selector", "tag": t.RouteTag(),
				"outbounds": []string{tunnelPrefix + t.Name, fallback},
				"default":   current,
			})
		}
	}

	// The proxy group always exists, so a rule can name it whether or not
	// there is anything in it yet. Empty, it goes direct.
	members := []string{}
	if len(nodes) > 0 {
		tags := make([]string, 0, len(nodes))
		for _, n := range nodes {
			ob, err := n.Outbound()
			if err != nil {
				return nil, fmt.Errorf("node %s: %w", n.Name, err)
			}
			outbounds = append(outbounds, ob)
			tags = append(tags, n.OutboundTag())
		}
		// auto follows whichever node answers fastest, and is where the
		// group points until somebody picks one.
		outbounds = append(outbounds, map[string]any{
			"type":      "urltest",
			"tag":       tagAuto,
			"outbounds": tags,
			"url":       latencyURL,
			"interval":  "10m",
			"tolerance": 50,
		})
		members = append(append(members, tagAuto), tags...)
	}
	members = append(members, tagDirect)
	outbounds = append(outbounds, map[string]any{
		"type":      "selector",
		"tag":       tagProxy,
		"outbounds": members,
		"default":   selectedOutbound(cfg, nodes),
		// Connections already open through the old choice are closed, so
		// switching node takes effect for everything, not only what starts
		// afterwards.
		"interrupt_exist_connections": true,
	})

	return outbounds, nil
}

// AutoRules generates Rule objects representing automatic tunnel routing and domain rules.
func AutoRules(cfg *Config, tunnels []TunnelState) []Rule {
	var auto []Rule
	for _, t := range tunnels {
		if len(t.SearchDomains) > 0 {
			for _, d := range t.SearchDomains {
				disabled := !cfg.AutoDomains || cfg.IsAutoRuleDisabled(t.Name, "domain_suffix", d)
				auto = append(auto, Rule{
					DomainSuffix: []string{d},
					Tunnel:       t.Name,
					Disabled:     disabled,
					Auto:         true,
				})
			}
		}
		if len(t.Routes) > 0 {
			for _, r := range t.Routes {
				disabled := !cfg.AutoRoutes || cfg.IsAutoRuleDisabled(t.Name, "ip_cidr", r)
				auto = append(auto, Rule{
					IPCIDR:   []string{r},
					Tunnel:   t.Name,
					Disabled: disabled,
					Auto:     true,
				})
			}
		}
	}
	return auto
}

// buildRouteRules lays the rules out in the order they win: the enterprise
// gateway's explicit rules, then the ones derived from what its tunnels
// report, then -- in rule mode -- the proxy rules. Whatever is left goes to
// route.final.
func buildRouteRules(cfg *Config, gateway bool, tunnels []TunnelState, byName map[string]TunnelState, nodes []CustomNode, sets *ruleSets) []map[string]any {
	rules := []map[string]any{
		// Sniffing must come first: without a name extracted from the TLS
		// handshake or HTTP request, traffic arriving on TUN is only an
		// address and no domain rule can match it.
		{"action": "sniff"},
		// DNS queries go to the DNS module rather than to whatever resolver
		// the machine was configured with, which is what lets a tunnel's
		// internal names resolve at all.
		{"protocol": "dns", "action": "hijack-dns"},
	}

	// Explicit rules come before derived ones so a specific choice always
	// beats an inferred one.
	for _, r := range cfg.Rules {
		if !gateway || r.Disabled {
			continue
		}
		if rule := compileRule(r, gatewayTarget(r.Tunnel, byName), sets); rule != nil {
			rules = append(rules, rule)
		}
	}

	for _, t := range tunnels {
		if cfg.AutoDomains && len(t.SearchDomains) > 0 {
			var enabledDomains []string
			for _, d := range t.SearchDomains {
				if !cfg.IsAutoRuleDisabled(t.Name, "domain_suffix", d) {
					enabledDomains = append(enabledDomains, d)
				}
			}
			if len(enabledDomains) > 0 {
				rules = append(rules, map[string]any{
					"domain_suffix": enabledDomains,
					"outbound":      t.RouteTag(),
				})
			}
		}
		if cfg.AutoRoutes && len(t.Routes) > 0 {
			var enabledRoutes []string
			for _, r := range t.Routes {
				if !cfg.IsAutoRuleDisabled(t.Name, "ip_cidr", r) {
					enabledRoutes = append(enabledRoutes, r)
				}
			}
			if len(enabledRoutes) > 0 {
				rules = append(rules, map[string]any{
					"ip_cidr":  enabledRoutes,
					"outbound": t.RouteTag(),
				})
			}
		}
	}

	if cfg.EffectiveMode() == ModeRule {
		for _, r := range cfg.ProxyRules {
			if r.Disabled {
				continue
			}
			if rule := compileRule(r, proxyTarget(r.Outbound, nodes), sets); rule != nil {
				rules = append(rules, rule)
			}
		}
	}
	return rules
}

// gatewayTarget is the outbound a gateway rule sends to.
func gatewayTarget(target string, byName map[string]TunnelState) string {
	switch target {
	case TargetDirect:
		return tagDirect
	case TargetBlock:
		return tagBlock
	}
	if t, ok := byName[target]; ok {
		return t.RouteTag()
	}
	return target
}

// proxyTarget is the outbound a proxy rule sends to. A node a subscription
// update has dropped falls back to the proxy group: the rule meant "through
// a proxy", and refusing to start over it would be worse.
func proxyTarget(target string, nodes []CustomNode) string {
	switch target {
	case TargetDirect:
		return tagDirect
	case TargetBlock:
		return tagBlock
	case TargetAuto:
		if len(nodes) > 0 {
			return tagAuto
		}
		return tagProxy
	case TargetProxy:
		return tagProxy
	}
	for _, n := range nodes {
		if n.OutboundTag() == target {
			return target
		}
	}
	return tagProxy
}

// compileRule turns one configured rule into a sing-box rule sending to
// outbound, or nil when it matches nothing. A rule that matched only by rule
// sets none of which could be downloaded matches nothing.
func compileRule(r Rule, outbound string, sets *ruleSets) map[string]any {
	if !r.hasMatcher() {
		return nil
	}
	rule := map[string]any{}
	if len(r.Domain) > 0 {
		rule["domain"] = r.Domain
	}
	if len(r.DomainSuffix) > 0 {
		rule["domain_suffix"] = r.DomainSuffix
	}
	if len(r.DomainKeyword) > 0 {
		rule["domain_keyword"] = r.DomainKeyword
	}
	if len(r.IPCIDR) > 0 {
		rule["ip_cidr"] = r.IPCIDR
	}
	if len(r.Port) > 0 {
		rule["port"] = r.Port
	}
	if len(r.ProcessName) > 0 {
		rule["process_name"] = r.ProcessName
	}
	geo := len(r.GeoSite)+len(r.GeoIP) > 0
	if tags := sets.use(r.ruleTags()); len(tags) > 0 {
		rule["rule_set"] = tags
	} else if geo && len(r.Domain)+len(r.DomainSuffix)+len(r.DomainKeyword)+len(r.IPCIDR) == 0 {
		return nil
	}

	if outbound == tagBlock {
		rule["action"] = "reject"
	} else {
		rule["outbound"] = outbound
	}
	return rule
}

// ruleSets keeps track of which downloaded rule sets the rules use, so only
// those are declared.
type ruleSets struct {
	cfg  *Config
	used map[string]bool
}

// use returns the tags out of want that have been downloaded, and records
// them as used.
func (s *ruleSets) use(want []string) []string {
	var ready []string
	for _, tag := range want {
		if s.cfg.ruleSetReady(tag) {
			s.used[tag] = true
			ready = append(ready, tag)
		}
	}
	return ready
}

func (s *ruleSets) definitions() []map[string]any {
	tags := make([]string, 0, len(s.used))
	for tag := range s.used {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	defs := make([]map[string]any, 0, len(tags))
	for _, tag := range tags {
		defs = append(defs, map[string]any{
			"type": "local", "tag": tag, "format": "binary", "path": s.cfg.ruleSetPath(tag),
		})
	}
	return defs
}

// buildDNSRules mirrors the routing rules.
//
// This is the part that is easy to get wrong: an intranet name resolves only
// through the VPN's own resolver, which is reachable only through that
// tunnel. Routing the traffic without also routing the lookup leaves internal
// names failing to resolve while everything looks correctly configured. The
// same holds for a name sent through a proxy node, which is looked up
// through the node so the answer is one the node can use.
func buildDNSRules(cfg *Config, tunnels []TunnelState, byName map[string]TunnelState, sets *ruleSets, remote bool) []map[string]any {
	// Never nil: a nil slice marshals to null, and an empty list is both
	// clearer to read and safer to feed back in.
	rules := []map[string]any{}

	for _, r := range cfg.Rules {
		if r.Disabled || !r.hasDomainMatcher() {
			continue
		}
		switch r.Tunnel {
		case TargetDirect, TargetBlock:
			continue
		}
		t, ok := byName[r.Tunnel]
		if !ok || t.DNSTag() == "" {
			continue
		}
		if rule := dnsRule(r, t.DNSTag(), sets); rule != nil {
			rules = append(rules, rule)
		}
	}

	if cfg.AutoDomains {
		for _, t := range tunnels {
			if t.DNSTag() == "" || len(t.SearchDomains) == 0 {
				continue
			}
			var enabledDomains []string
			for _, d := range t.SearchDomains {
				if !cfg.IsAutoRuleDisabled(t.Name, "domain_suffix", d) {
					enabledDomains = append(enabledDomains, d)
				}
			}
			if len(enabledDomains) > 0 {
				rules = append(rules, map[string]any{
					"domain_suffix": enabledDomains,
					"server":        t.DNSTag(),
				})
			}
		}
	}

	if remote && cfg.EffectiveMode() == ModeRule {
		// Direct rules are mirrored too, in their place: a name a direct rule
		// claims ahead of a proxy rule must not be resolved remotely because
		// the proxy rule also matches it.
		for _, r := range cfg.ProxyRules {
			if r.Disabled || !r.hasDomainMatcher() || len(r.ProcessName) > 0 {
				continue
			}
			server := tagDNSRemote
			switch r.Outbound {
			case TargetBlock:
				continue
			case TargetDirect:
				server = tagDNSDefault
			}
			if rule := dnsRule(r, server, sets); rule != nil {
				rules = append(rules, rule)
			}
		}
	}
	return rules
}

// dnsRule is the name half of a rule, sending lookups to server. Addresses,
// ports and processes say nothing about a lookup, so they are left out.
func dnsRule(r Rule, server string, sets *ruleSets) map[string]any {
	rule := map[string]any{"server": server}
	if len(r.Domain) > 0 {
		rule["domain"] = r.Domain
	}
	if len(r.DomainSuffix) > 0 {
		rule["domain_suffix"] = r.DomainSuffix
	}
	if len(r.DomainKeyword) > 0 {
		rule["domain_keyword"] = r.DomainKeyword
	}
	var geosite []string
	for _, name := range r.GeoSite {
		geosite = append(geosite, geositeTag(name))
	}
	if tags := sets.use(geosite); len(tags) > 0 {
		rule["rule_set"] = tags
	}
	if len(rule) == 1 {
		return nil
	}
	return rule
}

func buildDNSServers(cfg *Config, tunnels []TunnelState, remote bool) ([]map[string]any, error) {
	servers := make([]map[string]any, 0, len(tunnels)+2)

	for _, t := range tunnels {
		if t.DNSTag() == "" {
			continue
		}
		// A tunnel's data plane carries TCP always and datagrams only when
		// it says so, so an unqualified UDP query would silently time out.
		kind := "tcp"
		if t.UDP {
			kind = "udp"
		}
		servers = append(servers, map[string]any{
			"type": kind,
			"tag":  t.DNSTag(),
			// Only the first resolver is used; sing-box takes one address per
			// server and a second entry would need its own tag and rules.
			"server": t.DNSNS(),
			// Through the selector, so the resolver follows the tunnel down.
			"detour": t.RouteTag(),
		})
	}

	// No detour on the default resolver: direct is where an outbound-less
	// server already goes, and sing-box rejects an explicit detour to it.
	def, err := parseDNSURL(cfg.DNS.Default, tagDNSDefault, "")
	if err != nil {
		return nil, err
	}
	servers = append(servers, def)

	if remote {
		// Through the proxy group, so it follows whichever node is chosen.
		r, err := parseDNSURL(cfg.DNS.Remote, tagDNSRemote, tagProxy)
		if err != nil {
			return nil, fmt.Errorf("dns.remote: %w", err)
		}
		servers = append(servers, r)
	}
	return servers, nil
}

// DNSNS returns the resolver address to use for this tunnel.
func (t TunnelState) DNSNS() string {
	if len(t.DNS) == 0 {
		return ""
	}
	return t.DNS[0]
}

// parseDNSURL turns "https://1.1.1.1/dns-query", "tls://1.1.1.1",
// "udp://192.168.1.1", "tcp://10.0.0.1" or "local" into a DNS server entry.
func parseDNSURL(raw, tag, detour string) (map[string]any, error) {
	if raw == "local" {
		// Defer to whatever the operating system is configured with.
		return map[string]any{"type": "local", "tag": tag}, nil
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("dns.default: %q is not a URL: %w", raw, err)
	}
	server := map[string]any{"tag": tag}
	if detour != "" {
		server["detour"] = detour
	}

	switch u.Scheme {
	case "udp", "tcp", "tls", "quic", "h3":
		server["type"] = u.Scheme
	case "https":
		server["type"] = "https"
		if u.Path != "" && u.Path != "/" {
			server["path"] = u.Path
		}
	default:
		return nil, fmt.Errorf("dns.default: unsupported scheme %q in %q", u.Scheme, raw)
	}

	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("dns.default: %q has no host", raw)
	}
	server["server"] = host
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("dns.default: %q has an invalid port", raw)
		}
		server["server_port"] = n
	}
	return server, nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
