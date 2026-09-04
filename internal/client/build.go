package client

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
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
func BuildConfig(cfg *Config, bundle *clientcfg.Bundle, tunnels []TunnelState) ([]byte, error) {
	byName := make(map[string]TunnelState, len(tunnels))
	for _, t := range tunnels {
		byName[t.Name] = t
	}
	if err := validateRuleTargets(cfg.Rules, byName, cfg); err != nil {
		return nil, err
	}

	outbounds, err := buildOutbounds(cfg, bundle, tunnels)
	if err != nil {
		return nil, err
	}
	inbounds, err := buildInbounds(cfg)
	if err != nil {
		return nil, err
	}
	dnsServers, err := buildDNSServers(cfg, tunnels)
	if err != nil {
		return nil, err
	}

	routeRules := buildRouteRules(cfg, tunnels, byName)
	dnsRules := buildDNSRules(cfg, tunnels, byName)

	finalOutbound := tagDirect
	if cfg.EffectiveMode() == ModeGlobal {
		finalOutbound = tagProxy
	}

	out := map[string]any{
		"log": map[string]any{"level": cfg.LogLevel, "timestamp": true},
		"dns": map[string]any{
			"servers":  dnsServers,
			"rules":    dnsRules,
			"final":    tagDNSDefault,
			"strategy": cfg.DNS.Strategy,
		},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route": map[string]any{
			"rules": routeRules,
			// Outbounds need to resolve their own server names, and must do
			// so outside the tunnels they are dialing.
			"default_domain_resolver": map[string]any{"server": tagDNSDefault},
			"final":                   finalOutbound,
			// Without this the connection to the vpn-gateway server would be
			// captured by our own TUN routes and loop back into itself.
			"auto_detect_interface": true,
		},
	}
	return json.MarshalIndent(out, "", "  ")
}

func validateRuleTargets(rules []Rule, byName map[string]TunnelState, cfg *Config) error {
	var unknown []string
	for _, r := range rules {
		if r.Disabled {
			continue
		}
		switch r.Tunnel {
		case TargetDirect, TargetBlock, TargetProxy:
			continue
		}
		if _, ok := byName[r.Tunnel]; ok {
			continue
		}
		if cfg != nil {
			if _, ok := cfg.FindNode(r.Tunnel); ok {
				continue
			}
			target := r.Tunnel
			if strings.HasPrefix(target, "node-") || strings.HasPrefix(target, "node:") {
				nodeID := strings.TrimPrefix(strings.TrimPrefix(target, "node:"), "node-")
				if _, ok := cfg.FindNode(nodeID); ok {
					continue
				}
			}
		}
		unknown = append(unknown, r.Tunnel)
	}
	if len(unknown) > 0 {
		// Silently dropping the rule would send intranet traffic to the
		// internet, so a typo has to be loud.
		return fmt.Errorf("rules reference unknown tunnels or nodes: %s", strings.Join(dedupe(unknown), ", "))
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
			"stack":        cfg.TUN.Stack,
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

func buildOutbounds(cfg *Config, bundle *clientcfg.Bundle, tunnels []TunnelState) ([]map[string]any, error) {
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

	// Add custom and subscription nodes
	allNodes := cfg.AllNodes()
	var proxyTags []string
	for _, n := range allNodes {
		tag := n.OutboundTag()
		proxyTags = append(proxyTags, tag)

		sni := n.SNI
		if sni == "" {
			sni = n.Server
		}
		tls := map[string]any{"enabled": true, "server_name": sni}
		if n.AllowInsecure {
			tls["insecure"] = true
		}

		outbounds = append(outbounds, map[string]any{
			"type":        "trojan",
			"tag":         tag,
			"server":      n.Server,
			"server_port": n.Port,
			"password":    n.Password,
			"tls":         tls,
		})
	}

	needsProxySelector := len(proxyTags) > 0 || cfg.EffectiveMode() == ModeGlobal
	if !needsProxySelector {
		for _, r := range cfg.Rules {
			if r.Tunnel == TargetProxy {
				needsProxySelector = true
				break
			}
		}
	}

	if needsProxySelector {
		if len(proxyTags) > 0 {
			proxyOutbounds := append([]string(nil), proxyTags...)
			proxyOutbounds = append(proxyOutbounds, tagDirect)
			defaultOutbound := tagDirect
			if cfg.SelectedNode != "" {
				for _, pt := range proxyTags {
					if pt == cfg.SelectedNode || pt == "node-"+cfg.SelectedNode || "node-"+pt == cfg.SelectedNode {
						defaultOutbound = pt
						break
					}
				}
			}
			outbounds = append(outbounds, map[string]any{
				"type":      "selector",
				"tag":       tagProxy,
				"outbounds": proxyOutbounds,
				"default":   defaultOutbound,
			})
		} else {
			outbounds = append(outbounds, map[string]any{
				"type":      "selector",
				"tag":       tagProxy,
				"outbounds": []string{tagDirect},
				"default":   tagDirect,
			})
		}
	}

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

func buildRouteRules(cfg *Config, tunnels []TunnelState, byName map[string]TunnelState) []map[string]any {
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
		if r.Disabled {
			continue
		}
		if rule := compileRule(r, r.Tunnel, byName, cfg); rule != nil {
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
	return rules
}

// compileRule turns one configured rule into a sing-box rule, or nil when it
// matches nothing.
func compileRule(r Rule, target string, byName map[string]TunnelState, cfg *Config) map[string]any {
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

	switch target {
	case TargetBlock:
		rule["action"] = "reject"
	case TargetDirect:
		rule["outbound"] = tagDirect
	case TargetProxy:
		rule["outbound"] = tagProxy
	default:
		if t, ok := byName[target]; ok {
			rule["outbound"] = t.RouteTag()
		} else if cfg != nil {
			if n, ok := cfg.FindNode(target); ok {
				rule["outbound"] = n.OutboundTag()
			} else if strings.HasPrefix(target, "node-") || strings.HasPrefix(target, "node:") {
				nodeID := strings.TrimPrefix(strings.TrimPrefix(target, "node:"), "node-")
				if n, ok := cfg.FindNode(nodeID); ok {
					rule["outbound"] = n.OutboundTag()
				} else {
					rule["outbound"] = "node-" + nodeID
				}
			} else {
				rule["outbound"] = target
			}
		} else {
			rule["outbound"] = target
		}
	}
	return rule
}

// buildDNSRules mirrors the routing rules.
//
// This is the part that is easy to get wrong: an intranet name resolves only
// through the VPN's own resolver, which is reachable only through that
// tunnel. Routing the traffic without also routing the lookup leaves internal
// names failing to resolve while everything looks correctly configured.
func buildDNSRules(cfg *Config, tunnels []TunnelState, byName map[string]TunnelState) []map[string]any {
	// Never nil: a nil slice marshals to null, and an empty list is both
	// clearer to read and safer to feed back in.
	rules := []map[string]any{}

	for _, r := range cfg.Rules {
		if r.Disabled || !r.hasDomainMatcher() {
			continue
		}
		switch r.Tunnel {
		case TargetDirect, TargetBlock, TargetProxy:
			continue
		}
		t, ok := byName[r.Tunnel]
		if !ok || t.DNSTag() == "" {
			continue
		}
		rule := map[string]any{"server": t.DNSTag()}
		if len(r.Domain) > 0 {
			rule["domain"] = r.Domain
		}
		if len(r.DomainSuffix) > 0 {
			rule["domain_suffix"] = r.DomainSuffix
		}
		if len(r.DomainKeyword) > 0 {
			rule["domain_keyword"] = r.DomainKeyword
		}
		rules = append(rules, rule)
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
	return rules
}

func buildDNSServers(cfg *Config, tunnels []TunnelState) ([]map[string]any, error) {
	servers := make([]map[string]any, 0, len(tunnels)+1)

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
	return append(servers, def), nil
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
