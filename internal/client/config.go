// Package client is the desktop side of vpn-gateway: one TUN interface, one
// routing engine, and a trojan connection per tunnel.
//
// Nothing here knows about VPN protocols or containers. The client learns
// which tunnels exist, what they claim and whether they are up from the
// server's control API, and turns that into routing and DNS rules.
package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	tun "github.com/sagernet/sing-tun"

	"gopkg.in/yaml.v3"
)

// Reserved rule targets that are not tunnel names.
const (
	// TargetDirect sends traffic out the machine's normal connection.
	TargetDirect = "direct"
	// TargetBlock refuses the connection.
	TargetBlock = "block"
	// TargetProxy sends traffic out through the active proxy node group.
	TargetProxy = "proxy"
	// TargetAuto sends traffic out through whichever node answered fastest.
	TargetAuto = "auto"

	ModeRule   = "rule"
	ModeGlobal = "global"
	ModeDirect = "direct"
)

// Config is the client configuration, normally
// /etc/vpn-gateway/client.yaml.
//
// It describes two things that share one routing engine. The first is an
// ordinary proxy client: nodes, subscriptions and the rules that pick between
// them. The second is the enterprise gateway: a vpn-gateway server whose
// tunnels reach intranets. The gateway's rules are matched first, the proxy
// rules after them, and whatever neither claims goes direct.
type Config struct {
	// Bundle is the path to the JSON emitted by `vgctl client-config`. It
	// carries the server address, the certificate to pin and one password
	// per tunnel. Without one the client is an ordinary proxy client.
	Bundle string `yaml:"bundle"`

	// GatewayDisabled switches the enterprise gateway off while keeping
	// everything it needs, so it can be switched back on in one step. It is
	// the negative so that a file written before there was a switch, which
	// has a bundle and no opinion, keeps the gateway it was written for.
	GatewayDisabled bool `yaml:"gateway_disabled,omitempty" json:"gateway_disabled,omitempty"`

	TUN   TUNConfig   `yaml:"tun"`
	Proxy ProxyConfig `yaml:"proxy"`
	DNS   DNSConfig   `yaml:"dns"`
	UI    UIConfig    `yaml:"ui"`
	Auth  AuthConfig  `yaml:"auth,omitempty" json:"auth,omitempty"`

	// OnFailure is what happens to traffic for a tunnel that is not up:
	// "direct" or "block". A tunnel going down must never take the whole
	// machine offline, so this is answered explicitly rather than left to
	// whatever the connection error happens to be.
	OnFailure string `yaml:"on_failure,omitempty"`

	// Rules belong to the enterprise gateway. They are matched in order,
	// before any rule derived from what a tunnel reports, so an explicit
	// choice always wins over an inferred one -- and all of them before any
	// proxy rule, so intranet traffic never leaves through a proxy node.
	Rules []Rule `yaml:"rules,omitempty"`

	// DisabledAutoRules records keys of auto-derived rules disabled by the user.
	DisabledAutoRules []string `yaml:"disabled_auto_rules,omitempty" json:"disabled_auto_rules,omitempty"`

	// AutoRoutes turns the routes a tunnel reports into implicit ip_cidr
	// rules. This is what makes split routing usable without writing a rule
	// for every intranet range.
	AutoRoutes bool `yaml:"auto_routes,omitempty"`
	// AutoDomains does the same for the search domains a tunnel reports.
	AutoDomains bool `yaml:"auto_domains,omitempty"`

	// Mode controls everything the gateway does not claim: "rule" (the
	// default) follows ProxyRules, "global" sends all of it through the
	// proxy group, and "direct" sends all of it out directly.
	Mode string `yaml:"mode,omitempty" json:"mode,omitempty"`

	// ProxyRules are the ordinary client's rules, consulted in rule mode after
	// every gateway rule. Each names an Outbound rather than a tunnel.
	ProxyRules []Rule `yaml:"proxy_rules,omitempty" json:"proxy_rules,omitempty"`

	// Subscriptions holds remote node subscriptions.
	Subscriptions []Subscription `yaml:"subscriptions,omitempty" json:"subscriptions,omitempty"`

	// CustomNodes holds manually added proxy nodes.
	CustomNodes []CustomNode `yaml:"custom_nodes,omitempty" json:"custom_nodes,omitempty"`

	// SelectedNode is what the proxy group points at: a node's outbound tag
	// ("node-…"), "auto" for the fastest node, or "direct". Empty is auto.
	SelectedNode string `yaml:"selected_node,omitempty" json:"selected_node,omitempty"`

	// LogLevel is sing-box's log level.
	LogLevel string `yaml:"log_level,omitempty"`
	// RequestLog enables the in-memory, bounded request viewer.
	RequestLog bool `yaml:"request_log,omitempty" json:"request_log,omitempty"`

	// RuleSetDir is where downloaded geosite and geoip rule sets are kept. It
	// is not configured: the session puts them beside the configuration file,
	// which it can always write to.
	RuleSetDir string `yaml:"-" json:"-"`
}

// EffectiveMode returns the normalized mode ("rule", "global", "direct").
//
// Rule is the default. With no proxy rules and no nodes it sends everything
// direct, which is what a client used only for the gateway always did.
func (c *Config) EffectiveMode() string {
	if c.Mode == ModeGlobal || c.Mode == ModeDirect {
		return c.Mode
	}
	return ModeRule
}

// GatewayConfigured reports whether a bundle has been named.
func (c *Config) GatewayConfigured() bool { return c.Bundle != "" }

// GatewayWanted reports whether the enterprise gateway should be part of the
// engine when it runs.
func (c *Config) GatewayWanted() bool { return c.GatewayConfigured() && !c.GatewayDisabled }

// Clone returns a copy that shares nothing with c, so a handler can change it
// without touching the configuration a running engine is reading.
func (c *Config) Clone() *Config {
	raw, err := json.Marshal(c)
	if err != nil {
		panic("client: configuration does not encode: " + err.Error())
	}
	var out Config
	if err := json.Unmarshal(raw, &out); err != nil {
		panic("client: configuration does not decode: " + err.Error())
	}
	out.RuleSetDir = c.RuleSetDir
	return &out
}

// AuthConfig holds user credentials for server authentication.
type AuthConfig struct {
	Username string `yaml:"username,omitempty" json:"username,omitempty"`
	Password string `yaml:"password,omitempty" json:"password,omitempty"`
}

// TUNConfig controls the system-wide interface. Bringing it up needs
// elevated privileges on every platform.
type TUNConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Name is the interface name; empty lets the platform choose.
	Name string `yaml:"name,omitempty" json:"name,omitempty"`
	// Address is the interface's own prefix, e.g. "172.19.0.1/30".
	Address string `yaml:"address,omitempty" json:"address,omitempty"`
	MTU     uint32 `yaml:"mtu,omitempty" json:"mtu,omitempty"`
	// AutoRoute installs the system routes that send traffic to the
	// interface. Without it the interface exists but carries nothing.
	AutoRoute bool `yaml:"auto_route,omitempty" json:"auto_route,omitempty"`
	// StrictRoute additionally blocks traffic that tries to bypass the
	// interface. It is more thorough and more likely to interfere with other
	// networking on the machine, so it is off by default.
	StrictRoute bool `yaml:"strict_route,omitempty" json:"strict_route,omitempty"`
	// Stack is "system", "gvisor" or "mixed". Empty is this platform's
	// default; see EffectiveStack.
	Stack string `yaml:"stack,omitempty" json:"stack,omitempty"`
	// StackChosen records that Stack was picked by somebody rather than
	// written as a default. Clients up to build 0067 saved the default they
	// had, "system", into every file, and Windows has since changed default:
	// this is what tells that leftover apart from a choice to keep.
	StackChosen bool `yaml:"stack_chosen,omitempty" json:"stack_chosen,omitempty"`
	// OutboundInterface pins the network adapter the client's own
	// connections leave by -- to the server, and anything sent direct. Empty
	// lets it follow the system's default route.
	//
	// Following the default route is right until another program installs a
	// virtual adapter of its own and takes that route: a game accelerator, or
	// another VPN. The client then sends its connection to the server through
	// that program, which may not carry it. Naming the real adapter here
	// keeps it off whatever else is installed.
	OutboundInterface string `yaml:"outbound_interface,omitempty" json:"outbound_interface,omitempty"`
}

// ProxyConfig exposes a local SOCKS5 and HTTP port instead of, or as well as,
// the TUN interface. It needs no privileges, which makes it the way to try
// the client out and the fallback when TUN is not available.
type ProxyConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Listen  string `yaml:"listen,omitempty" json:"listen,omitempty"`
}

// DNSConfig controls name resolution for everything no tunnel claims.
// Per-tunnel resolvers are derived from what each tunnel reports.
type DNSConfig struct {
	// Default is the resolver for unclaimed names. "local" uses the system
	// resolver and is the default. Otherwise a URL:
	// "https://1.1.1.1/dns-query", "tls://1.1.1.1", "udp://192.168.1.1".
	//
	// A public resolver keeps names outside every tunnel off the local
	// network, which is worth having where it is reachable.
	Default string `yaml:"default,omitempty" json:"default,omitempty"`
	// Remote resolves names that leave through a proxy node, and is itself
	// reached through the proxy group. Resolving those names locally would
	// tell the local network what is being visited and, where answers are
	// tampered with, hand back an address the node cannot use.
	Remote string `yaml:"remote,omitempty" json:"remote,omitempty"`
	// Strategy is "prefer_ipv4", "prefer_ipv6", "ipv4_only" or "ipv6_only".
	Strategy string `yaml:"strategy,omitempty" json:"strategy,omitempty"`
}

// UIConfig controls the local interface.
type UIConfig struct {
	// Enabled serves the interface while the client is running.
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Listen must be a loopback address. Anything reachable from the network
	// would let a stranger reroute this machine's traffic.
	Listen string `yaml:"listen,omitempty" json:"listen,omitempty"`
	// StateDir holds the interface token, so the link stays the same between
	// restarts.
	StateDir string `yaml:"state_dir,omitempty" json:"state_dir,omitempty"`
	// Open launches a browser at the interface when the client starts.
	Open bool `yaml:"open,omitempty" json:"open,omitempty"`

	// LinkFile is where the client writes the full interface link, including
	// the token, so the tray application can find it without anyone copying
	// it by hand.
	//
	// The client usually runs elevated and keeps its state directory to
	// itself, which a desktop session cannot read. Naming the path here lets
	// the operator put the link somewhere their own user can, and decide who
	// that is: whoever can read this file can drive the interface.
	LinkFile string `yaml:"link_file,omitempty" json:"link_file,omitempty"`

	// LinkOwner is the user the link file is given to. A file root writes
	// belongs to root and is unreadable by the desktop session that has to
	// open it, so naming the owner is the other half of naming the path.
	//
	// Empty leaves it with whoever the client runs as, which is right for a
	// client that is not elevated in the first place.
	LinkOwner string `yaml:"link_owner,omitempty" json:"link_owner,omitempty"`
}

// Rule routes matching traffic. A gateway rule names a Tunnel; a proxy rule
// names an Outbound. Name and address matchers within one rule are combined
// with OR, matching sing-box's own semantics; port and process narrow them.
// The JSON names must match the YAML ones: the interface reads and writes
// rules over JSON and saves them back to the YAML file, so a mismatch would
// silently replace a person's rules with empty ones the first time they
// pressed apply.
type Rule struct {
	Domain        []string `yaml:"domain,omitempty" json:"domain,omitempty"`
	DomainSuffix  []string `yaml:"domain_suffix,omitempty" json:"domain_suffix,omitempty"`
	DomainKeyword []string `yaml:"domain_keyword,omitempty" json:"domain_keyword,omitempty"`
	IPCIDR        []string `yaml:"ip_cidr,omitempty" json:"ip_cidr,omitempty"`
	Port          []int    `yaml:"port,omitempty" json:"port,omitempty"`
	// GeoSite and GeoIP name rule sets from SagerNet's sing-geosite and
	// sing-geoip, such as "cn" or "geolocation-!cn". They are downloaded
	// once and kept beside the configuration.
	GeoSite []string `yaml:"geosite,omitempty" json:"geosite,omitempty"`
	GeoIP   []string `yaml:"geoip,omitempty" json:"geoip,omitempty"`
	// ProcessName matches the program that opened the connection, e.g.
	// "chrome.exe". It needs the TUN interface; a proxy port cannot tell.
	ProcessName []string `yaml:"process_name,omitempty" json:"process_name,omitempty"`

	// Tunnel is a gateway rule's target: a tunnel name, or "direct" or
	// "block".
	Tunnel string `yaml:"tunnel,omitempty" json:"tunnel,omitempty"`
	// Outbound is a proxy rule's target: "proxy" (the selected node), "auto",
	// "direct", "block", or one node's tag ("node-…").
	Outbound string `yaml:"outbound,omitempty" json:"outbound,omitempty"`

	// Disabled is whether this rule is currently inactive.
	Disabled bool `yaml:"disabled,omitempty" json:"disabled,omitempty"`

	// Auto indicates whether this rule was automatically generated by a tunnel.
	Auto bool `yaml:"auto,omitempty" json:"auto,omitempty"`
}

// AutoRuleKey returns a unique identifier for an auto-generated rule.
func AutoRuleKey(tunnel, kind, value string) string {
	return fmt.Sprintf("%s:%s:%s", tunnel, kind, value)
}

// AllNodes returns a flat list of all custom nodes and subscription nodes.
func (c *Config) AllNodes() []CustomNode {
	var all []CustomNode
	for _, n := range c.CustomNodes {
		all = append(all, n)
	}
	for _, sub := range c.Subscriptions {
		for _, n := range sub.Nodes {
			n.SubscriptionID = sub.ID
			all = append(all, n)
		}
	}
	return all
}

// FindNode finds a node by ID, Name, or Outbound Tag.
func (c *Config) FindNode(idOrTag string) (CustomNode, bool) {
	for _, n := range c.AllNodes() {
		if n.ID == idOrTag || n.OutboundTag() == idOrTag || n.Name == idOrTag {
			return n, true
		}
	}
	return CustomNode{}, false
}

// FindSubscription finds a subscription by ID.
func (c *Config) FindSubscription(id string) (Subscription, bool) {
	for _, s := range c.Subscriptions {
		if s.ID == id {
			return s, true
		}
	}
	return Subscription{}, false
}

// IsAutoRuleDisabled checks if an auto rule with the given params is disabled.
func (c *Config) IsAutoRuleDisabled(tunnel, kind, value string) bool {
	key := AutoRuleKey(tunnel, kind, value)
	for _, k := range c.DisabledAutoRules {
		if k == key {
			return true
		}
	}
	return false
}

// hasMatcher reports whether the rule matches anything at all.
func (r Rule) hasMatcher() bool {
	return len(r.Domain)+len(r.DomainSuffix)+len(r.DomainKeyword)+len(r.IPCIDR)+len(r.Port)+
		len(r.GeoSite)+len(r.GeoIP)+len(r.ProcessName) > 0
}

// hasDomainMatcher reports whether the rule selects by name. Only such rules
// get a matching DNS rule, because only they are consulted before an address
// is known.
func (r Rule) hasDomainMatcher() bool {
	return len(r.Domain)+len(r.DomainSuffix)+len(r.DomainKeyword)+len(r.GeoSite) > 0
}

// ruleSetName is what a geosite or geoip name may be. It becomes part of a
// file name and a download address, so nothing that could leave either.
var ruleSetName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9!@._-]*$`)

// IsNodeTarget reports whether a proxy rule's outbound names one node.
func IsNodeTarget(target string) bool { return strings.HasPrefix(target, nodePrefix) }

// validProxyTarget reports whether a proxy rule's outbound is one this client
// knows how to route to. A node that has since disappeared still counts: a
// subscription that dropped it should not make every rule unsaveable.
func validProxyTarget(target string) bool {
	switch target {
	case TargetProxy, TargetAuto, TargetDirect, TargetBlock:
		return true
	}
	return IsNodeTarget(target) && len(target) > len(nodePrefix)
}

// migrate moves what earlier clients kept in the wrong place. Rules pointing
// at the proxy group or at a node were briefly written among the gateway's
// rules; they are proxy rules, and are matched as such.
func (c *Config) migrate() {
	var kept []Rule
	for _, r := range c.Rules {
		if r.Tunnel == TargetProxy || IsNodeTarget(r.Tunnel) || strings.HasPrefix(r.Tunnel, "node:") {
			r.Outbound = strings.Replace(r.Tunnel, "node:", nodePrefix, 1)
			r.Tunnel = ""
			r.Auto = false
			c.ProxyRules = append(c.ProxyRules, r)
			continue
		}
		kept = append(kept, r)
	}
	c.Rules = kept
	if c.SelectedNode != "" && c.SelectedNode != TargetAuto && c.SelectedNode != TargetDirect && !IsNodeTarget(c.SelectedNode) {
		c.SelectedNode = nodePrefix + c.SelectedNode
	}
}

// EffectiveStack is the stack the TUN interface is built with.
func (t TUNConfig) EffectiveStack() string {
	if t.Stack != "" {
		return t.Stack
	}
	return DefaultStack(runtime.GOOS)
}

// DefaultStack is the TUN stack used where none was chosen.
//
// On Windows it is gvisor, which handles the interface's traffic in user
// space. The system stack hands it to Windows' own TCP/IP, and on machines
// running another program that hooks that -- a game accelerator, another VPN
// -- that program got in the way of this one. gvisor is also what Clash Verge
// shipped as its default for as long as it had one sing-box also offers.
//
// gvisor exists only in a build made with -tags with_gvisor, which the Windows
// build is. One made without it keeps the system stack rather than a default
// that cannot start.
func DefaultStack(goos string) string {
	if goos == "windows" && tun.WithGVisor {
		return "gvisor"
	}
	return "system"
}

// StackAvailable reports whether this build can run a TUN stack. gvisor and
// mixed (whose UDP half is gvisor) need -tags with_gvisor.
func StackAvailable(stack string) bool {
	switch stack {
	case "", "system":
		return true
	case "gvisor", "mixed":
		return tun.WithGVisor
	}
	return false
}

// forgetSavedDefaults drops values that earlier clients wrote as defaults
// rather than because anybody chose them, where the default has changed since.
func (c *Config) forgetSavedDefaults(goos string) {
	if goos == "windows" && c.TUN.Stack == "system" && !c.TUN.StackChosen {
		c.TUN.Stack = ""
	}
}

// LoadConfig reads and validates a client configuration.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.forgetSavedDefaults(runtime.GOOS)
	c.migrate()
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.OnFailure == "" {
		c.OnFailure = TargetDirect
	}
	if c.LogLevel == "" {
		c.LogLevel = "warn"
	}
	if c.DNS.Default == "" {
		// The system's own resolver. A public one over HTTPS would keep names
		// outside every tunnel off the local network, but several are
		// unreachable from some countries, and a default that times out is
		// worse than one that is merely less private: it looks like the whole
		// client is broken. Set dns.default to a DoH URL to change it.
		c.DNS.Default = "local"
	}
	if c.DNS.Remote == "" {
		c.DNS.Remote = "https://1.1.1.1/dns-query"
	}
	if c.DNS.Strategy == "" {
		c.DNS.Strategy = "prefer_ipv4"
	}
	if c.TUN.Enabled {
		if c.TUN.Address == "" {
			// Inside 172.16/12, small enough to be unlikely to collide with
			// an intranet range a tunnel claims.
			c.TUN.Address = "172.19.0.1/30"
		}
		if c.TUN.MTU == 0 {
			c.TUN.MTU = 1400
		}
	}
	if c.Proxy.Enabled && c.Proxy.Listen == "" {
		c.Proxy.Listen = "127.0.0.1:1080"
	}
	if c.UI.Listen == "" {
		c.UI.Listen = "127.0.0.1:8645"
	}
	if c.UI.StateDir == "" || (c.UI.StateDir == legacyStateDir && runtime.GOOS != "linux") {
		c.UI.StateDir = DefaultStateDir()
	}
}

// legacyStateDir is the state directory this program wrote into every
// configuration before there was one per platform: a Linux path, on machines
// that are not Linux. Windows turned it into C:\var\lib\vpn-gateway, at the
// root of somebody's system drive; macOS grew a /var/lib it never had.
//
// It is replaced wherever it is not this platform's own answer. Nobody chose
// it there -- it is a default of ours, and Linux is the one place it is right.
const legacyStateDir = "/var/lib/vpn-gateway"

// DefaultStateDir is where a client keeps the interface token, so the link it
// publishes survives a restart.
//
// This is machine state written by a background service, not anybody's
// documents, so it belongs where each platform keeps such things rather than
// in a directory invented at the root of a disk.
func DefaultStateDir() string {
	switch runtime.GOOS {
	case "windows":
		if dir := os.Getenv("ProgramData"); dir != "" {
			return filepath.Join(dir, "vpn-gateway")
		}
		return filepath.Join(`C:\ProgramData`, "vpn-gateway")
	case "darwin":
		return "/Library/Application Support/vpn-gateway"
	default:
		return legacyStateDir
	}
}

// Validate reports every problem it finds, so a broken file can be fixed in
// one pass.
func (c *Config) Validate() error {
	var errs []error

	if !c.TUN.Enabled && !c.Proxy.Enabled {
		errs = append(errs, errors.New("enable tun or proxy, otherwise there is no way for traffic to enter"))
	}
	switch c.OnFailure {
	case TargetDirect, TargetBlock:
	default:
		errs = append(errs, fmt.Errorf("on_failure: want direct or block, got %q", c.OnFailure))
	}
	switch c.DNS.Strategy {
	case "prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only":
	default:
		errs = append(errs, fmt.Errorf("dns.strategy: unsupported value %q", c.DNS.Strategy))
	}
	if c.TUN.Enabled {
		switch c.TUN.Stack {
		case "", "system", "gvisor", "mixed":
			if !StackAvailable(c.TUN.Stack) {
				errs = append(errs, fmt.Errorf("tun.stack: %s is not included in this build of the client; use system", c.TUN.Stack))
			}
		default:
			errs = append(errs, fmt.Errorf("tun.stack: want system, gvisor or mixed, got %q", c.TUN.Stack))
		}
		if c.TUN.MTU < 576 || c.TUN.MTU > 9000 {
			errs = append(errs, fmt.Errorf("tun.mtu: want 576-9000, got %d", c.TUN.MTU))
		}
	}

	if c.UI.Enabled {
		host, _, err := net.SplitHostPort(c.UI.Listen)
		if err != nil {
			errs = append(errs, fmt.Errorf("ui.listen: %q is not a host:port address", c.UI.Listen))
		} else if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			errs = append(errs, fmt.Errorf("ui.listen must be a loopback address, got %q", host))
		}
	}

	switch c.Mode {
	case "", ModeRule, ModeGlobal, ModeDirect:
	default:
		errs = append(errs, fmt.Errorf("mode: want rule, global or direct, got %q", c.Mode))
	}
	if c.DNS.Remote != "" && c.DNS.Remote != "local" {
		if _, err := parseDNSURL(c.DNS.Remote, tagDNSRemote, ""); err != nil {
			errs = append(errs, fmt.Errorf("dns.remote: %w", err))
		}
	}

	for i, r := range c.Rules {
		where := fmt.Sprintf("rules[%d]", i)
		if r.Tunnel == "" {
			errs = append(errs, fmt.Errorf("%s: tunnel is required", where))
		}
		errs = append(errs, r.validateMatchers(where)...)
	}
	for i, r := range c.ProxyRules {
		where := fmt.Sprintf("proxy_rules[%d]", i)
		if r.Outbound == "" {
			errs = append(errs, fmt.Errorf("%s: outbound is required", where))
		} else if !validProxyTarget(r.Outbound) {
			errs = append(errs, fmt.Errorf("%s: outbound %q is not proxy, auto, direct, block or a node", where, r.Outbound))
		}
		errs = append(errs, r.validateMatchers(where)...)
	}
	ids := map[string]bool{}
	for _, n := range c.AllNodes() {
		if ids[n.ID] {
			errs = append(errs, fmt.Errorf("nodes: id %q is used twice", n.ID))
		}
		ids[n.ID] = true
	}
	return errors.Join(errs...)
}

func (r Rule) validateMatchers(where string) []error {
	var errs []error
	if !r.hasMatcher() {
		// A rule with no matcher would silently capture everything or
		// nothing depending on how it is compiled; neither is intended.
		errs = append(errs, fmt.Errorf("%s: needs at least one of domain, domain_suffix, domain_keyword, ip_cidr, port, geosite, geoip or process_name", where))
	}
	for _, p := range r.Port {
		if p < 1 || p > 65535 {
			errs = append(errs, fmt.Errorf("%s: port %d is out of range", where, p))
		}
	}
	for _, cidr := range r.IPCIDR {
		if _, _, err := net.ParseCIDR(cidr); err != nil && net.ParseIP(cidr) == nil {
			errs = append(errs, fmt.Errorf("%s: %q is not an address or a CIDR range", where, cidr))
		}
	}
	for _, name := range append(append([]string(nil), r.GeoSite...), r.GeoIP...) {
		if !ruleSetName.MatchString(name) {
			errs = append(errs, fmt.Errorf("%s: %q is not a rule set name", where, name))
		}
	}
	return errs
}
