// Package client is the desktop side of vpn-gateway: one TUN interface, one
// routing engine, and a trojan connection per tunnel.
//
// Nothing here knows about VPN protocols or containers. The client learns
// which tunnels exist, what they claim and whether they are up from the
// server's control API, and turns that into routing and DNS rules.
package client

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Reserved rule targets that are not tunnel names.
const (
	// TargetDirect sends traffic out the machine's normal connection.
	TargetDirect = "direct"
	// TargetBlock refuses the connection.
	TargetBlock = "block"
)

// Config is the client configuration, normally
// /etc/vpn-gateway/client.yaml.
type Config struct {
	// Bundle is the path to the JSON emitted by `vgctl client-config`. It
	// carries the server address, the certificate to pin and one password
	// per tunnel.
	Bundle string `yaml:"bundle"`

	TUN   TUNConfig   `yaml:"tun"`
	Proxy ProxyConfig `yaml:"proxy"`
	DNS   DNSConfig   `yaml:"dns"`
	UI    UIConfig    `yaml:"ui"`

	// OnFailure is what happens to traffic for a tunnel that is not up:
	// "direct" or "block". A tunnel going down must never take the whole
	// machine offline, so this is answered explicitly rather than left to
	// whatever the connection error happens to be.
	OnFailure string `yaml:"on_failure,omitempty"`

	// Rules are matched in order, before any rule derived from what a tunnel
	// reports, so an explicit choice always wins over an inferred one.
	Rules []Rule `yaml:"rules,omitempty"`

	// AutoRoutes turns the routes a tunnel reports into implicit ip_cidr
	// rules. This is what makes split routing usable without writing a rule
	// for every intranet range.
	AutoRoutes bool `yaml:"auto_routes,omitempty"`
	// AutoDomains does the same for the search domains a tunnel reports.
	AutoDomains bool `yaml:"auto_domains,omitempty"`

	// LogLevel is sing-box's log level.
	LogLevel string `yaml:"log_level,omitempty"`
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
	// Stack is "system", "gvisor" or "mixed".
	Stack string `yaml:"stack,omitempty" json:"stack,omitempty"`
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

// Rule routes matching traffic to a tunnel. Every matcher within one rule is
// combined with OR, matching sing-box's own semantics.
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

	// Tunnel is a tunnel name, or "direct" or "block".
	Tunnel string `yaml:"tunnel" json:"tunnel"`
}

// hasMatcher reports whether the rule matches anything at all.
func (r Rule) hasMatcher() bool {
	return len(r.Domain)+len(r.DomainSuffix)+len(r.DomainKeyword)+len(r.IPCIDR)+len(r.Port) > 0
}

// hasDomainMatcher reports whether the rule selects by name. Only such rules
// get a matching DNS rule, because only they are consulted before an address
// is known.
func (r Rule) hasDomainMatcher() bool {
	return len(r.Domain)+len(r.DomainSuffix)+len(r.DomainKeyword) > 0
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
		if c.TUN.Stack == "" {
			c.TUN.Stack = "system"
		}
	}
	if c.Proxy.Enabled && c.Proxy.Listen == "" {
		c.Proxy.Listen = "127.0.0.1:1080"
	}
	if c.UI.Listen == "" {
		c.UI.Listen = "127.0.0.1:8645"
	}
	if c.UI.StateDir == "" {
		c.UI.StateDir = "/var/lib/vpn-gateway"
	}
}

// Validate reports every problem it finds, so a broken file can be fixed in
// one pass.
func (c *Config) Validate() error {
	var errs []error

	if c.Bundle == "" {
		errs = append(errs, errors.New("bundle: the path to the server bundle is required"))
	}
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
		case "system", "gvisor", "mixed":
		default:
			errs = append(errs, fmt.Errorf("tun.stack: want system, gvisor or mixed, got %q", c.TUN.Stack))
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

	for i, r := range c.Rules {
		where := fmt.Sprintf("rules[%d]", i)
		if r.Tunnel == "" {
			errs = append(errs, fmt.Errorf("%s: tunnel is required", where))
		}
		if !r.hasMatcher() {
			// A rule with no matcher would silently capture everything or
			// nothing depending on how it is compiled; neither is intended.
			errs = append(errs, fmt.Errorf("%s: needs at least one of domain, domain_suffix, domain_keyword, ip_cidr or port", where))
		}
		for _, p := range r.Port {
			if p < 1 || p > 65535 {
				errs = append(errs, fmt.Errorf("%s: port %d is out of range", where, p))
			}
		}
	}
	return errors.Join(errs...)
}
