// Package proxy runs the trojan listener that clients connect to.
//
// One TLS port carries every tunnel. Each tunnel is a trojan user, and the
// route table maps that user to the container's SOCKS5 proxy. Clients
// therefore choose a tunnel by choosing a password, and the server needs no
// routing rules of its own -- those live on the client, where they can differ
// per device.
package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/block"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/trojan"
	singjson "github.com/sagernet/sing/common/json"
)

// Tags used in the generated configuration.
const (
	inboundTag   = "trojan-in"
	blockTag     = "block"
	directTag    = "direct"
	tunnelPrefix = "tunnel-"
)

// Route describes one tunnel's presence in the listener: the trojan user that
// selects it and the container proxy or direct host interface it resolves to.
type Route struct {
	// Name is the tunnel name. It is the trojan user name and the suffix of
	// the outbound tag.
	Name string
	// TrojanPassword is what a client sends to select this tunnel.
	TrojanPassword string
	// Direct routes this tunnel directly through the server host's network
	// (e.g. for accessing the server's LAN or intranet) without a container proxy.
	Direct bool
	// TrojanOutbound forwards this tunnel's traffic to an upstream Trojan node.
	TrojanOutbound *TrojanOutboundConfig
	// DataHost and DataPort address the container's SOCKS5 data plane.
	DataHost string
	DataPort int
	// SOCKSUser and SOCKSPassword authenticate to that data plane.
	SOCKSUser     string
	SOCKSPassword string
}

// TrojanOutboundConfig configures an upstream Trojan server outbound.
type TrojanOutboundConfig struct {
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
	Password   string `json:"password"`
	ServerName string `json:"server_name,omitempty"`
	Insecure   bool   `json:"insecure,omitempty"`
}

// Options configures the listener.
type Options struct {
	// Listen is the address the trojan inbound binds, e.g. ":443".
	Listen string
	// ServerName is the SNI clients present.
	ServerName string
	// CertPath and KeyPath are the TLS material.
	CertPath string
	KeyPath  string
	// LogLevel is sing-box's own log level.
	LogLevel string

	Routes []Route
	// Authenticator validates incoming Trojan credentials dynamically.
	// When nil, static credentials from Routes are used.
	Authenticator Authenticator
}

// BuildConfig renders the sing-box configuration as JSON.
//
// The configuration is generated rather than hand-written, and produced as
// JSON rather than assembled from sing-box's option structs: JSON is the
// interface upstream documents and keeps stable, and a generated file can be
// dumped verbatim when something needs debugging.
func BuildConfig(opts Options) ([]byte, error) {
	if opts.Listen == "" {
		return nil, fmt.Errorf("proxy: a listen address is required")
	}
	if opts.CertPath == "" || opts.KeyPath == "" {
		return nil, fmt.Errorf("proxy: TLS certificate and key are required")
	}

	host, port, err := splitListen(opts.Listen)
	if err != nil {
		return nil, err
	}

	logLevel := opts.LogLevel
	if logLevel == "" {
		logLevel = "warn"
	}

	users := make([]map[string]any, 0, len(opts.Routes))
	outbounds := []map[string]any{
		// Every tunnel resolves to an outbound of its own, found by tag when a
		// connection arrives. block is where anything else ends up; direct
		// exists only so the configuration remains valid when no tunnel is
		// configured.
		{"type": "block", "tag": blockTag},
		{"type": "direct", "tag": directTag},
	}
	for _, r := range opts.Routes {
		ob, err := outboundFor(r)
		if err != nil {
			return nil, err
		}
		users = append(users, map[string]any{"name": r.Name, "password": r.TrojanPassword})
		outbounds = append(outbounds, ob)
	}

	cfg := map[string]any{
		"log": map[string]any{"level": logLevel, "timestamp": true},
		"inbounds": []map[string]any{{
			"type":        "trojan",
			"tag":         inboundTag,
			"listen":      host,
			"listen_port": port,
			"users":       users,
			"tls": map[string]any{
				"enabled":          true,
				"server_name":      opts.ServerName,
				"certificate_path": opts.CertPath,
				"key_path":         opts.KeyPath,
			},
		}},
		"outbounds": outbounds,
		"route": map[string]any{
			// Tunnels are not chosen by route rules: the inbound picks each
			// connection's outbound itself, so the set can change while the
			// listener runs. Anything that does not match a tunnel rule is blocked, never
			// sent out the server's own connection. A silent fall through to
			// direct would look like a working tunnel while leaking traffic
			// meant for an intranet, which is far harder to notice than a
			// refused connection.
			"final": blockTag,
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// outboundFor renders the outbound one tunnel's traffic leaves by.
func outboundFor(r Route) (map[string]any, error) {
	if r.Name == "" || r.TrojanPassword == "" {
		return nil, fmt.Errorf("proxy: tunnel %q needs a name and a trojan password", r.Name)
	}
	tag := tunnelPrefix + r.Name
	switch {
	case r.Direct:
		return map[string]any{"type": "direct", "tag": tag}, nil
	case r.TrojanOutbound != nil:
		tls := map[string]any{"enabled": true}
		if r.TrojanOutbound.ServerName != "" {
			tls["server_name"] = r.TrojanOutbound.ServerName
		}
		if r.TrojanOutbound.Insecure {
			tls["insecure"] = true
		}
		return map[string]any{
			"type":        "trojan",
			"tag":         tag,
			"server":      r.TrojanOutbound.Server,
			"server_port": r.TrojanOutbound.ServerPort,
			"password":    r.TrojanOutbound.Password,
			"tls":         tls,
		}, nil
	}
	ob := map[string]any{
		"type":        "socks",
		"tag":         tag,
		"server":      r.DataHost,
		"server_port": r.DataPort,
		"version":     "5",
	}
	if r.SOCKSUser != "" {
		ob["username"] = r.SOCKSUser
		ob["password"] = r.SOCKSPassword
	}
	return ob, nil
}

// Proxy owns a running sing-box instance.
type Proxy struct {
	instance *box.Box
	ctx      context.Context
	traffic  *trafficTracker
	auth     Authenticator
	log      *slog.Logger
}

// New builds and starts the listener described by opts.
func New(ctx context.Context, opts Options, log *slog.Logger) (*Proxy, error) {
	raw, err := BuildConfig(opts)
	if err != nil {
		return nil, err
	}
	auth := opts.Authenticator
	if auth == nil {
		auth = NewStaticAuthenticator(opts.Routes)
	}
	traffic := newTrafficTracker(opts.Routes)
	boxCtx := registryContext(ctx, auth, traffic)

	var parsed option.Options
	if err := singjson.UnmarshalContext(boxCtx, raw, &parsed); err != nil {
		return nil, fmt.Errorf("proxy: generated configuration was rejected: %w", err)
	}
	instance, err := box.New(box.Options{Context: boxCtx, Options: parsed})
	if err != nil {
		return nil, fmt.Errorf("proxy: build listener: %w", err)
	}
	if err := instance.Start(); err != nil {
		instance.Close()
		return nil, fmt.Errorf("proxy: start listener on %s: %w", opts.Listen, err)
	}

	log.Info("trojan listener started",
		"listen", opts.Listen, "server_name", opts.ServerName, "tunnels", len(opts.Routes))
	return &Proxy{instance: instance, ctx: boxCtx, traffic: traffic, auth: auth, log: log}, nil
}

// SetRoute adds a tunnel to the running listener, or replaces what it had for
// one, without disturbing any other tunnel's connections.
func (p *Proxy) SetRoute(r Route) error {
	ob, err := outboundFor(r)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(ob)
	if err != nil {
		return err
	}
	var parsed option.Outbound
	if err := singjson.UnmarshalContext(p.ctx, raw, &parsed); err != nil {
		return fmt.Errorf("proxy: tunnel %q: generated outbound was rejected: %w", r.Name, err)
	}
	tag := tunnelPrefix + r.Name
	logger := p.instance.LogFactory().NewLogger("outbound/" + parsed.Type + "[" + tag + "]")
	if err := p.instance.Outbound().Create(p.ctx, p.instance.Router(), logger, tag, parsed.Type, parsed.Options); err != nil {
		return fmt.Errorf("proxy: tunnel %q: %w", r.Name, err)
	}
	p.traffic.add(r.Name)
	if s, ok := p.auth.(*StaticAuthenticator); ok {
		s.set(r)
	}
	p.log.Info("listener route updated", "tunnel", r.Name)
	return nil
}

// RemoveRoute takes a tunnel out of the running listener. A client still
// holding its password is refused from then on.
func (p *Proxy) RemoveRoute(name string) {
	if err := p.instance.Outbound().Remove(tunnelPrefix + name); err != nil && !errors.Is(err, os.ErrInvalid) {
		p.log.Warn("removing a tunnel from the listener failed", "tunnel", name, "error", err)
	}
	p.traffic.remove(name)
	if s, ok := p.auth.(*StaticAuthenticator); ok {
		s.remove(name)
	}
}

// Close stops the listener.
func (p *Proxy) Close() error {
	if p == nil || p.instance == nil {
		return nil
	}
	return p.instance.Close()
}

// registryContext registers only the protocols this server uses. Pulling in
// sing-box's full registry would add Tor, Shadowsocks, the SSM API and more,
// none of which this server offers.
//
// Every type BuildConfig can emit has to be here. A configuration naming one
// that is not is refused when it is parsed, which is a server that will not
// start rather than a tunnel that does not work -- see the test that walks
// one of each kind through this.
func registryContext(ctx context.Context, auth Authenticator, traffic *trafficTracker) context.Context {
	inR := inbound.NewRegistry()
	inbound.Register[option.TrojanInboundOptions](inR, C.TypeTrojan, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TrojanInboundOptions) (adapter.Inbound, error) {
		return NewDynamicTrojanInbound(ctx, router, logger, tag, options, auth, traffic)
	})

	outR := outbound.NewRegistry()
	direct.RegisterOutbound(outR)
	block.RegisterOutbound(outR)
	socks.RegisterOutbound(outR)
	// A tunnel can be forwarded to an upstream trojan node rather than to a
	// container, so trojan is both what this server speaks to its clients and
	// what it may speak to somebody else's server.
	trojan.RegisterOutbound(outR)

	dnsR := dns.NewTransportRegistry()
	transport.RegisterUDP(dnsR)
	transport.RegisterTCP(dnsR)
	transport.RegisterTLS(dnsR)
	transport.RegisterHTTPS(dnsR)
	local.RegisterTransport(dnsR)

	return box.Context(ctx, inR, outR, endpoint.NewRegistry(), dnsR, service.NewRegistry())
}
