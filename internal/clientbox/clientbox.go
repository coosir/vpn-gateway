// Package clientbox runs the client side of the trojan connection.
//
// It is used today by `vgctl verify` to prove a server is reachable and that
// each tunnel carries traffic, and it is the piece the desktop client will
// build on: the same outbounds, with a TUN inbound and routing rules in front
// of them instead of a SOCKS5 port.
package clientbox

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/block"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/trojan"
	singjson "github.com/sagernet/sing/common/json"

	"github.com/vpn-gateway/vpn-gateway/internal/server/clientcfg"
)

// Session is a running client that exposes one tunnel as a local SOCKS5 port.
type Session struct {
	instance *box.Box
	// Addr is the loopback SOCKS5 address traffic for this tunnel enters.
	Addr string
}

// Dial opens a connection to addr through the tunnel.
func (s *Session) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d, err := socks5Dialer(s.Addr)
	if err != nil {
		return nil, err
	}
	return d.DialContext(ctx, network, addr)
}

// Close stops the client.
func (s *Session) Close() error {
	if s == nil || s.instance == nil {
		return nil
	}
	return s.instance.Close()
}

// Open starts a client for one tunnel in the bundle, listening on a free
// loopback port.
func Open(ctx context.Context, bundle *clientcfg.Bundle, tunnelName string) (*Session, error) {
	var selected *clientcfg.Tunnel
	for i := range bundle.Tunnels {
		if bundle.Tunnels[i].Name == tunnelName {
			selected = &bundle.Tunnels[i]
			break
		}
	}
	if selected == nil {
		return nil, fmt.Errorf("clientbox: the bundle has no tunnel named %q", tunnelName)
	}

	port, err := freePort()
	if err != nil {
		return nil, err
	}
	host, serverPort, err := splitHostPort(bundle.Server.Address)
	if err != nil {
		return nil, err
	}

	tls := map[string]any{"enabled": true, "server_name": bundle.Server.ServerName}
	if pem := bundle.Server.CertificatePEM; pem != "" {
		// Trust exactly this certificate. Disabling verification instead
		// would accept any certificate, which defeats the point of pinning.
		tls["certificate"] = strings.Split(strings.TrimSpace(pem), "\n")
	}

	cfg := map[string]any{
		"log": map[string]any{"level": "error"},
		"inbounds": []map[string]any{{
			"type": "socks", "tag": "local",
			"listen": "127.0.0.1", "listen_port": port,
		}},
		"outbounds": []map[string]any{{
			"type": "trojan", "tag": "tunnel",
			"server": host, "server_port": serverPort,
			"password": selected.Password,
			"tls":      tls,
		}},
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}

	boxCtx := registryContext(ctx)
	var parsed option.Options
	if err := singjson.UnmarshalContext(boxCtx, raw, &parsed); err != nil {
		return nil, fmt.Errorf("clientbox: build configuration: %w", err)
	}
	instance, err := box.New(box.Options{Context: boxCtx, Options: parsed})
	if err != nil {
		return nil, fmt.Errorf("clientbox: %w", err)
	}
	if err := instance.Start(); err != nil {
		instance.Close()
		return nil, fmt.Errorf("clientbox: start: %w", err)
	}
	return &Session{instance: instance, Addr: fmt.Sprintf("127.0.0.1:%d", port)}, nil
}

// registryContext registers the mirror image of the server's protocols.
func registryContext(ctx context.Context) context.Context {
	inR := inbound.NewRegistry()
	socks.RegisterInbound(inR)

	outR := outbound.NewRegistry()
	trojan.RegisterOutbound(outR)
	direct.RegisterOutbound(outR)
	block.RegisterOutbound(outR)

	dnsR := dns.NewTransportRegistry()
	transport.RegisterUDP(dnsR)
	transport.RegisterTCP(dnsR)
	transport.RegisterTLS(dnsR)
	transport.RegisterHTTPS(dnsR)
	local.RegisterTransport(dnsR)

	return box.Context(ctx, inR, outR, endpoint.NewRegistry(), dnsR, service.NewRegistry())
}

func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

func splitHostPort(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("clientbox: %q is not a host:port address: %w", addr, err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		return "", 0, fmt.Errorf("clientbox: %q has no port", addr)
	}
	return host, port, nil
}
