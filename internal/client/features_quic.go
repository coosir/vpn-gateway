//go:build with_quic

package client

import (
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/quic"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/tuic"
)

// quicAvailable reports whether this build can dial hysteria2 and tuic nodes.
const quicAvailable = true

func registerQUICOutbounds(r *outbound.Registry) {
	hysteria2.RegisterOutbound(r)
	tuic.RegisterOutbound(r)
}

func registerQUICTransports(r *dns.TransportRegistry) {
	quic.RegisterTransport(r)
	quic.RegisterHTTP3Transport(r)
}
