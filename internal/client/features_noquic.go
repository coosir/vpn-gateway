//go:build !with_quic

package client

import (
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/dns"
)

// quicAvailable reports whether this build can dial hysteria2 and tuic nodes.
// They need -tags with_quic, which the shipped builds have.
const quicAvailable = false

func registerQUICOutbounds(*outbound.Registry) {}

func registerQUICTransports(*dns.TransportRegistry) {}
