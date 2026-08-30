package agent

import (
	"net"
	"strings"
)

// tunnelPrefixes are the interface names a VPN client creates. openconnect
// and most vendor clients use tun; anything speaking PPP over TLS, such as
// Fortinet's own protocol, uses ppp.
var tunnelPrefixes = []string{"tun", "ppp", "utun", "tap"}

// TunnelInterfaceUp reports whether a VPN interface exists, is up, and has an
// address.
//
// This is the readiness signal for a client that installs its own interface
// rather than serving a proxy. Matching the client's log output instead would
// tie us to wording that changes between versions and differs between the
// seven protocols one client can speak.
func TunnelInterfaceUp() bool {
	name, _ := TunnelInterface()
	return name != ""
}

// TunnelInterface returns the name and address of the first VPN interface
// that is up and addressed, or empty strings when there is none.
func TunnelInterface() (name, addr string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || !isTunnelName(iface.Name) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ip, _, err := net.ParseCIDR(a.String())
			if err != nil {
				continue
			}
			// A link-local address means the interface came up but the VPN
			// has not assigned anything yet.
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
				continue
			}
			return iface.Name, ip.String()
		}
	}
	return "", ""
}

func isTunnelName(name string) bool {
	lower := strings.ToLower(name)
	for _, p := range tunnelPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}
