package agent

import "testing"

func TestIsTunnelName(t *testing.T) {
	tunnels := []string{"tun0", "tun1", "ppp0", "utun4", "tap0", "TUN0"}
	for _, name := range tunnels {
		if !isTunnelName(name) {
			t.Errorf("%q was not recognised as a VPN interface", name)
		}
	}

	// Matching too eagerly would report a tunnel as up before the client has
	// created one, and the agent would start refusing nothing.
	others := []string{"eth0", "lo", "docker0", "wlan0", "br-1a2b", "veth123"}
	for _, name := range others {
		if isTunnelName(name) {
			t.Errorf("%q was mistaken for a VPN interface", name)
		}
	}
}

func TestTunnelInterfaceIgnoresOrdinaryInterfaces(t *testing.T) {
	// On a machine with no VPN up this must report nothing rather than
	// picking whatever interface happens to be first.
	name, addr := TunnelInterface()
	if name == "" {
		return
	}
	if !isTunnelName(name) {
		t.Errorf("reported %q (%s), which is not a VPN interface", name, addr)
	}
}
