package agent

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
)

// BaseNetwork snapshots the container's original network routing and DNS configuration
// on startup, and restores them if a VPN process (e.g. openconnect vpnc-script or vendor client)
// exits without restoring the default gateway or corrupting /etc/resolv.conf.
type BaseNetwork struct {
	Gateway    string
	Interface  string
	ResolvConf []byte
}

// CaptureBaseNetwork records the container's base default gateway and /etc/resolv.conf.
func CaptureBaseNetwork() *BaseNetwork {
	bn := &BaseNetwork{}
	if data, err := os.ReadFile("/etc/resolv.conf"); err == nil && len(data) > 0 {
		bn.ResolvConf = data
	}
	gw, iface := getDefaultGateway()
	bn.Gateway = gw
	bn.Interface = iface
	return bn
}

// Restore checks if the default gateway or DNS configuration was lost or corrupted,
// and restores them.
func (bn *BaseNetwork) Restore(log *slog.Logger) {
	if bn == nil {
		return
	}

	// 1. Check default gateway. If missing, restore it.
	currentGW, _ := getDefaultGateway()
	if currentGW == "" && bn.Gateway != "" && bn.Interface != "" {
		if log != nil {
			log.Warn("default gateway missing after tunnel exit, restoring base route",
				"gateway", bn.Gateway, "interface", bn.Interface)
		}
		_ = exec.Command("ip", "route", "replace", "default", "via", bn.Gateway, "dev", bn.Interface).Run()
	}

	// 2. Check /etc/resolv.conf.
	if len(bn.ResolvConf) > 0 {
		current, err := os.ReadFile("/etc/resolv.conf")
		if err != nil || len(current) == 0 || !bytes.Equal(current, bn.ResolvConf) {
			// If resolv.conf changed and tunnel is down, restore original resolv.conf
			if err := os.WriteFile("/etc/resolv.conf", bn.ResolvConf, 0o644); err == nil && log != nil {
				log.Info("restored base /etc/resolv.conf")
			}
		}
	}
}

// getDefaultGateway finds the default route IPv4 gateway and interface.
func getDefaultGateway() (string, string) {
	// First check /proc/net/route (standard Linux kernel routing table)
	if f, err := os.Open("/proc/net/route"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 3 && fields[1] == "00000000" { // Destination 0.0.0.0 (default route)
				iface := fields[0]
				gwHex := fields[2]
				if d, err := hex.DecodeString(gwHex); err == nil && len(d) == 4 {
					// Gateway is stored in little-endian in /proc/net/route
					ip := net.IPv4(d[3], d[2], d[1], d[0])
					if !ip.IsUnspecified() {
						return ip.String(), iface
					}
				}
			}
		}
	}

	// Fallback to "ip -4 route show default" command
	out, err := exec.Command("ip", "-4", "route", "show", "default").Output()
	if err == nil {
		fields := strings.Fields(string(out))
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "via" && i+1 < len(fields) {
				gw := fields[i+1]
				iface := "eth0"
				for j := 0; j < len(fields)-1; j++ {
					if fields[j] == "dev" && j+1 < len(fields) {
						iface = fields[j+1]
						break
					}
				}
				return gw, iface
			}
		}
	}

	return "", ""
}
