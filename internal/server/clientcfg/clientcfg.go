// Package clientcfg renders what a client needs to reach this server.
//
// It is emitted by `vgctl client-config` so a device can be set up by copying
// one file, and it is the shape the desktop client will consume directly.
package clientcfg

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vpn-gateway/vpn-gateway/internal/server/certs"
)

// Bundle is everything a client needs: how to reach the server, how to trust
// it, and which tunnels exist with the password that selects each one.
type Bundle struct {
	Version int `json:"version"`

	Server ServerRef `json:"server"`
	// APIToken authenticates against the server's control API, which is how a
	// client learns tunnel state, routes and DNS.
	APIToken     string   `json:"api_token"`
	RequiresAuth bool     `json:"requires_auth,omitempty"`
	Tunnels      []Tunnel `json:"tunnels"`
}

// ServerRef locates and authenticates the server.
type ServerRef struct {
	// Address is the trojan listener as "host:port".
	Address string `json:"address"`
	// ServerName is the SNI to send and the name to verify.
	ServerName string `json:"server_name"`
	// APIURL is the control API base URL.
	APIURL string `json:"api_url"`

	// CertificatePEM is the server's certificate when it is self-signed. The
	// client trusts exactly this certificate rather than disabling
	// verification, which would accept any certificate at all.
	CertificatePEM string `json:"certificate_pem,omitempty"`
	// Fingerprint is the SHA-256 of that certificate, for a human to compare
	// out of band before trusting it.
	Fingerprint string `json:"fingerprint,omitempty"`
}

// Tunnel is one selectable tunnel.
type Tunnel struct {
	Name string `json:"name"`
	// Password selects this tunnel on the shared trojan port.
	Password string `json:"password"`
	Provider string `json:"provider"`
}

// Build assembles a bundle.
func Build(listen, apiURL string, mat *certs.Material, apiToken string, tunnels []Tunnel) *Bundle {
	b := &Bundle{
		Version: 1,
		Server: ServerRef{
			Address:    listen,
			ServerName: mat.ServerName,
			APIURL:     apiURL,
		},
		APIToken: apiToken,
		Tunnels:  tunnels,
	}
	// A publicly trusted certificate needs no pinning; shipping it would only
	// break renewals.
	if mat.SelfSigned {
		b.Server.CertificatePEM = mat.CertPEM
		b.Server.Fingerprint = mat.Fingerprint
	}
	return b
}

// JSON renders the bundle.
func (b *Bundle) JSON() ([]byte, error) { return json.MarshalIndent(b, "", "  ") }

// SingBoxOutbounds renders the bundle as sing-box outbounds, one per tunnel.
// It exists so the setup can be verified with a stock sing-box before the
// desktop client is written, and so a tunnel can be debugged in isolation.
func (b *Bundle) SingBoxOutbounds() ([]byte, error) {
	host, port, err := splitHostPort(b.Server.Address)
	if err != nil {
		return nil, err
	}

	outbounds := make([]map[string]any, 0, len(b.Tunnels))
	for _, t := range b.Tunnels {
		tls := map[string]any{
			"enabled":     true,
			"server_name": b.Server.ServerName,
		}
		if b.Server.CertificatePEM != "" {
			tls["certificate"] = strings.Split(strings.TrimSpace(b.Server.CertificatePEM), "\n")
		}
		outbounds = append(outbounds, map[string]any{
			"type":        "trojan",
			"tag":         "tunnel-" + t.Name,
			"server":      host,
			"server_port": port,
			"password":    t.Password,
			"tls":         tls,
		})
	}
	return json.MarshalIndent(outbounds, "", "  ")
}

func splitHostPort(addr string) (string, int, error) {
	var host string
	var port int
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return "", 0, fmt.Errorf("clientcfg: %q is not a host:port address", addr)
	}
	host = addr[:i]
	if _, err := fmt.Sscanf(addr[i+1:], "%d", &port); err != nil {
		return "", 0, fmt.Errorf("clientcfg: %q does not contain a port", addr)
	}
	if host == "" {
		return "", 0, fmt.Errorf("clientcfg: the server address needs a hostname clients can reach, got %q", addr)
	}
	return host, port, nil
}
