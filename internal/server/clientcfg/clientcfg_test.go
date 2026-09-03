package clientcfg

import (
	"strings"
	"testing"

	"github.com/vpn-gateway/vpn-gateway/internal/server/certs"
)

func testMaterial() *certs.Material {
	return &certs.Material{
		ServerName:  "vpn.example",
		SelfSigned:  true,
		Fingerprint: "AA:BB",
		CertPEM:     "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
	}
}

// The admin token unlocks every administrative endpoint on the server, so a
// bundle handed to a client must not carry it: the client authenticates as a
// user and is issued a session token scoped to what that user may do.
func TestBundleCarriesNoServerCredential(t *testing.T) {
	b := Build("vpn.example:443", "https://api.example", testMaterial(), []Tunnel{
		{Name: "office", Password: "pw-office", Provider: "fortinet"},
	})

	raw, err := b.JSON()
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"api_token", "apiToken"} {
		if strings.Contains(string(raw), forbidden) {
			t.Errorf("the bundle carries %q:\n%s", forbidden, raw)
		}
	}
	if !strings.Contains(string(raw), "pw-office") {
		t.Errorf("the tunnel password went missing:\n%s", raw)
	}
}

func TestSelfSignedCertificateIsPinned(t *testing.T) {
	b := Build("vpn.example:443", "https://api.example", testMaterial(), nil)
	if b.Server.Fingerprint != "AA:BB" || b.Server.CertificatePEM == "" {
		t.Errorf("a self-signed certificate should be pinned: %+v", b.Server)
	}

	mat := testMaterial()
	mat.SelfSigned = false
	b = Build("vpn.example:443", "https://api.example", mat, nil)
	if b.Server.Fingerprint != "" || b.Server.CertificatePEM != "" {
		t.Errorf("a publicly trusted certificate needs no pinning: %+v", b.Server)
	}
}
