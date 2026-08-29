// Package certs manages the TLS material for the trojan listener.
//
// A home server usually has no public domain and no way to answer an HTTP-01
// challenge behind NAT, so a self-signed certificate that clients pin is the
// default. Operators who do have a certificate -- from Let's Encrypt via a
// DNS-01 client, or anything else -- point at the files instead.
package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// selfSignedLifetime is how long a generated certificate is valid. It is long
// because rotating it means re-pinning on every client.
const selfSignedLifetime = 10 * 365 * 24 * time.Hour

// Material is a loaded certificate and key pair, plus the fingerprint a
// client pins.
type Material struct {
	CertPath string
	KeyPath  string
	// ServerName is the name clients must send as SNI and verify against.
	ServerName string
	// Fingerprint is the SHA-256 of the certificate DER, formatted as
	// colon-separated uppercase hex. Clients pin this when the certificate is
	// self-signed.
	Fingerprint string
	// SelfSigned reports whether clients need to pin rather than rely on a
	// public trust root.
	SelfSigned bool
	// CertPEM is the certificate chain, for embedding in a client config so
	// the client trusts it without a separate file.
	CertPEM string
}

// EnsureSelfSigned loads the self-signed certificate for serverName from dir,
// generating it on first use. Regenerating would invalidate every client's
// pin, so an existing certificate is reused even if it is close to expiry;
// the caller is told through NeedsRenewal.
func EnsureSelfSigned(dir, serverName string) (*Material, error) {
	if serverName == "" {
		return nil, errors.New("a server name is required to issue a certificate")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("prepare certificate directory: %w", err)
	}
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")

	if _, err := os.Stat(certPath); err == nil {
		m, err := Load(certPath, keyPath, serverName)
		if err != nil {
			return nil, fmt.Errorf("load existing certificate: %w", err)
		}
		m.SelfSigned = true
		return m, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if err := generate(certPath, keyPath, serverName); err != nil {
		return nil, err
	}
	m, err := Load(certPath, keyPath, serverName)
	if err != nil {
		return nil, err
	}
	m.SelfSigned = true
	return m, nil
}

// Load reads an existing certificate and key.
func Load(certPath, keyPath, serverName string) (*Material, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read certificate: %w", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s does not contain a PEM certificate", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	name := serverName
	if name == "" {
		if len(cert.DNSNames) > 0 {
			name = cert.DNSNames[0]
		} else {
			name = cert.Subject.CommonName
		}
	}

	return &Material{
		CertPath:    certPath,
		KeyPath:     keyPath,
		ServerName:  name,
		Fingerprint: Fingerprint(cert.Raw),
		CertPEM:     string(certPEM),
	}, nil
}

// NeedsRenewal reports whether the certificate expires within the given
// window.
func (m *Material) NeedsRenewal(within time.Duration) (bool, time.Time, error) {
	block, _ := pem.Decode([]byte(m.CertPEM))
	if block == nil {
		return false, time.Time{}, errors.New("certificate is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, time.Time{}, err
	}
	return time.Until(cert.NotAfter) < within, cert.NotAfter, nil
}

// Fingerprint formats the SHA-256 of a DER certificate as colon-separated
// uppercase hex, the form openssl and browsers display.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	hexStr := strings.ToUpper(hex.EncodeToString(sum[:]))
	var b strings.Builder
	for i := 0; i < len(hexStr); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(hexStr[i : i+2])
	}
	return b.String()
}

func generate(certPath, keyPath, serverName string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: serverName},
		// Backdated by an hour so a client whose clock is slightly behind
		// does not reject a freshly issued certificate.
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(selfSignedLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	// A home server is usually reached by a dynamic DNS name, but pinning an
	// IP directly must also work.
	if ip := net.ParseIP(serverName); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{serverName}
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	if err := writePEM(certPath, 0o644, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	return writePEM(keyPath, 0o600, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func writePEM(path string, mode os.FileMode, block *pem.Block) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, block); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return f.Close()
}
