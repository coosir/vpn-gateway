package certs

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnsureSelfSignedIsStable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")

	first, err := EnsureSelfSigned(dir, "vpn.test")
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if !first.SelfSigned || first.Fingerprint == "" {
		t.Fatalf("unexpected material: %+v", first)
	}

	// Regenerating would invalidate the pin on every client that has already
	// been set up, so a second call must reuse the existing certificate.
	second, err := EnsureSelfSigned(dir, "vpn.test")
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if second.Fingerprint != first.Fingerprint {
		t.Errorf("fingerprint changed across calls:\n  %s\n  %s", first.Fingerprint, second.Fingerprint)
	}
}

func TestSelfSignedKeyIsNotWorldReadable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	mat, err := EnsureSelfSigned(dir, "vpn.test")
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(mat.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("private key mode is %o, want 600", perm)
	}
}

func TestFingerprintFormat(t *testing.T) {
	// Colon-separated uppercase hex is what openssl and browsers show, so an
	// operator can compare the value by eye.
	got := Fingerprint([]byte("hello"))
	if len(got) != 32*3-1 {
		t.Fatalf("fingerprint has length %d, want %d", len(got), 32*3-1)
	}
	for i := 2; i < len(got); i += 3 {
		if got[i] != ':' {
			t.Fatalf("expected a colon at index %d in %q", i, got)
		}
	}
	if got != "2C:F2:4D:BA:5F:B0:A3:0E:26:E8:3B:2A:C5:B9:E2:9E:1B:16:1E:5C:1F:A7:42:5E:73:04:33:62:93:8B:98:24" {
		t.Errorf("unexpected fingerprint %q", got)
	}
}

func TestSelfSignedCoversTheServerName(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	mat, err := EnsureSelfSigned(dir, "vpn.example.dyndns.org")
	if err != nil {
		t.Fatal(err)
	}
	if mat.ServerName != "vpn.example.dyndns.org" {
		t.Errorf("ServerName = %q", mat.ServerName)
	}
	due, notAfter, err := mat.NeedsRenewal(24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if due {
		t.Errorf("a freshly issued certificate is already due for renewal at %s", notAfter)
	}
	// Long-lived on purpose: renewing means re-pinning every client.
	if time.Until(notAfter) < 5*365*24*time.Hour {
		t.Errorf("certificate expires at %s, sooner than expected", notAfter)
	}
}

func TestEnsureSelfSignedRequiresAName(t *testing.T) {
	if _, err := EnsureSelfSigned(t.TempDir(), ""); err == nil {
		t.Fatal("expected an error when no server name is given")
	}
}

func TestSelfSignedAcceptsAnIPAddress(t *testing.T) {
	// A home server may only be reachable by address.
	dir := filepath.Join(t.TempDir(), "tls")
	if _, err := EnsureSelfSigned(dir, "203.0.113.7"); err != nil {
		t.Fatalf("issuing for an IP address failed: %v", err)
	}
}
