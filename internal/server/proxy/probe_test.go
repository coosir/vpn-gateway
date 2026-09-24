package proxy

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/vpn-gateway/vpn-gateway/internal/server/certs"
)

// probeBed starts a listener with a direct tunnel "lan" and a container
// tunnel "office" in front of a stand-in SOCKS server.
func probeBed(t *testing.T) (*Proxy, int, string) {
	t.Helper()
	mat, err := certs.EnsureSelfSigned(filepath.Join(t.TempDir(), "tls"), "vpn.test")
	if err != nil {
		t.Fatal(err)
	}
	b := startLabelledSOCKS(t, "office", "vpngw", "socks-office")
	host, portStr, _ := net.SplitHostPort(b.addr)
	port, _ := strconv.Atoi(portStr)
	opts := Options{
		Listen:     "127.0.0.1:" + strconv.Itoa(freePort(t)),
		ServerName: "vpn.test",
		CertPath:   mat.CertPath,
		KeyPath:    mat.KeyPath,
		LogLevel:   "error",
		Routes: []Route{
			{Name: "lan", TrojanPassword: "trojan-lan", Direct: true},
			{Name: "office", TrojanPassword: "trojan-office", DataHost: host, DataPort: port,
				SOCKSUser: "vpngw", SOCKSPassword: "socks-office"},
		},
	}
	p, err := New(context.Background(), opts, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("start listener: %v", err)
	}
	t.Cleanup(func() { p.Close() })
	waitForPort(t, opts.Listen)
	_, lp, _ := net.SplitHostPort(opts.Listen)
	listenPort, _ := strconv.Atoi(lp)
	return p, listenPort, mat.CertPEM
}

func TestProbeGoesThroughTheTunnel(t *testing.T) {
	p, _, _ := probeBed(t)
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ok.Close()
	if err := p.Probe(context.Background(), "lan", ok.URL+"/generate_204"); err != nil {
		t.Fatalf("probe of a working path: %v", err)
	}
}

// A 400 is what a trojan node's cover website says to a password it does not
// take, so it must not pass for an answer.
func TestProbeRefusesAnErrorStatus(t *testing.T) {
	p, _, _ := probeBed(t)
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer bad.Close()
	err := p.Probe(context.Background(), "lan", bad.URL)
	if err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("want a 400 error, got %v", err)
	}
}

func TestProbeReportsAnUnreachableTarget(t *testing.T) {
	p, _, _ := probeBed(t)
	if err := p.Probe(context.Background(), "lan", "http://127.0.0.1:"+strconv.Itoa(freePort(t))); err == nil {
		t.Fatal("want an error for a port nobody listens on")
	}
	if err := p.Probe(context.Background(), "nope", "http://127.0.0.1/"); err == nil {
		t.Fatal("want an error for an unknown tunnel")
	}
}

func TestClientTrafficIsNoticed(t *testing.T) {
	p, port, certPEM := probeBed(t)
	if !p.LastTraffic("office").IsZero() {
		t.Fatal("traffic noticed before any was carried")
	}
	socksAddr := trojanClient(t, port, "office", certPEM)
	if _, err := fetchLabel(socksAddr); err != nil {
		t.Fatal(err)
	}
	if p.LastTraffic("office").IsZero() {
		t.Error("an answer carried back to a client was not noticed")
	}
	if !p.LastTraffic("lan").IsZero() {
		t.Error("traffic was credited to the wrong tunnel")
	}
}
