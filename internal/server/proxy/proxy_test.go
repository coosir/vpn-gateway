package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/block"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/trojan"
	singjson "github.com/sagernet/sing/common/json"
	"github.com/vpn-gateway/vpn-gateway/internal/server/certs"
	"golang.org/x/net/proxy"
)

// labelledSOCKS is a minimal SOCKS5 server that stands in for one tunnel's
// container. Every connection it proxies is answered with its own label, so a
// test can tell which tunnel carried the traffic.
type labelledSOCKS struct {
	label string
	user  string
	pass  string
	addr  string

	mu    sync.Mutex
	conns int
}

func startLabelledSOCKS(t *testing.T, label, user, pass string) *labelledSOCKS {
	t.Helper()
	// The label is served by a plain HTTP endpoint the SOCKS server always
	// connects to, whatever address was requested.
	target := httpLabelServer(t, label)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	s := &labelledSOCKS{label: label, user: user, pass: pass, addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c, target)
		}
	}()
	return s
}

func (s *labelledSOCKS) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns
}

func (s *labelledSOCKS) serve(c net.Conn, target string) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))

	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil || head[0] != 5 {
		return
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}

	if s.user != "" {
		if !contains(methods, 0x02) {
			c.Write([]byte{5, 0xFF})
			return
		}
		if _, err := c.Write([]byte{5, 0x02}); err != nil {
			return
		}
		ah := make([]byte, 2)
		if _, err := io.ReadFull(c, ah); err != nil {
			return
		}
		u := make([]byte, ah[1])
		if _, err := io.ReadFull(c, u); err != nil {
			return
		}
		pl := make([]byte, 1)
		if _, err := io.ReadFull(c, pl); err != nil {
			return
		}
		p := make([]byte, pl[0])
		if _, err := io.ReadFull(c, p); err != nil {
			return
		}
		if string(u) != s.user || string(p) != s.pass {
			c.Write([]byte{1, 1})
			return
		}
		if _, err := c.Write([]byte{1, 0}); err != nil {
			return
		}
	} else {
		if _, err := c.Write([]byte{5, 0}); err != nil {
			return
		}
	}

	// Read and discard the request; this stand-in always dials its own label
	// server regardless of the requested destination.
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	switch req[3] {
	case 1:
		io.ReadFull(c, make([]byte, 4))
	case 4:
		io.ReadFull(c, make([]byte, 16))
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return
		}
		io.ReadFull(c, make([]byte, l[0]))
	default:
		return
	}
	io.ReadFull(c, make([]byte, 2))

	up, err := net.Dial("tcp", target)
	if err != nil {
		c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	s.mu.Lock()
	s.conns++
	s.mu.Unlock()

	c.SetDeadline(time.Time{})
	go io.Copy(up, c)
	io.Copy(c, up)
}

func contains(b []byte, want byte) bool {
	for _, v := range b {
		if v == want {
			return true
		}
	}
	return false
}

// httpLabelServer answers every request with the given label.
func httpLabelServer(t *testing.T, label string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, label)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// testbed starts a trojan listener in front of one stand-in container per
// tunnel, and returns the listener port and the stand-ins by name.
func testbed(t *testing.T, names ...string) (int, map[string]*labelledSOCKS, string) {
	t.Helper()

	dir := t.TempDir()
	mat, err := certs.EnsureSelfSigned(filepath.Join(dir, "tls"), "vpn.test")
	if err != nil {
		t.Fatal(err)
	}

	backends := map[string]*labelledSOCKS{}
	opts := Options{
		Listen:     "127.0.0.1:" + strconv.Itoa(freePort(t)),
		ServerName: "vpn.test",
		CertPath:   mat.CertPath,
		KeyPath:    mat.KeyPath,
		LogLevel:   "error",
	}
	for _, name := range names {
		b := startLabelledSOCKS(t, name, "vpngw", "socks-"+name)
		backends[name] = b
		host, portStr, _ := net.SplitHostPort(b.addr)
		port, _ := strconv.Atoi(portStr)
		opts.Routes = append(opts.Routes, Route{
			Name:           name,
			TrojanPassword: "trojan-" + name,
			DataHost:       host,
			DataPort:       port,
			SOCKSUser:      "vpngw",
			SOCKSPassword:  "socks-" + name,
		})
	}

	p, err := New(context.Background(), opts, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("start listener: %v", err)
	}
	t.Cleanup(func() { p.Close() })

	_, portStr, _ := net.SplitHostPort(opts.Listen)
	port, _ := strconv.Atoi(portStr)
	waitForPort(t, opts.Listen)
	return port, backends, mat.CertPEM
}

func waitForPort(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("listener never came up on %s", addr)
}

// trojanClient builds a sing-box client whose SOCKS5 inbound forwards through
// the trojan outbound as the given user, and returns its SOCKS5 address.
func trojanClient(t *testing.T, serverPort int, user, certPEM string) string {
	t.Helper()
	socksPort := freePort(t)
	cfg := map[string]any{
		"log": map[string]any{"level": "error"},
		"inbounds": []map[string]any{{
			"type": "socks", "tag": "socks-in",
			"listen": "127.0.0.1", "listen_port": socksPort,
		}},
		"outbounds": []map[string]any{{
			"type": "trojan", "tag": "trojan-out",
			"server": "127.0.0.1", "server_port": serverPort,
			"password": "trojan-" + user,
			"tls": map[string]any{
				"enabled":     true,
				"server_name": "vpn.test",
				"certificate": strings.Split(strings.TrimSpace(certPEM), "\n"),
			},
		}},
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p, err := newClientBox(t, raw)
	if err != nil {
		t.Fatalf("start client for %q: %v", user, err)
	}
	t.Cleanup(func() { p.Close() })
	addr := "127.0.0.1:" + strconv.Itoa(socksPort)
	waitForPort(t, addr)
	return addr
}

// fetchLabel sends one request through the client's SOCKS5 port and returns
// which tunnel answered.
func fetchLabel(socksAddr string) (string, error) {
	d, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return "", err
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return "", fmt.Errorf("dialer does not support contexts")
	}
	client := &http.Client{
		Transport: &http.Transport{DialContext: cd.DialContext},
		Timeout:   20 * time.Second,
	}
	// The destination is irrelevant: each stand-in answers with its own
	// label, so the reply identifies the tunnel that carried the request.
	resp, err := client.Get("http://tunnel.probe/")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	return string(body), err
}

// newClientBox starts a sing-box instance acting as a client. It registers
// the mirror image of the server's protocols: a SOCKS5 inbound for the test
// to drive, and a trojan outbound to reach the listener.
func newClientBox(t *testing.T, raw []byte) (*box.Box, error) {
	t.Helper()

	inR := inbound.NewRegistry()
	socks.RegisterInbound(inR)

	outR := outbound.NewRegistry()
	trojan.RegisterOutbound(outR)
	direct.RegisterOutbound(outR)
	block.RegisterOutbound(outR)

	dnsR := dns.NewTransportRegistry()
	transport.RegisterUDP(dnsR)
	transport.RegisterTCP(dnsR)
	local.RegisterTransport(dnsR)

	ctx := box.Context(context.Background(), inR, outR, endpoint.NewRegistry(), dnsR, service.NewRegistry())

	var parsed option.Options
	if err := singjson.UnmarshalContext(ctx, raw, &parsed); err != nil {
		return nil, err
	}
	inst, err := box.New(box.Options{Context: ctx, Options: parsed})
	if err != nil {
		return nil, err
	}
	if err := inst.Start(); err != nil {
		inst.Close()
		return nil, err
	}
	return inst, nil
}

// TestAuthUserRoutesToTheRightTunnel is the acceptance gate for the
// single-port design: one trojan listener must direct each user to their own
// tunnel and nowhere else.
func TestAuthUserRoutesToTheRightTunnel(t *testing.T) {
	port, backends, certPEM := testbed(t, "office", "lab", "corp")

	for name := range backends {
		socksAddr := trojanClient(t, port, name, certPEM)
		got, err := fetchLabel(socksAddr)
		if err != nil {
			t.Fatalf("user %q: %v", name, err)
		}
		if got != name {
			t.Errorf("user %q reached tunnel %q", name, got)
		}
	}

	for name, b := range backends {
		if b.count() != 1 {
			t.Errorf("tunnel %q carried %d connections, want 1", name, b.count())
		}
	}
}

// TestAuthUserRoutingUnderConcurrency guards against the failure mode
// reported upstream, where auth_user matching was intermittent. A tunnel
// misrouting even once would send intranet traffic to the wrong network, so
// this runs enough interleaved requests to catch a race.
func TestAuthUserRoutingUnderConcurrency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping concurrency stress in short mode")
	}
	names := []string{"office", "lab", "corp"}
	port, backends, certPEM := testbed(t, names...)

	clients := map[string]string{}
	for _, name := range names {
		clients[name] = trojanClient(t, port, name, certPEM)
	}

	const perUser = 40
	var wg sync.WaitGroup
	errs := make(chan error, len(names)*perUser)

	for _, name := range names {
		for range perUser {
			wg.Add(1)
			go func() {
				defer wg.Done()
				got, err := fetchLabel(clients[name])
				if err != nil {
					errs <- fmt.Errorf("user %q: %w", name, err)
					return
				}
				if got != name {
					errs <- fmt.Errorf("user %q was routed to tunnel %q", name, got)
				}
			}()
		}
	}
	wg.Wait()
	close(errs)

	var failures []string
	for err := range errs {
		failures = append(failures, err.Error())
	}
	if len(failures) > 0 {
		t.Fatalf("%d of %d requests were misrouted or failed:\n  %s",
			len(failures), len(names)*perUser, strings.Join(failures[:min(len(failures), 10)], "\n  "))
	}

	for _, name := range names {
		if got := backends[name].count(); got != perUser {
			t.Errorf("tunnel %q carried %d connections, want %d", name, got, perUser)
		}
	}
}

// TestWrongPasswordIsRejected checks that a client cannot reach any tunnel
// without a configured user's password.
func TestWrongPasswordIsRejected(t *testing.T) {
	port, backends, certPEM := testbed(t, "office")

	socksAddr := trojanClient(t, port, "intruder", certPEM)
	if got, err := fetchLabel(socksAddr); err == nil {
		t.Fatalf("an unknown trojan password reached tunnel %q", got)
	}
	if n := backends["office"].count(); n != 0 {
		t.Errorf("tunnel office carried %d connections for an unknown user, want 0", n)
	}
}

// TestUnmatchedTrafficIsBlockedNotSentDirect checks the routing table's final
// action. Falling through to direct would look like a working tunnel while
// quietly sending intranet traffic to the internet.
func TestUnmatchedTrafficIsBlockedNotSentDirect(t *testing.T) {
	cfg, err := BuildConfig(Options{
		Listen:     ":443",
		ServerName: "vpn.test",
		CertPath:   "/tmp/c",
		KeyPath:    "/tmp/k",
		Routes:     []Route{{Name: "office", TrojanPassword: "pw", DataHost: "127.0.0.1", DataPort: 21000}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Route struct {
			Final string `json:"final"`
		} `json:"route"`
	}
	if err := json.Unmarshal(cfg, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Route.Final != blockTag {
		t.Errorf("route.final = %q, want %q", parsed.Route.Final, blockTag)
	}
}

func TestBuildConfigRejectsIncompleteInput(t *testing.T) {
	base := Options{Listen: ":443", ServerName: "n", CertPath: "c", KeyPath: "k"}

	tests := []struct {
		name string
		opts Options
	}{
		{"no listen address", Options{ServerName: "n", CertPath: "c", KeyPath: "k"}},
		{"no certificate", Options{Listen: ":443", ServerName: "n"}},
		{"tunnel without a password", func() Options {
			o := base
			o.Routes = []Route{{Name: "office"}}
			return o
		}()},
		{"tunnel without a name", func() Options {
			o := base
			o.Routes = []Route{{TrojanPassword: "pw"}}
			return o
		}()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := BuildConfig(tc.opts); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestSplitListen(t *testing.T) {
	tests := []struct {
		in       string
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{":443", "::", 443, false},
		{"127.0.0.1:8443", "127.0.0.1", 8443, false},
		{"443", "", 0, true},
		{":0", "", 0, true},
		{":99999", "", 0, true},
	}
	for _, tc := range tests {
		host, port, err := splitListen(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("splitListen(%q) succeeded, want an error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("splitListen(%q): %v", tc.in, err)
			continue
		}
		if host != tc.wantHost || port != tc.wantPort {
			t.Errorf("splitListen(%q) = %q, %d; want %q, %d", tc.in, host, port, tc.wantHost, tc.wantPort)
		}
	}
}

func TestBuildConfigDirectRoute(t *testing.T) {
	raw, err := BuildConfig(Options{
		Listen:     ":443",
		ServerName: "vpn.test",
		CertPath:   "/tmp/c",
		KeyPath:    "/tmp/k",
		Routes: []Route{
			{Name: "lan", TrojanPassword: "pw1", Direct: true},
			{Name: "office", TrojanPassword: "pw2", DataHost: "127.0.0.1", DataPort: 21000},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Inbounds []struct {
			Users []struct {
				Name     string `json:"name"`
				Password string `json:"password"`
			} `json:"users"`
		} `json:"inbounds"`
		Outbounds []struct {
			Tag  string `json:"tag"`
			Type string `json:"type"`
		} `json:"outbounds"`
		Route struct {
			Rules []struct {
				AuthUser []string `json:"auth_user"`
				Outbound string   `json:"outbound"`
			} `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}

	if len(parsed.Inbounds[0].Users) != 2 {
		t.Fatalf("users count = %d, want 2", len(parsed.Inbounds[0].Users))
	}
	obTypes := map[string]string{}
	for _, ob := range parsed.Outbounds {
		obTypes[ob.Tag] = ob.Type
	}
	if obTypes["tunnel-lan"] != "direct" {
		t.Errorf("outbound tunnel-lan type = %q, want direct", obTypes["tunnel-lan"])
	}
	if obTypes["tunnel-office"] != "socks" {
		t.Errorf("outbound tunnel-office type = %q, want socks", obTypes["tunnel-office"])
	}

	ruleTargets := map[string]string{}
	for _, r := range parsed.Route.Rules {
		if len(r.AuthUser) > 0 {
			ruleTargets[r.AuthUser[0]] = r.Outbound
		}
	}
	if ruleTargets["lan"] != "tunnel-lan" {
		t.Errorf("rule for lan = %q, want tunnel-lan", ruleTargets["lan"])
	}
}

func TestBuildConfigTrojanRoute(t *testing.T) {
	raw, err := BuildConfig(Options{
		Listen:   ":1443",
		CertPath: "/tmp/cert.pem",
		KeyPath:  "/tmp/key.pem",
		Routes: []Route{
			{
				Name:           "hk-node",
				TrojanPassword: "client-trojan-pass",
				TrojanOutbound: &TrojanOutboundConfig{
					Server:     "hk.example.com",
					ServerPort: 443,
					Password:   "upstream-trojan-pass",
					ServerName: "hk.example.com",
					Insecure:   true,
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var parsed struct {
		Outbounds []struct {
			Tag        string `json:"tag"`
			Type       string `json:"type"`
			Server     string `json:"server"`
			ServerPort int    `json:"server_port"`
			Password   string `json:"password"`
			TLS        struct {
				Enabled    bool   `json:"enabled"`
				ServerName string `json:"server_name"`
				Insecure   bool   `json:"insecure"`
			} `json:"tls"`
		} `json:"outbounds"`
		Route struct {
			Rules []struct {
				AuthUser []string `json:"auth_user"`
				Outbound string   `json:"outbound"`
			} `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}

	var trOb *struct {
		Tag        string `json:"tag"`
		Type       string `json:"type"`
		Server     string `json:"server"`
		ServerPort int    `json:"server_port"`
		Password   string `json:"password"`
		TLS        struct {
			Enabled    bool   `json:"enabled"`
			ServerName string `json:"server_name"`
			Insecure   bool   `json:"insecure"`
		} `json:"tls"`
	}
	for i := range parsed.Outbounds {
		if parsed.Outbounds[i].Tag == "tunnel-hk-node" {
			trOb = &parsed.Outbounds[i]
			break
		}
	}
	if trOb == nil {
		t.Fatal("outbound tunnel-hk-node not found")
	}
	if trOb.Type != "trojan" {
		t.Errorf("type = %q, want trojan", trOb.Type)
	}
	if trOb.Server != "hk.example.com" || trOb.ServerPort != 443 || trOb.Password != "upstream-trojan-pass" {
		t.Errorf("trojan outbound fields = %+v", trOb)
	}
	if !trOb.TLS.Enabled || trOb.TLS.ServerName != "hk.example.com" || !trOb.TLS.Insecure {
		t.Errorf("trojan TLS fields = %+v", trOb.TLS)
	}
}

func TestEveryOutboundItGeneratesIsOneItCanRun(t *testing.T) {
	// The configuration is generated here and parsed by sing-box, which only
	// knows the protocols this package registers. A type emitted by one and
	// missing from the other is not a tunnel that misbehaves: it is a server
	// that refuses to start, taking every other tunnel with it. That is what
	// adding an upstream trojan node did.
	//
	// So one route of every kind BuildConfig can produce is started for real.
	dir := t.TempDir()
	mat, err := certs.EnsureSelfSigned(filepath.Join(dir, "tls"), "vpn.test")
	if err != nil {
		t.Fatal(err)
	}

	opts := Options{
		Listen:     "127.0.0.1:" + strconv.Itoa(freePort(t)),
		ServerName: "vpn.test",
		CertPath:   mat.CertPath,
		KeyPath:    mat.KeyPath,
		LogLevel:   "error",
		Routes: []Route{
			// Through a container's SOCKS5 data plane.
			{
				Name: "container", TrojanPassword: "trojan-container",
				DataHost: "127.0.0.1", DataPort: 11080,
				SOCKSUser: "vpngw", SOCKSPassword: "socks-container",
			},
			// Out of the server's own interface.
			{Name: "host", TrojanPassword: "trojan-host", Direct: true},
			// On to somebody else's trojan server. The address is
			// documentation space and is never dialled: outbounds connect
			// when they carry traffic, not when they are built.
			{
				Name: "upstream", TrojanPassword: "trojan-upstream",
				TrojanOutbound: &TrojanOutboundConfig{
					Server: "192.0.2.10", ServerPort: 443,
					Password: "upstream-pass", ServerName: "hk.example.com",
				},
			},
		},
	}

	p, err := New(context.Background(), opts, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("the server would not start with one route of each kind: %v", err)
	}
	t.Cleanup(func() { p.Close() })
	waitForPort(t, opts.Listen)
}

func trojanClientWithPass(t *testing.T, serverPort int, pass, certPEM string) string {
	t.Helper()
	socksPort := freePort(t)
	cfg := map[string]any{
		"log": map[string]any{"level": "error"},
		"inbounds": []map[string]any{{
			"type": "socks", "tag": "socks-in",
			"listen": "127.0.0.1", "listen_port": socksPort,
		}},
		"outbounds": []map[string]any{{
			"type": "trojan", "tag": "trojan-out",
			"server": "127.0.0.1", "server_port": serverPort,
			"password": pass,
			"tls": map[string]any{
				"enabled":     true,
				"server_name": "vpn.test",
				"certificate": strings.Split(strings.TrimSpace(certPEM), "\n"),
			},
		}},
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p, err := newClientBox(t, raw)
	if err != nil {
		t.Fatalf("start client with pass: %v", err)
	}
	t.Cleanup(func() { p.Close() })
	addr := "127.0.0.1:" + strconv.Itoa(socksPort)
	waitForPort(t, addr)
	return addr
}

type mockSessionValidator struct {
	validSessions map[string]string // token -> username
}

func (m *mockSessionValidator) Validate(token string) (string, bool, bool) {
	u, ok := m.validSessions[token]
	return u, false, ok
}

func TestDynamicAuthenticatorEndToEnd(t *testing.T) {
	dir := t.TempDir()
	mat, err := certs.EnsureSelfSigned(filepath.Join(dir, "tls"), "vpn.test")
	if err != nil {
		t.Fatal(err)
	}

	backend := startLabelledSOCKS(t, "office", "vpngw", "socks-office")
	host, portStr, _ := net.SplitHostPort(backend.addr)
	port, _ := strconv.Atoi(portStr)

	validator := &mockSessionValidator{
		validSessions: map[string]string{
			"sess_alice": "alice",
		},
	}
	dynAuth := NewDynamicAuthenticator(validator, slog.New(slog.DiscardHandler))

	serverPort := freePort(t)
	opts := Options{
		Listen:     "127.0.0.1:" + strconv.Itoa(serverPort),
		ServerName: "vpn.test",
		CertPath:   mat.CertPath,
		KeyPath:    mat.KeyPath,
		LogLevel:   "error",
		Routes: []Route{
			{
				Name:           "office",
				TrojanPassword: "static-secret-office",
				DataHost:       host,
				DataPort:       port,
				SOCKSUser:      "vpngw",
				SOCKSPassword:  "socks-office",
			},
		},
		Authenticator: dynAuth,
	}

	p, err := New(context.Background(), opts, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("start listener: %v", err)
	}
	t.Cleanup(func() { p.Close() })
	waitForPort(t, opts.Listen)

	// 1. Trying to connect with static password must FAIL when DynamicAuthenticator is active
	staticClient := trojanClientWithPass(t, serverPort, "static-secret-office", mat.CertPEM)
	if got, err := fetchLabel(staticClient); err == nil {
		t.Fatalf("static secret should have been rejected, but got %q", got)
	}

	// 2. Dynamic password for alice on office tunnel must SUCCEED
	alicePass := dynAuth.GetOrCreatePassword("sess_alice", "alice", "office")
	aliceClient := trojanClientWithPass(t, serverPort, alicePass, mat.CertPEM)
	got, err := fetchLabel(aliceClient)
	if err != nil {
		t.Fatalf("fetchLabel with alicePass: %v", err)
	}
	if got != "office" {
		t.Errorf("got %q, want office", got)
	}

	// 3. Revoke alice's session -> connection must fail immediately
	dynAuth.RevokeSession("sess_alice")
	delete(validator.validSessions, "sess_alice")

	if got, err := fetchLabel(aliceClient); err == nil {
		t.Fatalf("revoked session should have been rejected, but got %q", got)
	}
}
