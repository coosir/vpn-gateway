package agent

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
	"golang.org/x/net/proxy"
)

// upProvider is a Provider that is immediately up and dials directly.
type upProvider struct{}

func (upProvider) Capabilities() []string { return []string{contract.CapTCP} }
func (upProvider) Run(ctx context.Context, cfg Config, rep Reporter) error {
	rep.SetState(contract.StateUp, nil)
	<-ctx.Done()
	return nil
}
func (upProvider) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}
func (upProvider) Answer(contract.AuthAnswer) error { return nil }

// startAgent brings up an agent with the given secret and a live SOCKS5
// listener, and returns the listener address.
func startAgent(t *testing.T, secret string) (*Agent, string) {
	t.Helper()
	a := &Agent{
		cfg:      Config{Provider: "test", Secret: secret},
		provider: upProvider{},
		log:      slog.New(slog.DiscardHandler),
		secret:   secret,
		state:    contract.StateUp,
		since:    time.Now(),
		subs:     map[int]chan contract.Event{},
		redial:   make(chan struct{}, 1),
	}
	now := time.Now()
	a.connectedAt = &now

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go a.ServeSOCKS(ctx, ln)
	return a, ln.Addr().String()
}

// echoServer is a target for the proxied connection.
func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

func TestSOCKSRequiresAuthWhenSecretIsSet(t *testing.T) {
	_, socksAddr := startAgent(t, "s3cret")
	target := echoServer(t)

	// A client offering only "no authentication" must be turned away: this
	// is the exact shape of a compromised sibling container probing the port.
	c, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 0x05 || reply[1] != 0xFF {
		t.Fatalf("got method reply %x, want 05ff (no acceptable methods)", reply)
	}

	// The correct credentials still work.
	d, err := proxy.SOCKS5("tcp", socksAddr, &proxy.Auth{User: contract.SOCKSUsername, Password: "s3cret"}, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := d.Dial("tcp", target)
	if err != nil {
		t.Fatalf("authenticated dial failed: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Errorf("echoed %q, want %q", buf, "ping")
	}
}

func TestSOCKSRejectsWrongSecret(t *testing.T) {
	_, socksAddr := startAgent(t, "right")
	d, err := proxy.SOCKS5("tcp", socksAddr, &proxy.Auth{User: contract.SOCKSUsername, Password: "wrong"}, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Dial("tcp", echoServer(t)); err == nil {
		t.Fatal("dial succeeded with the wrong secret")
	}
}

func TestSOCKSRejectsWrongUsername(t *testing.T) {
	_, socksAddr := startAgent(t, "right")
	d, err := proxy.SOCKS5("tcp", socksAddr, &proxy.Auth{User: "attacker", Password: "right"}, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Dial("tcp", echoServer(t)); err == nil {
		t.Fatal("dial succeeded with the wrong username")
	}
}

func TestSOCKSCountsTraffic(t *testing.T) {
	a, socksAddr := startAgent(t, "")
	d, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := d.Dial("tcp", echoServer(t))
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("0123456789")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	conn.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s := a.Status()
		if s.Traffic.TxBytes >= uint64(len(payload)) && s.Traffic.RxBytes >= uint64(len(payload)) {
			if s.Traffic.TotalConns != 1 {
				t.Errorf("TotalConns = %d, want 1", s.Traffic.TotalConns)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("counters never reached %d bytes: %+v", len(payload), a.Status().Traffic)
}

func TestSOCKSRefusesWhileTunnelIsDown(t *testing.T) {
	a, socksAddr := startAgent(t, "")
	a.SetState(contract.StateConnecting, nil)

	d, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	// Traffic must be refused rather than silently sent out of the wrong
	// interface while the tunnel is still coming up.
	if _, err := d.Dial("tcp", echoServer(t)); err == nil {
		t.Fatal("dial succeeded while the tunnel was not up")
	}
}

func TestSOCKSRejectsNonConnectCommands(t *testing.T) {
	_, socksAddr := startAgent(t, "")
	c, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))

	c.Write([]byte{0x05, 0x01, 0x00})
	io.ReadFull(c, make([]byte, 2))

	// BIND (0x02) is not implemented; the client must be told so rather than
	// left hanging.
	req := []byte{0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1}
	req = binary.BigEndian.AppendUint16(req, 80)
	c.Write(req)

	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != repCmdNotSupported {
		t.Errorf("reply code = %d, want %d (command not supported)", reply[1], repCmdNotSupported)
	}
}
