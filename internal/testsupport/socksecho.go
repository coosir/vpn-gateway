// Package testsupport provides stand-ins used by tests across the module.
//
// It is only imported from _test.go files; nothing in the shipped binaries
// depends on it.
package testsupport

import (
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

// LabelledSOCKS is a SOCKS5 server that stands in for one tunnel's container.
// Whatever address a client asks for, it connects to an HTTP endpoint that
// answers with this tunnel's label, so a test can tell which tunnel carried
// the traffic.
type LabelledSOCKS struct {
	Label string
	Addr  string

	user string
	pass string

	mu    sync.Mutex
	conns int
}

// StartLabelledSOCKS starts a stand-in. When user is empty it accepts
// unauthenticated clients.
func StartLabelledSOCKS(t *testing.T, label, user, pass string) *LabelledSOCKS {
	t.Helper()
	target := StartLabelServer(t, label)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	s := &LabelledSOCKS{Label: label, Addr: ln.Addr().String(), user: user, pass: pass}
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

// Conns reports how many connections this stand-in has carried.
func (s *LabelledSOCKS) Conns() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns
}

// HostPort splits Addr for callers that need the parts.
func (s *LabelledSOCKS) HostPort() (string, int) {
	host, portStr, _ := net.SplitHostPort(s.Addr)
	var port int
	for _, r := range portStr {
		port = port*10 + int(r-'0')
	}
	return host, port
}

func (s *LabelledSOCKS) serve(c net.Conn, target string) {
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
		if !containsByte(methods, 0x02) {
			c.Write([]byte{5, 0xFF})
			return
		}
		if _, err := c.Write([]byte{5, 0x02}); err != nil {
			return
		}
		if !s.authenticate(c) {
			return
		}
	} else if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}

	if !readSOCKSRequest(c) {
		return
	}

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

func (s *LabelledSOCKS) authenticate(c net.Conn) bool {
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return false
	}
	user := make([]byte, head[1])
	if _, err := io.ReadFull(c, user); err != nil {
		return false
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(c, plen); err != nil {
		return false
	}
	pass := make([]byte, plen[0])
	if _, err := io.ReadFull(c, pass); err != nil {
		return false
	}
	if string(user) != s.user || string(pass) != s.pass {
		c.Write([]byte{1, 1})
		return false
	}
	_, err := c.Write([]byte{1, 0})
	return err == nil
}

// readSOCKSRequest consumes a CONNECT request and discards the destination:
// this stand-in always dials its own label server.
func readSOCKSRequest(c net.Conn) bool {
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return false
	}
	switch req[3] {
	case 1:
		io.ReadFull(c, make([]byte, 4))
	case 4:
		io.ReadFull(c, make([]byte, 16))
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return false
		}
		io.ReadFull(c, make([]byte, l[0]))
	default:
		return false
	}
	_, err := io.ReadFull(c, make([]byte, 2))
	return err == nil
}

// StartLabelServer serves an HTTP endpoint that answers every request with
// label, and returns its address.
func StartLabelServer(t *testing.T, label string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, label)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close(); ln.Close() })
	return ln.Addr().String()
}

// FreePort returns a port that is free right now.
func FreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// WaitForPort blocks until addr accepts a connection.
func WaitForPort(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("nothing came up on %s", addr)
}

func containsByte(b []byte, want byte) bool {
	for _, v := range b {
		if v == want {
			return true
		}
	}
	return false
}
