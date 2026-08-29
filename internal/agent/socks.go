package agent

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

// SOCKS5 wire constants (RFC 1928).
const (
	socksVersion   = 0x05
	methodNoAuth   = 0x00
	methodUserPass = 0x02
	methodNone     = 0xFF

	// authVersion is the username/password sub-negotiation version
	// (RFC 1929), which is independent of the SOCKS version.
	authVersion = 0x01
	authSuccess = 0x00
	authFailure = 0x01

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSuccess          = 0x00
	repGeneralFailure   = 0x01
	repNetUnreachable   = 0x03
	repConnRefused      = 0x05
	repCmdNotSupported  = 0x07
	repAddrNotSupported = 0x08
)

// handshakeTimeout bounds the SOCKS negotiation. It does not bound the
// relayed connection, which may idle for hours.
const handshakeTimeout = 10 * time.Second

// ServeSOCKS accepts SOCKS5 connections on ln and relays each one through the
// agent's tunnel, counting bytes as it goes. It returns when ln is closed.
//
// Only CONNECT is implemented. UDP ASSOCIATE is deliberately absent: the
// agent advertises contract.CapUDP only when a provider can carry datagrams,
// and clients fall back to DNS-over-TCP otherwise.
func (a *Agent) ServeSOCKS(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return fmt.Errorf("socks accept: %w", err)
		}
		go a.handleSOCKS(ctx, c)
	}
}

func (a *Agent) handleSOCKS(ctx context.Context, client net.Conn) {
	defer client.Close()

	client.SetDeadline(time.Now().Add(handshakeTimeout))
	target, err := socksNegotiate(client, a.secret)
	if err != nil {
		a.log.Debug("socks handshake failed", "peer", client.RemoteAddr(), "error", err)
		return
	}

	remote, err := a.Dial(ctx, "tcp", target)
	if err != nil {
		a.log.Debug("socks dial failed", "target", target, "error", err)
		socksReply(client, dialFailureCode(err))
		return
	}
	defer remote.Close()

	if err := socksReply(client, repSuccess); err != nil {
		return
	}
	// The relay itself is unbounded; only the handshake was deadlined.
	client.SetDeadline(time.Time{})

	a.connOpened()
	defer a.connClosed()
	a.relay(client, remote)
}

// relay copies in both directions until either side closes, attributing bytes
// leaving the client as tx and bytes returning as rx.
func (a *Agent) relay(client, remote net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, _ := io.Copy(remote, client)
		a.addTx(n)
		closeWrite(remote)
	}()
	go func() {
		defer wg.Done()
		n, _ := io.Copy(client, remote)
		a.addRx(n)
		closeWrite(client)
	}()

	wg.Wait()
}

// closeWrite half-closes when the connection supports it, so the peer sees
// EOF instead of waiting for the whole relay to tear down.
func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
		return
	}
	c.Close()
}

// socksNegotiate performs the greeting and request exchange, returning the
// requested "host:port".
func socksNegotiate(c net.Conn, secret string) (string, error) {
	// Greeting: VER NMETHODS METHODS...
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return "", fmt.Errorf("read greeting: %w", err)
	}
	if head[0] != socksVersion {
		return "", fmt.Errorf("unsupported SOCKS version %d", head[0])
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return "", fmt.Errorf("read methods: %w", err)
	}
	// Authentication is mandatory whenever a secret is configured. Container
	// network isolation alone does not stop a compromised sibling container
	// from reaching this port on every engine.
	if secret != "" {
		if !containsByte(methods, methodUserPass) {
			c.Write([]byte{socksVersion, methodNone})
			return "", errors.New("client does not support username/password authentication")
		}
		if _, err := c.Write([]byte{socksVersion, methodUserPass}); err != nil {
			return "", err
		}
		if err := socksAuthenticate(c, secret); err != nil {
			return "", err
		}
	} else {
		if !containsByte(methods, methodNoAuth) {
			c.Write([]byte{socksVersion, methodNone})
			return "", errors.New("client offered no acceptable auth method")
		}
		if _, err := c.Write([]byte{socksVersion, methodNoAuth}); err != nil {
			return "", err
		}
	}

	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return "", fmt.Errorf("read request: %w", err)
	}
	if req[0] != socksVersion {
		return "", fmt.Errorf("unsupported SOCKS version %d", req[0])
	}
	if req[1] != cmdConnect {
		socksReply(c, repCmdNotSupported)
		return "", fmt.Errorf("unsupported command %d", req[1])
	}

	var host string
	switch req[3] {
	case atypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case atypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case atypDomain:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return "", err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		host = string(b)
	default:
		socksReply(c, repAddrNotSupported)
		return "", fmt.Errorf("unsupported address type %d", req[3])
	}

	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(pb)))), nil
}

// socksAuthenticate runs the RFC 1929 username/password sub-negotiation.
// Both fields are compared in constant time so a wrong secret leaks nothing
// about the right one.
func socksAuthenticate(c net.Conn, secret string) error {
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return fmt.Errorf("read auth header: %w", err)
	}
	if head[0] != authVersion {
		return fmt.Errorf("unsupported auth version %d", head[0])
	}
	user := make([]byte, head[1])
	if _, err := io.ReadFull(c, user); err != nil {
		return fmt.Errorf("read username: %w", err)
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(c, plen); err != nil {
		return fmt.Errorf("read password length: %w", err)
	}
	pass := make([]byte, plen[0])
	if _, err := io.ReadFull(c, pass); err != nil {
		return fmt.Errorf("read password: %w", err)
	}

	okUser := subtle.ConstantTimeCompare(user, []byte(contract.SOCKSUsername))
	okPass := subtle.ConstantTimeCompare(pass, []byte(secret))
	if okUser&okPass != 1 {
		c.Write([]byte{authVersion, authFailure})
		return errors.New("data plane authentication failed")
	}
	if _, err := c.Write([]byte{authVersion, authSuccess}); err != nil {
		return err
	}
	return nil
}

// socksReply sends a reply with a zero bound address, which clients ignore
// for CONNECT.
func socksReply(c net.Conn, code byte) error {
	_, err := c.Write([]byte{socksVersion, code, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

func dialFailureCode(err error) byte {
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return repGeneralFailure
	case errors.Is(err, net.ErrClosed):
		return repNetUnreachable
	}
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Op == "dial" {
		return repConnRefused
	}
	return repGeneralFailure
}

func containsByte(b []byte, want byte) bool {
	for _, v := range b {
		if v == want {
			return true
		}
	}
	return false
}
