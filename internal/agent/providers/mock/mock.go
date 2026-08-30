// Package mock implements a provider that carries traffic straight to the
// internet instead of through a VPN.
//
// It exists so the whole pipeline -- container orchestration, control plane,
// SOCKS5 data plane, routing rules, GUI -- can be exercised end to end
// without credentials for anyone's corporate VPN. Every other provider is
// hard to test; this one must never be.
package mock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/agent"
	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

func init() {
	agent.Register("mock", func() agent.Provider { return &Provider{answered: make(chan string, 1)} })
}

// Provider dials directly and reports a synthetic network.
//
// Recognised VG_EXTRA_JSON keys:
//
//	routes          comma-separated CIDRs to advertise (default 10.99.0.0/16)
//	dns             comma-separated resolver addresses (default 10.99.0.53)
//	search_domains  comma-separated suffixes (default mock.internal)
//	connect_delay   how long to sit in "connecting" (default 1s)
//	challenge       raise this challenge type once before connecting,
//	                one of sms, totp, password
//	answer          the value that satisfies the challenge (default 000000)
//	fail            fail every dial attempt with this message, to exercise
//	                the server's backoff and the client's failure isolation
type Provider struct {
	answered chan string
	want     string
}

func (p *Provider) Capabilities() []string {
	// No UDP: the agent's SOCKS5 front implements CONNECT only, so the mock
	// must not claim a capability the data plane cannot honour.
	return []string{
		contract.CapTCP, contract.CapRoutes, contract.CapDNS,
		contract.CapSMS, contract.CapTOTP, contract.CapCaptcha,
	}
}

func (p *Provider) Run(ctx context.Context, cfg agent.Config, rep agent.Reporter) error {
	if msg := cfg.Str("fail", ""); msg != "" {
		rep.SetState(contract.StateConnecting, nil)
		return errors.New(msg)
	}

	rep.SetState(contract.StateConnecting, nil)
	rep.Log("mock provider dialing %q as %q", cfg.Server, cfg.Username)

	if kind := cfg.Str("challenge", ""); kind != "" {
		if err := p.challenge(ctx, cfg, rep, kind); err != nil {
			return err
		}
	}

	delay, err := time.ParseDuration(cfg.Str("connect_delay", "1s"))
	if err != nil {
		return agent.Permanent(fmt.Errorf("bad connect_delay: %w", err))
	}
	select {
	case <-ctx.Done():
		return nil
	case <-time.After(delay):
	}

	rep.SetNetwork(contract.Network{
		Routes:        splitList(cfg.Str("routes", "10.99.0.0/16")),
		DNS:           splitList(cfg.Str("dns", "10.99.0.53")),
		SearchDomains: splitList(cfg.Str("search_domains", "mock.internal")),
		UDP:           false,
		MTU:           1400,
		AssignedIP:    "10.99.0.2",
	})
	rep.SetState(contract.StateUp, nil)

	<-ctx.Done()
	return nil
}

func (p *Provider) challenge(ctx context.Context, cfg agent.Config, rep agent.Reporter, kind string) error {
	p.want = cfg.Str("answer", "000000")
	rep.SetState(contract.StateAuthRequired, nil)
	rep.SetChallenge(&contract.Challenge{
		ID:        fmt.Sprintf("mock-%d", time.Now().UnixNano()),
		Type:      contract.ChallengeType(kind),
		Prompt:    "Enter the mock verification code (" + p.want + ")",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	})

	select {
	case <-ctx.Done():
		return nil
	case got := <-p.answered:
		if got != p.want {
			return agent.Permanent(fmt.Errorf("mock challenge rejected %q", got))
		}
	case <-time.After(5 * time.Minute):
		return errors.New("mock challenge timed out")
	}
	rep.Log("mock challenge accepted")
	return nil
}

func (p *Provider) Answer(a contract.AuthAnswer) error {
	select {
	case p.answered <- a.Value:
		return nil
	default:
		return errors.New("no challenge is awaiting an answer")
	}
}

func (p *Provider) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	return out
}
