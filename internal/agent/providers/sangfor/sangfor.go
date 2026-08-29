// Package sangfor connects to Sangfor EasyConnect and aTrust gateways by
// supervising zju-connect, a maintained Go reimplementation of both
// protocols, and re-exporting its SOCKS5 proxy through the agent contract.
//
// Both protocols share one implementation because zju-connect selects between
// them with a single -protocol flag.
package sangfor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"

	"github.com/vpn-gateway/vpn-gateway/internal/agent"
	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

// Loopback ports for the supervised child. They are deliberately not 1080 or
// 1081: those belong to the agent's own data and control planes, and
// zju-connect defaults to exactly that pair.
const (
	childSOCKS = "127.0.0.1:11080"
	childHTTP  = "127.0.0.1:11081"
)

// defaultBinary is the zju-connect path inside the image.
const defaultBinary = "/usr/local/bin/zju-connect"

func init() {
	agent.Register("easyconnect", func() agent.Provider { return &Provider{protocol: "easyconnect"} })
	agent.Register("atrust", func() agent.Provider { return &Provider{protocol: "atrust"} })
}

// Provider drives one Sangfor protocol.
//
// Recognised VG_EXTRA_JSON keys, beyond the shared network overrides handled
// by agent.ApplyNetworkOverrides:
//
//	port           gateway port (default 443)
//	totp_secret    TOTP seed, when the gateway demands two-factor auth
//	remote_dns     resolver to use inside the tunnel
//	binary         override the zju-connect path
//	extra_args     additional zju-connect flags, space separated
//
// aTrust only:
//
//	login_domain   authentication domain (upstream default "Radius")
//	auth_type      authentication type
//	phone          phone number, with country code, for SMS login
//	device_id      device identifier, for gateways that check device trust
type Provider struct {
	protocol string
	runner   agent.Runner

	// authFailed records that the child reported rejected credentials, so a
	// crash loop against a wrong password is reported as permanent instead
	// of being retried forever.
	authFailed atomic.Bool
}

func (p *Provider) Capabilities() []string {
	// TOTP is supplied as a seed at startup rather than prompted for, so this
	// provider raises no interactive challenges.
	return []string{contract.CapTCP, contract.CapRoutes, contract.CapDNS}
}

func (p *Provider) Run(ctx context.Context, cfg agent.Config, rep agent.Reporter) error {
	if cfg.Server == "" {
		return agent.Permanent(errors.New("VG_SERVER is required"))
	}
	if cfg.Username == "" {
		return agent.Permanent(errors.New("VG_USERNAME is required"))
	}
	p.authFailed.Store(false)

	// zju-connect parses flags with pflag, where a single dash introduces
	// short options. "-protocol atrust" is silently ignored and the tool
	// falls back to easyconnect, so every flag must use two dashes.
	args := []string{
		"--protocol", p.protocol,
		"--server", cfg.Server,
		"--port", cfg.Str("port", "443"),
		"--username", cfg.Username,
		"--password", cfg.Password,
		"--socks-bind", childSOCKS,
		"--http-bind", childHTTP,
		// Routing is decided by the vpn-gateway client, so the tunnel must
		// not second-guess which traffic belongs to it.
		"--skip-domain-resource",
	}
	if p.protocol == "easyconnect" {
		// The upstream tool ships defaults for one university's network, and
		// a general-purpose gateway must not inherit them. The flag applies
		// to easyconnect only; passing it under atrust is an error.
		args = append(args, "--disable-zju-config")
	}

	for _, opt := range []struct{ key, flag string }{
		{"totp_secret", "--totp-secret"},
		{"remote_dns", "--remote-dns-server"},
		{"login_domain", "--login-domain"},
		{"auth_type", "--auth-type"},
		{"phone", "--phone"},
		{"device_id", "--device-id"},
	} {
		if v := cfg.Str(opt.key, ""); v != "" {
			args = append(args, opt.flag, v)
		}
	}
	if v := cfg.Str("extra_args", ""); v != "" {
		args = append(args, strings.Fields(v)...)
	}

	p.runner = agent.Runner{
		Path:     cfg.Str("binary", defaultBinary),
		Args:     args,
		Upstream: childSOCKS,
		OnLine:   func(line string, rep agent.Reporter) { p.onLine(line, rep) },
	}

	// zju-connect does not report the gateway's pushed routes in a stable
	// machine-readable form, so the operator states them in VG_EXTRA_JSON.
	// Publishing them before the dial completes is harmless: the client only
	// applies a tunnel's routes once it reaches StateUp.
	rep.SetNetwork(agent.ApplyNetworkOverrides(cfg, contract.Network{
		UDP: false,
		MTU: 1400,
	}))

	err := p.runner.Run(ctx, rep)
	if err != nil && p.authFailed.Load() {
		return agent.Permanent(fmt.Errorf("%s rejected the credentials: %w", p.protocol, err))
	}
	return err
}

// onLine watches the child's output for credential rejection. Matching is
// keyword-based and covers both the English and Chinese messages the upstream
// tool emits; a missed match only costs a retry, never a wrong success.
func (p *Provider) onLine(line string, rep agent.Reporter) {
	l := strings.ToLower(line)
	for _, marker := range []string{
		"invalid username or password",
		"login failed",
		"auth failed",
		"authentication failed",
		"用户名或密码错误",
		"认证失败",
		"登录失败",
	} {
		if strings.Contains(l, marker) {
			p.authFailed.Store(true)
			rep.SetState(contract.StateError, errors.New(strings.TrimSpace(line)))
			return
		}
	}
}

func (p *Provider) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return p.runner.Dial(ctx, network, addr)
}

// Answer is unused: this provider raises no interactive challenges.
func (p *Provider) Answer(contract.AuthAnswer) error {
	return errors.New("this provider does not use interactive authentication")
}
