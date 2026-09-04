// Package sangfor connects to Sangfor EasyConnect and aTrust gateways by
// supervising zju-connect, a maintained Go reimplementation of both
// protocols, and re-exporting its SOCKS5 proxy through the agent contract.
//
// Both protocols share one implementation because zju-connect selects between
// them with a single -protocol flag.
package sangfor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
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
//
// When the gateway asks for a verification code, the provider raises a
// contract challenge instead of failing: the upstream client reads codes from
// standard input, and the agent writes the answer back there.
type Provider struct {
	protocol string
	runner   agent.Runner

	// authFailed records that the child reported rejected credentials, so a
	// crash loop against a wrong password is reported as permanent instead
	// of being retried forever.
	authFailed atomic.Bool
}

func (p *Provider) Capabilities() []string {
	caps := []string{
		contract.CapTCP, contract.CapRoutes, contract.CapDNS,
		contract.CapSMS, contract.CapTOTP, contract.CapCaptcha,
	}
	if p.protocol == "atrust" {
		// Only aTrust offers the single sign-on flows that end in pasting a
		// callback address.
		caps = append(caps, contract.CapURL)
	}
	return caps
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

	if p.protocol == "atrust" {
		// 1. Maintain a stable Linux machine-id across container restarts.
		if _, err := os.Stat("/data"); err == nil {
			midPath := "/data/machine-id"
			if data, err := os.ReadFile(midPath); err == nil && len(strings.TrimSpace(string(data))) > 0 {
				_ = os.WriteFile("/etc/machine-id", []byte(strings.TrimSpace(string(data))+"\n"), 0644)
			} else {
				b := make([]byte, 16)
				_, _ = rand.Read(b)
				mid := hex.EncodeToString(b)
				_ = os.WriteFile(midPath, []byte(mid+"\n"), 0644)
				_ = os.WriteFile("/etc/machine-id", []byte(mid+"\n"), 0644)
			}
		}

		// 2. Default login domain to local when not configured.
		loginDomain := cfg.Str("login_domain", "")
		if loginDomain == "" {
			loginDomain = "local"
		}
		args = append(args, "--login-domain", loginDomain)

		// 3. Persistent and stable Device ID.
		deviceID := cfg.Str("device_id", "")
		if deviceID == "" {
			if data, err := os.ReadFile("/data/device_id"); err == nil && len(strings.TrimSpace(string(data))) > 0 {
				deviceID = strings.TrimSpace(string(data))
			} else if _, err := os.Stat("/data"); err == nil {
				b := make([]byte, 16)
				_, _ = rand.Read(b)
				deviceID = hex.EncodeToString(b)
				_ = os.WriteFile("/data/device_id", []byte(deviceID+"\n"), 0644)
			}
		}
		if deviceID != "" {
			args = append(args, "--device-id", deviceID)
		}

		// 4. Client data file persistence (client_data.json)
		clientDataFile := cfg.Str("client_data_file", "")
		if clientDataFile == "" {
			if _, err := os.Stat("/data"); err == nil {
				clientDataFile = "/data/client_data.json"
			}
		}
		if clientDataFile != "" {
			args = append(args, "--client-data-file", clientDataFile)
		}

		// 5. Captcha image output file
		graphCodeFile := cfg.Str("graph_code_file", "")
		if graphCodeFile == "" {
			graphCodeFile = "/tmp/atrust-captcha.jpg"
		}
		args = append(args, "--graph-code-file", graphCodeFile)
	}

	for _, opt := range []struct{ key, flag string }{
		{"totp_secret", "--totp-secret"},
		{"remote_dns", "--remote-dns-server"},
		{"auth_type", "--auth-type"},
		{"phone", "--phone"},
	} {
		if v := cfg.Str(opt.key, ""); v != "" {
			args = append(args, opt.flag, v)
		}
	}
	if p.protocol != "atrust" {
		if v := cfg.Str("login_domain", ""); v != "" {
			args = append(args, "--login-domain", v)
		}
		if v := cfg.Str("device_id", ""); v != "" {
			args = append(args, "--device-id", v)
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
		Prompts:  prompts(),
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

// onLine watches the child's output for the two failures the agent has to act
// on. Matching is keyword-based and covers both the English and Chinese
// wordings the upstream tool emits.
//
// The order matters, because the two read almost alike. A rejected credential
// is permanent, and retrying it only walks an account towards being locked. A
// session the gateway has dropped is the opposite: the login was fine, it has
// merely aged out, and a fresh one fixes it. The gateway words that second one
// as
//
//	tcp tunnel authentication failed (code 10000004): invalid SID
//
// which the credential markers below would otherwise claim as a wrong
// password. So the recoverable case is checked first, and the credential
// markers only see what is left. Getting this backwards costs the tunnel: it
// parks as permanently broken while nothing is actually wrong with it.
//
// A missed match still only costs a retry, never a wrong success.
func (p *Provider) onLine(line string, rep agent.Reporter) {
	l := strings.ToLower(line)

	// A session the gateway no longer honours. The client does not exit over
	// it -- it stays up and fails every connection through it -- so the run
	// has to be ended for the supervisor to dial again and log in afresh.
	for _, marker := range []string{
		"invalid sid",
		"tcp tunnel authentication failed",
		"会话已失效",
		"会话过期",
	} {
		if strings.Contains(l, marker) {
			err := errors.New(strings.TrimSpace(line))
			rep.SetState(contract.StateError, err)
			p.runner.Fail(fmt.Errorf("the gateway dropped the session: %w", err))
			return
		}
	}

	// Credentials the gateway will not accept however often they are offered.
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

// Answer forwards a verification code to the supervised client, which is
// blocked reading it from standard input.
func (p *Provider) Answer(a contract.AuthAnswer) error {
	return p.runner.Answer(a)
}
