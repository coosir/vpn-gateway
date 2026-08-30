// Package openconnect connects to the enterprise SSL VPNs that OpenConnect
// speaks, by supervising the openconnect client inside the container.
//
// One implementation covers seven protocols, because OpenConnect already
// does: Fortinet, GlobalProtect, Pulse, F5, Juniper Network Connect, Array and
// AnyConnect. Each is registered as its own provider name so a tunnel names
// the VPN it is, not the tool underneath.
//
// The client installs a tun interface and routes inside the container's own
// network namespace. The agent shares that namespace, so once the tunnel is
// up an ordinary dial already goes through it, and nothing has to translate
// between the two.
package openconnect

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/agent"
	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

// defaultBinary is looked up on PATH rather than pinned: distributions do not
// agree on whether openconnect belongs in /usr/bin or /usr/sbin, and getting
// it wrong turns a working image into a permanent failure.
const defaultBinary = "openconnect"

// protocols maps a provider name to OpenConnect's own protocol identifier.
// The names on the left are what someone would call their VPN; the ones on
// the right are what the tool wants.
var protocols = map[string]string{
	"fortinet":      "fortinet",
	"globalprotect": "gp",
	"pulse":         "pulse",
	"f5":            "f5",
	"juniper":       "nc",
	"array":         "array",
	"anyconnect":    "anyconnect",
}

func init() {
	for name, proto := range protocols {
		agent.Register(name, func() agent.Provider { return &Provider{protocol: proto} })
	}
}

// Provider drives one OpenConnect protocol.
//
// Recognised VG_EXTRA_JSON keys, beyond the shared network overrides:
//
//	port           gateway port (default 443)
//	authgroup      realm or group to select from the gateway's login form
//	servercert     pin the gateway's certificate, as openconnect prints it
//	               when it first refuses to trust one
//	totp_secret    seed for a software token
//	totp_append    "true" when the gateway wants the code joined onto the end
//	               of the password rather than asked for separately
//	totp_digits    length of the code, 6 unless the gateway says otherwise
//	totp_period    seconds a code is valid for, 30 unless stated
//	totp_algorithm sha1 (default), sha256 or sha512
//	token_mode     software token type for the separate-prompt form: totp
//	               (default when a seed is set), hotp, rsa or oidc
//	form_entry     a login form answer, as FORM:OPTION=VALUE; repeat with a
//	               comma between entries
//	useragent      pretend to be the vendor's own client, which some
//	               gateways insist on
//	no_dtls        "true" to stay on TLS where UDP is blocked or unreliable
//	binary         override the openconnect path
//	extra_args     additional openconnect flags, space separated
type Provider struct {
	protocol string
	runner   agent.Runner

	// authFailed records that the gateway rejected the credentials, so a
	// crash loop against a wrong password is reported as permanent instead of
	// being retried against a corporate gateway that may lock the account.
	authFailed atomic.Bool
}

func (p *Provider) Capabilities() []string {
	// The tunnel is a real interface, so datagrams cross it as readily as
	// streams; the agent's own SOCKS5 front is what limits this to TCP today.
	return []string{
		contract.CapTCP, contract.CapRoutes, contract.CapDNS,
		contract.CapPassword, contract.CapTOTP,
	}
}

func (p *Provider) Run(ctx context.Context, cfg agent.Config, rep agent.Reporter) error {
	if cfg.Server == "" {
		return agent.Permanent(errors.New("VG_SERVER is required"))
	}
	if cfg.Username == "" {
		return agent.Permanent(errors.New("VG_USERNAME is required"))
	}
	p.authFailed.Store(false)

	args := buildArgs(p.protocol, cfg)

	rep.SetNetwork(agent.ApplyNetworkOverrides(cfg, contract.Network{UDP: false, MTU: 1400}))

	password, err := p.password(cfg, rep)
	if err != nil {
		return err
	}

	p.runner = agent.Runner{
		Path: cfg.Str("binary", defaultBinary),
		Args: args,
		// The password is the first thing the client reads.
		StdinPrelude: []string{password},
		// The client installs its routes in this namespace, so traffic
		// already leaves through them.
		DirectDial: true,
		// Readiness is the interface existing and being addressed rather than
		// a phrase in the output: the wording differs across the seven
		// protocols and changes between versions.
		ReadyWhen: agent.TunnelInterfaceUp,
		Prompts:   prompts(),
		OnLine:    func(line string, rep agent.Reporter) { p.onLine(line, rep) },
	}

	err = p.runner.Run(ctx, rep)
	if err != nil && p.authFailed.Load() {
		return agent.Permanent(fmt.Errorf("%s rejected the credentials: %w", p.protocol, err))
	}
	return err
}

// buildArgs assembles the openconnect command line.
//
// The password is deliberately absent: it goes in on standard input so it
// never appears in the container's process list.
func buildArgs(protocol string, cfg agent.Config) []string {
	args := []string{
		"--protocol=" + protocol,
		"--user=" + cfg.Username,
		"--passwd-on-stdin",
		// The client's own configuration script sets up the interface, the
		// routes and the resolver. All of it lands in this container's
		// network namespace and nowhere else.
		"--script=/etc/vpnc/vpnc-script",
		"--interface=tun0",
	}
	if port := cfg.Str("port", "443"); port != "443" {
		args = append(args, "--port="+port)
	}
	for _, opt := range []struct{ key, flag string }{
		{"authgroup", "--authgroup="},
		{"servercert", "--servercert="},
		{"useragent", "--useragent="},
	} {
		if v := cfg.Str(opt.key, ""); v != "" {
			args = append(args, opt.flag+v)
		}
	}
	// The appended form is answered in the password itself, so the client
	// must not also be told to expect a separate token prompt.
	if secret := cfg.Str("totp_secret", ""); secret != "" && !cfg.Bool("totp_append", false) {
		// Answering the token from a seed avoids prompting a person every
		// time the tunnel reconnects.
		args = append(args,
			"--token-mode="+cfg.Str("token_mode", "totp"),
			"--token-secret="+secret)
	}
	for _, entry := range splitList(cfg.Str("form_entry", "")) {
		args = append(args, "--form-entry="+entry)
	}
	if cfg.Bool("no_dtls", false) {
		args = append(args, "--no-dtls")
	}
	if v := cfg.Str("extra_args", ""); v != "" {
		args = append(args, strings.Fields(v)...)
	}
	// --non-inter is deliberately not passed: it makes the client exit the
	// moment the gateway asks anything, which is exactly the case the prompt
	// relay exists to handle.
	return append(args, cfg.Server)
}

// password builds what goes into the gateway's password field.
//
// Some gateways do not ask for a one-time code separately: they want it
// joined onto the end of the fixed password, so the field carries both and
// there is never a second prompt. Nothing in the protocol distinguishes the
// two, so which one this is has to be configured.
//
// The code is computed for each attempt, not once, so a reconnect an hour
// later sends a current one.
func (p *Provider) password(cfg agent.Config, rep agent.Reporter) (string, error) {
	if !cfg.Bool("totp_append", false) {
		return cfg.Password, nil
	}

	secret := cfg.Str("totp_secret", "")
	if secret == "" {
		return "", agent.Permanent(errors.New(
			"extra.totp_append is set but extra.totp_secret is empty; " +
				"there is nothing to compute a code from"))
	}

	opts := agent.TOTPOptions{
		Digits:    cfg.Int("totp_digits", 0),
		Period:    time.Duration(cfg.Int("totp_period", 0)) * time.Second,
		Algorithm: cfg.Str("totp_algorithm", ""),
	}

	// A code computed in the last moment of its period expires while the
	// gateway is still being dialled. Waiting for the next one costs a few
	// seconds; a rejected login costs an attempt against a corporate account,
	// and enough of those lock it.
	if left := agent.TOTPValidFor(time.Now(), opts); left < minCodeValidity {
		rep.Log("waiting %s for the next one-time code", left.Round(time.Second))
		time.Sleep(left)
	}

	code, err := agent.TOTP(secret, time.Now(), opts)
	if err != nil {
		// A seed that cannot be read will not start working later.
		return "", agent.Permanent(err)
	}
	rep.Log("using a one-time code joined to the password")
	return cfg.Password + code, nil
}

// minCodeValidity is how much of a code's life has to remain for it to be
// worth sending.
const minCodeValidity = 5 * time.Second

// prompts describe the questions openconnect relays.
//
// Their wording comes from the gateway's own login form, so there is no fixed
// phrase to look for. What is reliable is the shape: openconnect leaves the
// cursor after a question's colon, while everything it logs is terminated.
func prompts() []agent.Prompt {
	return []agent.Prompt{
		{
			Match: agent.GatewayQuestion(),
			Type:  contract.ChallengePassword,
			Describe: func(line string, recent []string) contract.Challenge {
				question := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), ":"))
				ch := contract.Challenge{
					Type:   classify(question),
					Prompt: question + " (asked by the VPN gateway)",
				}
				return ch
			},
		},
	}
}

// classify guesses what kind of answer a gateway's question wants, so a
// client can show the right thing. Guessing wrong only changes the wording
// shown; the answer is still typed and relayed the same way.
func classify(question string) contract.ChallengeType {
	q := strings.ToLower(question)
	switch {
	case strings.Contains(q, "sms") || strings.Contains(q, "短信"):
		return contract.ChallengeSMS
	case strings.Contains(q, "token") || strings.Contains(q, "totp") ||
		strings.Contains(q, "authenticator") || strings.Contains(q, "otp"):
		return contract.ChallengeTOTP
	case strings.Contains(q, "captcha") || strings.Contains(q, "image"):
		return contract.ChallengeCaptcha
	default:
		return contract.ChallengePassword
	}
}

// onLine watches for the gateway refusing the credentials, and for the
// certificate refusal that needs a pin rather than a retry.
func (p *Provider) onLine(line string, rep agent.Reporter) {
	l := strings.ToLower(line)

	for _, marker := range []string{
		"login failed", "authentication failed", "invalid credentials",
		"password verification failed", "permission denied",
	} {
		if strings.Contains(l, marker) {
			p.authFailed.Store(true)
			rep.SetState(contract.StateError, errors.New(strings.TrimSpace(line)))
			return
		}
	}

	// An untrusted certificate cannot be retried away: someone has to check
	// the fingerprint and pin it. Saying so beats a silent reconnect loop.
	if strings.Contains(l, "certificate from vpn server") && strings.Contains(l, "failed verification") {
		p.authFailed.Store(true)
		rep.SetState(contract.StateError, errors.New(
			"the gateway's certificate is not trusted; check its fingerprint and set extra.servercert"))
	}
}

func (p *Provider) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return p.runner.Dial(ctx, network, addr)
}

// Answer forwards a login form answer to the client, which is blocked reading
// it from standard input.
func (p *Provider) Answer(a contract.AuthAnswer) error {
	return p.runner.Answer(a)
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
