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
	"sync"
	"sync/atomic"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/agent"
	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

// defaultBinary is looked up on PATH rather than pinned: distributions do not
// agree on whether openconnect belongs in /usr/bin or /usr/sbin, and getting
// it wrong turns a working image into a permanent failure.
const defaultBinary = "openconnect"

// protoAnyConnect is OpenConnect's name for Cisco's protocol, which is the
// only one here that has a single sign-on path.
const protoAnyConnect = "anyconnect"

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
//	               gateways insist on; anyconnect claims to be Cisco's own
//	               unless this says otherwise
//	version_string what to report as the client version during login, which
//	               a gateway filtering on it reads alongside useragent
//	no_dtls        "true" to stay on TLS where UDP is blocked or unreliable
//	binary         override the openconnect path
//	extra_args     additional openconnect flags, space separated
//
// AnyConnect gateways that sign in through an identity provider recognise
// three more:
//
//	sso            "off" to never offer single sign-on, for a gateway that
//	               answers the question badly; anything else leaves it on
//	sso_timeout    seconds to wait for somebody to finish signing in, 300
//	               by default
//	sso_hours      how long a redeemed session is worth trying before asking
//	               for a fresh sign-on, 24 by default
type Provider struct {
	protocol string
	runner   agent.Runner

	// authFailed records that the gateway rejected the credentials, so a
	// crash loop against a wrong password is reported as permanent instead of
	// being retried against a corporate gateway that may lock the account.
	authFailed atomic.Bool
	// cookieRejected records the gateway refusing the session this dial was
	// built on. Unlike a rejected password it is not permanent: what fixes it
	// is another sign-on, which is exactly what the next attempt does.
	cookieRejected atomic.Bool

	// mu guards the sign-on question, which is asked by Run and answered
	// from the control plane.
	mu         sync.Mutex
	ssoPending *contract.Challenge
	ssoAnswer  chan string
}

func (p *Provider) Capabilities() []string {
	// The tunnel is a real interface, so datagrams cross it as readily as
	// streams; the agent's own SOCKS5 front is what limits this to TCP today.
	caps := []string{
		contract.CapTCP, contract.CapRoutes, contract.CapDNS,
		contract.CapPassword, contract.CapSMS, contract.CapTOTP,
	}
	// Only the Cisco protocol has a sign-on page to send anybody to. Claiming
	// it for the other six would promise a client something it can never be
	// asked for.
	if p.protocol == protoAnyConnect {
		caps = append(caps, contract.CapURL)
	}
	return caps
}

func (p *Provider) Run(ctx context.Context, cfg agent.Config, rep agent.Reporter) error {
	if cfg.Server == "" {
		return agent.Permanent(errors.New("VG_SERVER is required"))
	}
	p.authFailed.Store(false)
	p.cookieRejected.Store(false)
	p.clearSSO()

	rep.SetNetwork(agent.ApplyNetworkOverrides(cfg, contract.Network{UDP: false, MTU: 1400}))

	// A gateway that signs people in through an identity provider never sees
	// the password at all, so the question of whether this is one has to be
	// settled before anything is built around the answer.
	cookie, fresh, err := p.session(ctx, cfg, rep)
	if err != nil {
		return err
	}
	if cookie != "" {
		return p.runSession(ctx, cfg, rep, cookie, fresh)
	}

	if cfg.Username == "" {
		return agent.Permanent(errors.New("VG_USERNAME is required"))
	}
	password, err := p.password(cfg, rep)
	if err != nil {
		return err
	}

	p.runner = agent.Runner{
		Path: cfg.Str("binary", defaultBinary),
		Args: buildArgs(p.protocol, cfg, false),
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

// runSession brings the tunnel up on a session that was signed in for
// already, handing openconnect the cookie so it never touches the login.
//
// fresh says the session was signed in for moments ago. It decides what a
// failure means: a stored session the gateway will not honour is one to
// forget, so the next attempt asks a person instead of failing the same way
// forever, while a fresh one that fails is a gateway problem and throwing it
// away would only cost another sign-on.
func (p *Provider) runSession(ctx context.Context, cfg agent.Config, rep agent.Reporter, cookie string, fresh bool) error {
	var reachedUp atomic.Bool
	p.runner = agent.Runner{
		Path:         cfg.Str("binary", defaultBinary),
		Args:         buildArgs(p.protocol, cfg, true),
		StdinPrelude: []string{cookie},
		DirectDial:   true,
		ReadyWhen: func() bool {
			if !agent.TunnelInterfaceUp() {
				return false
			}
			reachedUp.Store(true)
			return true
		},
		// There is no login form left to answer, but a client handed a
		// session can still stop to ask about something else -- an untrusted
		// certificate, most likely. Relaying it beats a tunnel that hangs
		// until the readiness deadline with the question only in the log.
		Prompts: prompts(),
		OnLine:  func(line string, rep agent.Reporter) { p.onLine(line, rep) },
	}

	err := p.runner.Run(ctx, rep)
	if err == nil {
		return nil
	}
	// A tunnel that carried traffic and then stopped is a link that went
	// away, not a session that was refused: the cookie is very likely still
	// good, and discarding it would cost a sign-on to find that out.
	if !fresh && !reachedUp.Load() {
		rep.Log("the stored sign-on no longer works; the next attempt will ask for a new one")
		dropSession(stateDir(cfg))
	}
	if p.cookieRejected.Load() {
		// Deliberately not permanent. What fixes this is another sign-on,
		// which is what the next attempt does.
		return fmt.Errorf("the gateway refused the stored sign-on: %w", err)
	}
	return err
}

// userAgent is what the gateway is told is calling.
//
// Cisco's protocol gets Cisco's own string unless the configuration says
// otherwise, because an ASA answers the XML login with 404 when it does not
// recognise the caller, and openconnect reads that as "no XML login here" and
// quietly drops to scraping the legacy HTML form. See sso.go for what that
// looks like from the outside; it is not something a person could diagnose
// from the prompt they are shown.
func userAgent(protocol string, cfg agent.Config) string {
	if protocol == protoAnyConnect {
		return cfg.Str("useragent", ciscoUserAgent)
	}
	return cfg.Str("useragent", "")
}

func versionString(protocol string, cfg agent.Config) string {
	if protocol == protoAnyConnect {
		return cfg.Str("version_string", ciscoVersion)
	}
	return cfg.Str("version_string", "")
}

// buildArgs assembles the openconnect command line.
//
// The secret is deliberately absent whichever kind it is: the password, or
// the session cookie a sign-on produced, goes in on standard input so it
// never appears in the container's process list.
//
// signedOn says the login has already happened elsewhere and openconnect is
// only being asked to build the tunnel. Everything to do with answering a
// login form is left out then, because there is no form left to answer.
func buildArgs(protocol string, cfg agent.Config, signedOn bool) []string {
	args := []string{
		"--protocol=" + protocol,
		// The client's own configuration script sets up the interface, the
		// routes and the resolver. All of it lands in this container's
		// network namespace and nowhere else.
		"--script=/etc/vpnc/vpnc-script",
		"--interface=tun0",
	}
	if signedOn {
		args = append(args, "--cookie-on-stdin")
	} else {
		args = append(args, "--user="+cfg.Username, "--passwd-on-stdin")
	}
	if port := cfg.Str("port", "443"); port != "443" {
		args = append(args, "--port="+port)
	}
	if v := cfg.Str("servercert", ""); v != "" {
		args = append(args, "--servercert="+v)
	}
	if v := userAgent(protocol, cfg); v != "" {
		args = append(args, "--useragent="+v)
	}
	if v := versionString(protocol, cfg); v != "" {
		args = append(args, "--version-string="+v)
	}
	if !signedOn {
		if v := cfg.Str("authgroup", ""); v != "" {
			args = append(args, "--authgroup="+v)
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
	}
	if cfg.Bool("no_dtls", false) {
		args = append(args, "--no-dtls")
	}
	// When the link drops, the client reconnects with the session cookie it
	// already holds. That is the one way back that asks the gateway for
	// nothing: no password, no code off somebody's phone. Past this window it
	// gives up and exits, and what follows is a fresh authentication.
	//
	// The client's own default is five minutes, which is generous for a
	// gateway that only wants a password and far too short for one that wants
	// an SMS code. Left unset, the client's default stands.
	if v := cfg.Str("reconnect_timeout", ""); v != "" {
		args = append(args, "--reconnect-timeout="+v)
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

// --- single sign-on -------------------------------------------------------

// defaultSSOWait is how long somebody has to finish signing in.
//
// It is measured against a person finding a browser window, typing a
// corporate password, and waiting for a text message, not against a process
// that is stuck. Too short and the tunnel gives up while they are reading
// their phone; too long and a tunnel nobody is watching sits at
// auth_required holding a question that was never asked.
const defaultSSOWait = 5 * time.Minute

// defaultSSOHours is how long a redeemed session is worth trying before the
// person is asked again.
//
// Erring long is deliberate. Trying a session the gateway has since dropped
// costs one failed dial and is recovered from automatically; discarding one
// that would still have worked costs somebody another text message.
const defaultSSOHours = 24

// stateDir is where this tunnel keeps what has to outlive the container.
func stateDir(cfg agent.Config) string { return cfg.Str("state_dir", "/data") }

// session produces the cookie to build the tunnel on, asking for a sign-on
// when there is nothing stored to use.
//
// An empty cookie and no error means this gateway wants a password like any
// other, and the ordinary path takes it from here. That is the answer for the
// other six protocols without asking, and for a Cisco gateway it is what the
// gateway itself said.
func (p *Provider) session(ctx context.Context, cfg agent.Config, rep agent.Reporter) (cookie string, fresh bool, err error) {
	if p.protocol != protoAnyConnect || strings.EqualFold(cfg.Str("sso", ""), "off") {
		return "", false, nil
	}

	dir := stateDir(cfg)
	ttl := time.Duration(cfg.Int("sso_hours", defaultSSOHours)) * time.Hour
	if stored := loadSession(dir, cfg.Server, cfg.Username, ttl); stored != "" {
		rep.Log("reusing the sign-on this tunnel already has; nobody is being asked for anything")
		return stored, false, nil
	}

	client, err := newSSOClient(cfg.Server, cfg.Str("port", "443"),
		userAgent(p.protocol, cfg), versionString(p.protocol, cfg))
	if err != nil {
		return "", false, err
	}

	offer, err := client.offer(ctx)
	if err != nil {
		// Falling through is right -- a gateway that cannot be asked may
		// still take a password -- but it is worth saying out loud. On a
		// gateway that only does single sign-on, what follows is a password
		// prompt that can never be satisfied, and the reason is here.
		rep.Log("could not ask %s how it wants to be signed into (%v); trying the password form", cfg.Server, err)
		return "", false, nil
	}
	if offer == nil {
		return "", false, nil
	}

	token, err := p.askSSO(ctx, cfg, rep, offer)
	if err != nil {
		return "", false, err
	}

	cookie, err = client.redeem(ctx, offer, token)
	if err != nil {
		return "", false, err
	}
	if err := saveSession(dir, cfg.Server, cfg.Username, cookie); err != nil {
		// Worth continuing: the tunnel comes up either way, and what is lost
		// is only that the next container pays for the sign-on again.
		rep.Log("could not keep the sign-on for next time (%v)", err)
	}
	return cookie, true, nil
}

// askSSO raises the sign-on and waits for the value only a browser holds.
func (p *Provider) askSSO(ctx context.Context, cfg agent.Config, rep agent.Reporter, offer *ssoOffer) (string, error) {
	wait := defaultSSOWait
	if secs := cfg.Int("sso_timeout", 0); secs > 0 {
		wait = time.Duration(secs) * time.Second
	}

	ch := contract.Challenge{
		ID:   fmt.Sprintf("sso-%d", time.Now().UnixNano()),
		Type: contract.ChallengeURL,
		Prompt: "Sign in to " + cfg.Server +
			" on the page that opens. The tunnel connects by itself once you are through.",
		URL:        offer.LoginURL,
		FinalURL:   offer.FinalURL,
		CookieName: offer.TokenCookie,
		ExpiresAt:  time.Now().Add(wait),
	}

	answer := make(chan string, 1)
	p.mu.Lock()
	p.ssoPending = &ch
	p.ssoAnswer = answer
	p.mu.Unlock()
	defer func() {
		p.clearSSO()
		// A question that timed out or was abandoned has to come off the
		// screen too. The agent clears one that was answered; nothing else
		// clears one that was not, and it would sit there until the next
		// attempt happened to replace it.
		rep.SetChallenge(nil)
	}()

	rep.SetState(contract.StateAuthRequired, nil)
	rep.SetChallenge(&ch)

	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-timer.C:
		return "", fmt.Errorf("nobody finished signing in within %s", wait.Round(time.Second))
	case v := <-answer:
		if v == "" {
			return "", errors.New("the sign-on came back empty")
		}
		return v, nil
	}
}

// clearSSO takes down the sign-on question, so an answer arriving late is
// refused rather than delivered to a dial that has moved on.
func (p *Provider) clearSSO() {
	p.mu.Lock()
	p.ssoPending, p.ssoAnswer = nil, nil
	p.mu.Unlock()
}

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
	case strings.Contains(q, "sms") || strings.Contains(q, "短信") ||
		strings.Contains(q, "verification") || strings.Contains(q, "验证码") ||
		strings.Contains(q, "手机码") || strings.Contains(q, "动态密码") ||
		strings.Contains(q, "二次认证") || strings.Contains(q, "二次验证") ||
		strings.Contains(q, "challenge") || strings.Contains(q, "response"):
		return contract.ChallengeSMS
	case strings.Contains(q, "token") || strings.Contains(q, "totp") ||
		strings.Contains(q, "authenticator") || strings.Contains(q, "otp") ||
		strings.Contains(q, "passcode") || strings.Contains(q, "动态口令"):
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

	// A refused session is not a refused credential. The session was good
	// when it was issued and is not any more, and the way back is another
	// sign-on rather than a person checking what they typed -- so this is
	// recorded separately and never parked as permanent.
	if strings.Contains(l, "cookie was rejected") || strings.Contains(l, "session expired") {
		p.cookieRejected.Store(true)
		rep.SetState(contract.StateError, errors.New(strings.TrimSpace(line)))
		return
	}

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

// Answer supplies a response to whichever question is outstanding.
//
// There are two kinds and they are answered in different places. A sign-on is
// waiting inside this provider, because no child process has been started
// yet: the login happens over HTTP and openconnect is handed the result. Every
// other question is a supervised client blocked on standard input.
func (p *Provider) Answer(a contract.AuthAnswer) error {
	p.mu.Lock()
	pending, answer := p.ssoPending, p.ssoAnswer
	p.mu.Unlock()

	if pending == nil {
		return p.runner.Answer(a)
	}
	if a.ID != pending.ID {
		return fmt.Errorf("challenge %q is no longer pending", a.ID)
	}
	select {
	case answer <- strings.TrimSpace(a.Value):
		return nil
	default:
		return errors.New("that sign-on has already been answered")
	}
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
