package openconnect

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/agent"
	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

func cfgWith(extra map[string]string) agent.Config {
	return agent.Config{
		Provider: "fortinet",
		Server:   "vpn.corp.example",
		Username: "alice",
		Password: "s3cret",
		Extra:    extra,
	}
}

func TestPasswordNeverReachesTheCommandLine(t *testing.T) {
	// An argument is visible in the container's process list; standard input
	// is not.
	args := buildArgs("fortinet", cfgWith(nil))
	for _, a := range args {
		if strings.Contains(a, "s3cret") {
			t.Fatalf("the password appears in the arguments: %q", a)
		}
	}
	if !slices.Contains(args, "--passwd-on-stdin") {
		t.Error("--passwd-on-stdin is missing, so the password would have to go somewhere visible")
	}
}

func TestNonInteractiveIsNotPassed(t *testing.T) {
	// --non-inter makes the client exit the moment the gateway asks anything,
	// which is exactly what the prompt relay is for.
	for _, a := range buildArgs("fortinet", cfgWith(nil)) {
		if a == "--non-inter" {
			t.Fatal("--non-inter would defeat the interactive login relay")
		}
	}
}

func TestBuildArgsCarriesTheGatewaySettings(t *testing.T) {
	args := buildArgs("gp", cfgWith(map[string]string{
		"port":        "10443",
		"authgroup":   "corp-realm",
		"servercert":  "pin-sha256:abc",
		"useragent":   "PAN GlobalProtect",
		"totp_secret": "SEED",
		"form_entry":  "main:group=staff, main:extra=1",
		"no_dtls":     "true",
		"extra_args":  "--reconnect-timeout 60",
	}))

	want := []string{
		"--protocol=gp", "--user=alice", "--passwd-on-stdin",
		"--port=10443", "--authgroup=corp-realm", "--servercert=pin-sha256:abc",
		"--useragent=PAN GlobalProtect",
		"--token-mode=totp", "--token-secret=SEED",
		"--form-entry=main:group=staff", "--form-entry=main:extra=1",
		"--no-dtls", "--reconnect-timeout", "60",
	}
	for _, w := range want {
		if !slices.Contains(args, w) {
			t.Errorf("%q is missing from %v", w, args)
		}
	}
	if args[len(args)-1] != "vpn.corp.example" {
		t.Errorf("the server must come last, got %q", args[len(args)-1])
	}
}

func TestDefaultPortIsLeftOut(t *testing.T) {
	// Passing --port=443 is harmless but noisy, and some gateways behave
	// differently when the port is stated explicitly.
	for _, a := range buildArgs("fortinet", cfgWith(nil)) {
		if strings.HasPrefix(a, "--port=") {
			t.Errorf("the default port was passed anyway: %q", a)
		}
	}
}

func TestEveryProviderNameMapsToItsProtocol(t *testing.T) {
	// The registry is built in a loop, so a capture mistake would silently
	// point every name at one protocol.
	for name, want := range protocols {
		p, err := agent.New(name)
		if err != nil {
			t.Fatalf("provider %q is not registered: %v", name, err)
		}
		got, ok := p.(*Provider)
		if !ok {
			t.Fatalf("provider %q is not from this package", name)
		}
		if got.protocol != want {
			t.Errorf("provider %q uses protocol %q, want %q", name, got.protocol, want)
		}
	}
}

func TestGatewayQuestionIgnoresLogLines(t *testing.T) {
	// The gateway words its own questions, so the only reliable signal is
	// that a question is unterminated. Treating a log line as a question
	// would stop the tunnel to ask a person about nothing.
	match := agent.GatewayQuestion()

	logLines := []string{
		"Connected to 203.0.113.7:443",
		"SSL negotiation with vpn.corp.example",
		"Got CONNECT response: HTTP/1.1 200 OK",
		"Please enter your token:",
	}
	for _, line := range logLines {
		if match(line, true) {
			t.Errorf("a complete line was treated as a question: %q", line)
		}
	}

	questions := []string{
		"Password:",
		"Please enter your token: ",
		"SMS code:",
	}
	for _, q := range questions {
		if !match(q, false) {
			t.Errorf("an unterminated question was not recognised: %q", q)
		}
	}

	notQuestions := []string{
		"Established DTLS connection",
		"Connected as 10.30.7.31",
	}
	for _, line := range notQuestions {
		if match(line, false) {
			t.Errorf("a fragment with no colon was treated as a question: %q", line)
		}
	}
}

func TestClassifyPicksTheRightKindOfAnswer(t *testing.T) {
	tests := map[string]contract.ChallengeType{
		"Please enter your SMS code":        contract.ChallengeSMS,
		"短信验证码":                             contract.ChallengeSMS,
		"Response:":                         contract.ChallengeSMS,
		"Challenge:":                        contract.ChallengeSMS,
		"Verification code":                 contract.ChallengeSMS,
		"请输入验证码":                            contract.ChallengeSMS,
		"Please enter your token":           contract.ChallengeTOTP,
		"TOTP":                              contract.ChallengeTOTP,
		"Enter the code from Authenticator": contract.ChallengeTOTP,
		"Enter passcode":                    contract.ChallengeTOTP,
		"动态口令":                              contract.ChallengeTOTP,
		"Captcha":                           contract.ChallengeCaptcha,
		"Password":                          contract.ChallengePassword,
		"Answer":                            contract.ChallengePassword,
	}
	for question, want := range tests {
		if got := classify(question); got != want {
			t.Errorf("classify(%q) = %q, want %q", question, got, want)
		}
	}
}

func TestPromptDescribesTheGatewaysQuestion(t *testing.T) {
	ps := prompts()
	if len(ps) != 1 {
		t.Fatalf("got %d prompts, want one generic matcher", len(ps))
	}
	ch := ps[0].Describe("Please enter your token: ", nil)
	if ch.Type != contract.ChallengeTOTP {
		t.Errorf("challenge type = %q, want totp", ch.Type)
	}
	if !strings.Contains(ch.Prompt, "Please enter your token") {
		t.Errorf("the gateway's own wording was lost: %q", ch.Prompt)
	}
}

func TestRejectedCredentialsAreNotRetried(t *testing.T) {
	// A login loop against a corporate gateway is how accounts get locked.
	p := &Provider{protocol: "fortinet"}
	rep := &recordingReporter{}
	p.onLine("Login failed: invalid credentials", rep)

	if !p.authFailed.Load() {
		t.Error("a rejected login was not recorded as permanent")
	}
	if rep.state != contract.StateError {
		t.Errorf("state = %q, want error", rep.state)
	}
}

func TestUntrustedCertificateIsNotRetried(t *testing.T) {
	// Retrying cannot fix it; someone has to check the fingerprint and pin it.
	p := &Provider{protocol: "fortinet"}
	rep := &recordingReporter{}
	p.onLine("Certificate from VPN server \"vpn.corp.example\" failed verification.", rep)

	if !p.authFailed.Load() {
		t.Error("an untrusted certificate was not recorded as permanent")
	}
	if !strings.Contains(rep.err, "servercert") {
		t.Errorf("the message does not say how to fix it: %q", rep.err)
	}
}

func TestOrdinaryOutputIsNotAFailure(t *testing.T) {
	p := &Provider{protocol: "fortinet"}
	rep := &recordingReporter{}
	for _, line := range []string{
		"Connected to 203.0.113.7:443",
		"Established DTLS connection (using GnuTLS)",
		"Connected as 10.30.7.31, using SSL",
	} {
		p.onLine(line, rep)
	}
	if p.authFailed.Load() {
		t.Error("ordinary output was treated as a permanent failure")
	}
}

type recordingReporter struct {
	state contract.State
	err   string
}

func (r *recordingReporter) SetState(s contract.State, err error) {
	r.state = s
	if err != nil {
		r.err = err.Error()
	}
}
func (r *recordingReporter) SetNetwork(contract.Network)      {}
func (r *recordingReporter) SetChallenge(*contract.Challenge) {}
func (r *recordingReporter) Log(string, ...any)               {}

// recordingReporter already exists above; this one only needs the log lines.
type quietReporter struct{ logs []string }

func (q *quietReporter) SetState(contract.State, error)   {}
func (q *quietReporter) SetNetwork(contract.Network)      {}
func (q *quietReporter) SetChallenge(*contract.Challenge) {}
func (q *quietReporter) Log(format string, args ...any)   { q.logs = append(q.logs, format) }

// The RFC 6238 seed, so the expected codes can be computed independently.
const testSeed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestPasswordIsUntouchedWithoutAppending(t *testing.T) {
	p := &Provider{protocol: "fortinet"}
	got, err := p.password(cfgWith(nil), &quietReporter{})
	if err != nil {
		t.Fatal(err)
	}
	if got != "s3cret" {
		t.Errorf("password = %q", got)
	}
}

// TestCodeIsJoinedOntoThePassword covers the gateways that take both in one
// field rather than asking for the code separately.
func TestCodeIsJoinedOntoThePassword(t *testing.T) {
	p := &Provider{protocol: "fortinet"}
	cfg := cfgWith(map[string]string{"totp_append": "true", "totp_secret": testSeed})

	got, err := p.password(cfg, &quietReporter{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "s3cret") {
		t.Fatalf("the fixed part is missing: %q", got)
	}
	code := strings.TrimPrefix(got, "s3cret")
	if len(code) != 6 {
		t.Fatalf("appended %q, want six digits", code)
	}

	want, err := agent.TOTP(testSeed, time.Now(), agent.TOTPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if code != want {
		t.Errorf("appended %s, want %s", code, want)
	}
}

func TestAppendingHonoursTheGatewaysScheme(t *testing.T) {
	// Not every gateway uses six digits over thirty seconds with SHA-1.
	p := &Provider{protocol: "fortinet"}
	cfg := cfgWith(map[string]string{
		"totp_append":    "true",
		"totp_secret":    testSeed,
		"totp_digits":    "8",
		"totp_period":    "60",
		"totp_algorithm": "sha256",
	})

	got, err := p.password(cfg, &quietReporter{})
	if err != nil {
		t.Fatal(err)
	}
	code := strings.TrimPrefix(got, "s3cret")
	want, err := agent.TOTP(testSeed, time.Now(), agent.TOTPOptions{
		Digits: 8, Period: 60 * time.Second, Algorithm: "sha256",
	})
	if err != nil {
		t.Fatal(err)
	}
	if code != want {
		t.Errorf("appended %s, want %s", code, want)
	}
}

func TestAppendingWithoutASeedIsPermanent(t *testing.T) {
	// Retrying cannot conjure a seed, and a login loop against a corporate
	// gateway is how accounts get locked.
	p := &Provider{protocol: "fortinet"}
	_, err := p.password(cfgWith(map[string]string{"totp_append": "true"}), &quietReporter{})
	if err == nil {
		t.Fatal("appending was accepted with no seed")
	}
	if !errors.Is(err, agent.ErrPermanent) {
		t.Errorf("error is not permanent: %v", err)
	}
	if !strings.Contains(err.Error(), "totp_secret") {
		t.Errorf("the message does not say what is missing: %v", err)
	}
}

func TestAnUnreadableSeedIsPermanent(t *testing.T) {
	p := &Provider{protocol: "fortinet"}
	_, err := p.password(cfgWith(map[string]string{
		"totp_append": "true", "totp_secret": "not base32 !!",
	}), &quietReporter{})
	if err == nil {
		t.Fatal("an unreadable seed was accepted")
	}
	if !errors.Is(err, agent.ErrPermanent) {
		t.Errorf("error is not permanent: %v", err)
	}
}

// TestSeparateTokenFlagsAreDroppedWhenAppending checks the two forms do not
// both get configured: telling the client to expect a prompt that never comes
// leaves it waiting.
func TestSeparateTokenFlagsAreDroppedWhenAppending(t *testing.T) {
	appended := buildArgs("fortinet", cfgWith(map[string]string{
		"totp_append": "true", "totp_secret": testSeed,
	}))
	for _, a := range appended {
		if strings.HasPrefix(a, "--token-") {
			t.Errorf("%q was passed even though the code goes in the password", a)
		}
	}

	// The separate-prompt form still configures them.
	separate := buildArgs("fortinet", cfgWith(map[string]string{"totp_secret": testSeed}))
	if !slices.Contains(separate, "--token-mode=totp") {
		t.Error("--token-mode is missing from the separate-prompt form")
	}
}

// TestACodeAboutToExpireIsNotSent covers the wait: a code computed in the last
// moment of its period expires while the gateway is still being dialled.
func TestACodeAboutToExpireIsNotSent(t *testing.T) {
	// A short period, so the boundary this waits for arrives in seconds
	// rather than in most of a minute.
	const period = 6 * time.Second
	opts := agent.TOTPOptions{Period: period}

	// Line up with a moment shortly before a boundary.
	for agent.TOTPValidFor(time.Now(), opts) > minCodeValidity-time.Second {
		time.Sleep(100 * time.Millisecond)
	}

	p := &Provider{protocol: "fortinet"}
	start := time.Now()
	got, err := p.password(cfgWith(map[string]string{
		"totp_append": "true", "totp_secret": testSeed, "totp_period": "6",
	}), &quietReporter{})
	if err != nil {
		t.Fatal(err)
	}

	if time.Since(start) < 500*time.Millisecond {
		t.Error("it did not wait for the next code")
	}
	// What came back belongs to the period it waited for, with most of that
	// period still ahead of it.
	want, _ := agent.TOTP(testSeed, time.Now(), opts)
	if strings.TrimPrefix(got, "s3cret") != want {
		t.Error("the code returned is not the current one")
	}
	if left := agent.TOTPValidFor(time.Now(), opts); left < period-time.Second {
		t.Errorf("returned a code with only %v left of its life", left)
	}
}

// The reconnect window is the only way back that costs nothing: the client
// still holds the session cookie, so the gateway is not asked for a password
// or a code. On a gateway that wants an SMS code, running past it is the
// difference between a blip and somebody reaching for their phone.
func TestTheReconnectWindowCanBeWidened(t *testing.T) {
	args := buildArgs("anyconnect", cfgWith(map[string]string{"reconnect_timeout": "1800"}))
	if !slices.Contains(args, "--reconnect-timeout=1800") {
		t.Errorf("the reconnect window was not passed on: %v", args)
	}
}

// Left unset, the client's own default stands rather than one chosen here.
func TestTheReconnectWindowIsNotSetByDefault(t *testing.T) {
	for _, a := range buildArgs("anyconnect", cfgWith(nil)) {
		if strings.HasPrefix(a, "--reconnect-timeout") {
			t.Errorf("a reconnect window was passed without being asked for: %q", a)
		}
	}
}
