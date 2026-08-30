package openconnect

import (
	"slices"
	"strings"
	"testing"

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
		"Please enter your token":           contract.ChallengeTOTP,
		"TOTP":                              contract.ChallengeTOTP,
		"Enter the code from Authenticator": contract.ChallengeTOTP,
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
