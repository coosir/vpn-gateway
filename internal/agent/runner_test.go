package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

// buildFakeVPN compiles the stand-in client once per test binary.
var buildFakeVPN = sync.OnceValues(func() (string, error) {
	dir, err := os.MkdirTemp("", "fakevpn")
	if err != nil {
		return "", err
	}
	bin := filepath.Join(dir, "fakevpn")
	cmd := exec.Command("go", "build", "-o", bin, "./testdata/fakevpn")
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", &buildError{string(out), err}
	}
	return bin, nil
})

type buildError struct {
	out string
	err error
}

func (e *buildError) Error() string { return e.err.Error() + ": " + e.out }

func fakeVPNPath(t *testing.T) string {
	t.Helper()
	bin, err := buildFakeVPN()
	if err != nil {
		t.Fatalf("build the fake VPN client: %v", err)
	}
	return bin
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// promptProvider drives the fake client through a Runner, so the whole
// prompt-to-stdin path is exercised.
type promptProvider struct {
	binary string
	style  string
	steps  string
	code   string
	addr   string
	runner Runner
}

func (p *promptProvider) Capabilities() []string {
	return []string{contract.CapTCP, contract.CapSMS, contract.CapTOTP, contract.CapURL}
}

func (p *promptProvider) Run(ctx context.Context, cfg Config, rep Reporter) error {
	p.runner = Runner{
		Path: p.binary,
		Args: []string{
			"-listen", p.addr, "-style", p.style,
			"-steps", p.steps, "-code", p.code,
		},
		Upstream:     p.addr,
		ReadyTimeout: 20 * time.Second,
		Prompts: []Prompt{
			{Marker: "enter the sms verification code", Type: contract.ChallengeSMS},
			{Marker: "enter your sms code", Type: contract.ChallengeSMS},
			{Marker: "enter the totp token", Type: contract.ChallengeTOTP},
			{
				Marker: "enter the callback url",
				Type:   contract.ChallengeURL,
				Describe: func(line string, recent []string) contract.Challenge {
					ch := contract.Challenge{Type: contract.ChallengeURL, Prompt: line}
					for i := len(recent) - 1; i >= 0; i-- {
						if u := urlIn(recent[i]); u != "" {
							ch.URL = u
							break
						}
					}
					return ch
				},
			},
		},
	}
	return p.runner.Run(ctx, rep)
}

func (p *promptProvider) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return p.runner.Dial(ctx, network, addr)
}
func (p *promptProvider) Answer(a contract.AuthAnswer) error { return p.runner.Answer(a) }

func urlIn(s string) string {
	i := indexOf(s, "https://")
	if i < 0 {
		return ""
	}
	rest := s[i:]
	for j := 0; j < len(rest); j++ {
		if rest[j] == ' ' || rest[j] == ',' {
			return rest[:j]
		}
	}
	return rest
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// runAgentWithPrompts starts an agent driving the fake client and returns its
// control plane base URL.
func runAgentWithPrompts(t *testing.T, style, steps, code string) (*Agent, string) {
	t.Helper()

	p := &promptProvider{
		binary: fakeVPNPath(t),
		style:  style,
		steps:  steps,
		code:   code,
		addr:   freeAddr(t),
	}
	a := &Agent{
		cfg:      Config{Provider: "prompt-test"},
		provider: p,
		log:      slog.New(slog.DiscardHandler),
		state:    contract.StateConnecting,
		since:    time.Now(),
		subs:     map[int]chan contract.Event{},
		redial:   make(chan struct{}, 1),
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go a.Supervise(ctx)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: a.ControlHandler()}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	return a, "http://" + ln.Addr().String()
}

// waitForChallenge polls the control plane until a challenge appears.
func waitForChallenge(t *testing.T, base string) contract.Challenge {
	t.Helper()
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(base + contract.PathChallenge)
		if err == nil {
			var ch contract.Challenge
			json.NewDecoder(resp.Body).Decode(&ch)
			resp.Body.Close()
			if ch.ID != "" {
				return ch
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("no challenge was raised")
	return contract.Challenge{}
}

func answer(t *testing.T, base string, ch contract.Challenge, value string) int {
	t.Helper()
	body, _ := json.Marshal(contract.AuthAnswer{ID: ch.ID, Value: value})
	resp, err := http.Post(base+contract.PathAuth, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func waitForState(t *testing.T, a *Agent, want contract.State, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if a.Status().State == want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("state is %q after %s, want %q", a.Status().State, within, want)
}

// TestSMSPromptBecomesAChallenge covers the aTrust shape: the prompt is
// written through the log package, so it arrives as a terminated line.
func TestSMSPromptBecomesAChallenge(t *testing.T) {
	a, base := runAgentWithPrompts(t, "atrust", "sms", "482915")

	ch := waitForChallenge(t, base)
	if ch.Type != contract.ChallengeSMS {
		t.Errorf("challenge type = %q, want sms", ch.Type)
	}
	waitForState(t, a, contract.StateAuthRequired, 5*time.Second)

	if code := answer(t, base, ch, "482915"); code != http.StatusNoContent {
		t.Fatalf("answering returned %d, want 204", code)
	}
	// Answering unblocks the client, which then serves its proxy.
	waitForState(t, a, contract.StateUp, 25*time.Second)
}

// TestUnterminatedPromptBecomesAChallenge covers the EasyConnect shape, where
// the prompt has no trailing newline. This is the case a line-based reader
// would miss entirely, leaving the tunnel blocked with nothing to show.
func TestUnterminatedPromptBecomesAChallenge(t *testing.T) {
	a, base := runAgentWithPrompts(t, "easyconnect", "sms", "112233")

	ch := waitForChallenge(t, base)
	if ch.Type != contract.ChallengeSMS {
		t.Errorf("challenge type = %q, want sms", ch.Type)
	}
	if code := answer(t, base, ch, "112233"); code != http.StatusNoContent {
		t.Fatalf("answering returned %d, want 204", code)
	}
	waitForState(t, a, contract.StateUp, 25*time.Second)
}

// TestSeveralPromptsInSequence covers a gateway that asks more than one
// question before letting anyone in.
func TestSeveralPromptsInSequence(t *testing.T) {
	a, base := runAgentWithPrompts(t, "atrust", "sms,totp", "999000")

	first := waitForChallenge(t, base)
	if first.Type != contract.ChallengeSMS {
		t.Fatalf("first challenge is %q, want sms", first.Type)
	}
	answer(t, base, first, "999000")

	deadline := time.Now().Add(15 * time.Second)
	var second contract.Challenge
	for time.Now().Before(deadline) {
		if ch := a.Challenge(); ch != nil && ch.ID != first.ID {
			second = *ch
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if second.Type != contract.ChallengeTOTP {
		t.Fatalf("second challenge is %q, want totp", second.Type)
	}
	answer(t, base, second, "999000")
	waitForState(t, a, contract.StateUp, 25*time.Second)
}

// TestSSOPromptCarriesTheLoginURL checks that the address printed before the
// prompt is captured, so a person is not left to find it in the logs.
func TestSSOPromptCarriesTheLoginURL(t *testing.T) {
	_, base := runAgentWithPrompts(t, "atrust", "sso", "unused")

	ch := waitForChallenge(t, base)
	if ch.Type != contract.ChallengeURL {
		t.Fatalf("challenge type = %q, want url", ch.Type)
	}
	if ch.URL != "https://sso.example.com/login?id=abc" {
		t.Errorf("challenge URL = %q, want the address printed before the prompt", ch.URL)
	}
}

// TestStaleAnswerIsRejected checks that an answer to a previous question
// cannot satisfy the current one.
func TestStaleAnswerIsRejected(t *testing.T) {
	_, base := runAgentWithPrompts(t, "atrust", "sms", "482915")
	ch := waitForChallenge(t, base)

	stale := contract.Challenge{ID: ch.ID + "-old"}
	if code := answer(t, base, stale, "482915"); code == http.StatusNoContent {
		t.Error("a stale challenge id was accepted")
	}
	if code := answer(t, base, ch, "482915"); code != http.StatusNoContent {
		t.Errorf("the current challenge id was rejected with %d", code)
	}
}

// TestAnswerWithNewlineIsRejected guards the standard input path: the client
// reads one whitespace-delimited token, so an embedded newline would answer
// this question and the next one at the same time.
func TestAnswerWithNewlineIsRejected(t *testing.T) {
	_, base := runAgentWithPrompts(t, "atrust", "sms", "482915")
	ch := waitForChallenge(t, base)

	if code := answer(t, base, ch, "482915\nextra"); code == http.StatusNoContent {
		t.Error("an answer containing a newline was accepted")
	}
}

// TestAuthDoesNotTimeOutWhileWaiting checks that the readiness deadline is
// suspended while a person is finding their code. A fixed timeout would kill
// the client mid-login and the tunnel could never come up.
func TestAuthDoesNotTimeOutWhileWaiting(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the timing test in short mode")
	}
	p := &promptProvider{
		binary: fakeVPNPath(t),
		style:  "atrust",
		steps:  "sms",
		code:   "482915",
		addr:   freeAddr(t),
	}
	a := &Agent{
		cfg:      Config{Provider: "prompt-test"},
		provider: p,
		log:      slog.New(slog.DiscardHandler),
		state:    contract.StateConnecting,
		since:    time.Now(),
		subs:     map[int]chan contract.Event{},
		redial:   make(chan struct{}, 1),
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// A readiness timeout far shorter than the wait below: without the
	// suspension the client would be killed before the answer arrives.
	go func() {
		p.runner.ReadyTimeout = 2 * time.Second
		a.Supervise(ctx)
	}()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: a.ControlHandler()}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	base := "http://" + ln.Addr().String()

	ch := waitForChallenge(t, base)
	time.Sleep(5 * time.Second)

	if got := a.Status().State; got != contract.StateAuthRequired {
		t.Fatalf("state is %q after waiting, want the tunnel still waiting for an answer", got)
	}
	if code := answer(t, base, ch, "482915"); code != http.StatusNoContent {
		t.Fatalf("answering after the wait returned %d", code)
	}
	waitForState(t, a, contract.StateUp, 25*time.Second)
}
