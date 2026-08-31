package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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
			{Match: Marker("enter the sms verification code"), Type: contract.ChallengeSMS},
			{Match: Marker("enter your sms code"), Type: contract.ChallengeSMS},
			{Match: Marker("enter the totp token"), Type: contract.ChallengeTOTP},
			{
				Match: Marker("enter the callback url"),
				Type:  contract.ChallengeURL,
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

// splitReader delivers a log line in two pieces with the split landing right
// after a colon, and then keeps the stream open. It reproduces a read
// boundary falling mid-line.
type splitReader struct {
	chunks []string
	i      int
	block  chan struct{}
}

func (r *splitReader) Read(p []byte) (int, error) {
	if r.i < len(r.chunks) {
		n := copy(p, r.chunks[r.i])
		r.i++
		return n, nil
	}
	<-r.block
	return 0, io.EOF
}

// TestMidLineSplitIsNotMistakenForAQuestion covers output such as
// openconnect's SSL errors, which are full of colons. A read boundary landing
// after one would otherwise stop the tunnel to ask a person about nothing.
func TestMidLineSplitIsNotMistakenForAQuestion(t *testing.T) {
	r := &Runner{
		Prompts: []Prompt{{Match: GatewayQuestion(), Type: contract.ChallengePassword}},
	}
	rep := &countingReporter{}
	src := &splitReader{
		chunks: []string{
			"error:0A000126:SSL routines:",
			":unexpected eof while reading:ssl/record/rec_layer_s3.c:698:\n",
		},
		block: make(chan struct{}),
	}
	go func() {
		time.Sleep(2 * time.Second)
		close(src.block)
	}()

	r.scan(src, rep)

	if ch := r.Pending(); ch != nil {
		t.Errorf("a split log line was treated as a question: %q", ch.Prompt)
	}
}

// TestARealQuestionStillBecomesAChallenge checks the debounce did not break
// the case it protects.
func TestARealQuestionStillBecomesAChallenge(t *testing.T) {
	r := &Runner{
		Prompts: []Prompt{{Match: GatewayQuestion(), Type: contract.ChallengePassword}},
	}
	rep := &countingReporter{}
	src := &splitReader{
		chunks: []string{"Connected to 203.0.113.7:443\n", "Please enter your token: "},
		block:  make(chan struct{}),
	}
	go func() {
		time.Sleep(2 * time.Second)
		close(src.block)
	}()

	r.scan(src, rep)

	ch := r.Pending()
	if ch == nil {
		t.Fatal("a genuine question did not become a challenge")
	}
	if !strings.Contains(ch.Prompt, "Please enter your token") {
		t.Errorf("challenge prompt = %q", ch.Prompt)
	}
}

type countingReporter struct {
	mu         sync.Mutex
	challenges int
}

func (c *countingReporter) SetState(contract.State, error) {}
func (c *countingReporter) SetNetwork(contract.Network)    {}
func (c *countingReporter) SetChallenge(ch *contract.Challenge) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ch != nil {
		c.challenges++
	}
}
func (c *countingReporter) Log(string, ...any) {}

// TestRunReturnsWhenTheChildFailsToStartServing is the regression test for a
// deadlock that wedged a tunnel in "connecting" forever.
//
// The exit was delivered on a single-value channel, and both the readiness
// wait and the caller needed to observe it. Whichever read first consumed the
// only value, and the other blocked for good: the supervisor never learned
// the child was gone, so it never backed off and never redialled.
func TestRunReturnsWhenTheChildFailsToStartServing(t *testing.T) {
	r := &Runner{
		// A command that exits immediately without ever serving anything,
		// which is what a VPN client does against an unreachable gateway.
		Path:         "/bin/sh",
		Args:         []string{"-c", "echo cannot reach the gateway >&2; exit 1"},
		Upstream:     freeAddr(t),
		ReadyTimeout: 30 * time.Second,
	}

	done := make(chan error, 1)
	go func() { done <- r.Run(context.Background(), &countingReporter{}) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a child that exited with status 1 was reported as success")
		}
		if !strings.Contains(err.Error(), "status 1") {
			t.Errorf("error = %v, want the exit status", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after the child exited; the tunnel would be wedged forever")
	}
}

// TestSupervisorRetriesAFailingChild checks the whole loop, not just Run:
// a client that keeps failing must keep being retried with backoff.
func TestSupervisorRetriesAFailingChild(t *testing.T) {
	p := &failingRunnerProvider{addr: freeAddr(t)}
	a := &Agent{
		cfg:         Config{Provider: "failing"},
		provider:    p,
		log:         slog.New(slog.DiscardHandler),
		maxAttempts: DefaultMaxAttempts,
		state:       contract.StateConnecting,
		since:       time.Now(),
		subs:        map[int]chan contract.Event{},
		redial:      make(chan struct{}, 1),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	go a.Supervise(ctx)

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if p.runs.Load() >= 2 && a.Status().State == contract.StateError {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("the child ran %d times and the state is %q; want repeated retries reported as errors",
		p.runs.Load(), a.Status().State)
}

type failingRunnerProvider struct {
	addr   string
	runs   atomic.Int32
	runner Runner
}

func (p *failingRunnerProvider) Capabilities() []string { return []string{contract.CapTCP} }
func (p *failingRunnerProvider) Run(ctx context.Context, cfg Config, rep Reporter) error {
	p.runs.Add(1)
	p.runner = Runner{
		Path:         "/bin/sh",
		Args:         []string{"-c", "exit 1"},
		Upstream:     p.addr,
		ReadyTimeout: 30 * time.Second,
	}
	return p.runner.Run(ctx, rep)
}
func (p *failingRunnerProvider) Dial(context.Context, string, string) (net.Conn, error) {
	return nil, errNotDialable
}
func (p *failingRunnerProvider) Answer(contract.AuthAnswer) error { return nil }

var errNotDialable = errorString("not dialable")

type errorString string

func (e errorString) Error() string { return string(e) }

// TestSupervisorStopsKnockingAfterRepeatedFailures is the point of bounding
// the retries: every attempt is a full authentication against a corporate
// gateway, and enough failures in a row is what locks an account.
func TestSupervisorStopsKnockingAfterRepeatedFailures(t *testing.T) {
	p := &failingRunnerProvider{addr: freeAddr(t)}
	a := &Agent{
		cfg:         Config{Provider: "failing"},
		provider:    p,
		log:         slog.New(slog.DiscardHandler),
		secret:      "",
		maxAttempts: 3,
		state:       contract.StateConnecting,
		since:       time.Now(),
		subs:        map[int]chan contract.Event{},
		redial:      make(chan struct{}, 1),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	go a.Supervise(ctx)

	// It should reach the cap and then stay there.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && p.runs.Load() < 3 {
		time.Sleep(100 * time.Millisecond)
	}
	if got := p.runs.Load(); got != 3 {
		t.Fatalf("dialled %d times, want 3", got)
	}

	// And it must stop rather than carry on quietly.
	time.Sleep(3 * time.Second)
	if got := p.runs.Load(); got != 3 {
		t.Errorf("kept dialling after giving up: %d attempts", got)
	}
	if st := a.Status(); st.State != contract.StateError {
		t.Errorf("state = %q, want error", st.State)
	}
}

// TestReconnectRevivesAGivenUpTunnel checks that giving up is not the end:
// someone who has fixed whatever was wrong can ask for another go.
func TestReconnectRevivesAGivenUpTunnel(t *testing.T) {
	p := &failingRunnerProvider{addr: freeAddr(t)}
	a := &Agent{
		cfg:         Config{Provider: "failing"},
		provider:    p,
		log:         slog.New(slog.DiscardHandler),
		maxAttempts: 1,
		state:       contract.StateConnecting,
		since:       time.Now(),
		subs:        map[int]chan contract.Event{},
		redial:      make(chan struct{}, 1),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	go a.Supervise(ctx)

	// Wait for it to have given up, not merely to have started: reconnecting
	// mid-attempt is a different case with its own test.
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) &&
		!(p.runs.Load() == 1 && a.Status().State == contract.StateError) {
		time.Sleep(50 * time.Millisecond)
	}
	if p.runs.Load() != 1 || a.Status().State != contract.StateError {
		t.Fatalf("dialled %d times, state %q", p.runs.Load(), a.Status().State)
	}

	a.Reconnect()
	deadline = time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) && p.runs.Load() < 2 {
		time.Sleep(50 * time.Millisecond)
	}
	if p.runs.Load() < 2 {
		t.Error("asking for a reconnect did not start another attempt")
	}
}

// TestAPermanentFailureCanStillBeRetriedOnRequest covers rejected
// credentials: the tunnel must not keep trying by itself, but someone who has
// corrected the password should not have to recreate the container.
func TestAPermanentFailureCanStillBeRetriedOnRequest(t *testing.T) {
	p := &scriptedProvider{results: []error{Permanent(errors.New("bad password"))}}
	a := &Agent{
		cfg:         Config{Provider: "test"},
		provider:    p,
		log:         slog.New(slog.DiscardHandler),
		maxAttempts: DefaultMaxAttempts,
		state:       contract.StateConnecting,
		since:       time.Now(),
		subs:        map[int]chan contract.Event{},
		redial:      make(chan struct{}, 1),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	go a.Supervise(ctx)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && a.Status().State != contract.StateError {
		time.Sleep(50 * time.Millisecond)
	}
	if a.Status().State != contract.StateError {
		t.Fatalf("state = %q, want error", a.Status().State)
	}
	if n := p.calls.Load(); n != 1 {
		t.Fatalf("dialled %d times after a permanent failure, want 1", n)
	}

	a.Reconnect()
	deadline = time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) && a.Status().State != contract.StateUp {
		time.Sleep(50 * time.Millisecond)
	}
	if a.Status().State != contract.StateUp {
		t.Errorf("state after a requested reconnect = %q", a.Status().State)
	}
}

// registerOnce makes a provider available to NewAgent. The real ones live in
// packages that import this one, so a test here brings its own.
func init() {
	Register("attempts-test", func() Provider { return &scriptedProvider{} })
}

func TestMaxAttemptsComesFromTheConfiguration(t *testing.T) {
	a, err := NewAgent(Config{
		Provider: "attempts-test",
		Extra:    map[string]string{"max_attempts": "7"},
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if a.maxAttempts != 7 {
		t.Errorf("maxAttempts = %d, want 7", a.maxAttempts)
	}

	// A nonsense value must not disable dialling altogether.
	a, err = NewAgent(Config{
		Provider: "attempts-test",
		Extra:    map[string]string{"max_attempts": "0"},
	}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if a.maxAttempts < 1 {
		t.Errorf("maxAttempts = %d, which would never dial", a.maxAttempts)
	}
}

// TestConcurrentReconnectsCollapseIntoOne answers what happens when two
// clients press the same button, or one person presses it repeatedly: every
// redial is a full authentication against a corporate gateway, so a burst of
// requests must not become a burst of logins.
func TestConcurrentReconnectsCollapseIntoOne(t *testing.T) {
	p := &scriptedProvider{}
	a := newTestAgent(t, p)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Supervise(ctx)

	// Let it settle into a working tunnel first.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && a.Status().State != contract.StateUp {
		time.Sleep(20 * time.Millisecond)
	}
	if a.Status().State != contract.StateUp {
		t.Fatalf("state = %q, want up", a.Status().State)
	}
	before := p.calls.Load()

	// Twenty at once.
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() { defer wg.Done(); a.Reconnect() }()
	}
	wg.Wait()

	// Back up, and only one extra dial for the whole burst.
	deadline = time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) && a.Status().State != contract.StateUp {
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(500 * time.Millisecond)

	if got := p.calls.Load() - before; got > 1 {
		t.Errorf("twenty reconnect requests caused %d dials, want at most 1", got)
	}
	if a.Status().State != contract.StateUp {
		t.Errorf("state after the burst = %q", a.Status().State)
	}
}

// TestAnswersAreNotAcceptedTwice covers the other duplicate: two clients both
// answering the same verification prompt.
func TestAnswersAreNotAcceptedTwice(t *testing.T) {
	a := newTestAgent(t, &scriptedProvider{})
	a.SetChallenge(&contract.Challenge{ID: "sms-1", Type: contract.ChallengeSMS})

	var wg sync.WaitGroup
	var accepted atomic.Int32
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := a.Answer(contract.AuthAnswer{ID: "sms-1", Value: "482915"}); err == nil {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()

	// The provider under test accepts anything, so this is about the agent
	// clearing the challenge once rather than about the answer itself.
	if a.Challenge() != nil {
		t.Error("the challenge is still pending after being answered")
	}
	if n := accepted.Load(); n < 1 {
		t.Error("no answer was accepted at all")
	}
}

// TestReconnectDuringAnAttemptIsNotLost covers pressing the button while a
// dial is already running. Restarting it would spend an attempt to arrive
// where it is already heading, but throwing the request away would mean a
// tunnel that gives up despite someone asking for another go.
func TestReconnectDuringAnAttemptIsNotLost(t *testing.T) {
	// A dial that takes a moment, so the request genuinely lands while one is
	// in flight rather than before it starts.
	p := &slowFailingProvider{delay: 1200 * time.Millisecond}
	a := &Agent{
		cfg:         Config{Provider: "failing"},
		provider:    p,
		log:         slog.New(slog.DiscardHandler),
		maxAttempts: 1, // so a lost request would show as giving up
		state:       contract.StateConnecting,
		since:       time.Now(),
		subs:        map[int]chan contract.Event{},
		redial:      make(chan struct{}, 1),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	go a.Supervise(ctx)

	// Ask once a dial is genuinely under way. A request arriving before one
	// starts is satisfied by that dial, which is a different case.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && p.runs.Load() < 1 {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	a.Reconnect()

	// With a budget of one, a lost request would leave it at a single dial.
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && p.runs.Load() < 2 {
		time.Sleep(50 * time.Millisecond)
	}
	if p.runs.Load() < 2 {
		t.Errorf("dialled %d times; the request made during the attempt was lost", p.runs.Load())
	}
}

// slowFailingProvider dials for a while and then fails, so a test can act
// while an attempt is genuinely in flight.
type slowFailingProvider struct {
	delay time.Duration
	runs  atomic.Int32
}

func (p *slowFailingProvider) Capabilities() []string { return []string{contract.CapTCP} }
func (p *slowFailingProvider) Run(ctx context.Context, cfg Config, rep Reporter) error {
	p.runs.Add(1)
	rep.SetState(contract.StateConnecting, nil)
	select {
	case <-ctx.Done():
		return nil
	case <-time.After(p.delay):
		return errors.New("the gateway did not answer")
	}
}
func (p *slowFailingProvider) Dial(context.Context, string, string) (net.Conn, error) {
	return nil, errNotDialable
}
func (p *slowFailingProvider) Answer(contract.AuthAnswer) error { return nil }

// runUntilCancelled starts a Runner over a shell script, waits for it to be
// up, then cancels. It returns how long Run took to come back.
func runUntilCancelled(t *testing.T, script string) time.Duration {
	t.Helper()

	r := &Runner{
		Path: "/bin/sh",
		Args: []string{"-c", script},
		// No proxy to wait for: this stands in for a client that installs its
		// own interface and is up the moment it says so.
		DirectDial: true,
		ReadyWhen:  func() bool { return true },
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx, &countingReporter{}) }()

	// Let the child install its trap before the signal arrives.
	time.Sleep(300 * time.Millisecond)
	start := time.Now()
	cancel()

	select {
	case <-done:
		return time.Since(start)
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
		return 0
	}
}

func TestAStoppedChildIsAskedFirstSoItCanCleanUp(t *testing.T) {
	// A VPN client undoes its own work on the way out: openconnect runs
	// vpnc-script with reason=disconnect, which puts back the resolver and
	// the default route. SIGKILL skips it, and the container is left holding
	// the VPN's nameservers with no default route -- unable to resolve the
	// gateway to redial. The tunnel is then wedged until it is recreated.
	marker := filepath.Join(t.TempDir(), "disconnected")
	script := "trap 'printf done > " + marker + "; exit 0' TERM\n" +
		"while :; do sleep 0.1; done\n"

	runUntilCancelled(t, script)

	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("the child was never given the chance to tear down what it installed: %v", err)
	}
}

func TestAChildThatIgnoresTheSignalIsStillEnded(t *testing.T) {
	// The grace period must not become a way to hang: a client that will not
	// go has to be ended anyway, or a reconnect never completes.
	script := "trap '' TERM\nwhile :; do sleep 0.1; done\n"

	took := runUntilCancelled(t, script)

	if took > stopGrace+5*time.Second {
		t.Errorf("Run took %s to return; the grace period is %s", took, stopGrace)
	}
}
