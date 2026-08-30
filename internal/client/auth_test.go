package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

// scriptedPrompter answers challenges from a queue and records what it saw.
type scriptedPrompter struct {
	mu      sync.Mutex
	answers []string
	asked   []contract.Challenge
	notes   []string
	fail    error
	done    chan struct{}
	once    sync.Once
}

func newScriptedPrompter(answers ...string) *scriptedPrompter {
	return &scriptedPrompter{answers: answers, done: make(chan struct{})}
}

func (p *scriptedPrompter) Ask(ctx context.Context, tunnel string, ch contract.Challenge) (string, error) {
	p.mu.Lock()
	p.asked = append(p.asked, ch)
	if p.fail != nil {
		err := p.fail
		p.mu.Unlock()
		return "", err
	}
	var answer string
	if len(p.answers) > 0 {
		answer = p.answers[0]
		p.answers = p.answers[1:]
	}
	p.mu.Unlock()
	return answer, nil
}

func (p *scriptedPrompter) Notify(format string, args ...any) {
	p.mu.Lock()
	p.notes = append(p.notes, format)
	p.mu.Unlock()
	if strings.Contains(format, "accepted") {
		p.once.Do(func() { close(p.done) })
	}
}

func (p *scriptedPrompter) seen() []contract.Challenge {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]contract.Challenge(nil), p.asked...)
}

// challengeServer stands in for a vpn-gateway server that has one tunnel
// waiting on a verification code.
type challengeServer struct {
	*httptest.Server
	mu       sync.Mutex
	answered []contract.AuthAnswer
	reject   bool
}

func newChallengeServer(t *testing.T, snapshots ...Snapshot) *challengeServer {
	t.Helper()
	cs := &challengeServer{}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		for _, snap := range snapshots {
			b, _ := json.Marshal(Event{At: time.Now(), Tunnel: snap})
			w.Write([]byte("data: " + string(b) + "\n\n"))
			rc.Flush()
		}
		<-r.Context().Done()
	})

	mux.HandleFunc("POST /api/v1/tunnels/{name}/auth", func(w http.ResponseWriter, r *http.Request) {
		var ans contract.AuthAnswer
		json.NewDecoder(r.Body).Decode(&ans)
		cs.mu.Lock()
		cs.answered = append(cs.answered, ans)
		reject := cs.reject
		cs.mu.Unlock()
		if reject {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(contract.APIError{Message: "challenge is no longer pending"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	cs.Server = httptest.NewServer(mux)
	t.Cleanup(cs.Close)
	return cs
}

func (cs *challengeServer) submitted() []contract.AuthAnswer {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return append([]contract.AuthAnswer(nil), cs.answered...)
}

func challengeSnapshot(name string, ch *contract.Challenge) Snapshot {
	return Snapshot{
		Name:      name,
		Reachable: true,
		Status:    contract.Status{State: contract.StateAuthRequired},
		Challenge: ch,
	}
}

func TestChallengeIsAnsweredFromTheEventStream(t *testing.T) {
	ch := &contract.Challenge{ID: "sms-1", Type: contract.ChallengeSMS, Prompt: "Enter the code"}
	srv := newChallengeServer(t, challengeSnapshot("corp", ch))
	p := newScriptedPrompter("482915")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go WatchChallenges(ctx, NewAPI(srv.URL, "tok"), p)

	select {
	case <-p.done:
	case <-ctx.Done():
		t.Fatal("the challenge was never answered")
	}

	got := srv.submitted()
	if len(got) != 1 {
		t.Fatalf("submitted %d answers, want 1", len(got))
	}
	if got[0].ID != "sms-1" || got[0].Value != "482915" {
		t.Errorf("submitted %+v", got[0])
	}
	if seen := p.seen(); len(seen) != 1 || seen[0].Type != contract.ChallengeSMS {
		t.Errorf("prompter saw %+v", seen)
	}
}

func TestTheSameChallengeIsNotAskedTwice(t *testing.T) {
	// The stream repeats the current state on reconnect and on any unrelated
	// change, so a client that asked on every event would pester the person
	// with a question they already answered.
	ch := &contract.Challenge{ID: "sms-1", Type: contract.ChallengeSMS}
	snap := challengeSnapshot("corp", ch)
	srv := newChallengeServer(t, snap, snap, snap)
	p := newScriptedPrompter("482915", "000000", "111111")

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	go WatchChallenges(ctx, NewAPI(srv.URL, "tok"), p)

	select {
	case <-p.done:
	case <-ctx.Done():
		t.Fatal("the challenge was never answered")
	}
	time.Sleep(500 * time.Millisecond)

	if n := len(p.seen()); n != 1 {
		t.Errorf("the person was asked %d times, want 1", n)
	}
}

func TestARejectedAnswerCanBeRetried(t *testing.T) {
	// A code that arrives too late must not leave the tunnel stuck with no
	// way to ask again.
	ch := &contract.Challenge{ID: "sms-1", Type: contract.ChallengeSMS}
	snap := challengeSnapshot("corp", ch)
	srv := newChallengeServer(t, snap, snap)
	srv.mu.Lock()
	srv.reject = true
	srv.mu.Unlock()

	p := newScriptedPrompter("482915", "999999")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go WatchChallenges(ctx, NewAPI(srv.URL, "tok"), p)

	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if len(p.seen()) >= 2 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("after a rejected answer the person was asked %d times, want at least 2", len(p.seen()))
}

func TestAbandonedChallengeIsAskedAgain(t *testing.T) {
	ch := &contract.Challenge{ID: "sms-1", Type: contract.ChallengeSMS}
	snap := challengeSnapshot("corp", ch)
	srv := newChallengeServer(t, snap, snap)
	p := newScriptedPrompter()
	p.fail = errors.New("nobody is at the keyboard")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go WatchChallenges(ctx, NewAPI(srv.URL, "tok"), p)

	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if len(p.seen()) >= 2 {
			if n := len(srv.submitted()); n != 0 {
				t.Errorf("an abandoned challenge submitted %d answers, want 0", n)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("an abandoned challenge was asked %d times, want at least 2", len(p.seen()))
}

func TestNoChallengeMeansNoPrompt(t *testing.T) {
	srv := newChallengeServer(t, Snapshot{
		Name: "office", Reachable: true,
		Status: contract.Status{State: contract.StateUp},
	})
	p := newScriptedPrompter("unused")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	WatchChallenges(ctx, NewAPI(srv.URL, "tok"), p)

	if n := len(p.seen()); n != 0 {
		t.Errorf("a healthy tunnel produced %d prompts", n)
	}
}

func TestTerminalPrompterShowsWhatIsNeeded(t *testing.T) {
	var out strings.Builder
	p := &TerminalPrompter{In: strings.NewReader("https://sso.example.com/cb?code=1\n"), Out: &out}

	got, err := p.Ask(context.Background(), "corp", contract.Challenge{
		Type:      contract.ChallengeURL,
		Prompt:    "Sign in and paste the address",
		URL:       "https://sso.example.com/login",
		ExpiresAt: time.Now().Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://sso.example.com/cb?code=1" {
		t.Errorf("answer = %q", got)
	}
	text := out.String()
	for _, want := range []string{"corp", "sign-on address", "https://sso.example.com/login", "Expires in"} {
		if !strings.Contains(text, want) {
			t.Errorf("the prompt does not mention %q:\n%s", want, text)
		}
	}
}

func TestTerminalPrompterRejectsAnEmptyAnswer(t *testing.T) {
	var out strings.Builder
	p := &TerminalPrompter{In: strings.NewReader("\n"), Out: &out}
	if _, err := p.Ask(context.Background(), "corp", contract.Challenge{Type: contract.ChallengeSMS}); err == nil {
		t.Error("an empty answer was accepted")
	}
}
