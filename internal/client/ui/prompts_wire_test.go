package ui

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/client"
	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

func TestAChallengeWithNoDeadlineSaysNothingAboutOne(t *testing.T) {
	b, err := json.Marshal(PromptView{ID: "corp:sms-1"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "expires_at") {
		t.Errorf("a challenge with no deadline still carries one: %s", b)
	}
}

func TestARealDeadlineIsStillSent(t *testing.T) {
	when := time.Now().Add(90 * time.Second)
	b, err := json.Marshal(PromptView{ID: "corp:sms-1", ExpiresAt: when})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "expires_at") {
		t.Errorf("the deadline was dropped: %s", b)
	}
}

// Pressing "later" has to reach the queue, or the question keeps its slot
// until it expires and is raised all over again.
func TestPuttingAQuestionAsideReleasesIt(t *testing.T) {
	q := newPromptQueue()

	type result struct {
		value string
		err   error
	}
	done := make(chan result, 1)
	go func() {
		v, err := q.Ask(context.Background(), "corp",
			contract.Challenge{ID: "sms-1", Type: contract.ChallengeSMS})
		done <- result{v, err}
	}()

	waitUntil(t, func() bool { return len(q.pending()) == 1 })

	if err := q.defer_("corp:sms-1"); err != nil {
		t.Fatalf("putting it aside: %v", err)
	}

	select {
	case r := <-done:
		if !errors.Is(r.err, client.ErrPromptDeferred) {
			t.Fatalf("Ask returned %v, want it to say the question was put aside", r.err)
		}
		if r.value != "" {
			t.Errorf("an answer was invented: %q", r.value)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Ask kept its slot after the question was put aside")
	}

	waitUntil(t, func() bool { return len(q.pending()) == 0 })
}

// Nothing to put aside is worth saying so rather than pretending.
func TestPuttingAsideSomethingThatIsGoneIsRefused(t *testing.T) {
	q := newPromptQueue()
	if err := q.defer_("corp:gone"); err == nil {
		t.Error("putting aside a question nobody asked was accepted")
	}
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition never held")
}
