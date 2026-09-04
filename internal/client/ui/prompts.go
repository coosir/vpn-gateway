package ui

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/client"
	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

// promptQueue routes authentication challenges to the interface and carries
// the answers back.
//
// It implements client.Prompter, so the same watcher that drives the terminal
// prompt drives the interface: the client does not need to know which one is
// listening.
type promptQueue struct {
	mu      sync.Mutex
	waiting map[string]*waitingPrompt
	subs    map[chan struct{}]struct{}
}

type waitingPrompt struct {
	view   PromptView
	answer chan string
	// deferred is closed when a person puts the question aside. Ask gives up
	// its slot then, rather than holding it until the challenge expires and
	// then being raised all over again.
	deferred chan struct{}
	once     sync.Once
}

func newPromptQueue() *promptQueue {
	return &promptQueue{
		waiting: map[string]*waitingPrompt{},
		subs:    map[chan struct{}]struct{}{},
	}
}

// Ask publishes a challenge and blocks until the interface answers it, the
// challenge expires, or ctx is cancelled.
func (q *promptQueue) Ask(ctx context.Context, tunnel string, ch contract.Challenge) (string, error) {
	// The id is scoped to the tunnel: two tunnels can be waiting on codes at
	// the same time, and a gateway's ids are only unique to itself.
	id := tunnel + ":" + ch.ID

	p := &waitingPrompt{
		view: PromptView{
			ID: id, Tunnel: tunnel,
			Type: string(ch.Type), Prompt: ch.Prompt,
			URL: ch.URL, Image: ch.ImageB64, VNCPort: ch.VNCPort,
			ExpiresAt: ch.ExpiresAt,
		},
		answer:   make(chan string, 1),
		deferred: make(chan struct{}),
	}
	if p.view.Prompt == "" {
		p.view.Prompt = "The gateway is asking for a verification code."
	}

	q.mu.Lock()
	q.waiting[id] = p
	q.mu.Unlock()
	q.notify()

	defer func() {
		q.mu.Lock()
		delete(q.waiting, id)
		q.mu.Unlock()
		q.notify()
	}()

	// Without a deadline a challenge nobody answers would hold the watcher
	// forever, and the tunnel would never be asked about again.
	deadline := time.Until(ch.ExpiresAt)
	if ch.ExpiresAt.IsZero() || deadline <= 0 {
		deadline = 10 * time.Minute
	}
	timer := time.NewTimer(deadline)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-p.deferred:
		return "", client.ErrPromptDeferred
	case <-timer.C:
		return "", fmt.Errorf("nobody answered within %s", deadline.Round(time.Second))
	case value := <-p.answer:
		return value, nil
	}
}

// Notify is part of client.Prompter. The interface shows tunnel state
// directly, so there is nothing extra to display here.
func (q *promptQueue) Notify(format string, args ...any) {}

// answer delivers a person's response to whoever is waiting for it.
func (q *promptQueue) answer(id, value string) error {
	q.mu.Lock()
	p, ok := q.waiting[id]
	q.mu.Unlock()
	if !ok {
		return errors.New("that question is no longer waiting for an answer")
	}
	select {
	case p.answer <- value:
		return nil
	default:
		return errors.New("that question has already been answered")
	}
}

// defer_ puts a question aside without answering it.
//
// The gateway has not stopped waiting, and the tunnel stays where it is. What
// this releases is the box on screen: without it the question sits in the
// queue until it expires, and is then raised again -- which is how a person
// who pressed "later" ends up looking at the same prompt, expired, ten
// minutes on.
func (q *promptQueue) defer_(id string) error {
	q.mu.Lock()
	p, ok := q.waiting[id]
	q.mu.Unlock()
	if !ok {
		return errors.New("that question is no longer waiting for an answer")
	}
	p.once.Do(func() { close(p.deferred) })
	return nil
}

// pending lists the challenges the interface should show.
func (q *promptQueue) pending() []PromptView {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]PromptView, 0, len(q.waiting))
	for _, p := range q.waiting {
		out = append(out, p.view)
	}
	return out
}

func (q *promptQueue) subscribe() chan struct{} {
	ch := make(chan struct{}, 1)
	q.mu.Lock()
	q.subs[ch] = struct{}{}
	q.mu.Unlock()
	return ch
}

func (q *promptQueue) unsubscribe(ch chan struct{}) {
	q.mu.Lock()
	delete(q.subs, ch)
	q.mu.Unlock()
}

func (q *promptQueue) notify() {
	q.mu.Lock()
	defer q.mu.Unlock()
	for ch := range q.subs {
		select {
		case ch <- struct{}{}:
		default: // already has one queued; the payload is the whole state anyway
		}
	}
}
