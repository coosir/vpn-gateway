package client

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

// Prompter asks a person to answer a challenge. The desktop client uses a
// terminal implementation; a graphical client will provide its own.
type Prompter interface {
	// Ask presents the challenge for tunnel and returns the answer. Returning
	// an error abandons this challenge; the tunnel will raise it again.
	Ask(ctx context.Context, tunnel string, ch contract.Challenge) (string, error)
	// Notify reports something worth telling the person, such as a tunnel
	// coming back up.
	Notify(format string, args ...any)
}

// authRetryDelay is how long to wait before reconnecting a dropped event
// stream.
const authRetryDelay = 3 * time.Second

// ErrPromptDeferred is what a Prompter returns when a person put the question
// aside rather than failing to answer it.
//
// The gateway is still waiting, so the tunnel is not going anywhere, but
// asking again is the opposite of what they said. It is distinct from an
// ordinary failure for exactly that reason: those are asked again.
var ErrPromptDeferred = errors.New("the question was put aside")

// WatchChallenges answers interactive authentication prompts as they arrive,
// until ctx is cancelled.
//
// Prompts are pushed rather than polled: a verification code is usually valid
// for a minute or two, so the person has to hear about it immediately rather
// than whenever a poll happens to come round.
func WatchChallenges(ctx context.Context, api *API, p Prompter) error {
	// The asker outlives a dropped stream, so a person part way through
	// typing a code is not asked the same thing again when it reconnects.
	a := newAsker()
	defer a.close()

	for {
		err := api.Events(ctx, func(ev Event) {
			a.handle(ctx, api, p, ev)
		})
		if ctx.Err() != nil {
			return ctx.Err()
		}
		p.Notify("lost the connection to the server (%v); retrying in %s", err, authRetryDelay)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(authRetryDelay):
		}
	}
}

// FollowChallenges answers challenges for whichever connection is current,
// rebinding whenever that connection is replaced, until ctx is cancelled.
//
// next reports the API of the running connection, or nil when nothing is
// connected, along with a channel closed when it is replaced. It must return
// the two together from one consistent read, and never a channel that is
// already closed: this rebinds as soon as that channel fires, so a stale one
// would spin. Session.CurrentAPI is the implementation that matters.
//
// WatchChallenges on its own is bound to one connection for its whole life,
// and a connection does not survive a disconnect: every Connect logs in for a
// session token of its own and Disconnect revokes the previous one. A watcher
// left on the old API retries a credential the server has already forgotten,
// so the next login prompt -- an SMS code, a captcha -- is raised to nobody
// and the only way to get one through is to restart the process.
func FollowChallenges(ctx context.Context, next func() (*API, <-chan struct{}), p Prompter) {
	for {
		if ctx.Err() != nil {
			return
		}
		api, replaced := next()
		if api == nil {
			// Nothing to watch yet: an interface can be open long before
			// anybody presses connect.
			select {
			case <-ctx.Done():
				return
			case <-replaced:
			}
			continue
		}

		bound, unbind := context.WithCancel(ctx)
		go func() {
			select {
			case <-replaced:
			case <-bound.Done():
			}
			unbind()
		}()
		// Returns only once this connection is no longer the current one, or
		// ctx is done; a dropped stream is retried inside.
		WatchChallenges(bound, api, p)
		unbind()
	}
}

// askRetryDelay is how long to wait before putting a question again that is
// still pending because nobody answered it or the answer was refused.
const askRetryDelay = time.Second

// asker puts the gateway's questions to a person, one at a time per tunnel.
//
// Asking happens on its own goroutine, never on the one reading the event
// stream. A prompt waits for a person, and a person may be away from the
// machine, at a phone, or have dismissed the box: putting that wait in the
// reader stops the client hearing anything else the server says, so the next
// tunnel to ask for a code raises it to nobody. That is the whole bug this
// shape exists to prevent.
type asker struct {
	mu sync.Mutex
	// open is the question being put right now, by tunnel. A tunnel has at
	// most one: the server's snapshot carries one challenge.
	open map[string]openAsk
	// answered records questions already settled, by tunnel and challenge id,
	// so a repeated snapshot does not ask the same thing twice.
	answered map[string]bool
	closed   bool
}

type openAsk struct {
	id     string
	cancel context.CancelFunc
}

func newAsker() *asker {
	return &asker{open: map[string]openAsk{}, answered: map[string]bool{}}
}

// close withdraws every outstanding question. Whoever was being asked is no
// longer being asked by this connection.
func (a *asker) close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	for name, ask := range a.open {
		ask.cancel()
		delete(a.open, name)
	}
}

// handle reacts to one tunnel's state. It never blocks.
func (a *asker) handle(ctx context.Context, api *API, p Prompter, ev Event) {
	name := ev.Tunnel.Name
	ch := ev.Tunnel.Challenge

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return
	}

	if ch == nil || ch.ID == "" {
		// The tunnel has stopped asking, so take the box away rather than
		// leaving a person typing a code into a question nobody is waiting
		// on any more.
		a.withdrawLocked(name)
		if ev.Tunnel.Up() {
			// Clear the record once the tunnel is up, so a later prompt for
			// the same tunnel is not mistaken for one already handled.
			for key := range a.answered {
				if strings.HasPrefix(key, name+"\x00") {
					delete(a.answered, key)
				}
			}
		}
		return
	}

	if cur, ok := a.open[name]; ok {
		if cur.id == ch.ID {
			return // already being asked
		}
		a.withdrawLocked(name) // the gateway is asking something else now
	}
	if a.answered[name+"\x00"+ch.ID] {
		return
	}

	askCtx, cancel := context.WithCancel(ctx)
	a.open[name] = openAsk{id: ch.ID, cancel: cancel}
	go a.ask(askCtx, api, p, name, *ch)
}

// withdrawLocked cancels the question outstanding for one tunnel.
func (a *asker) withdrawLocked(name string) {
	ask, ok := a.open[name]
	if !ok {
		return
	}
	ask.cancel()
	delete(a.open, name)
}

// ask puts one question until it is answered, withdrawn, or the connection
// goes away.
//
// It keeps asking because a challenge the person ignored or fumbled is still
// pending on the gateway, and the server has nothing new to publish about it:
// giving up after one attempt leaves the tunnel waiting on a question nobody
// will ever be asked again.
func (a *asker) ask(ctx context.Context, api *API, p Prompter, name string, ch contract.Challenge) {
	for {
		// A challenge whose window has closed cannot be answered: whatever
		// code it wanted is not the code the gateway will take now. Putting
		// it back on screen only asks somebody to type something that will be
		// refused, so this waits for the gateway to raise a new one instead.
		if expired(ch) {
			a.finish(name, ch.ID, true)
			return
		}

		value, err := p.Ask(ctx, name, ch)
		switch {
		case err != nil:
			if ctx.Err() != nil {
				a.finish(name, ch.ID, false)
				return
			}
			if errors.Is(err, ErrPromptDeferred) {
				// Settled as far as this connection is concerned: raising it
				// again is what the person just declined. A different
				// question -- a new challenge id -- still gets through.
				a.finish(name, ch.ID, true)
				return
			}
			p.Notify("tunnel %s: %v", name, err)
		default:
			if err := api.Answer(ctx, name, contract.AuthAnswer{ID: ch.ID, Value: value}); err != nil {
				if ctx.Err() != nil {
					a.finish(name, ch.ID, false)
					return
				}
				p.Notify("tunnel %s: the server rejected the answer: %v", name, err)
			} else {
				p.Notify("tunnel %s: answer accepted", name)
				a.finish(name, ch.ID, true)
				return
			}
		}

		select {
		case <-ctx.Done():
			a.finish(name, ch.ID, false)
			return
		case <-time.After(askRetryDelay):
		}
	}
}

// expired reports whether a challenge's own deadline has passed. A challenge
// that named no deadline never expires here; how long to wait for an answer
// is then the prompter's business.
func expired(ch contract.Challenge) bool {
	return !ch.ExpiresAt.IsZero() && !time.Now().Before(ch.ExpiresAt)
}

// finish releases a tunnel's slot. A question that was settled is remembered
// so a repeated snapshot does not raise it again; one that was withdrawn is
// not, because it was never answered.
func (a *asker) finish(name, id string, settled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if cur, ok := a.open[name]; ok && cur.id == id {
		delete(a.open, name)
	}
	if settled {
		a.answered[name+"\x00"+id] = true
	}
}

// TerminalPrompter asks on a terminal.
type TerminalPrompter struct {
	In  io.Reader
	Out io.Writer
}

// Ask prints the challenge and reads one line.
func (t *TerminalPrompter) Ask(ctx context.Context, tunnel string, ch contract.Challenge) (string, error) {
	fmt.Fprintf(t.Out, "\n%s needs authentication: %s\n", tunnel, describe(ch))
	if ch.Prompt != "" {
		fmt.Fprintf(t.Out, "  %s\n", ch.Prompt)
	}
	if ch.URL != "" {
		fmt.Fprintf(t.Out, "  Open: %s\n", ch.URL)
	}
	if ch.ImageB64 != "" {
		fmt.Fprintf(t.Out, "  (this gateway sent an image; a graphical client can display it)\n")
	}
	if !ch.ExpiresAt.IsZero() {
		if d := time.Until(ch.ExpiresAt); d > 0 {
			fmt.Fprintf(t.Out, "  Expires in %s\n", d.Round(time.Second))
		}
	}
	fmt.Fprintf(t.Out, "  > ")

	// Reading blocks, so cancellation is reported by whichever finishes
	// first; the read itself is abandoned with the process.
	type result struct {
		line string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		line, err := bufio.NewReader(t.In).ReadString('\n')
		done <- result{strings.TrimSpace(line), err}
	}()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case r := <-done:
		if r.err != nil && r.line == "" {
			return "", fmt.Errorf("read the answer: %w", r.err)
		}
		if r.line == "" {
			return "", errors.New("no answer given")
		}
		return r.line, nil
	}
}

// Notify prints a line.
func (t *TerminalPrompter) Notify(format string, args ...any) {
	fmt.Fprintf(t.Out, format+"\n", args...)
}

func describe(ch contract.Challenge) string {
	switch ch.Type {
	case contract.ChallengeSMS:
		return "a code sent by SMS"
	case contract.ChallengeTOTP:
		return "a code from your authenticator app"
	case contract.ChallengeCaptcha:
		return "the characters from an image"
	case contract.ChallengeURL:
		return "a sign-on address to visit"
	case contract.ChallengePassword:
		return "a password or token"
	case contract.ChallengeVNC:
		return "a graphical login, which needs a client that can show it"
	default:
		return string(ch.Type)
	}
}
