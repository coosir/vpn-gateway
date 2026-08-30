package client

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
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

// WatchChallenges answers interactive authentication prompts as they arrive,
// until ctx is cancelled.
//
// Prompts are pushed rather than polled: a verification code is usually valid
// for a minute or two, so the person has to hear about it immediately rather
// than whenever a poll happens to come round.
func WatchChallenges(ctx context.Context, api *API, p Prompter) error {
	// answered records the challenge ids already dealt with, so a repeated
	// snapshot does not ask the same question twice.
	answered := map[string]bool{}

	for {
		err := api.Events(ctx, func(ev Event) {
			handleChallengeEvent(ctx, api, p, ev, answered)
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

func handleChallengeEvent(ctx context.Context, api *API, p Prompter, ev Event, answered map[string]bool) {
	ch := ev.Tunnel.Challenge
	if ch == nil || ch.ID == "" {
		if ev.Tunnel.Up() {
			// Clear the record once the tunnel is up, so a later prompt for
			// the same tunnel is not mistaken for one already handled.
			for id := range answered {
				if strings.HasPrefix(id, ev.Tunnel.Name+"\x00") {
					delete(answered, id)
				}
			}
		}
		return
	}

	key := ev.Tunnel.Name + "\x00" + ch.ID
	if answered[key] {
		return
	}
	answered[key] = true

	value, err := p.Ask(ctx, ev.Tunnel.Name, *ch)
	if err != nil {
		p.Notify("tunnel %s: %v", ev.Tunnel.Name, err)
		delete(answered, key) // let it be asked again
		return
	}
	if err := api.Answer(ctx, ev.Tunnel.Name, contract.AuthAnswer{ID: ch.ID, Value: value}); err != nil {
		p.Notify("tunnel %s: the server rejected the answer: %v", ev.Tunnel.Name, err)
		delete(answered, key)
		return
	}
	p.Notify("tunnel %s: answer accepted", ev.Tunnel.Name)
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
