package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
	"golang.org/x/net/proxy"
)

// Runner supervises an external VPN client that exposes its own SOCKS5 proxy
// on loopback inside the container, and adapts it to the Provider contract.
//
// Most providers are shaped this way: a reimplemented or vendor client does
// the protocol work and hands us a proxy; the agent's job is to watch it,
// translate its output into contract state, and re-export it with counters.
type Runner struct {
	// Path and Args are the child process command line. Secrets belong in
	// Env, not Args, so they stay out of the container's process list.
	Path string
	Args []string
	Env  []string

	// Upstream is the "host:port" the child's SOCKS5 listens on. It must be
	// loopback: only the agent may talk to it directly.
	//
	// With DirectDial set it is instead an address inside the tunnel, probed
	// to decide when the tunnel is carrying traffic.
	Upstream string

	// DirectDial makes Dial use the container's own routing rather than a
	// proxy the child serves.
	//
	// A vendor client installs its routes in this network namespace, so once
	// it has connected an ordinary dial already goes through the tunnel.
	// Running a forwarder to reach it would only add a hop.
	DirectDial bool

	// ReadyWhen reports whether the tunnel is carrying traffic. When nil the
	// runner waits for Upstream to accept a connection, which suits a child
	// that signals readiness by opening its proxy port. A vendor client
	// signals it by what it prints instead.
	ReadyWhen func() bool

	// OnLine inspects one line of child output. It is where a provider
	// recognises pushed routes and failures. It may be nil.
	OnLine func(line string, rep Reporter)

	// Prompts describe the interactive questions this child can ask. When one
	// matches, the runner raises a contract challenge and writes the answer
	// back to the child's standard input.
	Prompts []Prompt

	// ReadyTimeout bounds how long the child may take to start serving its
	// SOCKS5 port before the attempt is abandoned.
	ReadyTimeout time.Duration

	mu     sync.RWMutex
	dialer proxy.Dialer
	stdin  io.WriteCloser
	// pending is the challenge the child is currently blocked on.
	pending *contract.Challenge
	// recent holds the last few output lines, so a prompt can be described
	// with the context printed just before it -- a login URL, for instance.
	recent []string
}

// Prompt recognises one interactive question a supervised client can ask.
type Prompt struct {
	// Marker is matched case-insensitively against the child's output.
	Marker string
	Type   contract.ChallengeType
	// Describe builds the text shown to the person answering. recent holds
	// the preceding output lines, newest last.
	Describe func(line string, recent []string) contract.Challenge
}

// recentLines is how much context is kept for Describe.
const recentLines = 8

// DefaultReadyTimeout applies when Runner.ReadyTimeout is zero. Vendor
// clients with interactive login can be slow, so this is generous.
const DefaultReadyTimeout = 90 * time.Second

// Run starts the child, waits for its proxy to accept connections, reports
// StateUp, and blocks until the child exits or ctx is cancelled.
func (r *Runner) Run(ctx context.Context, rep Reporter) error {
	if r.Upstream == "" {
		return Permanent(errors.New("runner: Upstream is required"))
	}
	rep.SetState(contract.StateConnecting, nil)

	cmd := exec.CommandContext(ctx, r.Path, r.Args...)
	cmd.Env = append(os.Environ(), r.Env...)
	// Give the child its own process group so cancelling the context kills
	// any helper processes it spawned, not just the immediate child.
	cmd.Cancel = func() error { return cmd.Process.Kill() }
	cmd.WaitDelay = 5 * time.Second

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}
	// Interactive clients ask for verification codes on standard input, so
	// the pipe is opened whether or not this provider declares prompts.
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	r.mu.Lock()
	r.stdin = stdin
	r.pending = nil
	r.recent = nil
	r.mu.Unlock()

	if err := cmd.Start(); err != nil {
		// A missing binary is a broken image, not a transient fault.
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			return Permanent(fmt.Errorf("start %s: %w", r.Path, err))
		}
		return fmt.Errorf("start %s: %w", r.Path, err)
	}

	var scanWG sync.WaitGroup
	scanWG.Add(2)
	go func() { defer scanWG.Done(); r.scan(stdout, rep) }()
	go func() { defer scanWG.Done(); r.scan(stderr, rep) }()

	exited := make(chan error, 1)
	go func() {
		scanWG.Wait()
		exited <- cmd.Wait()
	}()

	ready := r.ReadyTimeout
	if ready == 0 {
		ready = DefaultReadyTimeout
	}
	if err := r.waitReady(ctx, ready, exited); err != nil {
		cmd.Cancel()
		<-exited
		return err
	}

	if !r.DirectDial {
		d, err := proxy.SOCKS5("tcp", r.Upstream, nil, proxy.Direct)
		if err != nil {
			return Permanent(fmt.Errorf("build upstream dialer: %w", err))
		}
		r.mu.Lock()
		r.dialer = d
		r.mu.Unlock()
	}

	// The child may already have reported a finer-grained state through
	// OnLine; SetState is idempotent for an unchanged state.
	rep.SetState(contract.StateUp, nil)

	select {
	case err := <-exited:
		r.mu.Lock()
		r.dialer = nil
		r.mu.Unlock()
		return childExitError(err)
	case <-ctx.Done():
		<-exited
		return nil
	}
}

// waitReady blocks until the child serves its proxy, exits, or stays silent
// for too long.
//
// The deadline is suspended while an interactive question is pending: a person
// fetching a code from their phone can easily take longer than any timeout
// worth setting for a stuck process, and killing the client mid-login would
// make the tunnel impossible to bring up at all.
func (r *Runner) waitReady(ctx context.Context, timeout time.Duration, exited <-chan error) error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	var dialer net.Dialer
	deadline := time.Now().Add(timeout)

	for {
		select {
		case err := <-exited:
			return childExitError(err)
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}

		if r.ReadyWhen != nil {
			if r.ReadyWhen() {
				return nil
			}
		} else {
			probeCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
			conn, err := dialer.DialContext(probeCtx, "tcp", r.Upstream)
			cancel()
			if err == nil {
				conn.Close()
				return nil
			}
		}

		if r.Pending() != nil {
			// Waiting on a human, not on a stuck process.
			deadline = time.Now().Add(timeout)
			continue
		}
		if time.Now().After(deadline) {
			if r.ReadyWhen != nil {
				return fmt.Errorf("%s did not report a working tunnel within %s", r.Path, timeout)
			}
			return fmt.Errorf("%s did not serve %s within %s", r.Path, r.Upstream, timeout)
		}
	}
}

// Dial opens a connection through the tunnel.
func (r *Runner) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if r.DirectDial {
		// The vendor client's routes are already in effect here.
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	r.mu.RLock()
	d := r.dialer
	r.mu.RUnlock()
	if d == nil {
		return nil, errors.New("upstream proxy is not ready")
	}
	if cd, ok := d.(proxy.ContextDialer); ok {
		return cd.DialContext(ctx, network, addr)
	}
	return d.Dial(network, addr)
}

func (r *Runner) scan(rc io.Reader, rep Reporter) {
	scanLines(rc, func(line string, complete bool) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			return
		}
		if complete {
			rep.Log("%s", trimmed)
			r.remember(trimmed)
			if r.OnLine != nil {
				r.OnLine(trimmed, rep)
			}
		}
		// A prompt is usually an unterminated fragment, so both kinds are
		// checked.
		r.checkPrompt(line, rep)
	})
}

func (r *Runner) remember(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recent = append(r.recent, line)
	if len(r.recent) > recentLines {
		r.recent = r.recent[len(r.recent)-recentLines:]
	}
}

// checkPrompt raises a challenge when the child asks an interactive question.
func (r *Runner) checkPrompt(line string, rep Reporter) {
	if len(r.Prompts) == 0 {
		return
	}
	lower := strings.ToLower(line)
	for _, p := range r.Prompts {
		if !strings.Contains(lower, strings.ToLower(p.Marker)) {
			continue
		}

		r.mu.Lock()
		if r.pending != nil {
			// Already waiting on this question; a repeated fragment must not
			// invalidate the id the client was given.
			r.mu.Unlock()
			return
		}
		recent := append([]string(nil), r.recent...)
		r.mu.Unlock()

		ch := contract.Challenge{Type: p.Type, Prompt: strings.TrimSpace(line)}
		if p.Describe != nil {
			ch = p.Describe(strings.TrimSpace(line), recent)
			if ch.Type == "" {
				ch.Type = p.Type
			}
		}
		ch.ID = fmt.Sprintf("%s-%d", p.Type, time.Now().UnixNano())
		if ch.ExpiresAt.IsZero() {
			ch.ExpiresAt = time.Now().Add(5 * time.Minute)
		}

		r.mu.Lock()
		r.pending = &ch
		r.mu.Unlock()

		rep.SetState(contract.StateAuthRequired, nil)
		rep.SetChallenge(&ch)
		return
	}
}

// Answer writes a challenge response to the child's standard input.
func (r *Runner) Answer(a contract.AuthAnswer) error {
	r.mu.Lock()
	pending, stdin := r.pending, r.stdin
	r.mu.Unlock()

	if pending == nil {
		return errors.New("no question is waiting for an answer")
	}
	if a.ID != pending.ID {
		return fmt.Errorf("challenge %q is no longer pending", a.ID)
	}
	if stdin == nil {
		return errors.New("the VPN client is not running")
	}
	// The child reads with a scan that stops at whitespace, so an answer must
	// be a single line and must be terminated.
	if strings.ContainsAny(a.Value, "\r\n") {
		return errors.New("an answer must not contain a newline")
	}
	if _, err := io.WriteString(stdin, a.Value+"\n"); err != nil {
		return fmt.Errorf("send the answer to the VPN client: %w", err)
	}

	r.mu.Lock()
	r.pending = nil
	r.mu.Unlock()
	return nil
}

// Pending reports the challenge the child is blocked on, if any.
func (r *Runner) Pending() *contract.Challenge {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.pending
}

func childExitError(err error) error {
	if err == nil {
		return errors.New("VPN client exited unexpectedly")
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return fmt.Errorf("VPN client exited with status %d", ee.ExitCode())
	}
	return fmt.Errorf("VPN client failed: %w", err)
}
