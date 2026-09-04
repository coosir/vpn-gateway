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
	"syscall"
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

	// StdinPrelude is written to the child as soon as it starts, one line
	// each. It carries answers that are known in advance, such as a password
	// a client insists on reading from standard input rather than taking as
	// an argument, which is where it would be visible in the process list.
	StdinPrelude []string

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
	// fatal carries an error raised from OnLine for a client that has stopped
	// carrying traffic without exiting. It belongs to one run and is replaced
	// at the start of the next.
	fatal chan error
}

// Prompt recognises one interactive question a supervised client can ask.
type Prompt struct {
	// Match reports whether this output is the question. complete says
	// whether the output was newline-terminated, which is what separates a
	// log line from a prompt left waiting on the same line.
	Match func(line string, complete bool) bool
	Type  contract.ChallengeType
	// Describe builds the challenge shown to the person answering. recent
	// holds the preceding output lines, newest last.
	Describe func(line string, recent []string) contract.Challenge
}

// Marker matches output containing s, case-insensitively. It suits a client
// whose questions are worded by the client itself.
func Marker(s string) func(line string, complete bool) bool {
	lower := strings.ToLower(s)
	return func(line string, _ bool) bool {
		return strings.Contains(strings.ToLower(line), lower)
	}
}

// GatewayQuestion matches an unterminated fragment that ends in a colon.
//
// Some clients relay a question worded by the gateway, so there is no phrase
// to look for. What can be relied on is the shape: a log line is always
// terminated, while a question leaves the cursor after its colon waiting for
// an answer.
func GatewayQuestion() func(line string, complete bool) bool {
	return func(line string, complete bool) bool {
		if complete {
			return false
		}
		return strings.HasSuffix(strings.TrimRight(line, " \t"), ":")
	}
}

// recentLines is how much context is kept for Describe.
const recentLines = 8

// DefaultReadyTimeout applies when Runner.ReadyTimeout is zero. Vendor
// clients with interactive login can be slow, so this is generous.
const DefaultReadyTimeout = 90 * time.Second

// stopGrace is how long a VPN client has to put back what it changed before
// it is ended outright.
const stopGrace = 5 * time.Second

// stopChild asks the child to stop and makes sure it goes.
//
// os/exec arranges this itself when the context is cancelled, through Cancel
// and WaitDelay. This is for the paths that stop a child for their own
// reasons: without the kill behind the signal, a client that ignores SIGTERM
// would leave Run waiting on an exit that never arrives.
func stopChild(p *os.Process, exited <-chan struct{}) {
	if exited == nil {
		// A child that has only just started has installed nothing worth
		// unwinding, and there is no exit here to wait for, so it gets no
		// grace it could not use.
		p.Kill()
		return
	}
	if err := p.Signal(syscall.SIGTERM); err != nil {
		// Already gone, or a platform that will not deliver it.
		p.Kill()
		return
	}
	select {
	case <-exited:
	case <-time.After(stopGrace):
		p.Kill()
	}
}

// Fail ends the current run with err, stopping the child.
//
// The supervisor only reacts to a child exiting, so a provider that
// recognises a dead tunnel in the output cannot get itself redialled by
// reporting a state alone: the client keeps running, Run keeps blocking on an
// exit that never comes, and the tunnel stays down until somebody notices.
// This ends the process instead, which is what a redial needs.
//
// Only the first call within a run has an effect. Later ones are dropped
// rather than queued: the child is already on its way out, and the first
// reason is the one worth reporting.
func (r *Runner) Fail(err error) {
	r.mu.RLock()
	ch := r.fatal
	r.mu.RUnlock()
	if ch == nil {
		return // no run in progress
	}
	select {
	case ch <- err:
	default:
	}
}

// Run starts the child, waits for its proxy to accept connections, reports
// StateUp, and blocks until the child exits or ctx is cancelled.
func (r *Runner) Run(ctx context.Context, rep Reporter) error {
	// Upstream is only needed when readiness is a port to connect to. A
	// client that installs its own interface reports readiness through
	// ReadyWhen and has no proxy to point at.
	if r.Upstream == "" && r.ReadyWhen == nil {
		return Permanent(errors.New("runner: set Upstream, or ReadyWhen for a client that has no proxy"))
	}
	if r.Upstream == "" && !r.DirectDial {
		return Permanent(errors.New("runner: without Upstream, DirectDial must be set: there is no proxy to dial through"))
	}
	rep.SetState(contract.StateConnecting, nil)

	cmd := exec.CommandContext(ctx, r.Path, r.Args...)
	cmd.Env = append(os.Environ(), r.Env...)
	// Ask the child to stop rather than ending it outright. A VPN client
	// undoes its own work on the way out: openconnect runs vpnc-script with
	// reason=disconnect, which puts back the resolver and the default route
	// it replaced. SIGKILL skips all of that, and what is left is a container
	// holding the VPN's own nameservers with no default route -- which then
	// cannot resolve the gateway to redial. The tunnel is wedged until the
	// container is recreated, and the only clue is "getaddrinfo failed for
	// host ...: Try again" from every attempt.
	//
	// WaitDelay is the other half: os/exec sends SIGKILL itself once it
	// elapses, so a client that ignores SIGTERM still goes.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = stopGrace

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
	fatal := make(chan error, 1)
	r.mu.Lock()
	r.stdin = stdin
	r.pending = nil
	r.recent = nil
	r.fatal = fatal
	r.mu.Unlock()

	if err := cmd.Start(); err != nil {
		stdin.Close()
		// A missing binary is a broken image, not a transient fault.
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			return Permanent(fmt.Errorf("start %s: %w", r.Path, err))
		}
		return fmt.Errorf("start %s: %w", r.Path, err)
	}

	for _, line := range r.StdinPrelude {
		if _, err := io.WriteString(stdin, line+"\n"); err != nil {
			stopChild(cmd.Process, nil)
			return fmt.Errorf("send the opening input to %s: %w", r.Path, err)
		}
	}

	var scanWG sync.WaitGroup
	scanWG.Add(2)
	go func() { defer scanWG.Done(); r.scan(stdout, rep) }()
	go func() { defer scanWG.Done(); r.scan(stderr, rep) }()

	// The exit is delivered by closing a channel rather than sending on one,
	// so it can be observed more than once. A single-value channel deadlocks
	// the moment two places both need to know the child is gone, and the
	// symptom is a tunnel wedged in "connecting" that never retries.
	exit := &childExit{done: make(chan struct{})}
	go func() {
		scanWG.Wait()
		exit.err = cmd.Wait()
		close(exit.done)
	}()

	ready := r.ReadyTimeout
	if ready == 0 {
		ready = DefaultReadyTimeout
	}
	if err := r.waitReady(ctx, ready, exit, fatal); err != nil {
		stopChild(cmd.Process, exit.done)
		<-exit.done
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
	case <-exit.done:
		r.mu.Lock()
		r.dialer = nil
		r.mu.Unlock()
		return childExitError(exit.err)
	case err := <-fatal:
		// The child is still running and still failing every connection, so
		// it has to go before the supervisor can dial a fresh one.
		stopChild(cmd.Process, exit.done)
		<-exit.done
		r.mu.Lock()
		r.dialer = nil
		r.mu.Unlock()
		return err
	case <-ctx.Done():
		<-exit.done
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
func (r *Runner) waitReady(ctx context.Context, timeout time.Duration, exit *childExit, fatal <-chan error) error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	var dialer net.Dialer
	deadline := time.Now().Add(timeout)

	for {
		select {
		case <-exit.done:
			return childExitError(exit.err)
		case err := <-fatal:
			return err
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

// promptSettle is how long an unterminated fragment must stand unchanged
// before it is treated as a question.
//
// A real prompt is followed by silence, because the child is blocked reading
// the answer. A read that happens to split a log line mid-way is followed
// immediately by the rest of it. Without this wait, output such as
// "...rec_layer_s3.c:698:" split at the wrong byte would stop the tunnel to
// ask a person about nothing.
const promptSettle = 400 * time.Millisecond

func (r *Runner) scan(rc io.Reader, rep Reporter) {
	var (
		mu      sync.Mutex
		pending *time.Timer
	)
	cancelPending := func() {
		mu.Lock()
		if pending != nil {
			pending.Stop()
			pending = nil
		}
		mu.Unlock()
	}
	defer cancelPending()

	scanLines(rc, func(line string, complete bool) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			return
		}
		if complete {
			// More output arrived, so whatever fragment was waiting was part
			// of a line rather than a question.
			cancelPending()
			rep.Log("%s", trimmed)
			r.remember(trimmed)
			if r.OnLine != nil {
				r.OnLine(trimmed, rep)
			}
			r.checkPrompt(line, true, rep)
			return
		}

		cancelPending()
		mu.Lock()
		pending = time.AfterFunc(promptSettle, func() { r.checkPrompt(line, false, rep) })
		mu.Unlock()
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
func (r *Runner) checkPrompt(line string, complete bool, rep Reporter) {
	if len(r.Prompts) == 0 {
		return
	}
	for _, p := range r.Prompts {
		if p.Match == nil || !p.Match(line, complete) {
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

// childExit carries the child's exit status to everything watching for it.
type childExit struct {
	done chan struct{}
	err  error
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
