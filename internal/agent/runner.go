package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
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
	Upstream string

	// OnLine inspects one line of child output. It is where a provider
	// recognises authentication prompts, pushed routes and failures. It may
	// be nil.
	OnLine func(line string, rep Reporter)

	// ReadyTimeout bounds how long the child may take to start serving its
	// SOCKS5 port before the attempt is abandoned.
	ReadyTimeout time.Duration

	mu     sync.RWMutex
	dialer proxy.Dialer
}

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
	waitCtx, cancelWait := context.WithTimeout(ctx, ready)
	defer cancelWait()

	select {
	case err := <-exited:
		return childExitError(err)
	case err := <-waitForPort(waitCtx, r.Upstream):
		if err != nil {
			cmd.Cancel()
			<-exited
			return fmt.Errorf("%s did not serve %s within %s: %w", r.Path, r.Upstream, ready, err)
		}
	}

	d, err := proxy.SOCKS5("tcp", r.Upstream, nil, proxy.Direct)
	if err != nil {
		return Permanent(fmt.Errorf("build upstream dialer: %w", err))
	}
	r.mu.Lock()
	r.dialer = d
	r.mu.Unlock()

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

// Dial opens a connection through the child's proxy.
func (r *Runner) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
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
	sc := bufio.NewScanner(rc)
	sc.Buffer(make([]byte, 0, 4<<10), 256<<10)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		rep.Log("%s", line)
		if r.OnLine != nil {
			r.OnLine(line, rep)
		}
	}
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

// waitForPort polls addr until a TCP connection succeeds or ctx expires.
func waitForPort(ctx context.Context, addr string) <-chan error {
	out := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		var d net.Dialer
		for {
			c, err := d.DialContext(ctx, "tcp", addr)
			if err == nil {
				c.Close()
				out <- nil
				return
			}
			select {
			case <-ctx.Done():
				out <- ctx.Err()
				return
			case <-ticker.C:
			}
		}
	}()
	return out
}
