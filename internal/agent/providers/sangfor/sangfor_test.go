package sangfor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vpn-gateway/vpn-gateway/internal/agent"
	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

// recordingReporter keeps the last state the provider reported.
type recordingReporter struct {
	state contract.State
	err   error
}

func (r *recordingReporter) SetState(s contract.State, err error) { r.state, r.err = s, err }
func (r *recordingReporter) SetNetwork(contract.Network)          {}
func (r *recordingReporter) SetChallenge(*contract.Challenge)     {}
func (r *recordingReporter) Log(string, ...any)                   {}

// TestADroppedSessionIsNotMistakenForABadPassword covers the failure that took
// a working tunnel down for good. aTrust ages a session out and then refuses
// every connection through it with
//
//	tcp tunnel authentication failed (code 10000004): invalid SID
//
// The credential markers matched "authentication failed" inside that, latched
// the password as rejected, and the run was thereafter reported as permanently
// broken -- so the supervisor parked a tunnel whose login was perfectly good
// and waited for a person to press reconnect.
func TestADroppedSessionIsNotMistakenForABadPassword(t *testing.T) {
	p := &Provider{protocol: "atrust"}
	rep := &recordingReporter{}

	p.onLine("[SOCKS5] 2026/09/04 03:49:24 [E]: server: connect to 10.0.2.23:9999 "+
		"failed, tcp tunnel authentication failed (code 10000004): invalid SID", rep)

	if p.authFailed.Load() {
		t.Error("an expired session was recorded as rejected credentials, " +
			"which parks the tunnel instead of dialling again")
	}
	if rep.state != contract.StateError {
		t.Errorf("state is %q, want %q: the tunnel is not carrying traffic", rep.state, contract.StateError)
	}
}

func TestRejectedCredentialsAreStillRecognised(t *testing.T) {
	// The narrower matching must not lose the case it was there for: a wrong
	// password retried in a loop is what locks an account.
	for _, line := range []string{
		"Login failed: invalid username or password",
		"认证失败：用户名或密码错误",
	} {
		p := &Provider{protocol: "atrust"}
		rep := &recordingReporter{}
		p.onLine(line, rep)
		if !p.authFailed.Load() {
			t.Errorf("rejected credentials went unnoticed in %q", line)
		}
		if rep.state != contract.StateError {
			t.Errorf("state is %q for %q, want %q", rep.state, line, contract.StateError)
		}
	}
}

func TestOrdinaryOutputChangesNothing(t *testing.T) {
	p := &Provider{protocol: "atrust"}
	rep := &recordingReporter{}
	p.onLine("Best node in group 162a5d3c: zt.example.com:441 with quality score 78 ms", rep)
	if p.authFailed.Load() || rep.state != "" {
		t.Errorf("a routine log line was treated as a failure: state=%q", rep.state)
	}
}

func TestKeepAliveURLReachesTheClient(t *testing.T) {
	// The session token this refreshes is the one thing the agent's own
	// keepalive cannot touch, so a setting that quietly failed to reach the
	// client would look exactly like the bug it fixes: a tunnel that dies
	// every forty minutes for no visible reason.
	cfg := agent.Config{Extra: map[string]string{
		"keep_alive_url": "http://10.0.2.24:8100",
		"totp_secret":    "SEED",
	}}
	args := optionArgs(cfg)

	var found bool
	for i, a := range args {
		if a == "--keep-alive-url" {
			if i+1 >= len(args) || args[i+1] != "http://10.0.2.24:8100" {
				t.Fatalf("--keep-alive-url was passed without its value: %v", args)
			}
			found = true
		}
	}
	if !found {
		t.Errorf("keep_alive_url did not reach the client: %v", args)
	}
}

func TestUnsetOptionsArePassedAtAll(t *testing.T) {
	// An empty setting must not become an empty flag: zju-connect would take
	// "--keep-alive-url" followed by the next flag as its value.
	if args := optionArgs(agent.Config{}); len(args) != 0 {
		t.Errorf("unset options produced %v, want nothing", args)
	}
}

// The password and the TOTP seed must never be on zju-connect's command line,
// where ps and docker top show them to anybody. They travel in its
// environment, which it reads as ZJU_CONNECT_<key>.
func TestSecretsStayOffTheCommandLine(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "seen")
	script := filepath.Join(dir, "zju-connect")
	// Stands in for the client: records what it was given, then exits.
	body := "#!/bin/sh\n" +
		"{ printf 'ARGS %s\\n' \"$*\"; printf 'PASSWORD %s\\n' \"$ZJU_CONNECT_PASSWORD\"; printf 'SEED %s\\n' \"$ZJU_CONNECT_TOTP_SECRET\"; } > " + out + "\n" +
		"exit 1\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := agent.Config{
		Server:   "vpn.corp.example",
		Username: "alice",
		Password: "hunter2-secret",
		Extra: map[string]string{
			"binary":      script,
			"totp_secret": "SEEDVALUE",
		},
	}
	p := &Provider{protocol: "easyconnect"}
	_ = p.Run(context.Background(), cfg, &recordingReporter{})

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("the stand-in client never ran: %v", err)
	}
	seen := string(raw)
	args := strings.SplitN(seen, "\n", 2)[0]
	for _, secret := range []string{"hunter2-secret", "SEEDVALUE", "--password", "--totp-secret"} {
		if strings.Contains(args, secret) {
			t.Errorf("%q is on the command line: %s", secret, args)
		}
	}
	if !strings.Contains(seen, "PASSWORD hunter2-secret") {
		t.Errorf("the password did not reach the client's environment:\n%s", seen)
	}
	if !strings.Contains(seen, "SEED SEEDVALUE") {
		t.Errorf("the TOTP seed did not reach the client's environment:\n%s", seen)
	}
}
