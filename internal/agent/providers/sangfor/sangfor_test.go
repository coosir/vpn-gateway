package sangfor

import (
	"testing"

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
