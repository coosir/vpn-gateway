package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

// reconnectServer accepts one token at a time, the way the real server does:
// every login mints a session token and logging out revokes the previous one.
// A stream holding a revoked token is refused.
type reconnectServer struct {
	*httptest.Server
	mu sync.Mutex
	// token is the only credential the server accepts, and revoke is closed
	// when it stops being one. The real server does both together: logging
	// out revokes the token and cancels every stream holding it.
	token  string
	revoke chan struct{}
	raise  chan struct{}
	asked  []contract.AuthAnswer
}

func newReconnectServer(t *testing.T, first string, snap Snapshot) *reconnectServer {
	t.Helper()
	rs := &reconnectServer{token: first, revoke: make(chan struct{}), raise: make(chan struct{})}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/events", func(w http.ResponseWriter, r *http.Request) {
		revoke, ok := rs.accept(r)
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		select {
		case <-rs.raise:
		case <-revoke:
			return
		case <-r.Context().Done():
			return
		}
		b, _ := json.Marshal(Event{At: time.Now(), Tunnel: snap})
		w.Write([]byte("data: " + string(b) + "\n\n"))
		rc.Flush()
		select {
		case <-revoke:
		case <-r.Context().Done():
		}
	})
	mux.HandleFunc("POST /api/v1/tunnels/{name}/auth", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := rs.accept(r); !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var ans contract.AuthAnswer
		json.NewDecoder(r.Body).Decode(&ans)
		rs.mu.Lock()
		rs.asked = append(rs.asked, ans)
		rs.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})

	rs.Server = httptest.NewServer(mux)
	t.Cleanup(rs.Close)
	return rs
}

// accept reports the request's revocation channel, or false when it carries a
// credential the server no longer honours.
func (rs *reconnectServer) accept(r *http.Request) (<-chan struct{}, bool) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+rs.token {
		return nil, false
	}
	return rs.revoke, true
}

// rotate revokes the current token, dropping the streams that hold it, and
// accepts a new one. That is what a disconnect followed by a reconnect does
// to the server's view of a client.
func (rs *reconnectServer) rotate(next string) {
	rs.mu.Lock()
	close(rs.revoke)
	rs.revoke = make(chan struct{})
	rs.token = next
	rs.mu.Unlock()
}

func (rs *reconnectServer) submitted() []contract.AuthAnswer {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return append([]contract.AuthAnswer(nil), rs.asked...)
}

// connect and disconnect drive a session's client without standing up a
// routing engine: what the watcher follows is the API of whatever client is
// installed, and how it got there does not change the question.
func connect(s *Session, url, token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setClient(&Client{api: NewAPI(url, token)}, func() {})
}

func disconnect(s *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setClient(nil, nil)
}

// A watcher bound to the first connection never sees anything again once that
// connection is replaced: its token is revoked and the connection that took
// over has one of its own. The symptom was a captcha or SMS prompt that only
// ever appeared on a freshly started process, because reinstalling the
// background service was the only thing that rebuilt the watcher.
func TestChallengeAfterAReconnectStillReachesThePerson(t *testing.T) {
	ch := &contract.Challenge{ID: "sms-1", Type: contract.ChallengeSMS, Prompt: "Enter the code"}
	srv := newReconnectServer(t, "tok1", challengeSnapshot("corp", ch))
	p := newScriptedPrompter("482915")

	// Driven from a real session, because the swap it announces is the part
	// that was missing.
	session := &Session{replaced: make(chan struct{})}
	connect(session, srv.URL, "tok1")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	go FollowChallenges(ctx, session.CurrentAPI, p)

	// Let the watcher settle on the first connection before it goes away.
	time.Sleep(200 * time.Millisecond)

	// Disconnect and connect again: the old token is revoked and the streams
	// holding it are dropped, and the new connection logs in for its own.
	disconnect(session)
	srv.rotate("tok2")
	connect(session, srv.URL, "tok2")

	// Only now does the gateway ask for a code.
	time.Sleep(200 * time.Millisecond)
	close(srv.raise)

	select {
	case <-p.done:
	case <-ctx.Done():
		t.Fatal("a challenge raised after a reconnect never reached the person")
	}

	got := srv.submitted()
	if len(got) != 1 || got[0].ID != "sms-1" || got[0].Value != "482915" {
		t.Fatalf("submitted %+v, want one answer of sms-1/482915", got)
	}
}

// Nothing is connected when an interface first opens, so the watcher has to
// wait for a connection rather than give up or spin.
func TestFollowChallengesWaitsForTheFirstConnection(t *testing.T) {
	ch := &contract.Challenge{ID: "cap-1", Type: contract.ChallengeCaptcha}
	srv := newChallengeServer(t, challengeSnapshot("corp", ch))
	p := newScriptedPrompter("wm3k")

	session := &Session{replaced: make(chan struct{})}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go FollowChallenges(ctx, session.CurrentAPI, p)

	time.Sleep(200 * time.Millisecond)
	if n := len(p.seen()); n != 0 {
		t.Fatalf("asked %d times before anything was connected", n)
	}

	connect(session, srv.URL, "tok")

	select {
	case <-p.done:
	case <-ctx.Done():
		t.Fatal("the challenge was never answered after connecting")
	}
}

// The session is the real source FollowChallenges is driven from, so what it
// reports has to change as the connection does.
func TestSessionCurrentAPIAnnouncesTheSwap(t *testing.T) {
	s := &Session{replaced: make(chan struct{})}

	api, replaced := s.CurrentAPI()
	if api != nil {
		t.Fatal("an unconnected session reported an API")
	}
	select {
	case <-replaced:
		t.Fatal("an unconnected session already announced a change")
	default:
	}

	c := &Client{api: NewAPI("http://example.invalid", "tok1")}
	s.mu.Lock()
	s.setClient(c, func() {})
	s.mu.Unlock()

	select {
	case <-replaced:
	case <-time.After(time.Second):
		t.Fatal("connecting did not announce the change")
	}

	api, replaced = s.CurrentAPI()
	if api != c.api {
		t.Fatal("the session did not report the connected client's API")
	}

	s.mu.Lock()
	s.setClient(nil, nil)
	s.mu.Unlock()

	select {
	case <-replaced:
	case <-time.After(time.Second):
		t.Fatal("disconnecting did not announce the change")
	}
	if api, _ := s.CurrentAPI(); api != nil {
		t.Fatal("a disconnected session still reported an API")
	}
}
