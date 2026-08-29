package agent

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

// ControlHandler builds the contract v1 control plane. This is the only
// interface the vpn-gateway server uses to learn a tunnel's state, uptime,
// pushed routes and pending auth prompts.
func (a *Agent) ControlHandler() http.Handler {
	mux := http.NewServeMux()
	auth := a.requireSecret

	mux.HandleFunc("GET "+contract.PathStatus, auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, a.Status())
	}))

	mux.HandleFunc("GET "+contract.PathNetwork, auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, a.Network())
	}))

	mux.HandleFunc("GET "+contract.PathChallenge, auth(func(w http.ResponseWriter, r *http.Request) {
		if ch := a.Challenge(); ch != nil {
			writeJSON(w, http.StatusOK, ch)
			return
		}
		// An absent challenge is the normal case, not an error: the client
		// distinguishes it by the empty id.
		writeJSON(w, http.StatusOK, contract.Challenge{})
	}))

	mux.HandleFunc("POST "+contract.PathAuth, auth(func(w http.ResponseWriter, r *http.Request) {
		var ans contract.AuthAnswer
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&ans); err != nil {
			writeErr(w, http.StatusBadRequest, "malformed answer: "+err.Error())
			return
		}
		if err := a.Answer(ans); err != nil {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	mux.HandleFunc("POST "+contract.PathReconnect, auth(func(w http.ResponseWriter, r *http.Request) {
		a.Reconnect()
		w.WriteHeader(http.StatusAccepted)
	}))

	mux.HandleFunc("GET "+contract.PathEvents, auth(a.serveEvents))

	return mux
}

// requireSecret rejects requests that do not carry the tunnel's shared
// secret. The control plane can expose corporate network topology and accept
// authentication answers, so it is not left open to sibling containers.
func (a *Agent) requireSecret(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.secret != "" {
			// CutPrefix returns the input unchanged when the prefix is
			// absent, so the ok result must be checked: without it a bare
			// secret with no scheme would be accepted.
			got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(a.secret)) != 1 {
				writeErr(w, http.StatusUnauthorized, "invalid or missing bearer token")
				return
			}
		}
		next(w, r)
	}
}

// serveEvents streams state changes as server-sent events. The first event is
// always the current status, so a subscriber that connects late does not have
// to also poll /v1/status to learn where things stand.
func (a *Agent) serveEvents(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	events, release := a.Subscribe()
	defer release()

	status := a.Status()
	if !writeEvent(w, rc, contract.Event{Type: contract.EventStatus, At: time.Now(), Status: &status}) {
		return
	}
	if n := a.Network(); len(n.Routes) > 0 || len(n.DNS) > 0 {
		if !writeEvent(w, rc, contract.Event{Type: contract.EventNetwork, At: time.Now(), Network: &n}) {
			return
		}
	}
	if ch := a.Challenge(); ch != nil {
		if !writeEvent(w, rc, contract.Event{Type: contract.EventChallenge, At: time.Now(), Challenge: ch}) {
			return
		}
	}

	// Comment-only keepalives stop intermediaries from reaping an idle
	// stream during a long stable connection.
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			if !writeEvent(w, rc, ev) {
				return
			}
		case <-ticker.C:
			if _, err := w.Write([]byte(": keepalive\n\n")); err != nil {
				return
			}
			if rc.Flush() != nil {
				return
			}
		}
	}
}

func writeEvent(w http.ResponseWriter, rc *http.ResponseController, ev contract.Event) bool {
	b, err := json.Marshal(ev)
	if err != nil {
		return false
	}
	if _, err := w.Write([]byte("data: " + string(b) + "\n\n")); err != nil {
		return false
	}
	return rc.Flush() == nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, contract.APIError{Message: msg})
}
