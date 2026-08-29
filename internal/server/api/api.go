// Package api serves the vpn-gateway control API that clients poll to learn
// which tunnels exist, whether they are up, what routes and DNS they claim,
// and to answer interactive authentication prompts.
//
// This is the only interface between a client and the server's container
// fleet. Clients never talk to a container directly.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/server/tunnel"
	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

// Server exposes the control API.
type Server struct {
	mgr *tunnel.Manager
	log *slog.Logger
	// token authenticates clients. It is required: this API can reveal
	// corporate network topology and accept authentication answers.
	token string
}

// New builds the API server.
func New(mgr *tunnel.Manager, token string, log *slog.Logger) *Server {
	return &Server{mgr: mgr, log: log, token: token}
}

// Handler returns the routed, authenticated handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Health is deliberately unauthenticated so a reverse proxy or the
	// systemd unit can probe it. It reveals nothing.
	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "contract": contract.Version})
	})

	mux.HandleFunc("GET /api/v1/tunnels", s.auth(s.listTunnels))
	mux.HandleFunc("GET /api/v1/tunnels/{name}", s.auth(s.getTunnel))
	mux.HandleFunc("GET /api/v1/tunnels/{name}/logs", s.auth(s.getLogs))
	mux.HandleFunc("GET /api/v1/tunnels/{name}/challenge", s.auth(s.getChallenge))
	mux.HandleFunc("POST /api/v1/tunnels/{name}/auth", s.auth(s.postAuth))
	mux.HandleFunc("POST /api/v1/tunnels/{name}/reconnect", s.auth(s.postReconnect))

	return mux
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// CutPrefix returns the input unchanged when the prefix is absent, so
		// the ok result must be checked: without it a bare token with no
		// scheme would be accepted.
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
			writeErr(w, http.StatusUnauthorized, "invalid or missing bearer token")
			return
		}
		next(w, r)
	}
}

func (s *Server) listTunnels(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.mgr.Snapshots())
}

func (s *Server) getTunnel(w http.ResponseWriter, r *http.Request) {
	t, ok := s.mgr.Lookup(r.PathValue("name"))
	if !ok {
		writeErr(w, http.StatusNotFound, "no such tunnel")
		return
	}
	writeJSON(w, http.StatusOK, t.Snapshot())
}

func (s *Server) getLogs(w http.ResponseWriter, r *http.Request) {
	t, ok := s.mgr.Lookup(r.PathValue("name"))
	if !ok {
		writeErr(w, http.StatusNotFound, "no such tunnel")
		return
	}
	tail := 200
	if v := r.URL.Query().Get("tail"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 5000 {
			tail = n
		}
	}
	out, err := t.Logs(r.Context(), tail)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(out))
}

func (s *Server) getChallenge(w http.ResponseWriter, r *http.Request) {
	t, ok := s.mgr.Lookup(r.PathValue("name"))
	if !ok {
		writeErr(w, http.StatusNotFound, "no such tunnel")
		return
	}
	ch, err := t.Client().Challenge(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ch == nil {
		writeJSON(w, http.StatusOK, contract.Challenge{})
		return
	}
	writeJSON(w, http.StatusOK, ch)
}

// postAuth relays an authentication answer from the client GUI to the
// container. The answer is never logged.
func (s *Server) postAuth(w http.ResponseWriter, r *http.Request) {
	t, ok := s.mgr.Lookup(r.PathValue("name"))
	if !ok {
		writeErr(w, http.StatusNotFound, "no such tunnel")
		return
	}
	var ans contract.AuthAnswer
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&ans); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed answer: "+err.Error())
		return
	}
	if err := t.Client().Answer(r.Context(), ans); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	s.log.Info("relayed auth answer", "tunnel", t.Snapshot().Name)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) postReconnect(w http.ResponseWriter, r *http.Request) {
	t, ok := s.mgr.Lookup(r.PathValue("name"))
	if !ok {
		writeErr(w, http.StatusNotFound, "no such tunnel")
		return
	}
	if err := t.Client().Reconnect(r.Context()); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// Serve runs the API until ctx is cancelled.
func Serve(ctx context.Context, addr string, h http.Handler, log *slog.Logger) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutCtx)
	}()
	log.Info("control API listening", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, contract.APIError{Message: msg})
}
