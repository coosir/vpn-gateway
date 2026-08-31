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
	"github.com/vpn-gateway/vpn-gateway/internal/server/users"
	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

type contextKey string

const userContextKey contextKey = "username"

// Server exposes the control API.
type Server struct {
	mgr      *tunnel.Manager
	log      *slog.Logger
	token    string
	usersMgr *users.Manager
}

// New builds the API server.
func New(mgr *tunnel.Manager, token string, usersMgr *users.Manager, log *slog.Logger) *Server {
	return &Server{mgr: mgr, log: log, token: token, usersMgr: usersMgr}
}

// LoginRequest is the body for POST /api/v1/auth/login.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse is the reply for POST /api/v1/auth/login.
type LoginResponse struct {
	OK       bool   `json:"ok"`
	Username string `json:"username,omitempty"`
	Token    string `json:"token,omitempty"`
	Error    string `json:"error,omitempty"`
}

// Handler returns the routed, authenticated handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Health is deliberately unauthenticated so a reverse proxy or the
	// systemd unit can probe it. It reveals nothing.
	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":            true,
			"contract":      contract.Version,
			"requires_auth": true,
		})
	})

	// Login is unauthenticated so a client can verify credentials and obtain a session token.
	mux.HandleFunc("POST /api/v1/auth/login", s.postLogin)
	mux.HandleFunc("POST /api/v1/login", s.postLogin)

	// User management endpoints (Admin only)
	mux.HandleFunc("GET /api/v1/users", s.adminAuth(s.listUsers))
	mux.HandleFunc("POST /api/v1/users", s.adminAuth(s.postUser))
	mux.HandleFunc("PUT /api/v1/users/{username}", s.adminAuth(s.putUser))
	mux.HandleFunc("DELETE /api/v1/users/{username}", s.adminAuth(s.deleteUser))

	// Client endpoints (Authenticated user or Admin)
	mux.HandleFunc("GET /api/v1/tunnels", s.auth(s.listTunnels))
	mux.HandleFunc("GET /api/v1/events", s.auth(s.streamEvents))
	mux.HandleFunc("GET /api/v1/tunnels/{name}", s.auth(s.getTunnel))
	mux.HandleFunc("GET /api/v1/tunnels/{name}/logs", s.auth(s.getLogs))
	mux.HandleFunc("GET /api/v1/tunnels/{name}/challenge", s.auth(s.getChallenge))
	mux.HandleFunc("POST /api/v1/tunnels/{name}/auth", s.auth(s.postAuth))
	mux.HandleFunc("POST /api/v1/tunnels/{name}/start", s.auth(s.postStart))
	mux.HandleFunc("POST /api/v1/tunnels/{name}/stop", s.auth(s.postStop))
	mux.HandleFunc("POST /api/v1/tunnels/{name}/reconnect", s.auth(s.postReconnect))

	return mux
}

func (s *Server) postLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request: "+err.Error())
		return
	}

	if s.usersMgr == nil {
		writeJSON(w, http.StatusUnauthorized, LoginResponse{
			OK:    false,
			Error: "user authentication required but user manager not initialized",
		})
		return
	}

	token, err := s.usersMgr.Authenticate(req.Username, req.Password)
	if err != nil {
		s.log.Warn("user authentication failed", "username", req.Username, "error", err)
		writeJSON(w, http.StatusUnauthorized, LoginResponse{
			OK:    false,
			Error: "invalid username or password",
		})
		return
	}

	s.log.Info("user authenticated successfully", "username", req.Username)
	writeJSON(w, http.StatusOK, LoginResponse{
		OK:       true,
		Username: req.Username,
		Token:    token,
	})
}

// adminAuth requires the admin API token.
func (s *Server) adminAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if ok && subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) == 1 {
			next(w, r)
			return
		}
		writeErr(w, http.StatusUnauthorized, "admin authorization required")
	}
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Admin API token
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if ok && subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) == 1 {
			next(w, r)
			return
		}

		// 2. User session token
		if ok && s.usersMgr != nil {
			if username, valid := s.usersMgr.Validate(got); valid {
				r = r.WithContext(context.WithValue(r.Context(), userContextKey, username))
				next(w, r)
				return
			}
		}

		// 3. Basic Auth
		if s.usersMgr != nil {
			username, password, ok := r.BasicAuth()
			if ok {
				if _, err := s.usersMgr.Authenticate(username, password); err == nil {
					r = r.WithContext(context.WithValue(r.Context(), userContextKey, username))
					next(w, r)
					return
				}
			}
		}

		writeErr(w, http.StatusUnauthorized, "invalid or missing authorization")
	}
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	if s.usersMgr == nil {
		writeJSON(w, http.StatusOK, []users.UserSummary{})
		return
	}
	writeJSON(w, http.StatusOK, s.usersMgr.List())
}

func (s *Server) postUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request: "+err.Error())
		return
	}
	if s.usersMgr == nil {
		writeErr(w, http.StatusInternalServerError, "user manager not available")
		return
	}
	if err := s.usersMgr.Add(req.Username, req.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "username": req.Username})
}

func (s *Server) putUser(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request: "+err.Error())
		return
	}
	if s.usersMgr == nil {
		writeErr(w, http.StatusInternalServerError, "user manager not available")
		return
	}
	if err := s.usersMgr.UpdatePassword(username, req.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": username})
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	if s.usersMgr == nil {
		writeErr(w, http.StatusInternalServerError, "user manager not available")
		return
	}
	if err := s.usersMgr.Delete(username); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": username})
}

func (s *Server) listTunnels(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.mgr.Snapshots())
}

// streamEvents pushes tunnel state changes to a client as server-sent
// events. It is how an interactive authentication prompt reaches the person
// who has to answer it without them watching for it.
func (s *Server) streamEvents(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	username, _ := r.Context().Value(userContextKey).(string)
	if username != "" && s.usersMgr != nil {
		unreg := s.usersMgr.RegisterCancel(username, cancel)
		defer unreg()
	}

	events, release := s.mgr.Subscribe()
	defer release()

	// Send the current state first, so a client that connects late does not
	// also have to poll to learn where things stand -- including a challenge
	// that was raised before it arrived.
	now := time.Now()
	for _, snap := range s.mgr.Snapshots() {
		if !writeEvent(w, rc, tunnel.Event{At: now, Tunnel: snap}) {
			return
		}
	}

	// Comment-only keepalives stop an intermediary from reaping a stream
	// that is idle because nothing is changing, which is the normal case.
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
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

func writeEvent(w http.ResponseWriter, rc *http.ResponseController, ev tunnel.Event) bool {
	b, err := json.Marshal(ev)
	if err != nil {
		return false
	}
	if _, err := w.Write([]byte("data: " + string(b) + "\n\n")); err != nil {
		return false
	}
	return rc.Flush() == nil
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

// postStart asks a tunnel to dial. Tunnels wait to be asked rather than
// dialling on their own: every attempt authenticates against a corporate
// gateway, and a server reconnecting on its own schedule can lock an account
// while nobody is watching.
func (s *Server) postStart(w http.ResponseWriter, r *http.Request) {
	if err := s.mgr.Start(r.PathValue("name")); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.log.Info("tunnel asked to dial", "tunnel", r.PathValue("name"))
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) postStop(w http.ResponseWriter, r *http.Request) {
	if err := s.mgr.Stop(r.PathValue("name")); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.log.Info("tunnel asked to stop", "tunnel", r.PathValue("name"))
	w.WriteHeader(http.StatusAccepted)
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
