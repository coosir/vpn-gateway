// Package ui serves the local interface for the vpn-gateway client.
//
// It listens on loopback only and requires a token. Loopback alone is not
// enough: this interface can reroute traffic, read tunnel state and answer
// authentication prompts, so any other process on the machine must not be
// able to drive it just by connecting.
package ui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/client"
	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

//go:embed assets
var assets embed.FS

// Controller is what the interface can do to the running client.
type Controller interface {
	Tunnels() []client.TunnelState
	Settings() *client.Config
	Config() ([]byte, error)
	API() *client.API
	Reload(ctx context.Context, cfg *client.Config) error
}

// Server serves the interface.
type Server struct {
	ctl        Controller
	configPath string
	token      string
	log        *slog.Logger

	// prompts receives challenges the interface should show, and returns the
	// answers a person gives it.
	prompts *promptQueue
}

// New builds the interface server. configPath is where rule changes are
// written back.
func New(ctl Controller, configPath, token string, log *slog.Logger) *Server {
	return &Server{
		ctl:        ctl,
		configPath: configPath,
		token:      token,
		log:        log,
		prompts:    newPromptQueue(),
	}
}

// Prompter returns the client.Prompter that routes challenges to the
// interface instead of a terminal.
func (s *Server) Prompter() client.Prompter { return s.prompts }

// Handler returns the routed handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	sub, err := fs.Sub(assets, "assets")
	if err != nil {
		panic("ui: embedded assets are missing: " + err.Error())
	}
	files := http.FileServerFS(sub)

	// The page itself is not behind the token: it carries no data and asks
	// for the token from the address bar before it fetches anything.
	mux.Handle("GET /", files)

	mux.HandleFunc("GET /api/state", s.auth(s.getState))
	mux.HandleFunc("GET /api/events", s.auth(s.streamEvents))
	mux.HandleFunc("GET /api/rules", s.auth(s.getRules))
	mux.HandleFunc("PUT /api/rules", s.auth(s.putRules))
	mux.HandleFunc("GET /api/generated-config", s.auth(s.getGeneratedConfig))
	mux.HandleFunc("GET /api/tunnels/{name}/logs", s.auth(s.getLogs))
	mux.HandleFunc("POST /api/tunnels/{name}/reconnect", s.auth(s.postReconnect))
	mux.HandleFunc("POST /api/prompts/{id}", s.auth(s.postPromptAnswer))

	return mux
}

// auth accepts the token from a header or, for the page's own first request,
// a query parameter.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if got == "" {
			got = r.URL.Query().Get("token")
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
			writeErr(w, http.StatusUnauthorized, "invalid or missing token")
			return
		}
		next(w, r)
	}
}

// State is everything the interface needs to draw itself.
type State struct {
	Tunnels []TunnelView  `json:"tunnels"`
	Prompts []PromptView  `json:"prompts"`
	Client  ClientView    `json:"client"`
	Server  ServerView    `json:"server"`
	At      time.Time     `json:"at"`
	Rules   []client.Rule `json:"rules"`
}

// TunnelView is one tunnel as the interface shows it.
type TunnelView struct {
	Name          string   `json:"name"`
	Up            bool     `json:"up"`
	Routes        []string `json:"routes"`
	DNS           []string `json:"dns"`
	SearchDomains []string `json:"search_domains"`
	UDP           bool     `json:"udp"`
}

// PromptView is a challenge waiting for an answer.
type PromptView struct {
	ID     string `json:"id"`
	Tunnel string `json:"tunnel"`
	Type   string `json:"type"`
	Prompt string `json:"prompt"`
	URL    string `json:"url,omitempty"`
	Image  string `json:"image_b64,omitempty"`
	// VNCPort is set when the tunnel needs a graphical login, which this
	// interface cannot show; it tells the person where to point a viewer.
	VNCPort   int       `json:"vnc_port,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ClientView describes how traffic enters and what happens when a tunnel is
// down.
type ClientView struct {
	TUN         bool   `json:"tun"`
	Proxy       bool   `json:"proxy"`
	ProxyListen string `json:"proxy_listen,omitempty"`
	OnFailure   string `json:"on_failure"`
	AutoRoutes  bool   `json:"auto_routes"`
	AutoDomains bool   `json:"auto_domains"`
	DNSDefault  string `json:"dns_default"`
}

// ServerView describes the server the client is attached to.
type ServerView struct {
	Address    string `json:"address"`
	ServerName string `json:"server_name"`
	Pinned     bool   `json:"pinned"`
}

func (s *Server) state() State {
	cfg := s.ctl.Settings()
	tunnels := s.ctl.Tunnels()

	views := make([]TunnelView, 0, len(tunnels))
	for _, t := range tunnels {
		views = append(views, TunnelView{
			Name: t.Name, Up: t.Up,
			Routes: t.Routes, DNS: t.DNS,
			SearchDomains: t.SearchDomains, UDP: t.UDP,
		})
	}

	return State{
		Tunnels: views,
		Prompts: s.prompts.pending(),
		Rules:   cfg.Rules,
		Client: ClientView{
			TUN:         cfg.TUN.Enabled,
			Proxy:       cfg.Proxy.Enabled,
			ProxyListen: cfg.Proxy.Listen,
			OnFailure:   cfg.OnFailure,
			AutoRoutes:  cfg.AutoRoutes,
			AutoDomains: cfg.AutoDomains,
			DNSDefault:  cfg.DNS.Default,
		},
		At: time.Now(),
	}
}

func (s *Server) getState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.state())
}

// streamEvents pushes the whole state whenever it changes.
//
// The state is small and sending all of it means a client that misses an
// update is still correct after the next one, which matters more here than
// the bytes saved by sending differences.
func (s *Server) streamEvents(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	send := func() bool {
		b, err := json.Marshal(s.state())
		if err != nil {
			return false
		}
		if _, err := w.Write([]byte("data: " + string(b) + "\n\n")); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	if !send() {
		return
	}

	changes := s.prompts.subscribe()
	defer s.prompts.unsubscribe(changes)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-changes:
			// A challenge appearing or being answered must show at once; a
			// person has a minute or two to type a code.
			if !send() {
				return
			}
		case <-ticker.C:
			if !send() {
				return
			}
		}
	}
}

func (s *Server) getRules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.ctl.Settings().Rules)
}

// putRules validates, applies and only then saves.
//
// Saving first would leave a file on disk that the running client rejected,
// so the next start would fail with rules that were never in effect.
func (s *Server) putRules(w http.ResponseWriter, r *http.Request) {
	var rules []client.Rule
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&rules); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed rules: "+err.Error())
		return
	}

	next := *s.ctl.Settings()
	next.Rules = rules
	if err := s.ctl.Reload(r.Context(), &next); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := client.SaveRules(s.configPath, rules); err != nil {
		// The rules are live but not written down. Say so plainly rather than
		// reporting success and losing them at the next start.
		writeErr(w, http.StatusInternalServerError,
			"the rules are in effect but could not be saved to "+s.configPath+": "+err.Error())
		return
	}
	s.log.Info("rules updated from the interface", "count", len(rules))
	writeJSON(w, http.StatusOK, rules)
}

func (s *Server) getGeneratedConfig(w http.ResponseWriter, r *http.Request) {
	raw, err := s.ctl.Config()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(raw)
}

func (s *Server) getLogs(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	tail := 200
	if v := r.URL.Query().Get("tail"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 2000 {
			tail = n
		}
	}
	body, err := s.ctl.API().Logs(r.Context(), name, tail)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(body))
}

func (s *Server) postReconnect(w http.ResponseWriter, r *http.Request) {
	if err := s.ctl.API().Reconnect(r.Context(), r.PathValue("name")); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) postPromptAnswer(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed answer: "+err.Error())
		return
	}
	if err := s.prompts.answer(r.PathValue("id"), body.Value); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Serve runs the interface until ctx is cancelled, and returns the address it
// listened on.
func Serve(ctx context.Context, addr string, h http.Handler, log *slog.Logger) (string, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("ui.listen: %q is not a host:port address: %w", addr, err)
	}
	// Anything reachable from the network would let a stranger reroute this
	// machine's traffic.
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return "", fmt.Errorf("ui.listen must be a loopback address, got %q", host)
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", fmt.Errorf("listen for the interface on %s: %w", addr, err)
	}

	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(shutCtx)
	}()
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("the interface stopped serving", "error", err)
		}
	}()
	return ln.Addr().String(), nil
}

// LoadOrCreateToken returns the interface token, generating one on first run.
// It is persisted so the link stays the same between restarts.
func LoadOrCreateToken(stateDir string) (string, error) {
	path := filepath.Join(stateDir, "ui-token")
	if b, err := os.ReadFile(path); err == nil {
		if tok := strings.TrimSpace(string(b)); tok != "" {
			return tok, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read the interface token: %w", err)
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write the interface token: %w", err)
	}
	return token, nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, contract.APIError{Message: msg})
}
