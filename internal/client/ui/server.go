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
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/client"
	"github.com/vpn-gateway/vpn-gateway/internal/version"
	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

//go:embed assets
var assets embed.FS

// Controller is what the interface can do to the session behind it.
//
// It is the whole session rather than a running client because the interface
// has to be usable before anything is connected: that is the state someone
// opening the application for the first time is in.
type Controller interface {
	Status() client.SessionStatus
	Settings() *client.Config
	Client() *client.Client

	ImportBundle(raw []byte) error
	Connect(ctx context.Context) error
	Disconnect() error
	Apply(ctx context.Context, cfg *client.Config) error
}

// Server serves the interface.
type Server struct {
	ctl        Controller
	configPath string
	token      string
	log        *slog.Logger

	// managed is set by an application that owns the window this interface is
	// displayed in. Such an application moves the window itself, once it has
	// checked that there is something to move it to, so the page must not
	// also try: two navigations to the same place is one reload too many.
	managed bool

	// busy counts the service installs and removals in flight. It is what
	// stops the application moving the window out from under one.
	busy atomic.Int32

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

// Managed tells the interface that an application is displaying it and will
// move that window itself when the engine changes hands.
func (s *Server) Managed() { s.managed = true }

// Busy reports whether the background service is being installed or removed
// right now. The page doing it is the one that has to survive to say how it
// went, so nothing else may navigate it away in the meantime.
func (s *Server) Busy() bool { return s.busy.Load() > 0 }

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
	mux.HandleFunc("PUT /api/settings", s.auth(s.putSettings))
	mux.HandleFunc("GET /api/service", s.auth(s.getService))
	mux.HandleFunc("POST /api/service/install", s.auth(s.postServiceInstall))
	mux.HandleFunc("POST /api/service/uninstall", s.auth(s.postServiceUninstall))
	mux.HandleFunc("POST /api/bundle", s.auth(s.postBundle))
	mux.HandleFunc("POST /api/connect", s.auth(s.postConnect))
	mux.HandleFunc("POST /api/disconnect", s.auth(s.postDisconnect))
	mux.HandleFunc("GET /api/generated-config", s.auth(s.getGeneratedConfig))
	mux.HandleFunc("GET /api/tunnels/{name}/logs", s.auth(s.getLogs))
	mux.HandleFunc("POST /api/tunnels/{name}/start", s.auth(s.postTunnelStart))
	mux.HandleFunc("POST /api/tunnels/{name}/stop", s.auth(s.postTunnelStop))
	mux.HandleFunc("POST /api/tunnels/{name}/reconnect", s.auth(s.postReconnect))
	mux.HandleFunc("POST /api/prompts/{id}", s.auth(s.postPromptAnswer))
	mux.HandleFunc("DELETE /api/prompts/{id}", s.auth(s.deferPrompt))

	mux.HandleFunc("GET /api/nodes", s.auth(s.getNodes))
	mux.HandleFunc("POST /api/nodes", s.auth(s.postNode))
	mux.HandleFunc("PUT /api/nodes/{id}", s.auth(s.putNode))
	mux.HandleFunc("DELETE /api/nodes/{id}", s.auth(s.deleteNode))
	mux.HandleFunc("POST /api/nodes/select", s.auth(s.postSelectNode))
	mux.HandleFunc("POST /api/nodes/ping", s.auth(s.postPingNodes))
	mux.HandleFunc("POST /api/mode", s.auth(s.postMode))
	mux.HandleFunc("POST /api/subscriptions", s.auth(s.postSubscription))
	mux.HandleFunc("POST /api/subscriptions/{id}/update", s.auth(s.postUpdateSubscription))
	mux.HandleFunc("DELETE /api/subscriptions/{id}", s.auth(s.deleteSubscription))

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
	Session       client.SessionStatus  `json:"session"`
	Tunnels       []TunnelView          `json:"tunnels"`
	Prompts       []PromptView          `json:"prompts"`
	Client        ClientView            `json:"client"`
	At            time.Time             `json:"at"`
	Rules         []client.Rule         `json:"rules"`
	Subscriptions []client.Subscription `json:"subscriptions"`
	CustomNodes   []client.CustomNode   `json:"custom_nodes"`
	AllNodes      []client.CustomNode   `json:"all_nodes"`
	SelectedNode  string                `json:"selected_node"`
	Mode          string                `json:"mode"`
	Version       string                `json:"version"`
	IsAdmin       bool                  `json:"is_admin"`
}

// TunnelView is one tunnel as the interface shows it.
type TunnelView struct {
	Name string `json:"name"`
	Up   bool   `json:"up"`
	// Wanted is whether this tunnel has been asked to dial. One that has not
	// is stopped on purpose, and the interface says so rather than showing it
	// as a failure.
	Wanted        bool     `json:"wanted"`
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
	VNCPort int `json:"vnc_port,omitempty"`
	// ExpiresAt is omitted when the gateway named no deadline. Sent as a zero
	// time it is a real date in the year 1, which the page reads as a
	// challenge that expired two thousand years ago and says so.
	ExpiresAt time.Time `json:"expires_at,omitzero"`
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
	Username    string `json:"username,omitempty"`
	Password    string `json:"password,omitempty"`
}

func (s *Server) state() State {
	cfg := s.ctl.Settings()

	var tunnels []client.TunnelState
	views := []TunnelView{}
	var isAdmin bool
	if c := s.ctl.Client(); c != nil {
		isAdmin = c.IsAdmin()
		tunnels = c.Tunnels()
		for _, t := range tunnels {
			views = append(views, TunnelView{
				Name: t.Name, Up: t.Up, Wanted: t.Wanted,
				Routes: t.Routes, DNS: t.DNS,
				SearchDomains: t.SearchDomains, UDP: t.UDP,
			})
		}
	}

	userRules := cfg.Rules
	if userRules == nil {
		userRules = []client.Rule{}
	}
	autoRules := client.AutoRules(cfg, tunnels)
	allRules := make([]client.Rule, 0, len(userRules)+len(autoRules))
	allRules = append(allRules, userRules...)
	allRules = append(allRules, autoRules...)

	subs := cfg.Subscriptions
	if subs == nil {
		subs = []client.Subscription{}
	}
	customNodes := cfg.CustomNodes
	if customNodes == nil {
		customNodes = []client.CustomNode{}
	}
	allNodes := cfg.AllNodes()
	if allNodes == nil {
		allNodes = []client.CustomNode{}
	}

	return State{
		Session:       s.ctl.Status(),
		Tunnels:       views,
		Prompts:       s.prompts.pending(),
		Rules:         allRules,
		Subscriptions: subs,
		CustomNodes:   customNodes,
		AllNodes:      allNodes,
		SelectedNode:  cfg.SelectedNode,
		Mode:          cfg.EffectiveMode(),
		Version:       version.Full(),
		IsAdmin:       isAdmin,
		Client: ClientView{
			TUN:         cfg.TUN.Enabled,
			Proxy:       cfg.Proxy.Enabled,
			ProxyListen: cfg.Proxy.Listen,
			OnFailure:   cfg.OnFailure,
			AutoRoutes:  cfg.AutoRoutes,
			AutoDomains: cfg.AutoDomains,
			DNSDefault:  cfg.DNS.Default,
			Username:    cfg.Auth.Username,
			Password:    cfg.Auth.Password,
		},
		At: time.Now(),
	}
}

func (s *Server) getState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.state())
}

// streamEvents pushes the whole state when something happens that nobody
// asked for.
//
// It does not poll. Tunnel state is read back by the interface when a person
// asks for it; sending it every couple of seconds mostly repeated what the
// page already had. What has to arrive on its own is a challenge waiting for
// an answer, because nobody would think to press refresh for a code they were
// never told to expect.
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

	ticker := time.NewTicker(15 * time.Second)
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
			// Send an SSE keepalive comment to prevent intermediate gateways and webview timeouts
			if _, err := w.Write([]byte(": ping\n\n")); err != nil {
				return
			}
			if rc.Flush() != nil {
				return
			}
		}
	}
}

func (s *Server) getRules(w http.ResponseWriter, r *http.Request) {
	cfg := s.ctl.Settings()
	var tunnels []client.TunnelState
	if c := s.ctl.Client(); c != nil {
		tunnels = c.Tunnels()
	}
	userRules := cfg.Rules
	if userRules == nil {
		userRules = []client.Rule{}
	}
	autoRules := client.AutoRules(cfg, tunnels)
	allRules := make([]client.Rule, 0, len(userRules)+len(autoRules))
	allRules = append(allRules, userRules...)
	allRules = append(allRules, autoRules...)
	writeJSON(w, http.StatusOK, allRules)
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

	var userRules []client.Rule
	var disabledAutoKeys []string
	for _, r := range rules {
		if r.Auto {
			if r.Disabled {
				for _, d := range r.DomainSuffix {
					disabledAutoKeys = append(disabledAutoKeys, client.AutoRuleKey(r.Tunnel, "domain_suffix", d))
				}
				for _, d := range r.Domain {
					disabledAutoKeys = append(disabledAutoKeys, client.AutoRuleKey(r.Tunnel, "domain", d))
				}
				for _, kw := range r.DomainKeyword {
					disabledAutoKeys = append(disabledAutoKeys, client.AutoRuleKey(r.Tunnel, "domain_keyword", kw))
				}
				for _, cidr := range r.IPCIDR {
					disabledAutoKeys = append(disabledAutoKeys, client.AutoRuleKey(r.Tunnel, "ip_cidr", cidr))
				}
			}
		} else {
			userRules = append(userRules, r)
		}
	}

	next := *s.ctl.Settings()
	next.Rules = userRules
	next.DisabledAutoRules = disabledAutoKeys
	// Apply validates, reconfigures a running engine, and only then saves.
	// Saving first would leave a file the client rejected, so the next start
	// would fail with rules that were never in effect.
	if err := s.ctl.Apply(r.Context(), &next); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.log.Info("rules updated from the interface", "user_rules", len(userRules), "disabled_auto", len(disabledAutoKeys))
	writeJSON(w, http.StatusOK, s.state().Rules)
}

// Settings are the parts of the configuration the interface can change.
// Everything else stays as written in the file.
type Settings struct {
	TUN         *client.TUNConfig   `json:"tun,omitempty"`
	Proxy       *client.ProxyConfig `json:"proxy,omitempty"`
	DNSDefault  *string             `json:"dns_default,omitempty"`
	OnFailure   *string             `json:"on_failure,omitempty"`
	AutoRoutes  *bool               `json:"auto_routes,omitempty"`
	AutoDomains *bool               `json:"auto_domains,omitempty"`
	Username    *string             `json:"username,omitempty"`
	Password    *string             `json:"password,omitempty"`
}

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	var in Settings
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed settings: "+err.Error())
		return
	}

	next := *s.ctl.Settings()
	if in.TUN != nil {
		next.TUN = *in.TUN
	}
	if in.Proxy != nil {
		next.Proxy = *in.Proxy
	}
	if in.DNSDefault != nil {
		next.DNS.Default = *in.DNSDefault
	}
	if in.OnFailure != nil {
		next.OnFailure = *in.OnFailure
	}
	if in.AutoRoutes != nil {
		next.AutoRoutes = *in.AutoRoutes
	}
	if in.AutoDomains != nil {
		next.AutoDomains = *in.AutoDomains
	}
	if in.Username != nil {
		next.Auth.Username = *in.Username
	}
	if in.Password != nil {
		next.Auth.Password = *in.Password
	}

	if err := s.ctl.Apply(r.Context(), &next); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.state())
}

// postBundle imports the file the server produced with `vgctl client-config`.
func (s *Server) postBundle(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.ctl.ImportBundle(raw); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.log.Info("imported a server bundle from the interface")
	writeJSON(w, http.StatusOK, s.state())
}

func (s *Server) postConnect(w http.ResponseWriter, r *http.Request) {
	if err := s.ctl.Connect(r.Context()); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.state())
}

func (s *Server) postDisconnect(w http.ResponseWriter, r *http.Request) {
	if err := s.ctl.Disconnect(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.state())
}

func (s *Server) getGeneratedConfig(w http.ResponseWriter, r *http.Request) {
	c := s.ctl.Client()
	if c == nil {
		writeErr(w, http.StatusConflict, "nothing is connected, so there is no configuration in effect")
		return
	}
	raw, err := c.Config()
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
	c := s.ctl.Client()
	if c == nil {
		writeErr(w, http.StatusConflict, "nothing is connected")
		return
	}
	body, err := c.API().Logs(r.Context(), name, tail)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(body))
}

// postTunnelStart asks the server to dial one tunnel. Tunnels wait to be
// asked: every attempt authenticates against a corporate gateway, and dialling
// on a schedule of our own can lock an account while nobody is watching.
func (s *Server) postTunnelStart(w http.ResponseWriter, r *http.Request) {
	c := s.ctl.Client()
	if c == nil {
		writeErr(w, http.StatusConflict, "nothing is connected")
		return
	}
	if !c.IsAdmin() {
		writeErr(w, http.StatusForbidden, "administrator privileges required to start tunnels")
		return
	}
	if err := c.API().StartTunnel(r.Context(), r.PathValue("name")); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) postTunnelStop(w http.ResponseWriter, r *http.Request) {
	c := s.ctl.Client()
	if c == nil {
		writeErr(w, http.StatusConflict, "nothing is connected")
		return
	}
	if !c.IsAdmin() {
		writeErr(w, http.StatusForbidden, "administrator privileges required to stop tunnels")
		return
	}
	if err := c.API().StopTunnel(r.Context(), r.PathValue("name")); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) postReconnect(w http.ResponseWriter, r *http.Request) {
	c := s.ctl.Client()
	if c == nil {
		writeErr(w, http.StatusConflict, "nothing is connected")
		return
	}
	if !c.IsAdmin() {
		writeErr(w, http.StatusForbidden, "administrator privileges required to reconnect tunnels")
		return
	}
	if err := c.API().Reconnect(r.Context(), r.PathValue("name")); err != nil {
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

// deferPrompt puts a question aside. It is what "later" means: the box goes
// away and is not raised again by itself. A different question from the same
// tunnel still reaches the person.
func (s *Server) deferPrompt(w http.ResponseWriter, r *http.Request) {
	if err := s.prompts.defer_(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getNodes(w http.ResponseWriter, r *http.Request) {
	st := s.state()
	writeJSON(w, http.StatusOK, map[string]any{
		"subscriptions": st.Subscriptions,
		"custom_nodes":  st.CustomNodes,
		"all_nodes":     st.AllNodes,
		"selected_node": st.SelectedNode,
	})
}

type createNodeReq struct {
	URL           string `json:"url,omitempty"`
	Name          string `json:"name,omitempty"`
	Server        string `json:"server,omitempty"`
	Port          int    `json:"port,omitempty"`
	Password      string `json:"password,omitempty"`
	SNI           string `json:"sni,omitempty"`
	AllowInsecure bool   `json:"allow_insecure,omitempty"`
}

func (s *Server) postNode(w http.ResponseWriter, r *http.Request) {
	var in createNodeReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request: "+err.Error())
		return
	}

	var node *client.CustomNode
	if in.URL != "" {
		n, err := client.ParseTrojanURL(in.URL)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid trojan URL: "+err.Error())
			return
		}
		if in.Name != "" {
			n.Name = in.Name
		}
		node = n
	} else {
		if in.Server == "" || in.Password == "" {
			writeErr(w, http.StatusBadRequest, "server and password are required")
			return
		}
		port := in.Port
		if port <= 0 || port > 65535 {
			port = 443
		}
		name := in.Name
		if name == "" {
			name = fmt.Sprintf("%s:%d", in.Server, port)
		}
		sni := in.SNI
		if sni == "" {
			sni = in.Server
		}
		node = &client.CustomNode{
			ID:            client.GenerateNodeID(),
			Name:          name,
			Type:          "trojan",
			Server:        in.Server,
			Port:          port,
			Password:      in.Password,
			SNI:           sni,
			AllowInsecure: in.AllowInsecure,
		}
	}

	next := *s.ctl.Settings()
	next.CustomNodes = append(next.CustomNodes, *node)
	if next.SelectedNode == "" {
		next.SelectedNode = node.OutboundTag()
	}
	if err := s.ctl.Apply(r.Context(), &next); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.log.Info("custom node added", "id", node.ID, "name", node.Name)
	writeJSON(w, http.StatusOK, s.state())
}

func (s *Server) putNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in createNodeReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request: "+err.Error())
		return
	}

	next := *s.ctl.Settings()
	found := false
	for i, n := range next.CustomNodes {
		if n.ID == id {
			if in.Name != "" {
				next.CustomNodes[i].Name = in.Name
			}
			if in.Server != "" {
				next.CustomNodes[i].Server = in.Server
			}
			if in.Port > 0 && in.Port <= 65535 {
				next.CustomNodes[i].Port = in.Port
			}
			if in.Password != "" {
				next.CustomNodes[i].Password = in.Password
			}
			if in.SNI != "" {
				next.CustomNodes[i].SNI = in.SNI
			}
			next.CustomNodes[i].AllowInsecure = in.AllowInsecure
			found = true
			break
		}
	}
	if !found {
		writeErr(w, http.StatusNotFound, "custom node not found")
		return
	}

	if err := s.ctl.Apply(r.Context(), &next); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.state())
}

func (s *Server) deleteNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	next := *s.ctl.Settings()
	var remaining []client.CustomNode
	for _, n := range next.CustomNodes {
		if n.ID != id {
			remaining = append(remaining, n)
		}
	}
	next.CustomNodes = remaining
	if next.SelectedNode == id || next.SelectedNode == "node-"+id {
		next.SelectedNode = ""
	}

	if err := s.ctl.Apply(r.Context(), &next); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.state())
}

func (s *Server) postSelectNode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID   string `json:"id"`
		Mode string `json:"mode,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request: "+err.Error())
		return
	}

	next := *s.ctl.Settings()
	if body.Mode != "" {
		next.Mode = body.Mode
	}

	targetTag := body.ID
	if targetTag == "" || targetTag == "none" || targetTag == "direct" || targetTag == "clear" {
		targetTag = ""
	} else if !strings.HasPrefix(targetTag, "node-") {
		targetTag = "node-" + targetTag
	}
	next.SelectedNode = targetTag

	if c := s.ctl.Client(); c != nil {
		c.SelectProxyNode(targetTag)
	}

	if err := s.ctl.Apply(r.Context(), &next); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.state())
}

func (s *Server) postMode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request: "+err.Error())
		return
	}

	next := *s.ctl.Settings()
	switch body.Mode {
	case client.ModeGlobal, client.ModeRule:
		next.Mode = body.Mode
	default:
		next.Mode = client.ModeDirect
	}

	if err := s.ctl.Apply(r.Context(), &next); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.state())
}

func (s *Server) postPingNodes(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id,omitempty"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body)

	cfg := s.ctl.Settings()
	allNodes := cfg.AllNodes()
	var toPing []client.CustomNode
	if body.ID != "" {
		if n, ok := cfg.FindNode(body.ID); ok {
			toPing = append(toPing, n)
		} else {
			writeErr(w, http.StatusNotFound, "node not found")
			return
		}
	} else {
		toPing = allNodes
	}

	latencies := map[string]int{}
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, n := range toPing {
		wg.Add(1)
		go func(node client.CustomNode) {
			defer wg.Done()
			pingCtx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			defer cancel()
			dur, err := client.PingNode(pingCtx, node)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				latencies[node.ID] = -1
			} else {
				latencies[node.ID] = int(dur.Milliseconds())
			}
		}(n)
	}
	wg.Wait()

	writeJSON(w, http.StatusOK, map[string]any{"latencies": latencies})
}

func (s *Server) postSubscription(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name       string `json:"name"`
		URL        string `json:"url"`
		AutoUpdate bool   `json:"auto_update,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request: "+err.Error())
		return
	}
	if body.Name == "" || body.URL == "" {
		writeErr(w, http.StatusBadRequest, "name and url are required")
		return
	}

	nodes, err := client.FetchSubscription(r.Context(), body.URL)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "fetch subscription failed: "+err.Error())
		return
	}

	subID := client.GenerateNodeID()
	for i := range nodes {
		nodes[i].SubscriptionID = subID
	}

	sub := client.Subscription{
		ID:         subID,
		Name:       body.Name,
		URL:        body.URL,
		AutoUpdate: body.AutoUpdate,
		UpdatedAt:  time.Now().Format(time.RFC3339),
		Nodes:      nodes,
	}

	next := *s.ctl.Settings()
	next.Subscriptions = append(next.Subscriptions, sub)
	if next.SelectedNode == "" && len(nodes) > 0 {
		next.SelectedNode = nodes[0].OutboundTag()
	}

	if err := s.ctl.Apply(r.Context(), &next); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.log.Info("subscription added", "id", sub.ID, "name", sub.Name, "nodes", len(nodes))
	writeJSON(w, http.StatusOK, s.state())
}

func (s *Server) postUpdateSubscription(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	next := *s.ctl.Settings()

	idx := -1
	for i, sub := range next.Subscriptions {
		if sub.ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		writeErr(w, http.StatusNotFound, "subscription not found")
		return
	}

	nodes, err := client.FetchSubscription(r.Context(), next.Subscriptions[idx].URL)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "fetch subscription failed: "+err.Error())
		return
	}
	for i := range nodes {
		nodes[i].SubscriptionID = id
	}

	next.Subscriptions[idx].Nodes = nodes
	next.Subscriptions[idx].UpdatedAt = time.Now().Format(time.RFC3339)

	if err := s.ctl.Apply(r.Context(), &next); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.log.Info("subscription updated", "id", id, "nodes", len(nodes))
	writeJSON(w, http.StatusOK, s.state())
}

func (s *Server) deleteSubscription(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	next := *s.ctl.Settings()

	var remaining []client.Subscription
	for _, sub := range next.Subscriptions {
		if sub.ID != id {
			remaining = append(remaining, sub)
		}
	}
	next.Subscriptions = remaining

	if err := s.ctl.Apply(r.Context(), &next); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.log.Info("subscription deleted", "id", id)
	writeJSON(w, http.StatusOK, s.state())
}

// NewToken generates an interface token. An application that keeps its own
// port also keeps its own token, generated per run: there is nothing else to
// hand it to.
func NewToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// ServeOn serves the interface on a listener the caller already opened, so
// the port can be chosen by the system and read back before anything is told
// where to look.
func ServeOn(ln net.Listener, h http.Handler, log *slog.Logger) error {
	host, _, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		return err
	}
	// Anything reachable from the network would let a stranger reroute this
	// machine's traffic.
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("the interface must listen on loopback, got %q", host)
	}

	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("the interface stopped serving", "error", err)
		}
	}()
	return nil
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

// WriteLink records the full interface link so a tray application can find
// it. The file is written 0600: whoever can read it can drive the interface.
func WriteLink(path, addr, token, owner string) error {
	dir := filepath.Dir(path)
	_, dirExisted := os.Stat(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("prepare the directory for %s: %w", path, err)
	}
	link := fmt.Sprintf("http://%s/?token=%s\n", addr, token)
	if err := os.WriteFile(path, []byte(link), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if owner == "" {
		return nil
	}
	// A directory this call created is root's and cannot even be entered by
	// the person the link is for, so it goes with the file.
	if dirExisted != nil {
		if err := chownTo(dir, owner); err != nil {
			return err
		}
	}
	return chownTo(path, owner)
}

// chownTo gives a path to a named user, so a link written by an elevated
// client can be read by the desktop session it was written for.
func chownTo(path, owner string) error {
	if runtime.GOOS == "windows" || owner == "" {
		return nil
	}
	u, err := user.Lookup(owner)
	if err != nil {
		return fmt.Errorf("ui.link_owner: %w", err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("ui.link_owner: %s has no numeric id", owner)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		gid = -1
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("give %s to %s: %w", path, owner, err)
	}
	return nil
}

// ReadLink returns a link written by WriteLink.
func ReadLink(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	link := strings.TrimSpace(string(b))
	if link == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return link, nil
}

// ReadToken returns the interface token without creating one. It is for
// anything attaching to a client that is already running, which must not
// invent a token the client is not using.
func ReadToken(stateDir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(stateDir, "ui-token"))
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(b))
	if token == "" {
		return "", fmt.Errorf("%s is empty", filepath.Join(stateDir, "ui-token"))
	}
	return token, nil
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
