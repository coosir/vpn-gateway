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
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	goruntime "runtime"
	"sort"
	"strconv"
	"strings"
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
	// Status reports where the session is. Its Rev must change whenever
	// Settings would return something different: it is how a page learns
	// about a change it did not make, and a Rev that stands still is a page
	// that goes on showing the old configuration.
	Status() client.SessionStatus
	Settings() *client.Config
	Client() *client.Client

	ImportBundle(raw []byte) error
	Connect(ctx context.Context) error
	Disconnect() error
	Apply(ctx context.Context, cfg *client.Config) error
	// Remember saves a change the running engine already reflects, without
	// rebuilding it.
	Remember(cfg *client.Config) error
	// SetGatewayEnabled is the enterprise gateway's own switch.
	SetGatewayEnabled(ctx context.Context, on bool) error
	// UpdateSubscription fetches one subscription again and applies it.
	UpdateSubscription(ctx context.Context, id string) error
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

// Prompts lists the questions waiting for an answer.
//
// It is the same list the page draws, read directly rather than over HTTP:
// when the engine is in this process there is nothing to be gained by going
// out and coming back. What reads it is the desktop shell, deciding whether a
// question needs a window of its own.
func (s *Server) Prompts() []PromptView { return s.prompts.pending() }

// AnswerPrompt delivers an answer that was collected somewhere other than the
// page -- the sign-on window, which reads a cookie out of a site the page
// itself can never see.
func (s *Server) AnswerPrompt(id, value string) error { return s.prompts.answer(id, value) }

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
	mux.HandleFunc("GET /api/proxy-rules", s.auth(s.getProxyRules))
	mux.HandleFunc("PUT /api/proxy-rules", s.auth(s.putProxyRules))
	mux.HandleFunc("POST /api/gateway", s.auth(s.postGateway))
	mux.HandleFunc("PUT /api/settings", s.auth(s.putSettings))
	mux.HandleFunc("GET /api/service", s.auth(s.getService))
	mux.HandleFunc("POST /api/service/install", s.auth(s.postServiceInstall))
	mux.HandleFunc("POST /api/service/uninstall", s.auth(s.postServiceUninstall))
	mux.HandleFunc("POST /api/service/start", s.auth(s.postServiceStart))
	mux.HandleFunc("GET /api/interfaces", s.auth(s.getInterfaces))
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
	mux.HandleFunc("PUT /api/subscriptions/{id}", s.auth(s.putSubscription))
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
	Session client.SessionStatus `json:"session"`
	Tunnels []TunnelView         `json:"tunnels"`
	Prompts []PromptView         `json:"prompts"`
	Client  ClientView           `json:"client"`
	At      time.Time            `json:"at"`
	// Rules are the enterprise gateway's: the explicit ones, then those
	// derived from what its tunnels report.
	Rules []client.Rule `json:"rules"`
	// ProxyRules are the ordinary client's.
	ProxyRules    []client.Rule         `json:"proxy_rules"`
	Subscriptions []client.Subscription `json:"subscriptions"`
	CustomNodes   []client.CustomNode   `json:"custom_nodes"`
	AllNodes      []NodeView            `json:"all_nodes"`
	SelectedNode  string                `json:"selected_node"`
	// ProxyNow is what the running proxy group points at, and AutoNow the
	// node the auto group has settled on. Both are empty while stopped.
	ProxyNow string `json:"proxy_now,omitempty"`
	AutoNow  string `json:"auto_now,omitempty"`
	// RuleSetErrors names the rule sets that could not be downloaded, and why.
	RuleSetErrors map[string]string `json:"rule_set_errors,omitempty"`
	Mode          string            `json:"mode"`
	Version       string            `json:"version"`
	IsAdmin       bool              `json:"is_admin"`
}

// NodeView is a node as the interface lists it: the node, and whether this
// build can use it.
type NodeView struct {
	client.CustomNode
	Unsupported string `json:"unsupported,omitempty"`
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
	// FinalURL and CookieName describe a sign-on that ends in a cookie
	// rather than in an address somebody can read off a browser. When
	// CookieName is set the answer is a value only the browser holds, so the
	// page has to be shown in a view this application can read it out of --
	// see the sign-on window in the desktop client.
	FinalURL   string `json:"final_url,omitempty"`
	CookieName string `json:"cookie_name,omitempty"`
	Image      string `json:"image_b64,omitempty"`
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
	TUN bool `json:"tun"`
	// How the TUN interface is built, for a machine where the defaults do
	// not get along with something else installed on it.
	TUNStack        string `json:"tun_stack"`
	TUNStackDefault string `json:"tun_stack_default"`
	// TUNGVisor says whether this build can run the gvisor and mixed stacks.
	TUNGVisor            bool   `json:"tun_gvisor"`
	TUNStrictRoute       bool   `json:"tun_strict_route"`
	TUNMTU               uint32 `json:"tun_mtu"`
	TUNOutboundInterface string `json:"tun_outbound_interface"`
	Proxy                bool   `json:"proxy"`
	ProxyListen          string `json:"proxy_listen,omitempty"`
	OnFailure            string `json:"on_failure"`
	AutoRoutes           bool   `json:"auto_routes"`
	AutoDomains          bool   `json:"auto_domains"`
	DNSDefault           string `json:"dns_default"`
	DNSRemote            string `json:"dns_remote"`
	Username             string `json:"username,omitempty"`
	Password             string `json:"password,omitempty"`
}

func (s *Server) state() State {
	cfg := s.ctl.Settings()

	var tunnels []client.TunnelState
	views := []TunnelView{}
	var isAdmin bool
	var proxyNow, autoNow string
	var ruleSetErrors map[string]string
	if c := s.ctl.Client(); c != nil {
		isAdmin = c.IsAdmin()
		tunnels = c.Tunnels()
		proxyNow, autoNow = c.ProxyNow()
		ruleSetErrors = c.RuleSetErrors()
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
	allNodes := []NodeView{}
	for _, n := range cfg.AllNodes() {
		allNodes = append(allNodes, NodeView{CustomNode: n, Unsupported: n.Unsupported()})
	}
	proxyRules := cfg.ProxyRules
	if proxyRules == nil {
		proxyRules = []client.Rule{}
	}

	return State{
		Session:       s.ctl.Status(),
		Tunnels:       views,
		Prompts:       s.prompts.pending(),
		Rules:         allRules,
		ProxyRules:    proxyRules,
		Subscriptions: subs,
		CustomNodes:   customNodes,
		AllNodes:      allNodes,
		SelectedNode:  cfg.SelectedNode,
		ProxyNow:      proxyNow,
		AutoNow:       autoNow,
		RuleSetErrors: ruleSetErrors,
		Mode:          cfg.EffectiveMode(),
		Version:       version.Full(),
		IsAdmin:       isAdmin,
		Client: ClientView{
			TUN:                  cfg.TUN.Enabled,
			TUNStack:             cfg.TUN.Stack,
			TUNStackDefault:      client.DefaultStack(goruntime.GOOS),
			TUNGVisor:            client.StackAvailable("gvisor"),
			TUNStrictRoute:       cfg.TUN.StrictRoute,
			TUNMTU:               cfg.TUN.MTU,
			TUNOutboundInterface: cfg.TUN.OutboundInterface,
			Proxy:                cfg.Proxy.Enabled,
			ProxyListen:          cfg.Proxy.Listen,
			OnFailure:            cfg.OnFailure,
			AutoRoutes:           cfg.AutoRoutes,
			AutoDomains:          cfg.AutoDomains,
			DNSDefault:           cfg.DNS.Default,
			DNSRemote:            cfg.DNS.Remote,
			Username:             cfg.Auth.Username,
			Password:             cfg.Auth.Password,
		},
		At: time.Now(),
	}
}

func (s *Server) getState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.state())
}

// stateWatchInterval is how often a stream checks whether anything it would
// show has moved.
const stateWatchInterval = time.Second

// fingerprint is everything about the state that can change without this page
// being what changed it.
//
// The page was once told only about challenges, on the assumption that it was
// the only thing that could act. It is not. A tray menu connects and
// disconnects, a tunnel goes down on its own, a second window edits the
// settings -- and none of that reached a page that was waiting to be told, so
// it went on showing what was true when somebody last clicked something. That
// is how a menu bar and the window in front of it came to disagree about
// whether the client was even connected.
//
// Cheap on purpose: it runs on a timer, and rendering the whole state to
// compare it would cost more than sending it.
func (s *Server) fingerprint() string {
	var b strings.Builder
	st := s.ctl.Status()
	fmt.Fprintf(&b, "%s|%d|%s|%d|%d|%s|%s|", st.Phase, st.Since.UnixNano(), st.LastError, st.TunnelCount, st.Rev,
		st.Gateway.Phase, st.Gateway.LastError)

	if c := s.ctl.Client(); c != nil {
		// The auto group moves on its own, and the page shows where it is.
		now, auto := c.ProxyNow()
		fmt.Fprintf(&b, "%s,%s,%d;", now, auto, len(c.RuleSetErrors()))
		// Already in name order, so this is stable between calls.
		for _, t := range c.Tunnels() {
			fmt.Fprintf(&b, "%s,%t,%t,%d,%s;",
				t.Name, t.Up, t.Wanted, len(t.Routes), strings.Join(t.DNS, "+"))
		}
	}
	b.WriteByte('|')

	// Pending prompts come out of a map, so they have to be put in an order
	// of their own or the fingerprint would change while nothing had.
	ids := make([]string, 0, 4)
	for _, p := range s.prompts.pending() {
		ids = append(ids, p.ID)
	}
	sort.Strings(ids)
	b.WriteString(strings.Join(ids, ";"))
	return b.String()
}

// streamEvents pushes the whole state whenever it changes, whoever changed it.
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

	// Taken before the send above rather than after: a change landing in
	// between is then sent again on the next tick, which costs one redundant
	// update. Taken after, it would be recorded as already delivered and the
	// page would sit on the older state until something else moved.
	last := s.fingerprint()

	watch := time.NewTicker(stateWatchInterval)
	defer watch.Stop()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-changes:
			// A challenge appearing or being answered must show at once; a
			// person has a minute or two to type a code.
			last = s.fingerprint()
			if !send() {
				return
			}
		case <-watch.C:
			now := s.fingerprint()
			if now == last {
				continue
			}
			last = now
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
			r.Outbound = ""
			userRules = append(userRules, r)
		}
	}

	next := s.ctl.Settings().Clone()
	next.Rules = userRules
	next.DisabledAutoRules = disabledAutoKeys
	// Apply validates, reconfigures a running engine, and only then saves.
	// Saving first would leave a file the client rejected, so the next start
	// would fail with rules that were never in effect.
	if err := s.ctl.Apply(r.Context(), next); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.log.Info("rules updated from the interface", "user_rules", len(userRules), "disabled_auto", len(disabledAutoKeys))
	writeJSON(w, http.StatusOK, s.state().Rules)
}

func (s *Server) getProxyRules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.state().ProxyRules)
}

// putProxyRules replaces the ordinary client's rules. Like the gateway's,
// they are validated and applied before anything is saved.
func (s *Server) putProxyRules(w http.ResponseWriter, r *http.Request) {
	var rules []client.Rule
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&rules); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed rules: "+err.Error())
		return
	}
	for i := range rules {
		rules[i].Tunnel, rules[i].Auto = "", false
	}
	next := s.ctl.Settings().Clone()
	next.ProxyRules = rules
	if err := s.ctl.Apply(r.Context(), next); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.log.Info("proxy rules updated from the interface", "rules", len(rules))
	writeJSON(w, http.StatusOK, s.state())
}

// postGateway is the enterprise gateway's switch.
func (s *Server) postGateway(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request: "+err.Error())
		return
	}
	// The engine outlives the request, and so does a gateway it brings up.
	if err := s.ctl.SetGatewayEnabled(context.WithoutCancel(r.Context()), body.Enabled); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.state())
}

// Settings are the parts of the configuration the interface can change.
// Everything else stays as written in the file.
type Settings struct {
	TUN         *tunPatch           `json:"tun,omitempty"`
	Proxy       *client.ProxyConfig `json:"proxy,omitempty"`
	DNSDefault  *string             `json:"dns_default,omitempty"`
	DNSRemote   *string             `json:"dns_remote,omitempty"`
	OnFailure   *string             `json:"on_failure,omitempty"`
	AutoRoutes  *bool               `json:"auto_routes,omitempty"`
	AutoDomains *bool               `json:"auto_domains,omitempty"`
	Username    *string             `json:"username,omitempty"`
	Password    *string             `json:"password,omitempty"`
}

// tunPatch changes only the TUN settings it names. Replacing the whole block,
// as saving the settings page used to, reset the stack, strict routing and
// MTU to their defaults every time anything at all was saved, so none of them
// could be changed from the interface.
type tunPatch struct {
	Enabled           *bool   `json:"enabled,omitempty"`
	AutoRoute         *bool   `json:"auto_route,omitempty"`
	StrictRoute       *bool   `json:"strict_route,omitempty"`
	Stack             *string `json:"stack,omitempty"`
	MTU               *uint32 `json:"mtu,omitempty"`
	Name              *string `json:"name,omitempty"`
	Address           *string `json:"address,omitempty"`
	OutboundInterface *string `json:"outbound_interface,omitempty"`
}

func (p *tunPatch) apply(t *client.TUNConfig) {
	if p.Enabled != nil {
		t.Enabled = *p.Enabled
	}
	if p.AutoRoute != nil {
		t.AutoRoute = *p.AutoRoute
	}
	if p.StrictRoute != nil {
		t.StrictRoute = *p.StrictRoute
	}
	if p.Stack != nil {
		// Empty is "this platform's default", which is not a choice; any
		// named stack is, and is kept even if the default changes again.
		t.Stack = *p.Stack
		t.StackChosen = *p.Stack != ""
	}
	if p.MTU != nil {
		t.MTU = *p.MTU
	}
	if p.Name != nil {
		t.Name = *p.Name
	}
	if p.Address != nil {
		t.Address = *p.Address
	}
	if p.OutboundInterface != nil {
		t.OutboundInterface = strings.TrimSpace(*p.OutboundInterface)
	}
}

// getInterfaces lists the network adapters an outbound interface can be
// pinned to: up, not loopback, with an address.
func (s *Server) getInterfaces(w http.ResponseWriter, r *http.Request) {
	type iface struct {
		Name      string   `json:"name"`
		Addresses []string `json:"addresses"`
	}
	out := []iface{}
	list, err := net.Interfaces()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, i := range list {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		var shown []string
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				shown = append(shown, ipn.IP.String())
			}
		}
		if len(shown) == 0 {
			continue
		}
		out = append(out, iface{Name: i.Name, Addresses: shown})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	var in Settings
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed settings: "+err.Error())
		return
	}

	next := s.ctl.Settings().Clone()
	if in.TUN != nil {
		in.TUN.apply(&next.TUN)
	}
	if in.Proxy != nil {
		next.Proxy = *in.Proxy
	}
	if in.DNSDefault != nil {
		next.DNS.Default = *in.DNSDefault
	}
	if in.DNSRemote != nil {
		next.DNS.Remote = strings.TrimSpace(*in.DNSRemote)
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

	if err := s.ctl.Apply(r.Context(), next); err != nil {
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
	api := s.gatewayAPI()
	if api == nil {
		writeErr(w, http.StatusConflict, "the enterprise gateway is not connected")
		return
	}
	body, err := api.Logs(r.Context(), name, tail)
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
	api := s.gatewayAPI()
	if api == nil {
		writeErr(w, http.StatusConflict, "the enterprise gateway is not connected")
		return
	}
	if !api.IsAdmin {
		writeErr(w, http.StatusForbidden, "administrator privileges required to start tunnels")
		return
	}
	if err := api.StartTunnel(r.Context(), r.PathValue("name")); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) postTunnelStop(w http.ResponseWriter, r *http.Request) {
	api := s.gatewayAPI()
	if api == nil {
		writeErr(w, http.StatusConflict, "the enterprise gateway is not connected")
		return
	}
	if !api.IsAdmin {
		writeErr(w, http.StatusForbidden, "administrator privileges required to stop tunnels")
		return
	}
	if err := api.StopTunnel(r.Context(), r.PathValue("name")); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) postReconnect(w http.ResponseWriter, r *http.Request) {
	api := s.gatewayAPI()
	if api == nil {
		writeErr(w, http.StatusConflict, "the enterprise gateway is not connected")
		return
	}
	if !api.IsAdmin {
		writeErr(w, http.StatusForbidden, "administrator privileges required to reconnect tunnels")
		return
	}
	if err := api.Reconnect(r.Context(), r.PathValue("name")); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// gatewayAPI is the attached gateway's control API, or nil.
func (s *Server) gatewayAPI() *client.API {
	if c := s.ctl.Client(); c != nil {
		return c.API()
	}
	return nil
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

// createNodeReq adds nodes from share links -- one, or many pasted at once --
// or one node filled in field by field.
type createNodeReq struct {
	URL  string             `json:"url,omitempty"`
	Node *client.CustomNode `json:"node,omitempty"`
}

func (s *Server) postNode(w http.ResponseWriter, r *http.Request) {
	var in createNodeReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request: "+err.Error())
		return
	}

	var added []client.CustomNode
	switch {
	case strings.TrimSpace(in.URL) != "":
		var bad []string
		for _, line := range strings.Split(in.URL, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			n, err := client.ParseNodeURL(line)
			if err != nil {
				bad = append(bad, err.Error())
				continue
			}
			added = append(added, *n)
		}
		if len(added) == 0 {
			msg := "no usable share link"
			if len(bad) > 0 {
				msg = bad[0]
			}
			writeErr(w, http.StatusBadRequest, msg)
			return
		}
	case in.Node != nil:
		n, err := cleanNode(*in.Node)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		n.ID = client.GenerateNodeID()
		added = append(added, n)
	default:
		writeErr(w, http.StatusBadRequest, "send a share link or a node")
		return
	}

	next := s.ctl.Settings().Clone()
	next.CustomNodes = append(next.CustomNodes, added...)
	if err := s.ctl.Apply(r.Context(), next); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.log.Info("nodes added", "count", len(added))
	writeJSON(w, http.StatusOK, s.state())
}

// cleanNode checks a node filled in by hand.
func cleanNode(n client.CustomNode) (client.CustomNode, error) {
	n.Server = strings.TrimSpace(n.Server)
	n.Name = strings.TrimSpace(n.Name)
	n.SubscriptionID = ""
	n.Type = n.EffectiveType()
	if n.Server == "" {
		return n, errors.New("the server address is required")
	}
	if n.Port < 1 || n.Port > 65535 {
		return n, errors.New("the port must be 1-65535")
	}
	if n.Name == "" {
		n.Name = net.JoinHostPort(n.Server, strconv.Itoa(n.Port))
	}
	if why := n.Unsupported(); why != "" {
		return n, errors.New(why)
	}
	return n, nil
}

func (s *Server) putNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in client.CustomNode
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request: "+err.Error())
		return
	}
	n, err := cleanNode(in)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	n.ID = id

	next := s.ctl.Settings().Clone()
	found := false
	for i := range next.CustomNodes {
		if next.CustomNodes[i].ID == id {
			next.CustomNodes[i] = n
			found = true
			break
		}
	}
	if !found {
		writeErr(w, http.StatusNotFound, "custom node not found")
		return
	}

	if err := s.ctl.Apply(r.Context(), next); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.state())
}

func (s *Server) deleteNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	next := s.ctl.Settings().Clone()
	var remaining []client.CustomNode
	for _, n := range next.CustomNodes {
		if n.ID != id {
			remaining = append(remaining, n)
		}
	}
	next.CustomNodes = remaining
	if next.SelectedNode == "node-"+id {
		next.SelectedNode = ""
	}

	if err := s.ctl.Apply(r.Context(), next); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.state())
}

// postSelectNode points the proxy group at a node, at auto, or at direct.
//
// A running group is switched in place: connections through other routes are
// not disturbed, and nothing is rebuilt. The choice is then saved so it
// survives a restart.
func (s *Server) postSelectNode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID   string `json:"id"`
		Mode string `json:"mode,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request: "+err.Error())
		return
	}

	target := body.ID
	switch target {
	case "", client.TargetAuto:
		target = client.TargetAuto
	case client.TargetDirect, "none", "clear":
		target = client.TargetDirect
	default:
		if !client.IsNodeTarget(target) {
			target = "node-" + target
		}
		if _, ok := s.ctl.Settings().FindNode(target); !ok {
			writeErr(w, http.StatusNotFound, "node not found")
			return
		}
	}

	next := s.ctl.Settings().Clone()
	next.SelectedNode = target
	if target == client.TargetAuto {
		next.SelectedNode = ""
	}
	modeChanged := body.Mode != "" && body.Mode != next.Mode
	if body.Mode != "" {
		next.Mode = body.Mode
	}

	c := s.ctl.Client()
	var err error
	if c != nil && !modeChanged && c.SelectProxyNode(target) {
		err = s.ctl.Remember(next)
	} else {
		err = s.ctl.Apply(r.Context(), next)
	}
	if err != nil {
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

	next := s.ctl.Settings().Clone()
	switch body.Mode {
	case client.ModeGlobal, client.ModeRule, client.ModeDirect:
		next.Mode = body.Mode
	default:
		writeErr(w, http.StatusBadRequest, "mode must be rule, global or direct")
		return
	}

	if err := s.ctl.Apply(r.Context(), next); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.state())
}

// postPingNodes measures each node with a real request through it.
func (s *Server) postPingNodes(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id,omitempty"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body)

	cfg := s.ctl.Settings()
	toPing := cfg.AllNodes()
	if body.ID != "" {
		n, ok := cfg.FindNode(body.ID)
		if !ok {
			writeErr(w, http.StatusNotFound, "node not found")
			return
		}
		toPing = []client.CustomNode{n}
	}

	latencies, err := client.TestLatency(r.Context(), s.ctl.Client(), toPing)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"latencies": latencies})
}

type subscriptionReq struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	AutoUpdate  bool   `json:"auto_update"`
	UpdateHours int    `json:"update_hours,omitempty"`
}

func (s *Server) postSubscription(w http.ResponseWriter, r *http.Request) {
	var body subscriptionReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request: "+err.Error())
		return
	}
	body.Name, body.URL = strings.TrimSpace(body.Name), strings.TrimSpace(body.URL)
	if body.URL == "" {
		writeErr(w, http.StatusBadRequest, "the subscription URL is required")
		return
	}
	if body.Name == "" {
		if u, err := url.Parse(body.URL); err == nil && u.Host != "" {
			body.Name = u.Host
		} else {
			body.Name = body.URL
		}
	}

	fetched, err := client.FetchSubscription(r.Context(), body.URL)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "fetch subscription failed: "+err.Error())
		return
	}

	subID := client.GenerateNodeID()
	for i := range fetched.Nodes {
		fetched.Nodes[i].SubscriptionID = subID
	}

	sub := client.Subscription{
		ID:          subID,
		Name:        body.Name,
		URL:         body.URL,
		AutoUpdate:  body.AutoUpdate,
		UpdateHours: body.UpdateHours,
		UpdatedAt:   time.Now().Format(time.RFC3339),
		Usage:       fetched.Usage,
		Nodes:       fetched.Nodes,
	}

	next := s.ctl.Settings().Clone()
	next.Subscriptions = append(next.Subscriptions, sub)
	if err := s.ctl.Apply(r.Context(), next); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.log.Info("subscription added", "id", sub.ID, "name", sub.Name, "nodes", len(fetched.Nodes))
	writeJSON(w, http.StatusOK, s.state())
}

// putSubscription changes a subscription's name, address or schedule. Its
// nodes are left as they are until it is next updated.
func (s *Server) putSubscription(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body subscriptionReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request: "+err.Error())
		return
	}
	next := s.ctl.Settings().Clone()
	found := false
	for i := range next.Subscriptions {
		if next.Subscriptions[i].ID != id {
			continue
		}
		if name := strings.TrimSpace(body.Name); name != "" {
			next.Subscriptions[i].Name = name
		}
		if u := strings.TrimSpace(body.URL); u != "" {
			next.Subscriptions[i].URL = u
		}
		next.Subscriptions[i].AutoUpdate = body.AutoUpdate
		next.Subscriptions[i].UpdateHours = body.UpdateHours
		found = true
	}
	if !found {
		writeErr(w, http.StatusNotFound, "subscription not found")
		return
	}
	if err := s.ctl.Remember(next); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.state())
}

func (s *Server) postUpdateSubscription(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.ctl.Settings().FindSubscription(id); !ok {
		writeErr(w, http.StatusNotFound, "subscription not found")
		return
	}
	if err := s.ctl.UpdateSubscription(r.Context(), id); err != nil {
		writeErr(w, http.StatusBadRequest, "fetch subscription failed: "+err.Error())
		return
	}
	s.log.Info("subscription updated", "id", id)
	writeJSON(w, http.StatusOK, s.state())
}

func (s *Server) deleteSubscription(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	next := s.ctl.Settings().Clone()

	var remaining []client.Subscription
	for _, sub := range next.Subscriptions {
		if sub.ID != id {
			remaining = append(remaining, sub)
		}
	}
	next.Subscriptions = remaining

	if err := s.ctl.Apply(r.Context(), next); err != nil {
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
