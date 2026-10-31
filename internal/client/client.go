package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/anytls"
	"github.com/sagernet/sing-box/protocol/block"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing-box/protocol/http"
	"github.com/sagernet/sing-box/protocol/mixed"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
	singjson "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/vpn-gateway/vpn-gateway/internal/server/clientcfg"
)

// pollInterval is how often the client refreshes tunnel state from the
// server.
const pollInterval = 5 * time.Second

// Client runs the routing engine. The enterprise gateway is a part of it that
// can be attached and detached while it runs: attached, the engine carries
// the gateway's tunnels and rules and is kept in step with the server;
// detached, it is an ordinary proxy client.
type Client struct {
	runCtx context.Context
	log    *slog.Logger

	// reloadMu lets one engine be built at a time. Three things rebuild it --
	// a person changing a setting, the server changing its tunnels, a rule set
	// arriving -- and two rebuilds interleaved would each close the engine the
	// other had just started.
	reloadMu sync.Mutex

	instanceMu sync.Mutex
	instance   *box.Box

	mu  sync.RWMutex
	cfg *Config
	// bundle, api and tunnels are the attached gateway, nil while there is
	// none.
	bundle       *clientcfg.Bundle
	api          *API
	tunnels      []TunnelState
	onAuthFailed func(error)
	stopWatch    context.CancelFunc
	// selected records which outbound each selector currently points at, so
	// a switch is only issued when something actually changed.
	selected map[string]string
	// ruleSetErrors says why each rule set the rules name could not be
	// downloaded. Rules using one are left out until it can be.
	ruleSetErrors map[string]string
	requests      *RequestLog
}

// ErrNoCredentials means the gateway has no username or password to sign in
// with. Like a refused password, trying again will not help until somebody
// fills them in.
var ErrNoCredentials = errors.New("authentication required: username and password must be configured")

// gatewayHopeless reports whether a gateway failure is one only a person can
// fix, so retrying would only knock on an account that may lock.
func gatewayHopeless(err error) bool {
	return errors.Is(err, ErrBadCredentials) || errors.Is(err, ErrNoCredentials)
}

// GatewayError is a failure to bring up the enterprise gateway: logging in to
// its server, or learning its tunnels. It is its own type because it is not a
// failure of the engine, which runs without the gateway rather than not at
// all.
type GatewayError struct{ Err error }

func (e *GatewayError) Error() string { return e.Err.Error() }
func (e *GatewayError) Unwrap() error { return e.Err }

// LoadBundle reads the JSON produced by `vgctl client-config`.
func LoadBundle(path string) (*clientcfg.Bundle, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read bundle: %w", err)
	}
	var b clientcfg.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("parse bundle %s: %w", path, err)
	}
	if b.Server.Address == "" {
		return nil, fmt.Errorf("bundle %s has no server address", path)
	}
	return &b, nil
}

// New builds a client. With a bundle it logs in to the gateway's server and
// learns the current tunnels before generating any configuration; a failure
// there is a *GatewayError. Without one it touches no network at all.
func New(ctx context.Context, cfg *Config, bundle *clientcfg.Bundle, log *slog.Logger) (*Client, error) {
	c := &Client{
		runCtx:   ctx,
		cfg:      cfg,
		log:      log,
		selected: map[string]string{},
		requests: NewRequestLog(cfg.RequestLog),
	}
	if bundle != nil {
		api, tunnels, err := c.login(ctx, cfg, bundle)
		if err != nil {
			return nil, &GatewayError{err}
		}
		c.bundle, c.api, c.tunnels = bundle, api, tunnels
	}
	return c, nil
}

// login trades the configured credentials for a session on the gateway's
// server and asks it which tunnels exist.
func (c *Client) login(ctx context.Context, cfg *Config, bundle *clientcfg.Bundle) (*API, []TunnelState, error) {
	if cfg.Auth.Username == "" || cfg.Auth.Password == "" {
		return nil, nil, ErrNoCredentials
	}
	// No token yet: the bundle carries none, and Login trades the user's
	// credentials for the session token every later call uses.
	api := NewAPI(bundle.Server.APIURL, "")
	if err := api.Login(ctx, cfg.Auth.Username, cfg.Auth.Password); err != nil {
		return nil, nil, err
	}
	tunnels, err := fetchTunnels(ctx, api, bundle, c.log)
	if err != nil {
		logoutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = api.Logout(logoutCtx)
		cancel()
		return nil, nil, err
	}
	return api, tunnels, nil
}

// SetOnAuthFailed registers a callback invoked when the server stops
// recognising the gateway's session. By then the gateway has already been
// detached from the engine.
func (c *Client) SetOnAuthFailed(fn func(error)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onAuthFailed = fn
}

// Config renders the sing-box configuration the client would run. It is
// exposed so `vpn-gateway config` can show it without starting anything.
func (c *Client) Config() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return BuildConfig(c.cfg, c.bundle, c.tunnels)
}

// API exposes the gateway server's control API, for answering prompts. It is
// nil while the gateway is not attached.
func (c *Client) API() *API {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.api
}

// GatewayAttached reports whether the enterprise gateway is part of the
// engine.
func (c *Client) GatewayAttached() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.bundle != nil
}

// IsAdmin reports whether the currently authenticated user has administrator privileges.
func (c *Client) IsAdmin() bool {
	api := c.API()
	return api != nil && api.IsAdmin
}

// Tunnels returns the client's current view.
func (c *Client) Tunnels() []TunnelState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]TunnelState(nil), c.tunnels...)
}

// RuleSetErrors says which rule sets the rules name could not be downloaded,
// and why.
func (c *Client) RuleSetErrors() map[string]string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]string, len(c.ruleSetErrors))
	for k, v := range c.ruleSetErrors {
		out[k] = v
	}
	return out
}

// fetchTunnels asks the server which tunnels exist and builds the live tunnel
// list. Tunnel credentials and routes are received directly from the server
// API.
func fetchTunnels(ctx context.Context, api *API, bundle *clientcfg.Bundle, log *slog.Logger) ([]TunnelState, error) {
	snapshots, err := api.Tunnels(ctx)
	if err != nil {
		return nil, fmt.Errorf("ask the server which tunnels exist: %w", err)
	}

	bundlePasswords := make(map[string]string)
	if bundle != nil {
		for _, bt := range bundle.Tunnels {
			bundlePasswords[bt.Name] = bt.Password
		}
	}

	var out []TunnelState
	for _, s := range snapshots {
		if s.Disabled {
			continue
		}
		pwd := s.TrojanPassword
		if pwd == "" {
			pwd = s.Password
		}
		if pwd == "" {
			pwd = bundlePasswords[s.Name]
		}
		if pwd == "" {
			log.Warn("tunnel has no trojan password", "tunnel", s.Name)
			continue
		}
		out = append(out, TunnelState{
			Name:          s.Name,
			Password:      pwd,
			Up:            s.Up(),
			Wanted:        s.Wanted,
			Routes:        s.Network.Routes,
			DNS:           s.Network.DNS,
			SearchDomains: s.Network.SearchDomains,
			UDP:           s.Network.UDP,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (c *Client) boxContext() context.Context {
	if c.runCtx != nil {
		return registryContext(c.runCtx)
	}
	return registryContext(context.Background())
}

// Start brings up the routing engine.
func (c *Client) Start(ctx context.Context) error {
	if c.runCtx == nil && ctx != nil {
		c.runCtx = ctx
	}
	c.reloadMu.Lock()
	defer c.reloadMu.Unlock()

	c.mu.RLock()
	cfg := c.cfg
	c.mu.RUnlock()
	// Before the engine exists there is no proxy to fetch through, so
	// whatever cannot be had directly is tried again once it does.
	c.prepareRuleSets(ctx, cfg, nil)
	if err := c.start(); err != nil {
		return err
	}
	go c.fetchMissingRuleSets()

	c.mu.RLock()
	up, total := countUp(c.tunnels), len(c.tunnels)
	c.mu.RUnlock()
	c.log.Info("routing engine started",
		"tunnels", total, "up", up,
		"tun", cfg.TUN.Enabled, "proxy", cfg.Proxy.Enabled)
	return nil
}

// start builds and starts an engine from the current state. The caller holds
// reloadMu.
func (c *Client) start() error {
	raw, err := c.Config()
	if err != nil {
		return err
	}

	boxCtx := c.boxContext()
	const maxAttempts = 3
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		var parsed option.Options
		if err := singjson.UnmarshalContext(boxCtx, raw, &parsed); err != nil {
			return fmt.Errorf("the generated configuration was rejected: %w", err)
		}
		instance, err := box.New(box.Options{Context: boxCtx, Options: parsed, PlatformLogWriter: c.requests})
		if err != nil {
			return fmt.Errorf("build the routing engine: %w", err)
		}
		if err := instance.Start(); err != nil {
			instance.Close()
			lastErr = err
			if attempt < maxAttempts {
				time.Sleep(time.Duration(attempt*150) * time.Millisecond)
				continue
			}
			c.mu.RLock()
			cfg := c.cfg
			c.mu.RUnlock()
			return startError(cfg, lastErr)
		}
		c.instanceMu.Lock()
		c.instance = instance
		c.instanceMu.Unlock()
		break
	}

	c.mu.Lock()
	c.selected = map[string]string{}
	for _, t := range c.tunnels {
		c.selected[t.RouteTag()] = c.wantedOutbound(t)
	}
	c.mu.Unlock()
	return nil
}

// prepareRuleSets downloads the rule sets cfg needs and records which could
// not be had. Each is tried directly first, then through proxy when one is
// given: a dead node must not stop a download the direct path can make, and
// a blocked download host is what the proxy is for.
func (c *Client) prepareRuleSets(ctx context.Context, cfg *Config, proxy dialFunc) {
	c.mu.RLock()
	gateway := c.bundle != nil
	c.mu.RUnlock()
	tags := neededRuleSets(cfg, gateway)
	if ctx == nil {
		ctx = context.Background()
	}
	errs := fetchRuleSets(ctx, cfg, tags, nil)
	if len(errs) > 0 && proxy != nil {
		retry := make([]string, 0, len(errs))
		for tag := range errs {
			retry = append(retry, tag)
		}
		direct := errs
		errs = fetchRuleSets(ctx, cfg, retry, proxy)
		for tag, err := range errs {
			errs[tag] = fmt.Errorf("%w (through the proxy: %v)", direct[tag], err)
		}
	}
	shown := make(map[string]string, len(errs))
	for tag, err := range errs {
		shown[tag] = err.Error()
		c.log.Warn("could not download a rule set; rules using it are left out", "rule_set", tag, "error", err)
	}
	c.mu.Lock()
	c.ruleSetErrors = shown
	c.mu.Unlock()
}

// fetchMissingRuleSets tries again, through the proxy group, for rule sets
// that could not be downloaded directly, and rebuilds the engine when any
// arrive. Where the download host is blocked, the proxy is the way to it.
func (c *Client) fetchMissingRuleSets() {
	c.mu.RLock()
	missing := len(c.ruleSetErrors) > 0
	cfg := c.cfg
	c.mu.RUnlock()
	if !missing || len(usableNodes(cfg)) == 0 {
		return
	}
	dial := c.proxyDialer()
	if dial == nil {
		return
	}
	c.prepareRuleSets(c.boxContext(), cfg, dial)
	c.mu.RLock()
	stillMissing := len(c.ruleSetErrors)
	c.mu.RUnlock()
	if stillMissing == len(neededRuleSets(cfg, c.GatewayAttached())) {
		return
	}
	c.log.Info("rule sets downloaded through the proxy; rebuilding the routing engine")
	if err := c.Reload(c.runCtx, cfg); err != nil {
		c.log.Warn("could not rebuild the routing engine with the new rule sets", "error", err)
	}
}

// proxyDialer dials through the running engine's proxy group, or is nil when
// nothing is running.
func (c *Client) proxyDialer() dialFunc {
	c.instanceMu.Lock()
	instance := c.instance
	c.instanceMu.Unlock()
	if instance == nil {
		return nil
	}
	ob, ok := instance.Outbound().Outbound(tagProxy)
	if !ok {
		return nil
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return ob.DialContext(ctx, network, M.ParseSocksaddr(addr))
	}
}

// startError explains the most common reason starting fails.
func startError(cfg *Config, err error) error {
	msg := strings.ToLower(err.Error())
	if cfg.TUN.Enabled && (strings.Contains(msg, "permission denied") || strings.Contains(msg, "operation not permitted") || strings.Contains(msg, "privileges") || strings.Contains(msg, "unable to create tun")) {
		return errors.New("TUN 模式需要系统管理员权限：请在首页安装“后台提权服务”，或在设置中切换为本地代理端口模式")
	}
	return err
}

// Close stops the routing engine, and the gateway watcher with it.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	if c.stopWatch != nil {
		c.stopWatch()
		c.stopWatch = nil
	}
	c.mu.Unlock()
	c.instanceMu.Lock()
	defer c.instanceMu.Unlock()
	if c.instance == nil {
		return nil
	}
	err := c.instance.Close()
	c.instance = nil
	return err
}

// running reports whether an engine is up.
func (c *Client) running() bool {
	c.instanceMu.Lock()
	defer c.instanceMu.Unlock()
	return c.instance != nil
}

// Reload applies a changed configuration.
//
// Routing rules are compiled into the engine, so unlike a tunnel going up or
// down they cannot be swapped in place: the engine has to be rebuilt. That
// interrupts every connection, so the new configuration is built and accepted
// by sing-box before the running one is touched. A rule with a typo in it
// leaves the client running exactly as it was.
func (c *Client) Reload(ctx context.Context, cfg *Config) error {
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("the new configuration is not valid: %w", err)
	}
	c.reloadMu.Lock()
	defer c.reloadMu.Unlock()
	c.prepareRuleSets(ctx, cfg, c.proxyDialer())
	return c.reload(ctx, cfg)
}

// reload rebuilds the engine with cfg and the current gateway. The caller
// holds reloadMu.
func (c *Client) reload(ctx context.Context, cfg *Config) error {
	c.mu.RLock()
	bundle := c.bundle
	tunnels := append([]TunnelState(nil), c.tunnels...)
	c.mu.RUnlock()

	raw, err := BuildConfig(cfg, bundle, tunnels)
	if err != nil {
		return fmt.Errorf("the new rules could not be compiled: %w", err)
	}

	boxCtx := c.boxContext()
	var testParsed option.Options
	if err := singjson.UnmarshalContext(boxCtx, raw, &testParsed); err != nil {
		return fmt.Errorf("the new configuration was rejected: %w", err)
	}
	if _, err := box.New(box.Options{Context: boxCtx, Options: testParsed}); err != nil {
		return fmt.Errorf("the new configuration could not be built: %w", err)
	}

	// The listening ports and virtual adapter are held by the running engine,
	// so it has to let go before the replacement can take them.
	c.instanceMu.Lock()
	previous := c.instance
	c.instance = nil
	c.instanceMu.Unlock()

	if previous != nil {
		previous.Close()
		// On Windows and other OSes, virtual adapter removal (e.g. Wintun) and
		// socket listener teardown are asynchronous in the kernel.
		// A brief settling period gives the OS time to release resources.
		time.Sleep(150 * time.Millisecond)
	}

	startBox := func(rawCfg []byte) (*box.Box, error) {
		const maxAttempts = 5
		var lastErr error
		for attempt := 1; attempt <= maxAttempts; attempt++ {
			if ctx != nil && ctx.Err() != nil {
				return nil, ctx.Err()
			}
			var parsed option.Options
			if err := singjson.UnmarshalContext(boxCtx, rawCfg, &parsed); err != nil {
				return nil, fmt.Errorf("the new configuration was rejected: %w", err)
			}
			inst, err := box.New(box.Options{Context: boxCtx, Options: parsed, PlatformLogWriter: c.requests})
			if err != nil {
				return nil, fmt.Errorf("the new configuration could not be built: %w", err)
			}
			if err := inst.Start(); err != nil {
				inst.Close()
				lastErr = err
				c.log.Warn("routing engine start attempt failed; retrying", "attempt", attempt, "error", err)
				if attempt < maxAttempts {
					time.Sleep(time.Duration(attempt*150) * time.Millisecond)
					continue
				}
				break
			}
			return inst, nil
		}
		return nil, lastErr
	}

	next, err := startBox(raw)
	if err != nil {
		// Nothing is running now. Put the old configuration back rather than
		// leaving the machine with no routing at all.
		c.log.Error("the new configuration failed to start; restoring the previous one", "error", err)
		if restoreErr := c.start(); restoreErr != nil {
			return fmt.Errorf("the new configuration failed to start (%w) and the previous one could not be restored: %w", err, restoreErr)
		}
		return fmt.Errorf("the new configuration failed to start: %w", err)
	}

	c.instanceMu.Lock()
	c.instance = next
	c.instanceMu.Unlock()

	c.mu.Lock()
	c.cfg = cfg
	c.selected = map[string]string{}
	for _, t := range tunnels {
		c.selected[t.RouteTag()] = c.wantedOutbound(t)
	}
	c.mu.Unlock()
	c.requests.Enable(cfg.RequestLog)

	c.log.Info("configuration reloaded", "rules", len(cfg.Rules), "proxy_rules", len(cfg.ProxyRules), "tunnels", len(tunnels))
	return nil
}

// Settings returns the configuration the client is running.
func (c *Client) Settings() *Config {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cfg
}

// Requests is the running engine's bounded request viewer.
func (c *Client) Requests() *RequestLog { return c.requests }

// SetRequestLogging updates the running setting without rebuilding the engine.
// Keeping cfg in step matters when a later rule or tunnel reload uses it.
func (c *Client) SetRequestLogging(enabled bool) {
	c.reloadMu.Lock()
	defer c.reloadMu.Unlock()
	c.mu.Lock()
	if c.cfg != nil {
		next := *c.cfg
		next.RequestLog = enabled
		c.cfg = &next
	}
	c.mu.Unlock()
	if c.requests != nil {
		c.requests.Enable(enabled)
	}
}

// AttachGateway logs in to the gateway's server and adds its tunnels and
// rules to the running engine, then keeps them in step with the server.
//
// Logging in happens before the engine is touched, so a server that cannot be
// reached leaves the engine exactly as it was.
func (c *Client) AttachGateway(ctx context.Context, bundle *clientcfg.Bundle) error {
	c.mu.RLock()
	cfg, attached := c.cfg, c.bundle != nil
	c.mu.RUnlock()
	if attached {
		return nil
	}
	api, tunnels, err := c.login(ctx, cfg, bundle)
	if err != nil {
		return &GatewayError{err}
	}

	c.reloadMu.Lock()
	c.mu.Lock()
	c.bundle, c.api, c.tunnels = bundle, api, tunnels
	c.mu.Unlock()
	if c.running() {
		c.prepareRuleSets(ctx, cfg, c.proxyDialer())
		err = c.reload(ctx, cfg)
	}
	c.reloadMu.Unlock()
	if err != nil {
		c.mu.Lock()
		c.bundle, c.api, c.tunnels = nil, nil, nil
		c.mu.Unlock()
		logoutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = api.Logout(logoutCtx)
		cancel()
		return err
	}
	c.StartWatch()
	c.log.Info("enterprise gateway attached", "tunnels", len(tunnels))
	return nil
}

// DetachGateway takes the gateway's tunnels and rules out of the engine. With
// logout it also ends the session on the server; a session the server has
// already dropped has nothing to end.
func (c *Client) DetachGateway(logout bool) error {
	c.mu.Lock()
	api, cfg := c.api, c.cfg
	if c.stopWatch != nil {
		c.stopWatch()
		c.stopWatch = nil
	}
	attached := c.bundle != nil
	c.bundle, c.api, c.tunnels = nil, nil, nil
	c.mu.Unlock()
	if !attached {
		return nil
	}
	if logout && api != nil {
		logoutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = api.Logout(logoutCtx)
		cancel()
	}
	var err error
	c.reloadMu.Lock()
	if c.running() {
		err = c.reload(c.runCtx, cfg)
	}
	c.reloadMu.Unlock()
	c.log.Info("enterprise gateway detached")
	return err
}

// StartWatch keeps the attached gateway in step with its server until it is
// detached or the client closes.
func (c *Client) StartWatch() {
	parent := c.runCtx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	c.mu.Lock()
	if c.stopWatch != nil {
		c.stopWatch()
	}
	c.stopWatch = cancel
	c.mu.Unlock()
	go c.watch(ctx)
}

// watch keeps the gateway's tunnels in step with the server until ctx is
// cancelled.
//
// A tunnel going up or down switches its selector in place. Rebuilding and
// restarting instead would tear down every other tunnel's connections, which
// is exactly the disruption tunnels are meant to be isolated from.
func (c *Client) watch(ctx context.Context) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		c.mu.RLock()
		api, bundle := c.api, c.bundle
		c.mu.RUnlock()
		if api == nil {
			return
		}
		fetched, err := fetchTunnels(ctx, api, bundle, c.log)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if errors.Is(err, ErrUnauthorized) || strings.Contains(err.Error(), "rejected the authorization") || strings.Contains(err.Error(), "unauthorized") {
				// The tunnels go with the session: a user the server no
				// longer recognises must not keep reaching its intranets.
				// The rest of the engine has nothing to do with the server
				// and keeps running.
				c.log.Error("the gateway server dropped this session; detaching the gateway", "error", err)
				if derr := c.DetachGateway(false); derr != nil {
					c.log.Error("could not rebuild the routing engine without the gateway", "error", derr)
				}
				c.mu.RLock()
				onFailed := c.onAuthFailed
				c.mu.RUnlock()
				if onFailed != nil {
					onFailed(err)
				}
				return
			}
			c.log.Warn("could not refresh tunnel state; keeping the current routing", "error", err)
			continue
		}

		c.mu.Lock()
		if c.api != api {
			// Detached, or replaced, while the request was out.
			c.mu.Unlock()
			return
		}
		oldTunnels := c.tunnels
		c.tunnels = fetched
		changed := tunnelsStructurallyChanged(oldTunnels, fetched)
		cfg := c.cfg
		c.mu.Unlock()

		if changed {
			c.log.Info("tunnel configuration changed on server, reloading routing engine",
				"previous_tunnels", len(oldTunnels), "current_tunnels", len(fetched))
			if err := c.Reload(ctx, cfg); err != nil {
				c.log.Error("failed to reload routing engine after server tunnel update", "error", err)
			}
		} else {
			c.applySelection(fetched)
		}
	}
}

// tunnelsStructurallyChanged reports whether tunnel list, passwords, routes or resolvers changed,
// requiring the sing-box routing engine to be rebuilt.
func tunnelsStructurallyChanged(old, new []TunnelState) bool {
	if len(old) != len(new) {
		return true
	}
	for i := range old {
		if old[i].Name != new[i].Name ||
			old[i].Password != new[i].Password ||
			old[i].UDP != new[i].UDP ||
			!slices.Equal(old[i].Routes, new[i].Routes) ||
			!slices.Equal(old[i].DNS, new[i].DNS) ||
			!slices.Equal(old[i].SearchDomains, new[i].SearchDomains) {
			return true
		}
	}
	return false
}

// applySelection points each tunnel's selector at the tunnel or at the
// fallback, depending on whether the server says it is up.
func (c *Client) applySelection(tunnels []TunnelState) {
	c.instanceMu.Lock()
	instance := c.instance
	c.instanceMu.Unlock()
	if instance == nil {
		return
	}
	manager := instance.Outbound()

	for _, t := range tunnels {
		want := c.wantedOutbound(t)

		c.mu.Lock()
		current, known := c.selected[t.RouteTag()]
		c.mu.Unlock()
		if known && current == want {
			continue
		}

		ob, ok := manager.Outbound(t.RouteTag())
		if !ok {
			c.log.Warn("no selector for tunnel", "tunnel", t.Name)
			continue
		}
		selector, ok := ob.(*group.Selector)
		if !ok {
			c.log.Warn("outbound is not a selector", "tunnel", t.Name)
			continue
		}
		if !selector.SelectOutbound(want) {
			c.log.Warn("could not switch tunnel routing", "tunnel", t.Name, "target", want)
			continue
		}

		c.mu.Lock()
		c.selected[t.RouteTag()] = want
		c.mu.Unlock()

		if t.Up {
			c.log.Info("tunnel is up; routing restored", "tunnel", t.Name)
		} else {
			c.log.Warn("tunnel is down; falling back", "tunnel", t.Name, "fallback", c.cfg.OnFailure)
		}
	}
}

// wantedOutbound is the outbound a tunnel's selector should point at.
func (c *Client) wantedOutbound(t TunnelState) string {
	if t.Up {
		return tunnelPrefix + t.Name
	}
	if c.cfg.OnFailure == TargetBlock {
		return tagBlock
	}
	return tagDirect
}

// SelectProxyNode points the running proxy group at target ("auto",
// "direct", or a node's tag) without rebuilding anything. It reports false
// when there is no running group or the group has no such member, in which
// case the caller has to rebuild to make the choice take effect.
func (c *Client) SelectProxyNode(target string) bool {
	c.instanceMu.Lock()
	instance := c.instance
	c.instanceMu.Unlock()
	if instance == nil {
		return false
	}
	ob, ok := instance.Outbound().Outbound(tagProxy)
	if !ok {
		return false
	}
	selector, ok := ob.(*group.Selector)
	if !ok {
		return false
	}
	return selector.SelectOutbound(target)
}

// ProxyNow reports what the proxy group points at, and, when that is the
// auto group, which node auto has settled on.
func (c *Client) ProxyNow() (selected, auto string) {
	c.instanceMu.Lock()
	instance := c.instance
	c.instanceMu.Unlock()
	if instance == nil {
		return "", ""
	}
	return groupNow(instance, tagProxy), groupNow(instance, tagAuto)
}

// groupNow is the tag of the member a group currently sends TCP through.
func groupNow(instance *box.Box, tag string) string {
	ob, ok := instance.Outbound().Outbound(tag)
	if !ok {
		return ""
	}
	g, ok := ob.(adapter.OutboundGroup)
	if !ok {
		return ""
	}
	if member := g.Selected(N.NetworkTCP); member != nil {
		return member.Tag()
	}
	return ""
}

func countUp(tunnels []TunnelState) int {
	n := 0
	for _, t := range tunnels {
		if t.Up {
			n++
		}
	}
	return n
}

// registryContext registers only the protocols the client uses.
func registryContext(ctx context.Context) context.Context {
	inR := inbound.NewRegistry()
	tun.RegisterInbound(inR)
	mixed.RegisterInbound(inR)

	outR := outbound.NewRegistry()
	direct.RegisterOutbound(outR)
	block.RegisterOutbound(outR)
	trojan.RegisterOutbound(outR)
	vmess.RegisterOutbound(outR)
	vless.RegisterOutbound(outR)
	shadowsocks.RegisterOutbound(outR)
	anytls.RegisterOutbound(outR)
	socks.RegisterOutbound(outR)
	http.RegisterOutbound(outR)
	group.RegisterSelector(outR)
	group.RegisterURLTest(outR)
	registerQUICOutbounds(outR)

	dnsR := dns.NewTransportRegistry()
	transport.RegisterUDP(dnsR)
	transport.RegisterTCP(dnsR)
	transport.RegisterTLS(dnsR)
	transport.RegisterHTTPS(dnsR)
	local.RegisterTransport(dnsR)
	registerQUICTransports(dnsR)

	return box.Context(ctx, inR, outR, endpoint.NewRegistry(), dnsR, service.NewRegistry(), certificate.NewRegistry())
}

// ensure the adapter import is used for its interface assertions.
var _ adapter.Outbound = (*group.Selector)(nil)
