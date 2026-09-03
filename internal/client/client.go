package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/block"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing-box/protocol/mixed"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/tun"
	singjson "github.com/sagernet/sing/common/json"

	"github.com/vpn-gateway/vpn-gateway/internal/server/clientcfg"
)

// pollInterval is how often the client refreshes tunnel state from the
// server.
const pollInterval = 5 * time.Second

// Client runs the routing engine and keeps it in step with the server.
type Client struct {
	cfg    *Config
	bundle *clientcfg.Bundle
	api    *API
	log    *slog.Logger

	instanceMu sync.Mutex
	instance   *box.Box

	mu           sync.RWMutex
	tunnels      []TunnelState
	onAuthFailed func(error)
	// selected records which outbound each selector currently points at, so
	// a switch is only issued when something actually changed.
	selected map[string]string
}

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

// New builds a client. It contacts the server to learn the current tunnel
// state before generating any configuration.
func New(ctx context.Context, cfg *Config, bundle *clientcfg.Bundle, log *slog.Logger) (*Client, error) {
	c := &Client{
		cfg:    cfg,
		bundle: bundle,
		// No token yet: the bundle carries none, and Login below trades the
		// user's credentials for the session token every later call uses.
		api:      NewAPI(bundle.Server.APIURL, ""),
		log:      log,
		selected: map[string]string{},
	}
	if cfg.Auth.Username == "" || cfg.Auth.Password == "" {
		return nil, errors.New("authentication required: username and password must be configured")
	}
	if err := c.api.Login(ctx, cfg.Auth.Username, cfg.Auth.Password); err != nil {
		return nil, err
	}
	tunnels, err := c.fetch(ctx)
	if err != nil {
		return nil, err
	}
	c.tunnels = tunnels
	return c, nil
}

// SetOnAuthFailed registers a callback invoked when authentication is revoked by the server.
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

// API exposes the server's control API, for answering prompts.
func (c *Client) API() *API { return c.api }

// IsAdmin reports whether the currently authenticated user has administrator privileges.
func (c *Client) IsAdmin() bool {
	return c.api != nil && c.api.IsAdmin
}

// Tunnels returns the client's current view.
func (c *Client) Tunnels() []TunnelState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]TunnelState(nil), c.tunnels...)
}

// fetch asks the server which tunnels exist and builds the live tunnel list.
// Tunnel credentials and routes are received directly from the server API.
func (c *Client) fetch(ctx context.Context) ([]TunnelState, error) {
	snapshots, err := c.api.Tunnels(ctx)
	if err != nil {
		return nil, fmt.Errorf("ask the server which tunnels exist: %w", err)
	}

	bundlePasswords := make(map[string]string)
	if c.bundle != nil {
		for _, bt := range c.bundle.Tunnels {
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
			c.log.Warn("tunnel has no trojan password", "tunnel", s.Name)
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

// Start brings up the routing engine.
func (c *Client) Start(ctx context.Context) error {
	raw, err := c.Config()
	if err != nil {
		return err
	}

	boxCtx := registryContext(ctx)
	var parsed option.Options
	if err := singjson.UnmarshalContext(boxCtx, raw, &parsed); err != nil {
		return fmt.Errorf("the generated configuration was rejected: %w", err)
	}
	instance, err := box.New(box.Options{Context: boxCtx, Options: parsed})
	if err != nil {
		return fmt.Errorf("build the routing engine: %w", err)
	}
	if err := instance.Start(); err != nil {
		instance.Close()
		return startError(c.cfg, err)
	}
	c.instanceMu.Lock()
	c.instance = instance
	c.instanceMu.Unlock()

	c.mu.Lock()
	for _, t := range c.tunnels {
		c.selected[t.RouteTag()] = c.wantedOutbound(t)
	}
	up := countUp(c.tunnels)
	total := len(c.tunnels)
	c.mu.Unlock()

	c.log.Info("routing engine started",
		"tunnels", total, "up", up,
		"tun", c.cfg.TUN.Enabled, "proxy", c.cfg.Proxy.Enabled)
	return nil
}

// startError explains the most common reason starting fails.
func startError(cfg *Config, err error) error {
	msg := strings.ToLower(err.Error())
	if cfg.TUN.Enabled && (strings.Contains(msg, "permission denied") || strings.Contains(msg, "operation not permitted") || strings.Contains(msg, "privileges") || strings.Contains(msg, "unable to create tun")) {
		return errors.New("TUN 模式需要系统管理员权限：请在首页安装“后台提权服务”，或在设置中切换为本地代理端口模式")
	}
	return err
}

// Close stops the routing engine.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.instanceMu.Lock()
	defer c.instanceMu.Unlock()
	if c.instance == nil {
		return nil
	}
	err := c.instance.Close()
	c.instance = nil
	return err
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

	c.mu.RLock()
	tunnels := append([]TunnelState(nil), c.tunnels...)
	c.mu.RUnlock()

	raw, err := BuildConfig(cfg, c.bundle, tunnels)
	if err != nil {
		return fmt.Errorf("the new rules could not be compiled: %w", err)
	}

	boxCtx := registryContext(ctx)
	var parsed option.Options
	if err := singjson.UnmarshalContext(boxCtx, raw, &parsed); err != nil {
		return fmt.Errorf("the new configuration was rejected: %w", err)
	}
	next, err := box.New(box.Options{Context: boxCtx, Options: parsed})
	if err != nil {
		return fmt.Errorf("the new configuration could not be built: %w", err)
	}

	// The listening ports are held by the running engine, so it has to let go
	// before the replacement can take them.
	c.instanceMu.Lock()
	previous := c.instance
	c.instance = nil
	c.instanceMu.Unlock()

	if previous != nil {
		previous.Close()
	}
	if err := next.Start(); err != nil {
		next.Close()
		// Nothing is running now. Put the old configuration back rather than
		// leaving the machine with no routing at all.
		c.log.Error("the new configuration failed to start; restoring the previous one", "error", err)
		if restoreErr := c.Start(ctx); restoreErr != nil {
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

	c.log.Info("configuration reloaded", "rules", len(cfg.Rules), "tunnels", len(tunnels))
	return nil
}

// Settings returns the configuration the client is running.
func (c *Client) Settings() *Config {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cfg
}

// Watch keeps the client in step with the server until ctx is cancelled.
//
// A tunnel going up or down switches its selector in place. Rebuilding and
// restarting instead would tear down every other tunnel's connections, which
// is exactly the disruption tunnels are meant to be isolated from.
func (c *Client) Watch(ctx context.Context) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		fetched, err := c.fetch(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if errors.Is(err, ErrUnauthorized) || strings.Contains(err.Error(), "rejected the authorization") || strings.Contains(err.Error(), "unauthorized") {
				c.log.Error("user authentication revoked by server, shutting down connection", "error", err)
				c.Close()
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
		oldTunnels := c.tunnels
		c.tunnels = fetched
		changed := tunnelsStructurallyChanged(oldTunnels, fetched)
		c.mu.Unlock()

		if changed {
			c.log.Info("tunnel configuration changed on server, reloading routing engine",
				"previous_tunnels", len(oldTunnels), "current_tunnels", len(fetched))
			if err := c.Reload(ctx, c.cfg); err != nil {
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

// SelectProxyNode switches the proxy group selector to targetTag (e.g. "node-xxx").
func (c *Client) SelectProxyNode(targetTag string) bool {
	c.instanceMu.Lock()
	instance := c.instance
	c.instanceMu.Unlock()
	if instance == nil {
		return false
	}
	manager := instance.Outbound()
	ob, ok := manager.Outbound(tagProxy)
	if !ok {
		return false
	}
	selector, ok := ob.(*group.Selector)
	if !ok {
		return false
	}
	if !selector.SelectOutbound(targetTag) {
		return false
	}
	c.mu.Lock()
	c.cfg.SelectedNode = targetTag
	c.mu.Unlock()
	return true
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
	group.RegisterSelector(outR)

	dnsR := dns.NewTransportRegistry()
	transport.RegisterUDP(dnsR)
	transport.RegisterTCP(dnsR)
	transport.RegisterTLS(dnsR)
	transport.RegisterHTTPS(dnsR)
	local.RegisterTransport(dnsR)

	return box.Context(ctx, inR, outR, endpoint.NewRegistry(), dnsR, service.NewRegistry())
}

// ensure the adapter import is used for its interface assertions.
var _ adapter.Outbound = (*group.Selector)(nil)
