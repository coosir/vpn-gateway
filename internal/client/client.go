package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
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

	instance *box.Box

	mu      sync.RWMutex
	tunnels []TunnelState
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
	if b.Server.Address == "" || len(b.Tunnels) == 0 {
		return nil, fmt.Errorf("bundle %s has no server address or no tunnels", path)
	}
	return &b, nil
}

// New builds a client. It contacts the server to learn the current tunnel
// state before generating any configuration.
func New(ctx context.Context, cfg *Config, bundle *clientcfg.Bundle, log *slog.Logger) (*Client, error) {
	c := &Client{
		cfg:      cfg,
		bundle:   bundle,
		api:      NewAPI(bundle.Server.APIURL, bundle.APIToken),
		log:      log,
		selected: map[string]string{},
	}
	tunnels, err := c.fetch(ctx)
	if err != nil {
		return nil, err
	}
	c.tunnels = tunnels
	return c, nil
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

// Tunnels returns the client's current view.
func (c *Client) Tunnels() []TunnelState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]TunnelState(nil), c.tunnels...)
}

// fetch asks the server which tunnels exist and merges that with the
// passwords from the bundle.
//
// The bundle is the authority on which tunnels this client may use: a tunnel
// the server reports but the bundle has no password for cannot be reached, so
// it is left out rather than generating rules that could never work.
func (c *Client) fetch(ctx context.Context) ([]TunnelState, error) {
	snapshots, err := c.api.Tunnels(ctx)
	if err != nil {
		return nil, fmt.Errorf("ask the server which tunnels exist: %w", err)
	}
	byName := make(map[string]Snapshot, len(snapshots))
	for _, s := range snapshots {
		byName[s.Name] = s
	}

	var out []TunnelState
	for _, bt := range c.bundle.Tunnels {
		s, known := byName[bt.Name]
		if !known {
			c.log.Warn("the bundle names a tunnel the server does not have", "tunnel", bt.Name)
			continue
		}
		out = append(out, TunnelState{
			Name:          bt.Name,
			Password:      bt.Password,
			Up:            s.Up(),
			Routes:        s.Network.Routes,
			DNS:           s.Network.DNS,
			SearchDomains: s.Network.SearchDomains,
			UDP:           s.Network.UDP,
		})
	}
	if len(out) == 0 {
		return nil, errors.New("none of the bundle's tunnels exist on the server")
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
	c.instance = instance

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
	if cfg.TUN.Enabled && (strings.Contains(msg, "permission denied") || strings.Contains(msg, "operation not permitted")) {
		return fmt.Errorf("creating the TUN interface needs elevated privileges: %w", err)
	}
	return err
}

// Close stops the routing engine.
func (c *Client) Close() error {
	if c == nil || c.instance == nil {
		return nil
	}
	return c.instance.Close()
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
			c.log.Warn("could not refresh tunnel state; keeping the current routing", "error", err)
			continue
		}

		c.mu.Lock()
		c.tunnels = fetched
		c.mu.Unlock()

		c.applySelection(fetched)
	}
}

// applySelection points each tunnel's selector at the tunnel or at the
// fallback, depending on whether the server says it is up.
func (c *Client) applySelection(tunnels []TunnelState) {
	if c.instance == nil {
		return
	}
	manager := c.instance.Outbound()

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
