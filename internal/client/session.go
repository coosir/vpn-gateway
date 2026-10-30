package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/server/clientcfg"
)

// Phase is where the routing engine is in its lifecycle.
type Phase string

const (
	// PhaseSetup is no longer entered: an engine with nothing configured
	// still runs, sending everything direct. It remains so that a page or a
	// tray built before that still has a name for it.
	PhaseSetup Phase = "setup"
	// PhaseIdle means the routing engine is stopped.
	PhaseIdle       Phase = "idle"
	PhaseConnecting Phase = "connecting"
	PhaseConnected  Phase = "connected"
	// PhaseFailed means connecting was attempted and did not work. LastError
	// says why.
	PhaseFailed Phase = "failed"
)

// GatewayPhase is where the enterprise gateway is. It is separate from the
// engine's phase because the two fail separately: a gateway server that is
// down for maintenance is no reason to stop proxying everything else.
type GatewayPhase string

const (
	// GatewayUnconfigured means no bundle has been imported.
	GatewayUnconfigured GatewayPhase = "unconfigured"
	// GatewayOff means it has been switched off.
	GatewayOff GatewayPhase = "off"
	// GatewayIdle means it is switched on and the engine is stopped; it comes
	// up with the engine.
	GatewayIdle       GatewayPhase = "idle"
	GatewayConnecting GatewayPhase = "connecting"
	GatewayConnected  GatewayPhase = "connected"
	// GatewayFailed means it could not be brought up. The engine runs
	// without it, and it is retried unless the credentials were refused.
	GatewayFailed GatewayPhase = "failed"
)

// Session owns a client's configuration and its routing engine.
//
// It exists so an application can be opened before anything is configured.
// The command line can require a complete configuration file and refuse to
// start without one; something opened from a launcher cannot, because there
// is nowhere for it to say so and nobody to type an answer.
type Session struct {
	configPath string
	bundlePath string
	log        *slog.Logger

	mu        sync.RWMutex
	cfg       *Config
	bundle    *clientcfg.Bundle
	client    *Client
	phase     Phase
	lastError string
	since     time.Time

	// gwPhase and gwError describe the gateway while the engine runs.
	gwPhase GatewayPhase
	gwError string

	// cancel stops everything belonging to the current connection.
	cancel context.CancelFunc
	// replaced is closed, and replaced with a fresh channel, every time the
	// gateway's control API changes: a new connection, or the gateway being
	// attached or detached. It is how a watcher bound to one API learns that
	// it is no longer the current one.
	replaced chan struct{}
	// rev counts how many times the configuration has changed. Comparing two
	// configurations field by field to notice is work; counting is not, and
	// what reads this only needs to know that they differ.
	rev uint64
	// stopRetry ends the loop bringing a lost gateway back, so a person
	// switching it off is not argued with.
	stopRetry context.CancelFunc
	// connecting is set while an engine is being built. The engine is built
	// outside the lock, so this is what keeps two callers from building two.
	connecting bool
	// stopBackground ends the subscription updater.
	stopBackground context.CancelFunc

	// newEngine builds and starts the routing engine, with the gateway when
	// bundle is not nil. It is a field only so a test can stand in for the
	// steps that need a real server and a real routing engine; nothing in the
	// product replaces it.
	newEngine func(ctx context.Context, cfg *Config, bundle *clientcfg.Bundle, log *slog.Logger) (*Client, error)
	// attach adds the gateway to a running engine. A field for the same
	// reason as newEngine.
	attach func(ctx context.Context, c *Client, bundle *clientcfg.Bundle) error
}

// startEngine is what newEngine is unless a test says otherwise.
func startEngine(ctx context.Context, cfg *Config, bundle *clientcfg.Bundle, log *slog.Logger) (*Client, error) {
	c, err := New(ctx, cfg, bundle, log)
	if err != nil {
		return nil, err
	}
	if err := c.Start(ctx); err != nil {
		if api := c.API(); api != nil {
			logoutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = api.Logout(logoutCtx)
			cancel()
		}
		c.Close()
		return nil, err
	}
	return c, nil
}

func attachGateway(ctx context.Context, c *Client, bundle *clientcfg.Bundle) error {
	return c.AttachGateway(ctx, bundle)
}

// Reconnect backoff. A server coming back from a restart is back in seconds;
// one that is off for the evening should not be knocked on every two.
const (
	reconnectMin = 2 * time.Second
	reconnectMax = time.Minute
)

// subscriptionCheck is how often auto-updating subscriptions are looked at.
const subscriptionCheck = 30 * time.Minute

// SessionStatus is a session's state, as the interface shows it.
type SessionStatus struct {
	Phase     Phase     `json:"phase"`
	Since     time.Time `json:"since"`
	LastError string    `json:"last_error,omitempty"`

	// Server describes what the imported bundle points at, empty without one.
	Server     string `json:"server,omitempty"`
	ServerName string `json:"server_name,omitempty"`
	// TunnelCount is how many tunnels the gateway has.
	TunnelCount int `json:"tunnel_count"`

	Gateway GatewayStatus `json:"gateway"`

	ConfigPath string `json:"config_path"`

	// Rev changes whenever the configuration does. It is for watchers that
	// have to notice a change they did not make, and means nothing to the
	// page, which is why it stays off the wire.
	Rev uint64 `json:"-"`
}

// GatewayStatus is the enterprise gateway's part of the status.
type GatewayStatus struct {
	Phase      GatewayPhase `json:"phase"`
	Configured bool         `json:"configured"`
	Enabled    bool         `json:"enabled"`
	LastError  string       `json:"last_error,omitempty"`
}

// NewSession loads whatever configuration exists. A missing or incomplete one
// is not an error: the session starts with defaults and the interface asks
// for what is missing.
func NewSession(configPath string, log *slog.Logger) *Session {
	s := &Session{
		configPath: configPath,
		bundlePath: filepath.Join(filepath.Dir(configPath), "client.json"),
		log:        log,
		phase:      PhaseIdle,
		since:      time.Now(),
		replaced:   make(chan struct{}),
		newEngine:  startEngine,
		attach:     attachGateway,
	}
	s.load()
	ctx, cancel := context.WithCancel(context.Background())
	s.stopBackground = cancel
	go s.updateSubscriptions(ctx)
	return s
}

// load reads the configuration and bundle. Either may be missing.
func (s *Session) load() {
	s.rev++
	s.bundle = nil
	cfg, err := LoadConfig(s.configPath)
	if err != nil {
		cfg = defaultConfig(s.bundlePath)
	}
	cfg.RuleSetDir = filepath.Join(filepath.Dir(s.configPath), "rule-sets")
	s.cfg = cfg
	if cfg.Bundle != "" {
		s.bundlePath = cfg.Bundle
	}

	bundle, err := LoadBundle(s.bundlePath)
	if err != nil {
		s.log.Debug("no server bundle yet", "path", s.bundlePath, "error", err)
		return
	}
	s.bundle = bundle
}

// defaultConfig is what a session starts with before anything is configured:
// a TUN interface and the system resolver.
func defaultConfig(bundlePath string) *Config {
	cfg := &Config{
		Bundle:      bundlePath,
		TUN:         TUNConfig{Enabled: true, AutoRoute: true},
		Proxy:       ProxyConfig{Enabled: true, Listen: "127.0.0.1:1080"},
		AutoRoutes:  true,
		AutoDomains: true,
	}
	cfg.applyDefaults()
	return cfg
}

// Reload re-reads the configuration and the bundle from disk.
//
// The background service edits the same file this session was loaded from, so
// once it has been running, what is on disk is newer than what is in memory.
// This is how a session that has just been handed the engine back catches up.
// A connected session is left alone: rereading under a running engine would
// describe a configuration it is not using.
func (s *Session) Reload() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client != nil {
		return
	}
	s.setPhase(PhaseIdle, nil)
	s.load()
}

// Status reports where the session is.
func (s *Session) Status() SessionStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	st := SessionStatus{
		Phase:      s.phase,
		Since:      s.since,
		LastError:  s.lastError,
		ConfigPath: s.configPath,
		Rev:        s.rev,
		Gateway: GatewayStatus{
			Phase:      s.gatewayPhase(),
			Configured: s.bundle != nil,
			Enabled:    s.bundle != nil && !s.cfg.GatewayDisabled,
		},
	}
	if st.Gateway.Phase == GatewayFailed || st.Gateway.Phase == GatewayConnecting {
		st.Gateway.LastError = s.gwError
	}
	if s.client != nil && s.client.GatewayAttached() {
		st.TunnelCount = len(s.client.Tunnels())
	} else if s.bundle != nil {
		st.TunnelCount = len(s.bundle.Tunnels)
	}
	if s.bundle != nil {
		st.Server = s.bundle.Server.Address
		st.ServerName = s.bundle.Server.ServerName
	}
	return st
}

// gatewayPhase is the gateway's phase as shown. The caller holds s.mu.
func (s *Session) gatewayPhase() GatewayPhase {
	switch {
	case s.bundle == nil:
		return GatewayUnconfigured
	case s.cfg.GatewayDisabled:
		return GatewayOff
	case s.client == nil:
		return GatewayIdle
	case s.gwPhase == "":
		return GatewayConnecting
	}
	return s.gwPhase
}

// Settings returns the configuration in effect.
func (s *Session) Settings() *Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// Client returns the running client, or nil when nothing is connected.
func (s *Session) Client() *Client {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.client
}

// CurrentAPI returns the gateway's control API, or nil when the gateway is
// not attached, together with a channel closed when that changes.
//
// Both come from the same read because a watcher that took them separately
// could bind to one API and then wait on another one's signal, which is
// exactly the change it would never be told about.
func (s *Session) CurrentAPI() (*API, <-chan struct{}) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.client == nil {
		return nil, s.replaced
	}
	return s.client.API(), s.replaced
}

// announce tells anything holding the gateway's API that it has changed. The
// caller holds s.mu.
//
// Every attachment logs in for a session token of its own, and detaching
// revokes the previous one, so anything holding the old API is holding a dead
// credential. Announcing the change is what lets those callers rebind instead
// of retrying against a session the server has already forgotten.
func (s *Session) announce() {
	close(s.replaced)
	s.replaced = make(chan struct{})
}

// setClient installs the running client and announces the change. The caller
// holds s.mu.
func (s *Session) setClient(c *Client, cancel context.CancelFunc) {
	s.cancel = cancel
	if s.client == c {
		return
	}
	s.client = c
	s.announce()
}

// ImportBundle accepts a server bundle, writes it beside the configuration,
// and attaches the gateway to a running engine.
//
// It is validated before anything is written: a bundle that cannot be parsed
// would otherwise replace a working one and leave nothing to connect with.
func (s *Session) ImportBundle(raw []byte) error {
	var bundle clientcfg.Bundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return fmt.Errorf("this does not look like a bundle: %w", err)
	}
	if bundle.Server.Address == "" {
		return errors.New("the bundle names no server address")
	}

	s.mu.Lock()
	path := s.bundlePath
	s.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("prepare %s: %w", filepath.Dir(path), err)
	}
	// It carries one password per tunnel.
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return fmt.Errorf("save the bundle: %w", err)
	}

	s.mu.Lock()
	s.bundle = &bundle
	next := s.cfg.Clone()
	next.Bundle = path
	s.cfg = next
	s.rev++
	running := s.client != nil && !s.client.GatewayAttached() && next.GatewayWanted()
	s.mu.Unlock()

	if err := s.save(); err != nil {
		return err
	}
	if running {
		go s.bringGatewayUp(context.Background())
	}
	return nil
}

// Connect starts the routing engine, with the enterprise gateway when it is
// switched on.
//
// A gateway that cannot be brought up does not stop the engine: it starts
// without the gateway, which is retried on its own.
func (s *Session) Connect(ctx context.Context) error {
	s.mu.Lock()
	if s.client != nil {
		s.mu.Unlock()
		return errors.New("already connected")
	}
	// Building the engine happens outside the lock, so without this a second
	// caller arriving while the first is still working would see nothing
	// connected and build one of its own. Two of them fight over the same
	// interface and the same routing table, and only one can win.
	if s.connecting {
		s.mu.Unlock()
		return errors.New("already connecting")
	}
	cfg := s.cfg
	var bundle *clientcfg.Bundle
	if cfg.GatewayWanted() && s.bundle != nil {
		bundle = s.bundle
	}
	s.connecting = true
	s.setPhase(PhaseConnecting, nil)
	s.gwPhase, s.gwError = "", ""
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.connecting = false
		s.mu.Unlock()
	}()

	// The engine outlives this call, so it gets a context of its own rather
	// than the request's.
	runCtx, cancel := context.WithCancel(context.Background())

	c, err := s.newEngine(runCtx, cfg, bundle, s.log)
	var gwErr error
	var gatewayErr *GatewayError
	if err != nil && bundle != nil && errors.As(err, &gatewayErr) {
		s.log.Warn("the enterprise gateway could not be brought up; starting without it", "error", err)
		gwErr = err
		c, err = s.newEngine(runCtx, cfg, nil, s.log)
	}
	if err != nil {
		cancel()
		s.fail(err)
		return err
	}

	s.mu.Lock()
	s.setClient(c, cancel)
	s.setPhase(PhaseConnected, nil)
	switch {
	case bundle == nil:
		s.gwPhase = ""
	case gwErr != nil:
		s.setGateway(GatewayFailed, gwErr)
	default:
		s.setGateway(GatewayConnected, nil)
	}
	s.mu.Unlock()

	if bundle != nil && gwErr == nil {
		s.followGateway(c)
	}
	if gwErr != nil && !gatewayHopeless(gwErr) {
		s.retryGateway(gwErr)
	}

	s.log.Info("connected", "gateway", bundle != nil && gwErr == nil)
	return nil
}

// followGateway keeps an attached gateway in step with its server, and
// brings it back when the server drops the session.
func (s *Session) followGateway(c *Client) {
	c.SetOnAuthFailed(func(err error) {
		s.mu.Lock()
		if s.client != c {
			s.mu.Unlock()
			return
		}
		s.announce()
		s.mu.Unlock()
		// Not a failure to sit in. A server that restarted forgot every
		// session it had issued, so this is what a restart looks like from
		// here, and the answer is to log in again rather than to wait for
		// somebody to notice.
		s.log.Info("the gateway server dropped this session; signing in again", "error", err)
		s.retryGateway(fmt.Errorf("the server no longer knows this session: %w", err))
	})
	c.StartWatch()
}

// bringGatewayUp attaches the gateway to the running engine, and keeps
// trying if that does not work.
func (s *Session) bringGatewayUp(ctx context.Context) error {
	err := s.attachOnce(ctx)
	if err != nil && !gatewayHopeless(err) && !errors.Is(err, errGatewayNotWanted) {
		s.retryGateway(err)
	}
	return err
}

// errGatewayNotWanted ends an attempt the situation has overtaken: the engine
// stopped, or the gateway was switched off, while it was being made.
var errGatewayNotWanted = errors.New("the gateway is no longer wanted")

// attachOnce makes one attempt to attach the gateway.
func (s *Session) attachOnce(ctx context.Context) error {
	s.mu.Lock()
	c, bundle := s.client, s.bundle
	if c == nil || bundle == nil || !s.cfg.GatewayWanted() {
		s.mu.Unlock()
		return errGatewayNotWanted
	}
	if c.GatewayAttached() {
		s.mu.Unlock()
		return nil
	}
	s.setGateway(GatewayConnecting, nil)
	s.mu.Unlock()

	err := s.attach(ctx, c, bundle)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client != c || !s.cfg.GatewayWanted() {
		// Overtaken while the attempt was out. An attachment that landed on
		// an engine nobody wants it on is taken off again.
		if err == nil {
			go c.DetachGateway(true)
		}
		return errGatewayNotWanted
	}
	if err != nil {
		s.setGateway(GatewayFailed, err)
		return err
	}
	s.setGateway(GatewayConnected, nil)
	s.announce()
	go s.followGateway(c)
	return nil
}

// retryGateway brings a gateway that could not be attached, or was lost,
// back -- until it is back, the person switches it off or disconnects, or
// the credentials themselves are refused.
//
// It exists because losing the gateway is usually nobody's decision: the
// server was upgraded, the network went away. Leaving it down until somebody
// notices makes a restart that takes seconds into an outage that lasts until
// the next time a person looks.
func (s *Session) retryGateway(reason error) {
	ctx, cancel := context.WithCancel(context.Background())

	s.mu.Lock()
	if s.stopRetry != nil {
		s.stopRetry() // only one of these at a time
	}
	s.stopRetry = cancel
	if s.client != nil {
		s.setGateway(GatewayConnecting, reason)
	}
	s.mu.Unlock()

	go func() {
		defer cancel()
		backoff := reconnectMin
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if ctx.Err() != nil {
				return
			}
			err := s.attachOnce(ctx)
			if err == nil {
				s.log.Info("the enterprise gateway is back")
				return
			}
			if ctx.Err() != nil || errors.Is(err, errGatewayNotWanted) {
				return
			}
			// A password the server does not accept will not start working
			// however many times it is sent, and every attempt is one more
			// against an account that may lock.
			if gatewayHopeless(err) {
				s.log.Error("not retrying the gateway until the credentials change", "error", err)
				return
			}
			s.mu.Lock()
			s.setGateway(GatewayConnecting, err)
			s.mu.Unlock()
			s.log.Warn("could not bring the gateway back; trying again", "error", err, "in", backoff)
			backoff = min(backoff*2, reconnectMax)
		}
	}()
}

// endRetry stops any loop bringing the gateway back. The caller holds s.mu.
func (s *Session) endRetry() {
	if s.stopRetry != nil {
		s.stopRetry()
		s.stopRetry = nil
	}
}

// SetGatewayEnabled switches the enterprise gateway on or off and remembers
// the choice.
//
// Switching it on with the engine stopped starts the engine: one switch is
// what gets somebody onto the intranet. Switching it off takes the gateway's
// tunnels and rules out of a running engine and leaves the rest running.
func (s *Session) SetGatewayEnabled(ctx context.Context, on bool) error {
	s.mu.Lock()
	if on && s.bundle == nil {
		s.mu.Unlock()
		return errors.New("no server bundle has been imported yet")
	}
	next := s.cfg.Clone()
	next.GatewayDisabled = !on
	s.cfg = next
	s.rev++
	c := s.client
	if !on {
		s.endRetry()
	}
	s.mu.Unlock()

	if err := s.save(); err != nil {
		return err
	}

	if !on {
		if c == nil {
			return nil
		}
		err := c.DetachGateway(true)
		s.mu.Lock()
		s.gwPhase, s.gwError = "", ""
		s.announce()
		s.mu.Unlock()
		return err
	}
	if c == nil {
		return s.Connect(ctx)
	}
	return s.bringGatewayUp(ctx)
}

// Disconnect stops the routing engine and puts the system back as it was.
func (s *Session) Disconnect() error {
	s.mu.Lock()
	s.endRetry()
	c, cancel := s.client, s.cancel
	s.setClient(nil, nil)
	s.gwPhase, s.gwError = "", ""
	if s.phase == PhaseConnected || s.phase == PhaseConnecting {
		s.setPhase(PhaseIdle, nil)
	}
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if c == nil {
		return nil
	}
	if api := c.API(); api != nil {
		logoutCtx, logoutCancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = api.Logout(logoutCtx)
		logoutCancel()
	}
	// Closing tears down the interface and the routes pointing at it;
	// leaving them behind would take the machine offline.
	err := c.Close()
	s.log.Info("disconnected")
	return err
}

// Apply changes the configuration. A connected session is reconfigured in
// place; an idle one just records it.
func (s *Session) Apply(ctx context.Context, next *Config) error {
	// The interface sends only what someone changed, so turning TUN on
	// arrives as an interface with no address, MTU or stack. Those are the
	// same defaults a configuration file gets when it omits them, so fill
	// them in here rather than making the interface repeat them.
	next.applyDefaults()
	if err := next.Validate(); err != nil {
		return err
	}

	s.mu.RLock()
	c := s.client
	prev := s.cfg
	if next.RuleSetDir == "" {
		next.RuleSetDir = prev.RuleSetDir
	}
	s.mu.RUnlock()

	if c != nil {
		if err := c.Reload(ctx, next); err != nil {
			return err
		}
	}

	s.mu.Lock()
	s.cfg = next
	s.rev++
	// New credentials are worth one more try at a gateway the old ones could
	// not bring up.
	retry := c != nil && next.GatewayWanted() && !c.GatewayAttached() &&
		s.gwPhase == GatewayFailed && next.Auth != prev.Auth
	s.mu.Unlock()
	if err := s.save(); err != nil {
		return err
	}
	if retry {
		go s.bringGatewayUp(context.Background())
	}
	return nil
}

// Remember records a configuration the running engine already reflects,
// without rebuilding it. It is for a change made in place -- the proxy group
// pointed at another node -- that only needs to survive a restart.
func (s *Session) Remember(next *Config) error {
	next.applyDefaults()
	if err := next.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	if next.RuleSetDir == "" {
		next.RuleSetDir = s.cfg.RuleSetDir
	}
	s.cfg = next
	s.rev++
	s.mu.Unlock()
	return s.save()
}

// updateSubscriptions fetches auto-updating subscriptions when they are due,
// until ctx is cancelled.
func (s *Session) updateSubscriptions(ctx context.Context) {
	ticker := time.NewTicker(subscriptionCheck)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		for _, sub := range s.Settings().Subscriptions {
			if !sub.Due(time.Now()) {
				continue
			}
			if err := s.UpdateSubscription(ctx, sub.ID); err != nil {
				s.log.Warn("could not update a subscription", "subscription", sub.Name, "error", err)
			} else {
				s.log.Info("subscription updated", "subscription", sub.Name)
			}
		}
	}
}

// UpdateSubscription fetches one subscription again and applies what it now
// holds. Nodes that are still there keep their IDs, so rules and the
// selection that name them are not broken by the update.
func (s *Session) UpdateSubscription(ctx context.Context, id string) error {
	sub, ok := s.Settings().FindSubscription(id)
	if !ok {
		return fmt.Errorf("no subscription %q", id)
	}
	fetched, err := FetchSubscription(ctx, sub.URL)
	if err != nil {
		return err
	}
	next := s.Settings().Clone()
	for i := range next.Subscriptions {
		if next.Subscriptions[i].ID != id {
			continue
		}
		KeepIDs(fetched.Nodes, next.Subscriptions[i].Nodes)
		for j := range fetched.Nodes {
			fetched.Nodes[j].SubscriptionID = id
		}
		next.Subscriptions[i].Nodes = fetched.Nodes
		next.Subscriptions[i].UpdatedAt = time.Now().Format(time.RFC3339)
		if fetched.Usage != nil {
			next.Subscriptions[i].Usage = fetched.Usage
		}
	}
	return s.Apply(ctx, next)
}

// save writes the configuration back, creating it on first use.
func (s *Session) save() error {
	s.mu.RLock()
	cfg, path := s.cfg, s.configPath
	s.mu.RUnlock()

	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := writeInitialConfig(path, cfg); err != nil {
			return err
		}
		return nil
	}
	// An existing file keeps its comments: only the parts the interface owns
	// are replaced.
	return SaveSettings(path, cfg)
}

func (s *Session) setPhase(p Phase, err error) {
	s.phase = p
	s.since = time.Now()
	if err != nil {
		s.lastError = err.Error()
	} else if p != PhaseFailed {
		s.lastError = ""
	}
}

// setGateway records the gateway's phase. The caller holds s.mu.
func (s *Session) setGateway(p GatewayPhase, err error) {
	s.gwPhase = p
	if err != nil {
		s.gwError = err.Error()
	} else if p != GatewayConnecting {
		s.gwError = ""
	}
}

func (s *Session) fail(err error) {
	s.mu.Lock()
	s.setPhase(PhaseFailed, err)
	s.mu.Unlock()
	s.log.Error("could not connect", "error", err)
}

// Close stops everything the session owns.
func (s *Session) Close() error {
	s.mu.Lock()
	if s.stopBackground != nil {
		s.stopBackground()
		s.stopBackground = nil
	}
	s.mu.Unlock()
	return s.Disconnect()
}
