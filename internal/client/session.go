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

// Phase is where a session is in its lifecycle.
type Phase string

const (
	// PhaseSetup means no server bundle has been imported yet, so there is
	// nothing to connect to.
	PhaseSetup Phase = "setup"
	// PhaseIdle means a bundle is present and the routing engine is stopped.
	PhaseIdle       Phase = "idle"
	PhaseConnecting Phase = "connecting"
	PhaseConnected  Phase = "connected"
	// PhaseFailed means connecting was attempted and did not work. LastError
	// says why.
	PhaseFailed Phase = "failed"
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

	// cancel stops the watcher belonging to the current connection.
	cancel context.CancelFunc
	// replaced is closed, and replaced with a fresh channel, every time the
	// running client changes. It is how a watcher bound to one connection
	// learns that the connection it holds is no longer the current one.
	replaced chan struct{}
}

// SessionStatus is a session's state, as the interface shows it.
type SessionStatus struct {
	Phase     Phase     `json:"phase"`
	Since     time.Time `json:"since"`
	LastError string    `json:"last_error,omitempty"`

	// Server describes what the imported bundle points at, empty in setup.
	Server     string `json:"server,omitempty"`
	ServerName string `json:"server_name,omitempty"`
	// TunnelCount is how many tunnels the bundle carries.
	TunnelCount int `json:"tunnel_count"`

	ConfigPath string `json:"config_path"`
}

// NewSession loads whatever configuration exists. A missing or incomplete one
// is not an error: the session starts in setup and the interface asks for
// what is missing.
func NewSession(configPath string, log *slog.Logger) *Session {
	s := &Session{
		configPath: configPath,
		bundlePath: filepath.Join(filepath.Dir(configPath), "client.json"),
		log:        log,
		phase:      PhaseSetup,
		since:      time.Now(),
		replaced:   make(chan struct{}),
	}
	s.load()
	return s
}

// load reads the configuration and bundle, leaving the session in setup when
// either is missing.
func (s *Session) load() {
	cfg, err := LoadConfig(s.configPath)
	if err != nil {
		s.cfg = defaultConfig(s.bundlePath)
		return
	}
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
	s.phase = PhaseIdle
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
	s.setPhase(PhaseSetup, nil)
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
	}
	if s.client != nil {
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

// CurrentAPI returns the control API of the running connection, or nil when
// nothing is connected, together with a channel closed when that connection
// is replaced.
//
// Both come from the same read because a watcher that took them separately
// could bind to one connection and then wait on another one's signal, which
// is exactly the connection it would never be told about.
func (s *Session) CurrentAPI() (*API, <-chan struct{}) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.client == nil {
		return nil, s.replaced
	}
	return s.client.API(), s.replaced
}

// setClient installs the running client and announces the change. The caller
// holds s.mu.
//
// Every connection logs in for a session token of its own, and disconnecting
// revokes the previous one, so anything holding the old client is holding a
// dead credential. Announcing the swap is what lets those callers rebind
// instead of retrying against a connection the server has already forgotten.
func (s *Session) setClient(c *Client, cancel context.CancelFunc) {
	s.cancel = cancel
	if s.client == c {
		return
	}
	s.client = c
	close(s.replaced)
	s.replaced = make(chan struct{})
}

// ImportBundle accepts a server bundle, writes it beside the configuration,
// and moves the session out of setup.
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
	s.cfg.Bundle = path
	if s.phase == PhaseSetup {
		s.setPhase(PhaseIdle, nil)
	}
	s.mu.Unlock()

	return s.save()
}

// Connect starts the routing engine.
func (s *Session) Connect(ctx context.Context) error {
	s.mu.Lock()
	if s.client != nil {
		s.mu.Unlock()
		return errors.New("already connected")
	}
	if s.bundle == nil {
		s.mu.Unlock()
		return errors.New("no server bundle has been imported yet")
	}
	cfg, bundle := s.cfg, s.bundle
	s.setPhase(PhaseConnecting, nil)
	s.mu.Unlock()

	// The engine outlives this call, so it gets a context of its own rather
	// than the request's.
	runCtx, cancel := context.WithCancel(context.Background())

	c, err := New(runCtx, cfg, bundle, s.log)
	if err != nil {
		cancel()
		s.fail(err)
		return err
	}
	if err := c.Start(runCtx); err != nil {
		cancel()
		c.Close()
		s.fail(err)
		return err
	}

	c.SetOnAuthFailed(func(err error) {
		s.mu.Lock()
		s.setClient(nil, nil)
		s.setPhase(PhaseFailed, fmt.Errorf("user authentication revoked by server: %w", err))
		s.mu.Unlock()
		cancel()
	})

	go c.Watch(runCtx)

	s.mu.Lock()
	s.setClient(c, cancel)
	s.setPhase(PhaseConnected, nil)
	s.mu.Unlock()

	s.log.Info("connected", "tunnels", len(bundle.Tunnels))
	return nil
}

// Disconnect stops the routing engine and puts the system back as it was.
func (s *Session) Disconnect() error {
	s.mu.Lock()
	c, cancel := s.client, s.cancel
	s.setClient(nil, nil)
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
	if c.api != nil {
		logoutCtx, logoutCancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = c.api.Logout(logoutCtx)
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
	s.mu.RUnlock()

	if c != nil {
		if err := c.Reload(ctx, next); err != nil {
			return err
		}
	}

	s.mu.Lock()
	s.cfg = next
	s.mu.Unlock()
	return s.save()
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

func (s *Session) fail(err error) {
	s.mu.Lock()
	s.setPhase(PhaseFailed, err)
	s.mu.Unlock()
	s.log.Error("could not connect", "error", err)
}

// Close stops everything the session owns.
func (s *Session) Close() error { return s.Disconnect() }
