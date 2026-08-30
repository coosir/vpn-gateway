package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"sync"

	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

// ErrPermanent wraps an error that retrying cannot fix, such as rejected
// credentials. The agent stops redialing and parks in StateError so a human
// (or the server, via the control plane) can intervene.
var ErrPermanent = errors.New("permanent failure")

// Permanent marks err as not worth retrying.
func Permanent(err error) error { return fmt.Errorf("%w: %w", ErrPermanent, err) }

// Config is the provider configuration assembled from the container
// environment. Secrets arrive by env because the server writes them into a
// 0600 env-file consumed at container create time, never on a command line.
type Config struct {
	Provider string
	Server   string
	Username string
	Password string
	// Extra carries provider-specific settings from VG_EXTRA_JSON.
	Extra map[string]string
	// Secret authenticates the agent's own data and control planes. It comes
	// from VG_AGENT_SECRET and is never passed to the VPN provider.
	Secret string
}

// Str returns the Extra value for key, or def when unset.
func (c Config) Str(key, def string) string {
	if v, ok := c.Extra[key]; ok && v != "" {
		return v
	}
	return def
}

// Int returns the Extra value for key parsed as an integer, or def when unset
// or unparseable.
func (c Config) Int(key string, def int) int {
	v, ok := c.Extra[key]
	if !ok || v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// Bool returns the Extra value for key parsed as a bool, or def when unset or
// unparseable.
func (c Config) Bool(key string, def bool) bool {
	v, ok := c.Extra[key]
	if !ok || v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

// ConfigFromEnv reads the contract's environment variables.
func ConfigFromEnv() (Config, error) {
	c := Config{
		Provider: os.Getenv("VG_PROVIDER"),
		Server:   os.Getenv("VG_SERVER"),
		Username: os.Getenv("VG_USERNAME"),
		Password: os.Getenv("VG_PASSWORD"),
		Secret:   os.Getenv(contract.EnvAgentSecret),
		Extra:    map[string]string{},
	}
	if raw := os.Getenv("VG_EXTRA_JSON"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &c.Extra); err != nil {
			return c, fmt.Errorf("VG_EXTRA_JSON is not a JSON object of strings: %w", err)
		}
	}
	if c.Provider == "" {
		return c, errors.New("VG_PROVIDER is required")
	}
	return c, nil
}

// Reporter is how a Provider tells the agent what is happening. The agent
// owns all state, uptime and traffic bookkeeping; a Provider only reports
// transitions. Every method is safe for concurrent use.
type Reporter interface {
	// SetState records a state transition. err is used only for
	// contract.StateError.
	SetState(s contract.State, err error)
	// SetNetwork publishes the routes and DNS the VPN pushed.
	SetNetwork(n contract.Network)
	// SetChallenge raises an interactive authentication prompt, or clears
	// the pending one when ch is nil.
	SetChallenge(ch *contract.Challenge)
	// Log emits a line for the event stream and the container log.
	Log(format string, args ...any)
}

// Provider drives one VPN protocol. Implementations live under
// internal/agent/providers and are compiled into the vg-agent binary; each
// container image starts the same binary with a different VG_PROVIDER.
type Provider interface {
	// Capabilities reports the contract capabilities this provider supports,
	// e.g. contract.CapTCP, contract.CapUDP, contract.CapSMS.
	Capabilities() []string

	// Run dials the VPN and blocks until ctx is cancelled or the tunnel
	// fails. It reports progress through rep. Returning nil means a clean
	// shutdown; wrapping the error with Permanent suppresses retries.
	//
	// Run may be called again after it returns, so it must leave no state
	// that prevents a redial.
	Run(ctx context.Context, cfg Config, rep Reporter) error

	// Dial opens a connection to addr ("host:port") through the tunnel. It is
	// called concurrently, only while the tunnel is up.
	Dial(ctx context.Context, network, addr string) (net.Conn, error)

	// Answer supplies a response to the challenge previously raised through
	// Reporter.SetChallenge.
	Answer(a contract.AuthAnswer) error
}

var (
	registryMu sync.RWMutex
	registry   = map[string]func() Provider{}
)

// Register makes a provider available under name. It panics on a duplicate,
// which can only be a build-time mistake.
func Register(name string, newFn func() Provider) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := registry[name]; dup {
		panic("agent: provider registered twice: " + name)
	}
	registry[name] = newFn
}

// New constructs the provider registered under name.
func New(name string) (Provider, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	newFn, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown provider %q (built in: %v)", name, providerNamesLocked())
	}
	return newFn(), nil
}

// Providers lists the registered provider names.
func Providers() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return providerNamesLocked()
}

func providerNamesLocked() []string {
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
