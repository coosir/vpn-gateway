// Package tunnel reconciles configured tunnels into running containers and
// keeps a live view of each one's state for the client-facing API.
package tunnel

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/server"
	"github.com/vpn-gateway/vpn-gateway/internal/server/proxy"
	"github.com/vpn-gateway/vpn-gateway/internal/server/runtime"
	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

const (
	// pollInterval is how often the server refreshes a tunnel's status from
	// its container.
	pollInterval = 3 * time.Second
	// unreachableLimit is how many consecutive failed polls mark a container
	// as wedged and trigger a restart. The agent reconnects internally, so
	// reaching this means the agent itself is gone.
	unreachableLimit = 5

	restartMin = 5 * time.Second
	restartMax = 5 * time.Minute

	stopGraceSeconds = 10

	// vncContainerPort is where an image that needs a graphical login serves
	// it, by convention across the tier that wraps a vendor client.
	vncContainerPort = 5901
)

// Snapshot is the server's view of one tunnel, as served to clients.
type Snapshot struct {
	Name     string `json:"name"`
	Provider string `json:"provider"`
	Disabled bool   `json:"disabled"`
	// Wanted is whether this tunnel has been asked to dial. A tunnel that has
	// not is stopped on purpose, not broken.
	Wanted bool `json:"wanted"`

	// TrojanPassword is what a client sends to select this tunnel over Trojan.
	TrojanPassword string `json:"trojan_password,omitempty"`

	// Reachable reports whether the container's control plane answered the
	// most recent poll. When false, Status is the last known value.
	Reachable       bool   `json:"reachable"`
	ContainerExists bool   `json:"container_exists"`
	ContainerUp     bool   `json:"container_up"`
	LastError       string `json:"last_error,omitempty"`

	Status    contract.Status     `json:"status"`
	Network   contract.Network    `json:"network"`
	Challenge *contract.Challenge `json:"challenge,omitempty"`
}

// Tunnel supervises one configured tunnel.
type Tunnel struct {
	cfg    server.TunnelConfig
	engine runtime.Engine
	client *contract.Client
	log    *slog.Logger

	stateDir   string
	pullPolicy string
	mgr        *Manager

	// wanted is whether this tunnel should be dialled. It is persisted, so a
	// server restart brings back what was running rather than everything.
	wanted atomic.Bool
	// wake interrupts the supervisor when the wanted state changes.
	wake chan struct{}
	// secret authenticates this tunnel's container on both planes.
	secret string
	// trojanPassword is what a client sends to select this tunnel. It is
	// distinct from secret: one faces the client, the other the container,
	// and leaking either must not compromise the other.
	trojanPassword string

	mu          sync.RWMutex
	initiator   string
	snap        Snapshot
	unreachable int
}

// Event reports that a tunnel's state changed.
type Event struct {
	At     time.Time `json:"at"`
	Tunnel Snapshot  `json:"tunnel"`
}

// Manager owns every tunnel.
type Manager struct {
	cfg     *server.Config
	engine  runtime.Engine
	log     *slog.Logger
	tunnels []*Tunnel

	subsMu sync.Mutex
	subs   map[int]chan Event
	nextID int
}

// Subscribe returns a channel of state changes and a function to release it.
//
// The channel is buffered and a subscriber that falls behind drops events
// rather than stalling the poll loop. Every event carries the whole snapshot,
// so a dropped one costs nothing: the next event is still complete.
func (m *Manager) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 64)
	m.subsMu.Lock()
	if m.subs == nil {
		m.subs = map[int]chan Event{}
	}
	id := m.nextID
	m.nextID++
	m.subs[id] = ch
	m.subsMu.Unlock()

	return ch, func() {
		m.subsMu.Lock()
		if c, ok := m.subs[id]; ok {
			delete(m.subs, id)
			close(c)
		}
		m.subsMu.Unlock()
	}
}

func (m *Manager) publish(ev Event) {
	m.subsMu.Lock()
	defer m.subsMu.Unlock()
	for _, ch := range m.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

// NewManager builds a manager for cfg.
func NewManager(cfg *server.Config, engine runtime.Engine, log *slog.Logger) (*Manager, error) {
	if err := os.MkdirAll(filepath.Join(cfg.StateDir, "env"), 0o700); err != nil {
		return nil, fmt.Errorf("prepare state dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(cfg.StateDir, "secrets"), 0o700); err != nil {
		return nil, fmt.Errorf("prepare secrets dir: %w", err)
	}
	m := &Manager{cfg: cfg, engine: engine, log: log}
	for _, tc := range cfg.Tunnels {
		trojanPassword, err := loadOrCreateSecret(cfg.StateDir, tc.Name+".trojan")
		if err != nil {
			return nil, err
		}
		var secret string
		var client *contract.Client
		if tc.NeedsContainer() {
			secret, err = loadOrCreateSecret(cfg.StateDir, tc.Name+".secret")
			if err != nil {
				return nil, err
			}
			client = contract.NewClient(fmt.Sprintf("127.0.0.1:%d", tc.ControlPort), secret)
		}

		var routes, dnsServers, searchDomains []string
		if tc.Extra != nil {
			if r := tc.Extra["routes"]; r != "" {
				for _, p := range strings.Split(r, ",") {
					if s := strings.TrimSpace(p); s != "" {
						routes = append(routes, s)
					}
				}
			}
			if d := tc.Extra["dns"]; d != "" {
				for _, p := range strings.Split(d, ",") {
					if s := strings.TrimSpace(p); s != "" {
						dnsServers = append(dnsServers, s)
					}
				}
			}
			if s := tc.Extra["search_domains"]; s != "" {
				for _, p := range strings.Split(s, ",") {
					if s := strings.TrimSpace(p); s != "" {
						searchDomains = append(searchDomains, s)
					}
				}
			}
			if s := tc.Extra["domains"]; s != "" {
				for _, p := range strings.Split(s, ",") {
					if s := strings.TrimSpace(p); s != "" {
						searchDomains = append(searchDomains, s)
					}
				}
			}
		}

		initialState := contract.StateDown
		isNoContainer := !tc.NeedsContainer()
		if isNoContainer {
			initialState = contract.StateUp
		}

		m.tunnels = append(m.tunnels, &Tunnel{
			cfg:            tc,
			engine:         engine,
			mgr:            m,
			secret:         secret,
			trojanPassword: trojanPassword,
			client:         client,
			log:            log.With("tunnel", tc.Name),
			stateDir:       cfg.StateDir,
			pullPolicy:     cfg.PullPolicy,
			wake:           make(chan struct{}, 1),
			snap: Snapshot{
				Name:            tc.Name,
				Provider:        tc.Provider,
				Disabled:        tc.Disabled,
				Reachable:       isNoContainer,
				ContainerExists: false,
				ContainerUp:     isNoContainer,
				Status: contract.Status{
					Contract: contract.Version,
					Provider: tc.Provider,
					State:    initialState,
				},
				Network: contract.Network{
					Routes:        routes,
					DNS:           dnsServers,
					SearchDomains: searchDomains,
					UDP:           true,
				},
			},
		})
	}
	for _, t := range m.tunnels {
		t.wanted.Store(t.restoreWish())
		t.mu.Lock()
		t.snap.Wanted = t.wanted.Load()
		t.mu.Unlock()
	}
	return m, nil
}

// wishPath records whether a tunnel was asked to dial, so a server restart
// brings back what was running rather than everything at once.
func (t *Tunnel) wishPath() string {
	return filepath.Join(t.stateDir, "wanted", t.cfg.Name)
}

func (t *Tunnel) restoreWish() bool {
	// A tunnel disabled in the configuration is not going to dial whatever
	// anybody wished for it, and saying otherwise describes it as a tunnel
	// that ought to be up and is not -- which is a warning in every interface
	// that reads this, and one nobody can clear.
	if t.cfg.Disabled {
		return false
	}
	b, err := os.ReadFile(t.wishPath())
	if err != nil {
		if !t.cfg.NeedsContainer() {
			return !t.cfg.Disabled
		}
		// Never asked either way: dial only if the configuration says to.
		return t.cfg.Autostart
	}
	return strings.TrimSpace(string(b)) == "yes"
}

func (t *Tunnel) recordWish(want bool) {
	value := "no"
	if want {
		value = "yes"
	}
	if err := os.MkdirAll(filepath.Dir(t.wishPath()), 0o700); err != nil {
		t.log.Warn("could not record whether this tunnel should dial", "error", err)
		return
	}
	if err := os.WriteFile(t.wishPath(), []byte(value+"\n"), 0o600); err != nil {
		t.log.Warn("could not record whether this tunnel should dial", "error", err)
	}
}

// SetInitiator records the user that started the tunnel.
func (t *Tunnel) SetInitiator(user string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.initiator = user
}

// Initiator returns the user that started the tunnel, if any.
func (t *Tunnel) Initiator() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.initiator
}

// Start asks a tunnel to dial.
func (m *Manager) Start(name string) error {
	return m.StartWithInitiator(name, "")
}

// StartWithInitiator asks a tunnel to dial on behalf of an authenticated user.
func (m *Manager) StartWithInitiator(name, initiator string) error {
	t, ok := m.Lookup(name)
	if !ok {
		return fmt.Errorf("no tunnel named %q", name)
	}
	if t.cfg.Disabled {
		return fmt.Errorf("tunnel %q is disabled in the configuration", name)
	}
	t.SetInitiator(initiator)
	t.setWanted(true)
	return nil
}

// Stop takes a tunnel down and leaves it down.
func (m *Manager) Stop(name string) error {
	t, ok := m.Lookup(name)
	if !ok {
		return fmt.Errorf("no tunnel named %q", name)
	}
	t.setWanted(false)
	return nil
}

func (t *Tunnel) setWanted(want bool) {
	if t.wanted.Swap(want) == want {
		return
	}
	t.recordWish(want)

	t.mu.Lock()
	t.snap.Wanted = want
	if !want {
		t.snap.Reachable = false
		t.snap.ContainerUp = false
		t.snap.Status.State = contract.StateDown
		t.snap.LastError = ""
	} else if !t.cfg.NeedsContainer() {
		t.snap.Reachable = true
		t.snap.ContainerUp = true
		t.snap.Status.State = contract.StateUp
		t.snap.LastError = ""
	}
	after := t.snap
	t.mu.Unlock()

	t.publish(after)
	if want {
		t.log.Info("asked to dial")
	} else {
		t.log.Info("asked to stop")
	}
	select {
	case t.wake <- struct{}{}:
	default:
	}
}

// Run reconciles and supervises every tunnel until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, t := range m.tunnels {
		wg.Add(1)
		go func() { defer wg.Done(); t.supervise(ctx) }()
	}
	wg.Wait()
}

// Snapshots returns the current view of every tunnel, in name order.
func (m *Manager) Snapshots() []Snapshot {
	out := make([]Snapshot, 0, len(m.tunnels))
	for _, t := range m.tunnels {
		out = append(out, t.Snapshot())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Lookup returns the tunnel with the given name.
func (m *Manager) Lookup(name string) (*Tunnel, bool) {
	for _, t := range m.tunnels {
		if t.cfg.Name == name {
			return t, true
		}
	}
	return nil, false
}

// Shutdown leaves the tunnel containers running, so the next start adopts the
// sessions that are already dialled instead of replacing them.
//
// Stopping them would not preserve anything: the VPN client lives inside the
// container, and killing it ends the session no matter that the container is
// kept around. reconcile already treats a running container with a matching
// configuration as the one it wanted, so the cost of a restart is the moment
// the listener is unbound rather than a fresh login at every gateway.
//
// stop_containers_on_exit asks for the older behaviour, for a server whose
// stopping should leave nothing dialled behind it.
func (m *Manager) Shutdown(ctx context.Context) {
	if !m.cfg.StopContainersOnExit {
		return
	}
	for _, t := range m.tunnels {
		if !t.cfg.NeedsContainer() {
			continue
		}
		if err := t.engine.Stop(ctx, t.cfg.ContainerName(), stopGraceSeconds); err != nil {
			t.log.Warn("stopping container failed", "error", err)
		}
	}
}

// Snapshot returns this tunnel's current state.
func (t *Tunnel) Snapshot() Snapshot {
	t.mu.RLock()
	defer t.mu.RUnlock()
	s := t.snap
	s.TrojanPassword = t.trojanPassword
	return s
}

// Client exposes the container's control plane, for relaying interactive
// authentication from a client.
func (t *Tunnel) Client() *contract.Client { return t.client }

// Logs returns recent container output.
func (t *Tunnel) Logs(ctx context.Context, tail int) (string, error) {
	if t.cfg.IsDirect() {
		return fmt.Sprintf("tunnel %q is a direct host tunnel routing through the server's network without a container", t.cfg.Name), nil
	}
	if t.cfg.IsTrojan() {
		return fmt.Sprintf("tunnel %q is an upstream Trojan tunnel forwarding traffic to %s (sni: %s)", t.cfg.Name, t.cfg.Server, t.cfg.UpstreamServerName()), nil
	}
	return t.engine.Logs(ctx, t.cfg.ContainerName(), tail)
}

func (t *Tunnel) supervise(ctx context.Context) {
	if t.cfg.Disabled {
		t.log.Info("tunnel is disabled, not starting")
		// A disabled tunnel must not keep a container from a previous run.
		if t.cfg.NeedsContainer() {
			if err := t.engine.Remove(ctx, t.cfg.ContainerName()); err != nil {
				t.log.Warn("removing disabled tunnel's container failed", "error", err)
			}
		}
		return
	}

	if !t.cfg.NeedsContainer() {
		start := time.Now()
		for {
			wanted := t.wanted.Load()
			t.mu.Lock()
			t.snap.Wanted = wanted
			t.snap.Reachable = wanted
			t.snap.ContainerUp = wanted
			if wanted {
				t.snap.Status.State = contract.StateUp
				t.snap.Status.Since = start
				t.snap.Status.ConnectedAt = &start
				t.snap.Status.UptimeSeconds = int64(time.Since(start).Seconds())
			} else {
				t.snap.Status.State = contract.StateDown
				t.snap.Status.UptimeSeconds = 0
			}
			after := t.snap
			t.mu.Unlock()
			t.publish(after)

			select {
			case <-ctx.Done():
				return
			case <-t.wake:
			}
		}
	}

	backoff := restartMin
	for {
		// A tunnel nobody has asked for stays down. Dialling on our own
		// schedule is what turns a gateway refusing us into an account
		// getting locked while nobody is watching.
		if !t.wanted.Load() {
			t.stopContainer(ctx)
			if !t.awaitWish(ctx) {
				return
			}
			backoff = restartMin
			continue
		}

		if err := t.reconcile(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			t.setError(err)
			wait := jitter(backoff)
			t.log.Warn("reconcile failed, retrying", "error", err, "in", wait.Round(time.Second))
			if !sleepCtx(ctx, wait) {
				return
			}
			backoff = min(backoff*2, restartMax)
			continue
		}
		backoff = restartMin

		// Poll until the container needs attention again.
		switch t.pollUntilUnhealthy(ctx) {
		case pollShuttingDown:
			return
		case pollAskedToStop:
			continue // the top of the loop takes it down
		}
		t.log.Warn("container is unresponsive, recreating")
		if err := t.engine.Remove(ctx, t.cfg.ContainerName()); err != nil {
			t.log.Warn("removing unresponsive container failed", "error", err)
		}
	}
}

// stopContainer takes the container down without removing it, so a tunnel
// that authenticated interactively does not have to do it again.
func (t *Tunnel) stopContainer(ctx context.Context) {
	st, err := t.engine.Inspect(ctx, t.cfg.ContainerName())
	if err != nil || !st.Running {
		return
	}
	if err := t.engine.Stop(ctx, t.cfg.ContainerName(), stopGraceSeconds); err != nil {
		t.log.Warn("stopping the container failed", "error", err)
	}
}

// awaitWish blocks until the tunnel is asked to dial, reporting false when
// the server is shutting down instead.
func (t *Tunnel) awaitWish(ctx context.Context) bool {
	for {
		// Checked before waiting as well as after: a start can arrive between
		// the supervisor deciding to wait and it actually doing so, and the
		// wish is the truth rather than the signal.
		if t.wanted.Load() {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-t.wake:
		}
	}
}

// reconcile brings the container in line with the configuration, creating or
// recreating it as needed.
func (t *Tunnel) reconcile(ctx context.Context) error {
	if err := t.engine.EnsureNetwork(ctx, t.cfg.NetworkName()); err != nil {
		return err
	}
	hash, err := t.writeEnvFile()
	if err != nil {
		return err
	}

	name := t.cfg.ContainerName()
	st, err := t.engine.Inspect(ctx, name)
	if err != nil {
		return err
	}

	// Recreate when the configuration behind the container changed. Comparing
	// a hash of the whole spec catches a rotated password just as well as a
	// new image.
	if st.Exists && st.ConfigHash != hash {
		t.log.Info("configuration changed, recreating container")
		if err := t.engine.Remove(ctx, name); err != nil {
			return err
		}
		st = runtime.Status{}
	}

	ports := []runtime.PortMap{
		{HostPort: t.cfg.DataPort, ContainerPort: contract.PortData},
		{HostPort: t.cfg.ControlPort, ContainerPort: contract.PortControl},
	}
	if t.cfg.VNCPort > 0 {
		// A graphical login screen, published on loopback like everything
		// else. It carries no authentication of its own, so it must never
		// reach further than the server itself.
		ports = append(ports, runtime.PortMap{HostPort: t.cfg.VNCPort, ContainerPort: vncContainerPort})
	}

	if !st.Exists {
		if err := t.ensureImage(ctx); err != nil {
			return err
		}
		tunnelDir := filepath.Join(t.stateDir, "tunnels", t.cfg.Name)
		if err := os.MkdirAll(tunnelDir, 0o777); err != nil {
			t.log.Warn("could not create tunnel data directory", "path", tunnelDir, "error", err)
		} else {
			_ = os.Chmod(tunnelDir, 0o777)
		}

		spec := runtime.Spec{
			Name:       name,
			Image:      t.cfg.Image,
			Network:    t.cfg.NetworkName(),
			Hostname:   cleanHostname("pc-" + t.cfg.Name),
			MacAddress: deterministicMAC(t.cfg.Name),
			Volumes:    []string{fmt.Sprintf("%s:/data", tunnelDir)},
			EnvFile:    t.cfg.EnvFilePath(t.stateDir),
			Ports:      ports,
			CapAdd:     t.cfg.CapAdd,
			Devices:    t.cfg.Devices,
			Labels: map[string]string{
				runtime.LabelConfigHash: hash,
				contract.LabelProvider:  t.cfg.Provider,
				contract.LabelContract:  fmt.Sprint(contract.Version),
			},
		}
		if err := t.engine.Create(ctx, spec); err != nil {
			return fmt.Errorf("create container: %w", err)
		}
	}
	if !st.Running {
		if err := t.engine.Start(ctx, name); err != nil {
			return fmt.Errorf("start container: %w", err)
		}
		t.log.Info("container started", "data_port", t.cfg.DataPort, "control_port", t.cfg.ControlPort)
	}

	t.mu.Lock()
	t.snap.ContainerExists = true
	t.snap.ContainerUp = true
	t.snap.LastError = ""
	t.unreachable = 0
	t.mu.Unlock()
	return nil
}

// ensureImage fetches the tunnel's image when it is needed.
//
// Images are built on a workstation and pushed to a registry, so a server
// that has never run this tunnel does not have one. Creating the container
// would fail with the engine's own message about an unknown image, which says
// nothing about where it was meant to come from.
func (t *Tunnel) ensureImage(ctx context.Context) error {
	switch t.pullPolicy {
	case "never":
		present, err := t.engine.HasImage(ctx, t.cfg.Image)
		if err != nil {
			return err
		}
		if !present {
			return fmt.Errorf("%s is not on this machine and pull_policy is never; "+
				"push it from wherever it is built, or change the policy", t.cfg.Image)
		}
		return nil
	case "always":
	default: // "missing"
		present, err := t.engine.HasImage(ctx, t.cfg.Image)
		if err != nil {
			return err
		}
		if present {
			return nil
		}
	}

	t.log.Info("fetching the image", "image", t.cfg.Image)
	if err := t.engine.Pull(ctx, t.cfg.Image); err != nil {
		return fmt.Errorf("fetch %s: %w", t.cfg.Image, err)
	}
	t.log.Info("image fetched", "image", t.cfg.Image)
	return nil
}

// pollOutcome says why polling stopped, because the three reasons call for
// three different things and telling them apart is what keeps a container
// from being recreated for no reason.
type pollOutcome int

const (
	// pollShuttingDown: the server is stopping.
	pollShuttingDown pollOutcome = iota
	// pollAskedToStop: someone asked for this tunnel to come down.
	pollAskedToStop
	// pollUnhealthy: the container stopped answering and needs recreating.
	pollUnhealthy
)

// pollUntilUnhealthy refreshes status until something needs doing.
func (t *Tunnel) pollUntilUnhealthy(ctx context.Context) pollOutcome {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return pollShuttingDown

		case <-t.wake:
			// A wake means the wish may have changed, not that anything is
			// wrong. It can also be stale: a start that arrived before this
			// loop began still leaves one buffered. Treating that as a fault
			// would tear the container down and dial the gateway again for
			// nothing, which is the opposite of what waiting to be asked is
			// for. So the wish is what decides.
			if !t.wanted.Load() {
				return pollAskedToStop
			}
			continue

		case <-ticker.C:
		}

		if !t.wanted.Load() {
			return pollAskedToStop
		}
		if t.poll(ctx) {
			continue
		}
		t.mu.Lock()
		t.unreachable++
		n := t.unreachable
		t.mu.Unlock()
		if n >= unreachableLimit {
			return pollUnhealthy
		}
	}
}

// poll refreshes one tunnel's state, reporting whether the control plane
// answered.
func (t *Tunnel) poll(ctx context.Context) bool {
	status, err := t.client.Status(ctx)
	if err != nil {
		t.mu.Lock()
		t.snap.Reachable = false
		t.snap.LastError = err.Error()
		t.mu.Unlock()
		return false
	}

	// Routes and DNS only become meaningful once the tunnel is up, so there
	// is no point fetching them before that.
	var network contract.Network
	if status.State == contract.StateUp {
		if n, err := t.client.Network(ctx); err == nil {
			network = n
		}
	}
	var challenge *contract.Challenge
	if status.State == contract.StateAuthRequired {
		challenge, _ = t.client.Challenge(ctx)
		if challenge != nil {
			t.mu.RLock()
			initUser := t.initiator
			t.mu.RUnlock()
			if initUser != "" {
				challenge.TargetUser = initUser
			}
		}
	}

	t.mu.Lock()
	if status.State == contract.StateUp || status.State == contract.StateDown || status.State == contract.StateError {
		t.initiator = ""
	}
	before := t.snap
	t.snap.Reachable = true
	t.snap.ContainerExists = true
	t.snap.ContainerUp = true
	t.snap.Status = status
	t.snap.Challenge = challenge
	if status.State == contract.StateUp {
		t.snap.Network = network
	}
	t.snap.LastError = status.Error
	t.unreachable = 0
	after := t.snap
	t.mu.Unlock()

	if changed(before, after) {
		t.publish(after)
	}
	return true
}

// changed reports whether a snapshot differs in a way a client cares about.
// Uptime and byte counters move on every poll, so comparing whole snapshots
// would turn the event stream into a firehose.
func changed(before, after Snapshot) bool {
	if before.Reachable != after.Reachable ||
		before.Status.State != after.Status.State ||
		before.LastError != after.LastError ||
		before.ContainerUp != after.ContainerUp {
		return true
	}
	beforeID, afterID := "", ""
	if before.Challenge != nil {
		beforeID = before.Challenge.ID
	}
	if after.Challenge != nil {
		afterID = after.Challenge.ID
	}
	if beforeID != afterID {
		return true
	}
	return !slices.Equal(before.Network.Routes, after.Network.Routes) ||
		!slices.Equal(before.Network.DNS, after.Network.DNS)
}

func (t *Tunnel) publish(snap Snapshot) {
	if t.mgr != nil {
		snap.TrojanPassword = t.trojanPassword
		t.mgr.publish(Event{At: time.Now(), Tunnel: snap})
	}
}

func (t *Tunnel) setError(err error) {
	t.mu.Lock()
	before := t.snap
	t.snap.Reachable = false
	t.snap.ContainerUp = false
	t.snap.LastError = err.Error()
	t.snap.Status.State = contract.StateError
	after := t.snap
	t.mu.Unlock()

	if changed(before, after) {
		t.publish(after)
	}
}

// writeEnvFile renders the container's environment to a 0600 file and returns
// a hash of it. Credentials go through a file so they never appear in the
// container engine's command line.
func (t *Tunnel) writeEnvFile() (string, error) {
	password, err := t.cfg.ResolvePassword()
	if err != nil {
		return "", err
	}
	// The attempt cap belongs to the agent, so it travels with the rest of
	// the provider settings rather than as a flag nobody would find.
	if t.cfg.MaxAttempts > 0 {
		if t.cfg.Extra == nil {
			t.cfg.Extra = map[string]string{}
		}
		if _, set := t.cfg.Extra["max_attempts"]; !set {
			t.cfg.Extra["max_attempts"] = strconv.Itoa(t.cfg.MaxAttempts)
		}
	}

	extra := "{}"
	if len(t.cfg.Extra) > 0 {
		b, err := json.Marshal(t.cfg.Extra)
		if err != nil {
			return "", fmt.Errorf("encode extra: %w", err)
		}
		extra = string(b)
	}

	// An env-file is parsed line by line, so a newline in a value would
	// silently truncate it or inject another variable.
	vars := [][2]string{
		{"VG_PROVIDER", t.cfg.Provider},
		{"VG_SERVER", t.cfg.Server},
		{"VG_USERNAME", t.cfg.Username},
		{"VG_PASSWORD", password},
		{"VG_EXTRA_JSON", extra},
		{contract.EnvAgentSecret, t.secret},
	}
	var b strings.Builder
	for _, kv := range vars {
		if strings.ContainsAny(kv[1], "\r\n") {
			return "", fmt.Errorf("%s must not contain a newline", kv[0])
		}
		fmt.Fprintf(&b, "%s=%s\n", kv[0], kv[1])
	}
	body := b.String()

	// The hash covers everything that would require a new container, not just
	// the environment.
	sum := sha256.Sum256([]byte(body + "\x00" + t.cfg.Image + "\x00" +
		strings.Join(t.cfg.CapAdd, ",") + "\x00" + strings.Join(t.cfg.Devices, ",") + "\x00" +
		fmt.Sprint(t.cfg.DataPort, t.cfg.ControlPort, t.cfg.VNCPort)))
	hash := hex.EncodeToString(sum[:8])

	path := t.cfg.EnvFilePath(t.stateDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return "", fmt.Errorf("write env file: %w", err)
	}
	return hash, nil
}

// Route describes this tunnel's place in the trojan listener.
func (t *Tunnel) Route() proxy.Route {
	if t.cfg.IsDirect() {
		return proxy.Route{
			Name:           t.cfg.Name,
			TrojanPassword: t.trojanPassword,
			Direct:         true,
		}
	}
	if t.cfg.IsTrojan() {
		host, port, _ := t.cfg.UpstreamHostPort()
		pass, _ := t.cfg.ResolvePassword()
		return proxy.Route{
			Name:           t.cfg.Name,
			TrojanPassword: t.trojanPassword,
			TrojanOutbound: &proxy.TrojanOutboundConfig{
				Server:     host,
				ServerPort: port,
				Password:   pass,
				ServerName: t.cfg.UpstreamServerName(),
				Insecure:   t.cfg.Insecure,
			},
		}
	}
	return proxy.Route{
		Name:           t.cfg.Name,
		TrojanPassword: t.trojanPassword,
		DataHost:       "127.0.0.1",
		DataPort:       t.cfg.DataPort,
		SOCKSUser:      contract.SOCKSUsername,
		SOCKSPassword:  t.secret,
	}
}

// Name is the tunnel's configured name.
func (t *Tunnel) Name() string { return t.cfg.Name }

// TrojanPassword is the client-facing credential for this tunnel.
func (t *Tunnel) TrojanPassword() string { return t.trojanPassword }

// Routes returns every enabled tunnel's listener entry. Disabled tunnels are
// left out so a client cannot select a tunnel that will never answer.
func (m *Manager) Routes() []proxy.Route {
	var out []proxy.Route
	for _, t := range m.tunnels {
		if t.cfg.Disabled {
			continue
		}
		out = append(out, t.Route())
	}
	return out
}

// Tunnels returns every managed tunnel, in configuration order.
func (m *Manager) Tunnels() []*Tunnel { return m.tunnels }

// loadOrCreateSecret returns a persisted random secret, generating one on
// first use. Persisting matters: a fresh secret each run would change every
// container's configuration hash and force every tunnel to redial, and would
// invalidate every client's saved trojan password.
func loadOrCreateSecret(stateDir, name string) (string, error) {
	path := filepath.Join(stateDir, "secrets", name)
	if b, err := os.ReadFile(path); err == nil {
		if v := strings.TrimSpace(string(b)); v != "" {
			return v, nil
		}
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("read secret for %q: %w", name, err)
	}

	raw := make([]byte, 32)
	if _, err := cryptorand.Read(raw); err != nil {
		return "", err
	}
	secret := hex.EncodeToString(raw)
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write secret for %q: %w", name, err)
	}
	return secret, nil
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func jitter(d time.Duration) time.Duration {
	return d/2 + time.Duration(rand.Int63n(int64(d/2)+1))
}

func deterministicMAC(name string) string {
	h := sha256.Sum256([]byte(name))
	return fmt.Sprintf("02:42:%02x:%02x:%02x:%02x", h[0], h[1], h[2], h[3])
}

func cleanHostname(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	res := strings.Trim(b.String(), "-")
	if len(res) > 63 {
		res = res[:63]
	}
	if res == "" {
		res = "vpngw-pc"
	}
	return res
}
