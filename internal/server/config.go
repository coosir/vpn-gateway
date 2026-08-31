package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

// DefaultPortBase is the first loopback port handed to a tunnel container.
// These ports are an implementation detail of the server: clients never see
// them, they reach tunnels through the trojan listener instead.
const DefaultPortBase = 21000

// Config is the vpn-gateway server configuration, normally
// /etc/vpn-gateway/config.yaml.
type Config struct {
	// APIListen is where the control API for clients listens.
	APIListen string `yaml:"api_listen"`
	// StateDir holds generated env files and runtime state.
	StateDir string `yaml:"state_dir"`
	// Runtime selects the container engine: "docker", "podman", or "auto".
	Runtime string `yaml:"runtime"`
	// PortBase is the first loopback port allocated to containers.
	PortBase int `yaml:"port_base"`

	// PullPolicy decides when to fetch an image from its registry:
	// "missing" (default) pulls only what is not here, "always" checks every
	// time a container is created, "never" refuses rather than reaching out.
	//
	// Images are built elsewhere and pushed, so a server that has never seen
	// one has to fetch it; without this it would fail to create the container
	// with nothing explaining why.
	PullPolicy string `yaml:"pull_policy"`

	// Trojan configures the listener clients connect to.
	Trojan TrojanConfig `yaml:"trojan"`

	// Users defines authorized clients that must authenticate to connect.
	Users []UserConfig `yaml:"users,omitempty"`

	Tunnels []TunnelConfig `yaml:"tunnels"`
}

// UserConfig describes an authorized user on the server.
type UserConfig struct {
	Username     string `yaml:"username" json:"username"`
	PasswordHash string `yaml:"password_hash" json:"password_hash"`
}

// Authenticate verifies the plaintext password against the configured password hash.
func (u UserConfig) Authenticate(password string) bool {
	if u.PasswordHash == "" {
		return false
	}
	// bcrypt hash ($2a$, $2b$, $2y$)
	if strings.HasPrefix(u.PasswordHash, "$2a$") ||
		strings.HasPrefix(u.PasswordHash, "$2b$") ||
		strings.HasPrefix(u.PasswordHash, "$2y$") {
		return bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) == nil
	}
	// sha256 prefix
	if strings.HasPrefix(u.PasswordHash, "sha256:") {
		h := sha256.Sum256([]byte(password))
		expected := strings.TrimPrefix(u.PasswordHash, "sha256:")
		return subtle.ConstantTimeCompare([]byte(hex.EncodeToString(h[:])), []byte(expected)) == 1
	}
	// raw 64-char sha256 hex
	if len(u.PasswordHash) == 64 {
		h := sha256.Sum256([]byte(password))
		return subtle.ConstantTimeCompare([]byte(hex.EncodeToString(h[:])), []byte(u.PasswordHash)) == 1
	}
	// direct constant-time match
	return subtle.ConstantTimeCompare([]byte(u.PasswordHash), []byte(password)) == 1
}

// TrojanConfig describes the single TLS port that carries every tunnel.
type TrojanConfig struct {
	// Listen is the address to bind, normally ":443" so the traffic looks
	// like ordinary HTTPS.
	Listen string `yaml:"listen"`
	// ServerName is the name clients send as SNI and verify. For a home
	// server this is usually a dynamic DNS name.
	ServerName string `yaml:"server_name"`

	// TLSMode is "selfsigned" or "files".
	//
	// "selfsigned" generates a long-lived certificate on first run and the
	// client pins its fingerprint. This is the default because a home server
	// behind NAT usually cannot answer an HTTP-01 challenge.
	//
	// "files" uses CertFile and KeyFile. Any ACME client that supports
	// DNS-01, such as certbot or lego, produces exactly these, which is the
	// right way to get a Let's Encrypt certificate without exposing port 80.
	TLSMode  string `yaml:"tls_mode"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`

	// LogLevel is sing-box's own log level, separate from the server's.
	LogLevel string `yaml:"log_level"`

	// Disabled runs the server without a listener, for managing containers
	// before any client exists.
	Disabled bool `yaml:"disabled"`
}

// TunnelConfig describes one VPN connection. Each becomes one container and
// one trojan user.
type TunnelConfig struct {
	// Name identifies the tunnel everywhere: container name, trojan user,
	// routing rule target. It must be a valid DNS label.
	Name string `yaml:"name"`
	// Provider is the VG_PROVIDER passed to the agent, e.g. "easyconnect".
	Provider string `yaml:"provider"`
	// Image is the container image implementing the contract.
	Image string `yaml:"image"`

	Server   string `yaml:"server"`
	Username string `yaml:"username"`
	// Password is the credential in plain text. Prefer PasswordEnv or
	// PasswordFile so it never lands in the config file.
	Password string `yaml:"password"`
	// PasswordEnv names an environment variable on the server holding the
	// password.
	PasswordEnv string `yaml:"password_env"`
	// PasswordFile names a file whose entire contents are the password.
	PasswordFile string `yaml:"password_file"`

	// Extra is passed through as VG_EXTRA_JSON. Provider-specific; see each
	// provider's package documentation.
	Extra map[string]string `yaml:"extra"`

	// Capabilities the image needs from the container runtime. Providers that
	// wrap a vendor client usually need NET_ADMIN and /dev/net/tun; native
	// reimplementations need neither, so this defaults to empty.
	CapAdd  []string `yaml:"cap_add"`
	Devices []string `yaml:"devices"`

	// Disabled keeps a tunnel's configuration without starting it, and
	// without offering it to a client either.
	Disabled bool `yaml:"disabled"`

	// Autostart dials this tunnel as soon as the server comes up, rather
	// than waiting to be told.
	//
	// It defaults to off. Every dial is a full authentication against a
	// corporate gateway, and a server that reconnects on its own schedule is
	// a server that can lock an account while nobody is watching. Turn it on
	// for a tunnel that should be up without anyone logging in, and accept
	// that trade.
	Autostart bool `yaml:"autostart"`

	// MaxAttempts bounds how many times this tunnel dials before it waits to
	// be told to try again. Zero uses the agent's own default.
	MaxAttempts int `yaml:"max_attempts"`

	// DataPort and ControlPort pin the loopback ports. Zero means the server
	// allocates them from PortBase in name order.
	DataPort    int `yaml:"data_port"`
	ControlPort int `yaml:"control_port"`

	// VNCPort publishes the container's graphical login screen on this
	// loopback port. Only needed by vendor clients that cannot log in
	// headlessly; zero leaves the screen unpublished.
	VNCPort int `yaml:"vnc_port"`
}

// nameRE matches names safe to use as a container name, a trojan user and a
// routing rule target at once.
var nameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)

// LoadConfig reads and validates a configuration file.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true) // a typo in a key must fail loudly, not be ignored
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.assignPorts()
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.APIListen == "" {
		c.APIListen = "127.0.0.1:8642"
	}
	if c.StateDir == "" {
		c.StateDir = "/var/lib/vpn-gateway"
	}
	if c.Runtime == "" {
		c.Runtime = "auto"
	}
	if c.PortBase == 0 {
		c.PortBase = DefaultPortBase
	}
	if c.PullPolicy == "" {
		c.PullPolicy = "missing"
	}
	if c.Trojan.Listen == "" {
		c.Trojan.Listen = ":443"
	}
	if c.Trojan.TLSMode == "" {
		c.Trojan.TLSMode = "selfsigned"
	}
	if c.Trojan.LogLevel == "" {
		c.Trojan.LogLevel = "warn"
	}
}

// Validate reports every problem it finds rather than only the first, so a
// misconfigured file can be fixed in one pass.
func (c *Config) Validate() error {
	var errs []error

	switch c.Runtime {
	case "auto", "docker", "podman":
	default:
		errs = append(errs, fmt.Errorf("runtime: want auto, docker or podman, got %q", c.Runtime))
	}
	if c.PortBase < 1024 || c.PortBase > 65000 {
		errs = append(errs, fmt.Errorf("port_base: want 1024-65000, got %d", c.PortBase))
	}
	switch c.PullPolicy {
	case "missing", "always", "never":
	default:
		errs = append(errs, fmt.Errorf("pull_policy: want missing, always or never, got %q", c.PullPolicy))
	}
	if len(c.Tunnels) == 0 {
		errs = append(errs, errors.New("tunnels: at least one tunnel is required"))
	}
	errs = append(errs, c.Trojan.validate()...)

	seenUsers := map[string]bool{}
	for i, u := range c.Users {
		where := fmt.Sprintf("users[%d]", i)
		if u.Username == "" {
			errs = append(errs, fmt.Errorf("%s: username is required", where))
		} else if seenUsers[u.Username] {
			errs = append(errs, fmt.Errorf("%s: duplicate username %q", where, u.Username))
		} else {
			seenUsers[u.Username] = true
		}
		if u.PasswordHash == "" {
			errs = append(errs, fmt.Errorf("%s (user %q): password_hash is required", where, u.Username))
		}
	}

	seen := map[string]bool{}
	for i, t := range c.Tunnels {
		where := fmt.Sprintf("tunnels[%d]", i)
		if t.Name != "" {
			where = fmt.Sprintf("tunnels[%q]", t.Name)
		}
		if !nameRE.MatchString(t.Name) {
			errs = append(errs, fmt.Errorf("%s: name must be 1-32 chars of a-z, 0-9 and -, not starting or ending with -", where))
		}
		if seen[t.Name] {
			errs = append(errs, fmt.Errorf("%s: duplicate name", where))
		}
		seen[t.Name] = true

		if t.Provider == "" {
			errs = append(errs, fmt.Errorf("%s: provider is required", where))
		}
		if t.Image == "" {
			errs = append(errs, fmt.Errorf("%s: image is required", where))
		}
		n := 0
		for _, set := range []bool{t.Password != "", t.PasswordEnv != "", t.PasswordFile != ""} {
			if set {
				n++
			}
		}
		if n > 1 {
			errs = append(errs, fmt.Errorf("%s: set at most one of password, password_env, password_file", where))
		}
	}
	return errors.Join(errs...)
}

func (t TrojanConfig) validate() []error {
	if t.Disabled {
		return nil
	}
	var errs []error
	if _, _, err := net.SplitHostPort(t.Listen); err != nil {
		errs = append(errs, fmt.Errorf("trojan.listen: %q is not a host:port address", t.Listen))
	}
	switch t.TLSMode {
	case "selfsigned":
		// The name is baked into the generated certificate and pinned by
		// clients, so it cannot be inferred later.
		if t.ServerName == "" {
			errs = append(errs, errors.New("trojan.server_name is required with tls_mode: selfsigned"))
		}
	case "files":
		if t.CertFile == "" || t.KeyFile == "" {
			errs = append(errs, errors.New("trojan.cert_file and trojan.key_file are required with tls_mode: files"))
		}
	default:
		errs = append(errs, fmt.Errorf("trojan.tls_mode: want selfsigned or files, got %q", t.TLSMode))
	}
	return errs
}

// assignPorts gives every tunnel a stable pair of loopback ports. Allocation
// follows sorted name order so it does not depend on the order tunnels appear
// in the file.
func (c *Config) assignPorts() {
	idx := make([]int, 0, len(c.Tunnels))
	for i := range c.Tunnels {
		idx = append(idx, i)
	}
	sort.Slice(idx, func(a, b int) bool { return c.Tunnels[idx[a]].Name < c.Tunnels[idx[b]].Name })

	next := c.PortBase
	for _, i := range idx {
		t := &c.Tunnels[i]
		if t.DataPort == 0 {
			t.DataPort = next
		}
		if t.ControlPort == 0 {
			t.ControlPort = next + 1
		}
		next += 2
	}
}

// ResolvePassword returns the tunnel's password from whichever source is
// configured.
func (t TunnelConfig) ResolvePassword() (string, error) {
	switch {
	case t.PasswordEnv != "":
		v, ok := os.LookupEnv(t.PasswordEnv)
		if !ok {
			return "", fmt.Errorf("tunnel %q: environment variable %s is not set", t.Name, t.PasswordEnv)
		}
		return v, nil
	case t.PasswordFile != "":
		b, err := os.ReadFile(t.PasswordFile)
		if err != nil {
			return "", fmt.Errorf("tunnel %q: %w", t.Name, err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	default:
		return t.Password, nil
	}
}

// ContainerName is the runtime name for this tunnel's container.
func (t TunnelConfig) ContainerName() string { return "vpngw-" + t.Name }

// NetworkName is the per-tunnel container network. Every tunnel gets its own
// so a compromised vendor client cannot reach another tunnel's container or
// the containers' shared default bridge.
func (t TunnelConfig) NetworkName() string { return "vpngw-net-" + t.Name }

// EnvFilePath is where the server writes this tunnel's credentials for the
// runtime to consume at container-create time.
func (t TunnelConfig) EnvFilePath(stateDir string) string {
	return filepath.Join(stateDir, "env", t.Name+".env")
}
