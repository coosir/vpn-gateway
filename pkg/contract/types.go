// Package contract defines the image contract v1 spoken between a vpn-gateway
// server and the agent running inside each VPN container.
//
// A conforming container exposes two ports:
//
//	1080/tcp  data plane    SOCKS5, bound to 0.0.0.0
//	1081/tcp  control plane HTTP/JSON, the endpoints in this file
//
// Both planes require the per-tunnel secret the server passes in as
// VG_AGENT_SECRET: SOCKS5 username/password authentication (RFC 1929) on the
// data plane, and a bearer token on the control plane. Container network
// isolation is not sufficient on its own -- some engines let containers on
// separate bridge networks reach each other -- and without authentication a
// compromised vendor client could pivot straight into another tunnel.
//
// Everything a provider needs to tell the outside world travels over the
// control plane. The server never parses provider-specific output.
package contract

import "time"

// Version is the contract revision implemented by this package. Containers
// advertise it in Status.Contract and in the io.vpn-gateway.contract label.
const Version = 1

// Well-known ports inside a conforming container.
const (
	PortData    = 1080
	PortControl = 1081
)

// EnvAgentSecret names the environment variable carrying the per-tunnel
// shared secret. The username paired with it on the data plane is
// SOCKSUsername.
const EnvAgentSecret = "VG_AGENT_SECRET"

// SOCKSUsername is the fixed username for data plane authentication; the
// password is the value of EnvAgentSecret.
const SOCKSUsername = "vpngw"

// Image labels the server reads to discover provider metadata without
// starting the container.
const (
	LabelContract     = "io.vpn-gateway.contract"
	LabelProvider     = "io.vpn-gateway.provider"
	LabelCapabilities = "io.vpn-gateway.capabilities"
)

// State is the connection state of a tunnel. It is deliberately coarse: the
// server drives restarts and the UI from these five values alone.
type State string

const (
	// StateConnecting covers dialing, authenticating and route negotiation.
	StateConnecting State = "connecting"
	// StateAuthRequired means the provider is blocked on a Challenge that a
	// human must answer. The server relays it to the client GUI.
	StateAuthRequired State = "auth_required"
	// StateUp means the data plane carries traffic.
	StateUp State = "up"
	// StateDown means the tunnel stopped cleanly and is not retrying.
	StateDown State = "down"
	// StateError means the tunnel failed. Error carries the reason.
	StateError State = "error"
)

// Terminal reports whether the state will not change without intervention.
func (s State) Terminal() bool { return s == StateDown || s == StateError }

// Capability names advertised in LabelCapabilities and Status.Capabilities.
const (
	CapTCP      = "tcp"      // SOCKS5 CONNECT works. Mandatory.
	CapUDP      = "udp"      // SOCKS5 UDP ASSOCIATE works.
	CapRoutes   = "routes"   // Network.Routes is populated from the server push.
	CapDNS      = "dns"      // Network.DNS is populated from the server push.
	CapPassword = "password" // May raise a ChallengePassword.
	CapSMS      = "sms"      // May raise a ChallengeSMS.
	CapTOTP     = "totp"     // May raise a ChallengeTOTP.
	CapCaptcha  = "captcha"  // May raise a ChallengeCaptcha.
	CapURL      = "url"      // May raise a ChallengeURL.
	CapVNC      = "vnc"      // May raise a ChallengeVNC for graphical first login.
)

// Traffic counters for a tunnel, measured at the agent's SOCKS5 front door.
// Counters are cumulative for the lifetime of the container.
type Traffic struct {
	TxBytes     uint64 `json:"tx_bytes"`
	RxBytes     uint64 `json:"rx_bytes"`
	ActiveConns int    `json:"active_conns"`
	TotalConns  uint64 `json:"total_conns"`
}

// Status is the response of GET /v1/status. It answers "is this tunnel up,
// and how long has it been up".
type Status struct {
	Contract int    `json:"contract"`
	Provider string `json:"provider"`
	State    State  `json:"state"`

	// Since is when the tunnel entered State.
	Since time.Time `json:"since"`
	// ConnectedAt is when the tunnel most recently entered StateUp. It is nil
	// until the first successful connection and survives later state changes,
	// so a UI can show "last connected at" while reconnecting.
	ConnectedAt *time.Time `json:"connected_at,omitempty"`
	// UptimeSeconds is how long the current connection has been up. It is 0
	// unless State is StateUp.
	UptimeSeconds int64 `json:"uptime_seconds"`

	// Error is set when State is StateError.
	Error string `json:"error,omitempty"`

	Capabilities []string `json:"capabilities"`
	Traffic      Traffic  `json:"traffic"`
}

// Uptime returns the current connection duration as a Duration.
func (s Status) Uptime() time.Duration {
	return time.Duration(s.UptimeSeconds) * time.Second
}

// Network is the response of GET /v1/network: what the VPN server pushed to
// us at connect time. The vpn-gateway client turns Routes into implicit
// ip_cidr routing rules and DNS into a tunnel-scoped resolver, which is what
// makes split routing usable without hand-written rules.
//
// Fields are zero until State reaches StateUp.
type Network struct {
	// Routes are CIDRs the tunnel claims, in "10.20.0.0/16" form.
	Routes []string `json:"routes"`
	// DNS are resolver addresses reachable only through this tunnel.
	DNS []string `json:"dns"`
	// SearchDomains are domain suffixes that should resolve via DNS.
	SearchDomains []string `json:"search_domains"`
	// UDP reports whether the data plane supports SOCKS5 UDP ASSOCIATE. When
	// false the client must query DNS over TCP.
	UDP bool `json:"udp"`
	// MTU of the tunnel, 0 when unknown.
	MTU int `json:"mtu"`
	// AssignedIP is the address the VPN server gave us, for display.
	AssignedIP string `json:"assigned_ip,omitempty"`
}

// ChallengeType enumerates interactive authentication steps a provider can
// demand. The client GUI renders each type differently.
type ChallengeType string

const (
	ChallengePassword ChallengeType = "password"
	ChallengeSMS      ChallengeType = "sms"
	ChallengeTOTP     ChallengeType = "totp"
	ChallengeCaptcha  ChallengeType = "captcha"
	// ChallengeURL means the person must open URL in a browser, complete a
	// single sign-on flow there, and paste back what it produces.
	ChallengeURL ChallengeType = "url"
	// ChallengeVNC means the provider needs a graphical login. The agent
	// exposes a VNC server and the client embeds a viewer. This is the escape
	// hatch for vendor clients that have no headless login path.
	ChallengeVNC ChallengeType = "vnc"
)

// Challenge is the response of GET /v1/auth/challenge.
type Challenge struct {
	// ID must be echoed back in AuthAnswer. It changes on every new
	// challenge so a stale answer cannot satisfy a fresh prompt.
	ID     string        `json:"id"`
	Type   ChallengeType `json:"type"`
	Prompt string        `json:"prompt"`

	// TargetUser restricts delivery of this challenge to the initiating user.
	TargetUser string `json:"target_user,omitempty"`

	// ImageB64 is a base64 PNG or JPEG for ChallengeCaptcha.
	ImageB64 string `json:"image_b64,omitempty"`
	// URL is an SSO page for the client to open, when applicable.
	URL string `json:"url,omitempty"`
	// VNCPort is the container port serving VNC for ChallengeVNC.
	VNCPort int `json:"vnc_port,omitempty"`

	ExpiresAt time.Time `json:"expires_at"`
}

// AuthAnswer is the body of POST /v1/auth.
type AuthAnswer struct {
	ID    string `json:"id"`
	Value string `json:"value"`
}

// EventType tags a server-sent event on GET /v1/events.
type EventType string

const (
	EventStatus    EventType = "status"
	EventNetwork   EventType = "network"
	EventChallenge EventType = "challenge"
	EventLog       EventType = "log"
)

// Event is one server-sent event. Exactly one payload field is set,
// determined by Type.
type Event struct {
	Type EventType `json:"type"`
	At   time.Time `json:"at"`

	Status    *Status    `json:"status,omitempty"`
	Network   *Network   `json:"network,omitempty"`
	Challenge *Challenge `json:"challenge,omitempty"`
	Log       string     `json:"log,omitempty"`
}

// Control plane paths.
const (
	PathStatus    = "/v1/status"
	PathNetwork   = "/v1/network"
	PathEvents    = "/v1/events"
	PathChallenge = "/v1/auth/challenge"
	PathAuth      = "/v1/auth"
	PathReconnect = "/v1/reconnect"
)

// APIError is the JSON body returned for any non-2xx control plane response.
type APIError struct {
	Message string `json:"error"`
}

func (e *APIError) Error() string { return e.Message }
