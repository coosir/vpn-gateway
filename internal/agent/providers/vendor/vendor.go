// Package vendor runs a vendor's own Linux client inside the container and
// re-exports it through the agent contract.
//
// This is the fallback for a VPN with no protocol reimplementation. The
// vendor client can mangle routes and DNS as much as it likes: it is doing so
// inside the container's own network namespace, where nothing else can see
// it. The agent shares that namespace, so once the client has connected an
// ordinary dial already goes through the tunnel and nothing else is needed to
// carry traffic.
//
// Some vendor clients have no headless login at all, so the image can expose
// a VNC server and the agent raises a contract.ChallengeVNC for the first
// login. That is ugly, and it is the honest price of a client that was never
// meant to run without a desktop.
package vendor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/agent"
	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

func init() {
	agent.Register("vendor", func() agent.Provider { return &Provider{} })
	// iNode is the vendor provider with H3C's defaults; the image supplies
	// the client itself.
	agent.Register("inode", func() agent.Provider { return &Provider{defaults: inodeDefaults} })
}

// inodeDefaults describe H3C's iNode client as the image installs it.
var inodeDefaults = defaults{
	entrypoint: "/opt/vpn-gateway/start-inode.sh",
	vncPort:    5901,
	// iNode's Linux client has no headless login.
	graphical: true,
}

type defaults struct {
	entrypoint string
	vncPort    int
	graphical  bool
}

// Provider supervises a vendor client.
//
// Recognised VG_EXTRA_JSON keys, beyond the shared network overrides:
//
//	entrypoint   script that starts the vendor client (required for "vendor")
//	vnc_port     container port serving VNC for a graphical login
//	graphical    "true" when the client cannot log in without a desktop
//	ready_probe  a host:port inside the tunnel to connect to as proof the
//	             tunnel works, instead of trusting the client's own output
type Provider struct {
	defaults defaults
	runner   agent.Runner
	vncPort  int

	// loggedIn records that the client reported a successful connection. It
	// is what marks the tunnel ready when there is no address to probe.
	loggedIn atomic.Bool
}

func (p *Provider) Capabilities() []string {
	caps := []string{contract.CapTCP, contract.CapRoutes, contract.CapDNS}
	if p.defaults.graphical {
		caps = append(caps, contract.CapVNC)
	}
	return caps
}

func (p *Provider) Run(ctx context.Context, cfg agent.Config, rep agent.Reporter) error {
	entrypoint := cfg.Str("entrypoint", p.defaults.entrypoint)
	if entrypoint == "" {
		return agent.Permanent(errors.New("extra.entrypoint is required: it starts the vendor client"))
	}
	if _, err := os.Stat(entrypoint); err != nil {
		// A missing entrypoint means the image was built without the
		// vendor's installer, which no amount of retrying will fix.
		return agent.Permanent(fmt.Errorf("%s is not in this image; rebuild it with the vendor installer: %w", entrypoint, err))
	}

	p.loggedIn.Store(false)
	p.vncPort = p.defaults.vncPort
	if v := cfg.Str("vnc_port", ""); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return agent.Permanent(fmt.Errorf("extra.vnc_port is not a number: %q", v))
		}
		p.vncPort = n
	}

	graphical := cfg.Bool("graphical", p.defaults.graphical)
	if graphical && p.vncPort > 0 {
		// Raised before the client starts: the person has to be watching the
		// screen while it asks, not after it gives up.
		rep.SetState(contract.StateAuthRequired, nil)
		rep.SetChallenge(&contract.Challenge{
			ID:      fmt.Sprintf("vnc-%d", time.Now().UnixNano()),
			Type:    contract.ChallengeVNC,
			Prompt:  "This client has no headless login. Connect to its screen and sign in; the session is kept afterwards.",
			VNCPort: p.vncPort,
			// Generous: someone has to notice, open a viewer and log in.
			ExpiresAt: time.Now().Add(30 * time.Minute),
		})
	}

	rep.SetNetwork(agent.ApplyNetworkOverrides(cfg, contract.Network{UDP: false, MTU: 1400}))

	probe := cfg.Str("ready_probe", "")
	p.runner = agent.Runner{
		Path: entrypoint,
		Args: vendorArgs(cfg),
		Env:  vendorEnv(cfg, p.vncPort),
		// The client installs its routes in this namespace, so traffic
		// leaves through them without any forwarder in between.
		DirectDial: true,
		Upstream:   probe,
		// A graphical login is a person finding a viewer and typing, so the
		// readiness deadline has to allow for it. It is suspended while a
		// challenge is pending; this covers the rest.
		ReadyTimeout: 15 * time.Minute,
		OnLine: func(line string, rep agent.Reporter) {
			if isLoggedIn(line) {
				p.loggedIn.Store(true)
				rep.SetChallenge(nil)
			}
		},
	}
	if probe == "" {
		// With nothing to connect to as proof, the client's own report of a
		// successful login is all there is to go on.
		p.runner.ReadyWhen = p.loggedIn.Load
	}
	return p.runner.Run(ctx, rep)
}

// vendorArgs passes the connection details as arguments the entrypoint script
// can read, in a fixed order so the script stays simple.
func vendorArgs(cfg agent.Config) []string {
	return []string{cfg.Server, cfg.Username}
}

// vendorEnv hands the entrypoint everything else. The password travels here
// rather than in an argument so it stays out of the container's process list.
func vendorEnv(cfg agent.Config, vncPort int) []string {
	env := []string{
		"VG_SERVER=" + cfg.Server,
		"VG_USERNAME=" + cfg.Username,
		"VG_PASSWORD=" + cfg.Password,
	}
	if vncPort > 0 {
		env = append(env, "VG_VNC_PORT="+strconv.Itoa(vncPort))
	}
	return env
}

// isLoggedIn recognises a vendor client reporting success, so the graphical
// challenge can be cleared once someone has finished with it.
func isLoggedIn(line string) bool {
	l := strings.ToLower(line)
	for _, marker := range []string{
		"login success", "logged in", "connected",
		"认证成功", "登录成功", "连接成功",
	} {
		if strings.Contains(l, marker) {
			return true
		}
	}
	return false
}

func (p *Provider) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return p.runner.Dial(ctx, network, addr)
}

// Answer accepts the acknowledgement that a graphical login is finished.
func (p *Provider) Answer(a contract.AuthAnswer) error {
	if err := p.runner.Answer(a); err == nil {
		return nil
	}
	// A VNC challenge has nothing to type back: the person logs in on the
	// screen and the client proceeds on its own. Accepting the answer just
	// clears the prompt.
	return nil
}
