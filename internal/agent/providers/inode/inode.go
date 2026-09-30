// Package inode drives H3C's iNode SSL VPN through the vendor's own Linux
// client, without its window.
//
// The client is two programs. The window (.iNode/iNodeClient) only collects
// what a person types and passes it on; the login, the tun interface and the
// tunnel itself all live in a service, AuthenMngService, which loads
// libiNodeSslvpnPt.so to speak the protocol. That service also dials any saved
// connection marked for automatic login as soon as it starts. So the agent
// writes that saved connection itself -- the same file the window would write,
// password encrypted the same way -- starts the service, and never needs a
// desktop.
//
// The client installs its routes inside this container's own network
// namespace, which the agent shares, so once it is up an ordinary dial goes
// through the tunnel.
//
// Recognised VG_EXTRA_JSON keys, beyond the shared network overrides:
//
//	port         the gateway's port when server does not name one (443)
//	domain       the authentication domain, for a gateway that offers several
//	ready_probe  a host:port inside the tunnel to connect to as proof the
//	             tunnel works, instead of waiting for the interface
//	install_dir  where the image installed the client (/opt/inode)
//	entrypoint   the script that runs the service (install_dir's start script)
//
// There is no challenge support: a gateway that wants a captcha or an SMS code
// sends that question to the window, which is not there to show it.
package inode

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/agent"
	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

func init() {
	agent.Register("inode", func() agent.Provider { return &Provider{} })
}

const (
	defaultInstallDir = "/opt/inode"
	defaultEntrypoint = "/opt/vpn-gateway/start-inode.sh"

	// profileDir is where the service looks for saved SSL VPN connections,
	// relative to the install directory. It is what utl_GetSslvpnConfPath
	// returns; 7000 is the SSL VPN protocol's number.
	profileDir = "clientfiles/7000"
	// profileName is the one connection this container ever has.
	profileName = "vpn-gateway"

	// lostGrace is how long the interface may go without an address, once the
	// tunnel was up, before the attempt is given up. The service rebuilds a
	// dropped tunnel on its own and that is worth waiting for; a service that
	// has stopped trying is not.
	lostGrace = 2 * time.Minute
)

// Provider supervises the iNode service.
type Provider struct {
	runner agent.Runner

	// rejected holds the gateway's refusal of the credentials, so the run
	// ends as permanent rather than trying the same password until the
	// account locks.
	rejected atomic.Pointer[string]
}

func (p *Provider) Capabilities() []string {
	return []string{contract.CapTCP, contract.CapRoutes, contract.CapDNS}
}

func (p *Provider) Run(ctx context.Context, cfg agent.Config, rep agent.Reporter) error {
	if cfg.Server == "" {
		return agent.Permanent(errors.New("VG_SERVER is required"))
	}
	if cfg.Username == "" {
		return agent.Permanent(errors.New("VG_USERNAME is required"))
	}
	host, port, err := splitServer(cfg.Server, cfg.Int("port", 443))
	if err != nil {
		return agent.Permanent(err)
	}
	p.rejected.Store(nil)

	dir := cfg.Str("install_dir", defaultInstallDir)
	entrypoint := cfg.Str("entrypoint", defaultEntrypoint)
	if _, err := os.Stat(filepath.Join(dir, "AuthenMngService")); err != nil {
		// The image was built without H3C's installer. No retry fixes that.
		return agent.Permanent(fmt.Errorf("the iNode client is not installed in this image; rebuild it with make image-inode: %w", err))
	}
	addr, err := resolveGateway(ctx, host)
	if err != nil {
		// Usually DNS having a bad moment; worth another try later.
		return err
	}
	if err := writeProfile(filepath.Join(dir, profileDir), profile{
		Name:     profileName,
		Host:     host,
		Addr:     addr,
		Port:     port,
		Username: cfg.Username,
		Password: cfg.Password,
		Domain:   cfg.Str("domain", ""),
	}); err != nil {
		return agent.Permanent(err)
	}

	rep.SetNetwork(agent.ApplyNetworkOverrides(cfg, contract.Network{UDP: false, MTU: 1400}))

	probe := cfg.Str("ready_probe", "")
	p.runner = agent.Runner{
		Path:       entrypoint,
		Args:       []string{dir},
		DirectDial: true,
		Upstream:   probe,
		// A login is a few round trips to the gateway; the service's own
		// retries are what can make it slow.
		ReadyTimeout: 2 * time.Minute,
		OnLine:       p.onLine,
	}
	if probe == "" {
		// The service brings tun0 up with only a link-local address before it
		// logs in, and assigns the gateway's address once the tunnel is
		// built, so an addressed interface is the tunnel working.
		p.runner.ReadyWhen = agent.TunnelInterfaceUp
	}

	watchCtx, stopWatch := context.WithCancel(ctx)
	defer stopWatch()
	go p.watchInterface(watchCtx)

	err = p.runner.Run(ctx, rep)
	if reason := p.rejected.Load(); reason != nil && err != nil {
		return agent.Permanent(fmt.Errorf("the gateway turned down the login: %s", *reason))
	}
	return err
}

// writeProfile leaves exactly one saved connection for the service to dial.
// Anything else in the directory would be dialled too.
func writeProfile(dir string, pr profile) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	old, _ := filepath.Glob(filepath.Join(dir, "*.icnf"))
	for _, f := range old {
		os.Remove(f)
	}
	path := filepath.Join(dir, pr.Name+".icnf")
	if err := os.WriteFile(path, pr.render(), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// watchInterface ends the run when a tunnel that was up has lost its address
// for longer than the service takes to rebuild one.
func (p *Provider) watchInterface(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	var wasUp bool
	var lostAt time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if agent.TunnelInterfaceUp() {
			wasUp, lostAt = true, time.Time{}
			continue
		}
		if !wasUp {
			continue
		}
		if lostAt.IsZero() {
			lostAt = time.Now()
			continue
		}
		if time.Since(lostAt) > lostGrace {
			p.runner.Fail(fmt.Errorf("the tunnel interface has had no address for %s", lostGrace))
			return
		}
	}
}

// onLine reads the service's own log, which the start script copies to its
// output.
func (p *Provider) onLine(line string, rep agent.Reporter) {
	switch lineKind(line) {
	case lineRejected:
		reason := strings.TrimSpace(line)
		p.rejected.Store(&reason)
		// Run marks it permanent on the way out.
		p.runner.Fail(errors.New(reason))
	case lineFailed:
		// The service stays running after giving up on a connection, so
		// nothing would redial without ending the run here.
		p.runner.Fail(fmt.Errorf("the iNode service could not connect: %s", strings.TrimSpace(line)))
	case lineBuilt:
		rep.Log("iNode tunnel built")
	}
}

type kind int

const (
	lineOther kind = iota
	lineBuilt
	lineRejected
	lineFailed
)

// lineKind classifies one line of libiNodeSslvpnPt.so's log. The wording is
// the library's own, taken from its strings.
func lineKind(line string) kind {
	switch {
	case strings.Contains(line, "Tunnel Build SUCCESSFULLY"),
		strings.Contains(line, "VPN REBUILD SUCCESSFULLY"):
		return lineBuilt
	// The gateway answered the login with an error of its own: a wrong
	// password, a locked or unknown account. Trying again sends the same
	// password again.
	case strings.Contains(line, "handleAuthRespMsg the response has error information"),
		strings.Contains(line, "hasErrorTitle the http response has error title"):
		return lineRejected
	case strings.Contains(line, "startConn Failed"):
		return lineFailed
	}
	return lineOther
}

func (p *Provider) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return p.runner.Dial(ctx, network, addr)
}

func (p *Provider) Answer(a contract.AuthAnswer) error {
	return errors.New("the iNode provider asks no questions")
}
