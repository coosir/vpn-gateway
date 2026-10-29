// Command vpn-gateway-server runs on the machine that hosts the VPN
// containers -- typically a home NAS or small always-on box.
//
// It reconciles the configured tunnels into containers, watches their
// contract control planes, and serves the client-facing control API.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/server"
	"github.com/vpn-gateway/vpn-gateway/internal/server/alert"
	"github.com/vpn-gateway/vpn-gateway/internal/server/api"
	"github.com/vpn-gateway/vpn-gateway/internal/server/certs"
	"github.com/vpn-gateway/vpn-gateway/internal/server/proxy"
	"github.com/vpn-gateway/vpn-gateway/internal/server/runtime"
	"github.com/vpn-gateway/vpn-gateway/internal/server/store"
	"github.com/vpn-gateway/vpn-gateway/internal/server/tunnel"
	"github.com/vpn-gateway/vpn-gateway/internal/server/users"
)

func main() {
	var (
		configPath = flag.String("config", "/etc/vpn-gateway/config.yaml", "path to the server configuration")
		check      = flag.Bool("check", false, "validate the configuration and exit")
		logLevel   = flag.String("log-level", "info", "debug, info, warn or error")
	)
	flag.Parse()

	if err := run(*configPath, *check, *logLevel); err != nil {
		fmt.Fprintln(os.Stderr, "vpn-gateway-server:", err)
		os.Exit(1)
	}
}

func run(configPath string, check bool, logLevel string) error {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(logLevel)); err != nil {
		return fmt.Errorf("bad log level %q: %w", logLevel, err)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
	slog.SetDefault(log)

	cfg, err := server.LoadConfig(configPath)
	if err != nil {
		return err
	}
	// Checking reads what the server would run without creating or filling a
	// database: it is often run as somebody other than the server, before the
	// server has ever started.
	_, statErr := os.Stat(filepath.Join(cfg.StateDir, store.FileName))
	var st *store.Store
	if !check || statErr == nil {
		if st, err = store.Open(cfg.StateDir); err != nil {
			return err
		}
		defer st.Close()
		if err := loadTunnels(cfg, st, check, log); err != nil {
			return err
		}
	}
	if check {
		// Resolving the credentials is part of checking: a password_env that
		// is not set would otherwise only surface when the tunnel tried to
		// log in, which for some gateways means a failed attempt against a
		// real account.
		var credErrs []error
		for _, t := range cfg.Tunnels {
			if t.Disabled {
				continue
			}
			if _, err := t.ResolvePassword(); err != nil {
				credErrs = append(credErrs, err)
			}
		}
		if len(credErrs) > 0 {
			return errors.Join(credErrs...)
		}

		fmt.Printf("configuration is valid: %d tunnel(s)\n", len(cfg.Tunnels))
		if cfg.Trojan.Disabled {
			fmt.Println("  trojan listener: disabled")
		} else {
			fmt.Printf("  trojan listener: %s  sni=%s  tls=%s\n",
				cfg.Trojan.Listen, cfg.Trojan.ServerName, cfg.Trojan.TLSMode)
		}
		for _, t := range cfg.Tunnels {
			state := "enabled"
			if t.Disabled {
				state = "disabled"
			}
			if t.IsDirect() {
				fmt.Printf("  %-20s %-14s %-9s host routing\n",
					t.Name, t.Provider, state)
			} else if t.IsTrojan() {
				fmt.Printf("  %-20s %-14s %-9s trojan -> %s\n",
					t.Name, t.Provider, state, t.Server)
			} else {
				fmt.Printf("  %-20s %-14s %-9s data=%d control=%d\n",
					t.Name, t.Provider, state, t.DataPort, t.ControlPort)
			}
			if target := t.ProbeTarget(cfg.Probe.URL); target != "" {
				fmt.Printf("  %-20s probe %s every %s\n", "", target, cfg.Probe.Interval)
			}
		}
		return nil
	}

	engine, err := runtime.Detect(cfg.Runtime)
	if err != nil {
		return err
	}
	log.Info("using container runtime", "engine", engine.Name())

	token, err := loadOrCreateToken(cfg.StateDir)
	if err != nil {
		return err
	}

	mgr, err := tunnel.NewManager(cfg, engine, log)
	if err != nil {
		return err
	}

	usersMgr, err := users.NewManagerWith(st, log)
	if err != nil {
		return err
	}

	trojanAuth := proxy.NewDynamicAuthenticator(usersMgr, log)
	usersMgr.SetRevokeHooks(
		func(username string) { trojanAuth.RevokeUser(username) },
		func(token string) { trojanAuth.RevokeSession(token) },
	)
	// Access narrowed: what the user is connected to and may no longer use
	// is cut off, not left running until they disconnect.
	usersMgr.SetAccessHook(trojanAuth.CloseDisallowed)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var listener *proxy.Proxy
	if !cfg.Trojan.Disabled {
		mat, err := resolveTLS(cfg)
		if err != nil {
			return err
		}
		if mat.SelfSigned {
			log.Info("using a self-signed certificate; clients must pin it",
				"fingerprint", mat.Fingerprint)
			if due, notAfter, err := mat.NeedsRenewal(30 * 24 * time.Hour); err == nil && due {
				log.Warn("the certificate is close to expiry; renewing it requires re-pinning every client",
					"not_after", notAfter)
			}
		}
		listener, err = proxy.New(ctx, proxy.Options{
			Listen:        cfg.Trojan.Listen,
			ServerName:    mat.ServerName,
			CertPath:      mat.CertPath,
			KeyPath:       mat.KeyPath,
			LogLevel:      cfg.Trojan.LogLevel,
			Routes:        mgr.Routes(),
			Authenticator: trojanAuth,
		}, log)
		if err != nil {
			return err
		}
		defer listener.Close()
		// The listener holds each tunnel's outbound, so it is what can send
		// a probe the way a client's traffic goes.
		mgr.SetProber(listener)
		// And it is what a tunnel added or changed in the admin page has to
		// reach before a client can use it.
		mgr.SetRouteSink(listener)
		log.Info("probing tunnels without an agent", "interval", cfg.Probe.Interval, "url", cfg.Probe.URL)
	} else {
		log.Warn("the trojan listener is disabled; no client can connect")
	}

	var wg sync.WaitGroup
	if cfg.Alerts.BarkURL != "" {
		watcher := alert.New(alert.Options{
			Notifier: alert.Bark{URL: cfg.Alerts.BarkURL},
			Grace:    cfg.Alerts.Grace,
			Label:    alertLabel(cfg),
			IsManual: mgr.IsManual,
			Log:      log.With("component", "alert"),
		})
		wg.Add(1)
		go func() { defer wg.Done(); watcher.Run(ctx, mgr) }()
		log.Info("alerting offline tunnels through Bark", "grace", cfg.Alerts.Grace)
	}
	wg.Add(1)
	go func() { defer wg.Done(); mgr.Run(ctx) }()

	apiErr := make(chan error, 1)
	apiSrv := api.New(mgr, token, usersMgr, log, trojanAuth)
	apiSrv.SetTunnelStore(st, cfg.PortBase)
	go func() {
		apiErr <- api.Serve(ctx, cfg.APIListen, apiSrv.Handler(), log)
	}()
	log.Info("admin page", "url", "http://"+adminHost(cfg.APIListen)+"/admin/")

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-apiErr:
		stop()
		if err != nil {
			wg.Wait()
			return fmt.Errorf("control API: %w", err)
		}
	}

	if listener != nil {
		listener.Close()
	}
	wg.Wait()
	// Containers are stopped, not removed, so tunnels that authenticated
	// interactively do not have to do it again after a server restart.
	shutCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	mgr.Shutdown(shutCtx)
	return nil
}

// alertLabel names this server in alerts, for someone running more than one.
func alertLabel(cfg *server.Config) string {
	if cfg.Alerts.Name != "" {
		return cfg.Alerts.Name
	}
	if cfg.Trojan.ServerName != "" {
		return cfg.Trojan.ServerName
	}
	host, _ := os.Hostname()
	return host
}

// loadTunnels replaces the configuration file's tunnels with the database's.
//
// The first time the server meets an empty database it fills it from the
// file -- tunnels, and the users from users.json or the file -- so upgrading
// changes nothing that was running. From then on the admin page edits the
// database, and tunnels left in the file are only a record of where things
// started.
func loadTunnels(cfg *server.Config, st *store.Store, readOnly bool, log *slog.Logger) error {
	seeded, err := st.Seeded()
	if err != nil {
		return err
	}
	if !seeded && readOnly {
		return nil
	}
	if !seeded {
		us, found, err := users.LoadJSONFile(cfg.StateDir)
		if err != nil {
			return err
		}
		if !found {
			us = users.FromConfig(cfg.Users)
		}
		if err := st.Seed(cfg.Tunnels, us); err != nil {
			return fmt.Errorf("import the configuration into the database: %w", err)
		}
		log.Info("imported the configuration into the database",
			"tunnels", len(cfg.Tunnels), "users", len(us), "path", filepath.Join(cfg.StateDir, store.FileName))
	} else if len(cfg.Tunnels) > 0 {
		log.Warn("the tunnels in the configuration file are not read any more; they are managed in the admin page",
			"in_file", len(cfg.Tunnels))
	}

	tunnels, err := st.Tunnels()
	if err != nil {
		return err
	}
	for i := range tunnels {
		t := &tunnels[i]
		if !readOnly && t.NeedsContainer() && (t.DataPort == 0 || t.ControlPort == 0) {
			server.AllocatePorts(t, tunnels, cfg.PortBase)
			if err := st.PutTunnel(*t); err != nil {
				return err
			}
		}
		if err := t.Validate(); err != nil {
			log.Warn("a stored tunnel does not validate; fix it in the admin page", "tunnel", t.Name, "error", err)
		}
	}
	cfg.Tunnels = tunnels
	return nil
}

// adminHost is where the admin page can be opened from this machine.
func adminHost(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return listen
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// resolveTLS produces the certificate the listener serves.
func resolveTLS(cfg *server.Config) (*certs.Material, error) {
	switch cfg.Trojan.TLSMode {
	case "files":
		return certs.Load(cfg.Trojan.CertFile, cfg.Trojan.KeyFile, cfg.Trojan.ServerName)
	default:
		return certs.EnsureSelfSigned(filepath.Join(cfg.StateDir, "tls"), cfg.Trojan.ServerName)
	}
}

// loadOrCreateToken returns the API bearer token, generating one on first
// run. It lives in the state directory at 0600 so the client can be pointed
// at it during setup.
func loadOrCreateToken(stateDir string) (string, error) {
	path := filepath.Join(stateDir, "api-token")
	b, err := os.ReadFile(path)
	if err == nil {
		if tok := strings.TrimSpace(string(b)); tok != "" {
			return tok, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read API token: %w", err)
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write API token: %w", err)
	}
	slog.Info("generated a new API token", "path", path)
	return token, nil
}
