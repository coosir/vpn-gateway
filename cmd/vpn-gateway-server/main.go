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
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/server"
	"github.com/vpn-gateway/vpn-gateway/internal/server/api"
	"github.com/vpn-gateway/vpn-gateway/internal/server/certs"
	"github.com/vpn-gateway/vpn-gateway/internal/server/proxy"
	"github.com/vpn-gateway/vpn-gateway/internal/server/runtime"
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
			} else {
				fmt.Printf("  %-20s %-14s %-9s data=%d control=%d\n",
					t.Name, t.Provider, state, t.DataPort, t.ControlPort)
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

	usersMgr, err := users.NewManager(cfg.StateDir, cfg.Users, log)
	if err != nil {
		return err
	}

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
			Listen:     cfg.Trojan.Listen,
			ServerName: mat.ServerName,
			CertPath:   mat.CertPath,
			KeyPath:    mat.KeyPath,
			LogLevel:   cfg.Trojan.LogLevel,
			Routes:     mgr.Routes(),
		}, log)
		if err != nil {
			return err
		}
		defer listener.Close()
	} else {
		log.Warn("the trojan listener is disabled; no client can connect")
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); mgr.Run(ctx) }()

	apiErr := make(chan error, 1)
	go func() {
		apiErr <- api.Serve(ctx, cfg.APIListen, api.New(mgr, token, usersMgr, log).Handler(), log)
	}()

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
