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
	"github.com/vpn-gateway/vpn-gateway/internal/server/runtime"
	"github.com/vpn-gateway/vpn-gateway/internal/server/tunnel"
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
		fmt.Printf("configuration is valid: %d tunnel(s)\n", len(cfg.Tunnels))
		for _, t := range cfg.Tunnels {
			state := "enabled"
			if t.Disabled {
				state = "disabled"
			}
			fmt.Printf("  %-20s %-14s %-9s data=%d control=%d\n",
				t.Name, t.Provider, state, t.DataPort, t.ControlPort)
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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); mgr.Run(ctx) }()

	apiErr := make(chan error, 1)
	go func() {
		apiErr <- api.Serve(ctx, cfg.APIListen, api.New(mgr, token, log).Handler(), log)
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

	wg.Wait()
	// Containers are stopped, not removed, so tunnels that authenticated
	// interactively do not have to do it again after a server restart.
	shutCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	mgr.Shutdown(shutCtx)
	return nil
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
