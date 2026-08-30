// Command vg-agent is the process that runs inside every vpn-gateway VPN
// container. It supervises one VPN provider and exposes the image contract:
// a SOCKS5 data plane on :1080 and an HTTP control plane on :1081.
//
// One binary serves every provider; the image selects one with VG_PROVIDER.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/agent"
	"github.com/vpn-gateway/vpn-gateway/pkg/contract"

	// Providers register themselves on import. Adding a VPN to vpn-gateway
	// starts here.
	_ "github.com/vpn-gateway/vpn-gateway/internal/agent/providers/mock"
	_ "github.com/vpn-gateway/vpn-gateway/internal/agent/providers/openconnect"
	_ "github.com/vpn-gateway/vpn-gateway/internal/agent/providers/sangfor"
	_ "github.com/vpn-gateway/vpn-gateway/internal/agent/providers/vendor"
)

func main() {
	var (
		dataAddr = flag.String("data", fmt.Sprintf(":%d", contract.PortData), "SOCKS5 data plane listen address")
		ctrlAddr = flag.String("control", fmt.Sprintf(":%d", contract.PortControl), "HTTP control plane listen address")
		list     = flag.Bool("providers", false, "list built-in providers and exit")
		tunnelUp = flag.Bool("tunnel-status", false, "report the VPN interface this container can see, and exit")
		logLevel = flag.String("log-level", "info", "debug, info, warn or error")
	)
	flag.Parse()

	if *list {
		fmt.Println(strings.Join(agent.Providers(), "\n"))
		return
	}

	// A container that never reports up is usually one whose client failed to
	// bring an interface up. Asking directly is faster than reading logs.
	if *tunnelUp {
		name, addr := agent.TunnelInterface()
		if name == "" {
			fmt.Println("no VPN interface is up in this container")
			os.Exit(1)
		}
		fmt.Printf("%s %s\n", name, addr)
		return
	}

	if err := run(*dataAddr, *ctrlAddr, *logLevel); err != nil {
		slog.Error("agent failed", "error", err)
		os.Exit(1)
	}
}

func run(dataAddr, ctrlAddr, logLevel string) error {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(logLevel)); err != nil {
		return fmt.Errorf("bad log level %q: %w", logLevel, err)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
	slog.SetDefault(log)

	cfg, err := agent.ConfigFromEnv()
	if err != nil {
		return err
	}
	a, err := agent.NewAgent(cfg, log.With("provider", cfg.Provider))
	if err != nil {
		return err
	}

	// SIGTERM is how a container runtime asks us to stop; cancelling here
	// unwinds the provider, both listeners and the supervisor together.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	dataLn, err := net.Listen("tcp", dataAddr)
	if err != nil {
		return fmt.Errorf("listen on data plane %s: %w", dataAddr, err)
	}
	ctrlLn, err := net.Listen("tcp", ctrlAddr)
	if err != nil {
		dataLn.Close()
		return fmt.Errorf("listen on control plane %s: %w", ctrlAddr, err)
	}

	ctrl := &http.Server{
		Handler: a.ControlHandler(),
		// No write timeout: the event stream is long-lived by design.
		ReadHeaderTimeout: 10 * time.Second,
	}

	errs := make(chan error, 2)
	go func() { errs <- a.ServeSOCKS(ctx, dataLn) }()
	go func() {
		if err := ctrl.Serve(ctrlLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- fmt.Errorf("control plane: %w", err)
			return
		}
		errs <- nil
	}()

	log.Info("agent started",
		"provider", cfg.Provider, "contract", contract.Version,
		"data", dataLn.Addr().String(), "control", ctrlLn.Addr().String(),
		"capabilities", a.Capabilities())

	supervised := make(chan struct{})
	go func() { defer close(supervised); a.Supervise(ctx) }()

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errs:
		stop()
		if err != nil {
			shutdown(ctrl)
			<-supervised
			return err
		}
	}

	shutdown(ctrl)
	<-supervised
	return nil
}

func shutdown(srv *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
}
