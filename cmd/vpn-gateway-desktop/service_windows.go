//go:build desktop && windows

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/client"
	"github.com/vpn-gateway/vpn-gateway/internal/client/ui"
	"golang.org/x/sys/windows/svc"
)

type desktopService struct {
	configPath string
	logLevel   string
}

func (s *desktopService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- runHeadlessService(ctx, s.configPath, s.logLevel)
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for {
		select {
		case err := <-errCh:
			if err != nil {
				changes <- svc.Status{State: svc.StopPending}
				return true, 1
			}
			changes <- svc.Status{State: svc.Stopped}
			return false, 0
		case req := <-r:
			switch req.Cmd {
			case svc.Interrogate:
				changes <- req.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				changes <- svc.Status{State: svc.Stopped}
				return false, 0
			}
		}
	}
}

func runWindowsService(configPath, logLevel string) error {
	return svc.Run("VPNGatewayClient", &desktopService{configPath: configPath, logLevel: logLevel})
}

func isWindowsService() bool {
	isSvc, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return isSvc
}

func runHeadlessService(ctx context.Context, configPath, logLevel string) error {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(logLevel)); err != nil {
		lvl = slog.LevelInfo
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))

	cfg, err := client.LoadConfig(configPath)
	if err != nil {
		return err
	}

	session := client.NewSession(configPath, log)
	defer session.Close()

	if err := session.Connect(ctx); err != nil {
		log.Warn("the interface is running; connecting can be retried there", "error", err)
	}

	prompter := client.Prompter(nil)
	if cfg.UI.Enabled {
		token, err := ui.LoadOrCreateToken(cfg.UI.StateDir)
		if err != nil {
			return err
		}
		srv := ui.New(session, configPath, token, log)
		addr, err := ui.Serve(ctx, cfg.UI.Listen, srv.Handler(), log)
		if err != nil {
			return err
		}
		if path := cfg.UI.LinkFile; path != "" {
			_ = ui.WriteLink(path, addr, token, cfg.UI.LinkOwner)
		}
		prompter = srv.Prompter()
	}

	go watchChallenges(ctx, session, prompter)

	<-ctx.Done()
	return session.Close()
}

func watchChallenges(ctx context.Context, session *client.Session, prompter client.Prompter) {
	for {
		c := session.Client()
		if c != nil && prompter != nil {
			_ = client.WatchChallenges(ctx, c.API(), prompter)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

func handleServiceCLI(configPath string) bool {
	if isWindowsService() {
		_ = runWindowsService(configPath, "info")
		return true
	}
	if len(flag.Args()) > 0 && flag.Arg(0) == "run" {
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		if err := runHeadlessService(ctx, configPath, "info"); err != nil {
			fmt.Fprintln(os.Stderr, "vpn-gateway:", err)
			os.Exit(1)
		}
		return true
	}
	return false
}
