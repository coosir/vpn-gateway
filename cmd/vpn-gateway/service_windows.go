//go:build windows

package main

import (
	"context"

	"golang.org/x/sys/windows/svc"
)

type windowsService struct {
	configPath string
	logLevel   string
}

func (s *windowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- run(ctx, s.configPath, s.logLevel, "run")
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
	return svc.Run("VPNGatewayClient", &windowsService{configPath: configPath, logLevel: logLevel})
}

func isWindowsService() bool {
	isSvc, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return isSvc
}
