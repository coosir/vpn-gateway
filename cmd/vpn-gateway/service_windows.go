//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"

	"github.com/vpn-gateway/vpn-gateway/internal/client/helper"
)

const (
	// serviceRetryMin and serviceRetryMax bound how long the service waits
	// before trying again after the client failed to come up.
	serviceRetryMin = 3 * time.Second
	serviceRetryMax = time.Minute
	// serviceStopWait is how long a stop waits for the client to tear down
	// its interface and routes before reporting stopped anyway.
	serviceStopWait = 20 * time.Second
	// serviceLogLimit is how large the log grows before it is set aside.
	serviceLogLimit = 10 << 20
)

type windowsService struct {
	configPath string
	logLevel   string
}

// Execute runs the client for the service manager.
//
// A client that fails to come up is tried again rather than taken as the
// service failing. At boot it is often early: the network, the profile
// holding the configuration or the TUN driver are not ready yet. Exiting then
// left a service reported stopped, which Windows does not restart, and which
// the person at the machine could only get back by reinstalling it.
func (s *windowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	logFile := openServiceLog()
	if logFile != nil {
		defer logFile.Close()
	}
	logf := func(format string, a ...any) {
		if logFile != nil {
			fmt.Fprintf(logFile, "%s service: %s\n", time.Now().Format(time.RFC3339), fmt.Sprintf(format, a...))
		}
	}
	logf("starting, config %s", s.configPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		wait := serviceRetryMin
		for {
			started := time.Now()
			// Each attempt has a context of its own, so whatever a failed one
			// left running -- its interface holding the port -- is shut down
			// before the next tries to open it.
			attempt, endAttempt := context.WithCancel(ctx)
			err := run(attempt, s.configPath, s.logLevel, "run")
			endAttempt()
			if ctx.Err() != nil {
				return
			}
			if err == nil {
				err = fmt.Errorf("the client stopped without being asked to")
			}
			// A client that ran for a while before failing is not failing to
			// start, so it gets the short wait again.
			if time.Since(started) > 5*serviceRetryMax {
				wait = serviceRetryMin
			}
			logf("the client stopped: %v; trying again in %s", err, wait)
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			wait = min(wait*2, serviceRetryMax)
		}
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for req := range r {
		switch req.Cmd {
		case svc.Interrogate:
			changes <- req.CurrentStatus
		case svc.Stop, svc.Shutdown:
			logf("asked to stop")
			changes <- svc.Status{State: svc.StopPending, WaitHint: uint32(serviceStopWait / time.Millisecond)}
			cancel()
			// Waiting matters: stopping takes the TUN interface and its routes
			// down, and a process killed half way leaves the machine offline.
			select {
			case <-done:
			case <-time.After(serviceStopWait):
				logf("the client did not finish stopping in %s", serviceStopWait)
			}
			changes <- svc.Status{State: svc.Stopped}
			return false, 0
		}
	}
	return false, 0
}

// openServiceLog points this process's output at the service log. A service
// has no console, so everything the client prints -- including why it would
// not start -- was going nowhere.
func openServiceLog() *os.File {
	path := helper.ServiceLogPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil
	}
	if fi, err := os.Stat(path); err == nil && fi.Size() > serviceLogLimit {
		_ = os.Rename(path, path+".1")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil
	}
	// run builds its logger on os.Stderr, so pointing that here is enough.
	os.Stderr = f
	os.Stdout = f
	return f
}

func runWindowsService(configPath, logLevel string) error {
	return svc.Run(helper.ServiceName, &windowsService{configPath: configPath, logLevel: logLevel})
}

func isWindowsService() bool {
	isSvc, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return isSvc
}
