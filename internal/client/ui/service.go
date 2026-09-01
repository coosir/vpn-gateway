package ui

import (
	"context"
	"errors"
	"net/http"
	"os/user"
	"path/filepath"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/client"
	"github.com/vpn-gateway/vpn-gateway/internal/client/helper"
)

// The background service is what makes a TUN interface possible from an
// application: creating one needs privileges nobody sitting at a desktop has,
// so the work is handed to a daemon that has them and the application becomes
// its front end.
//
// Installing is offered from the interface rather than a terminal because the
// person who needs it is the one who just tried to turn TUN on and was told
// they could not.

// serviceStatus is what the interface shows about the service. It is the
// helper's own answer plus the one thing only the session knows: whether there
// is anything for a service to run yet.
type serviceStatus struct {
	helper.Status
	// Ready is false while no bundle has been imported. A service installed
	// then would start, find nothing to connect to and be restarted by launchd
	// for as long as that stayed true.
	Ready bool `json:"ready"`
	// LinkFile is where the installed service publishes its interface link.
	// The application reads it to attach.
	LinkFile string `json:"link_file,omitempty"`
}

func (s *Server) serviceOptions() helper.Options {
	return helper.Options{ConfigPath: s.configPath}
}

func (s *Server) serviceState() serviceStatus {
	st := serviceStatus{
		Status:   helper.Inspect(s.serviceOptions()),
		Ready:    s.ctl.Status().Phase != client.PhaseSetup,
		LinkFile: s.ctl.Settings().UI.LinkFile,
	}
	// Answered in the order the steps have to happen in: being told to find an
	// executable, when the first thing missing is a server to connect to, is
	// an answer to a question nobody has reached yet.
	if !st.Ready {
		st.Blocker = "import a server bundle first; a service with nothing to connect to would only be restarted in a loop"
	}
	return st
}

func (s *Server) getService(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.serviceState())
}

// postServiceInstall hands this configuration to a service that can bring up a
// TUN interface, and starts it.
//
// The configuration is prepared first, while this process still owns the file:
// the service has to serve an interface, publish where it is, and give that
// link to the person who asked for the install, and none of it can be arranged
// afterwards from an application that no longer runs the engine.
func (s *Server) postServiceInstall(w http.ResponseWriter, r *http.Request) {
	st := s.serviceState()
	if !st.Supported {
		writeErr(w, http.StatusBadRequest, helper.ErrUnsupported.Error())
		return
	}
	if st.Blocker != "" {
		writeErr(w, http.StatusBadRequest, st.Blocker)
		return
	}

	if err := s.prepareForService(r.Context()); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := helper.Install(s.serviceOptions()); err != nil {
		if errors.Is(err, helper.ErrCancelled) {
			// Nothing happened, so nothing is reported as having gone wrong.
			writeJSON(w, http.StatusOK, s.serviceState())
			return
		}
		s.log.Error("could not install the background service", "error", err)
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.log.Info("installed the background service", "config", s.configPath)
	// Give the service a brief moment to be reported as running.
	var stAfter serviceStatus
	for i := 0; i < 10; i++ {
		stAfter = s.serviceState()
		if stAfter.Running {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	writeJSON(w, http.StatusOK, stAfter)
}

// prepareForService turns on the parts of the configuration only a service
// uses: an interface on a fixed port, and a link file the desktop session can
// read. Everything else is left as the person configured it.
func (s *Server) prepareForService(ctx context.Context) error {
	next := *s.ctl.Settings()
	next.UI.Enabled = true
	if next.UI.Listen == "" {
		next.UI.Listen = defaultServiceListen
	}
	if next.UI.LinkFile == "" {
		next.UI.LinkFile = ServiceLinkPath(s.configPath)
	}
	// Whoever authorises the install is who the link belongs to: root writes
	// it, and a file owned by root is one the desktop session cannot read.
	if u, err := user.Current(); err == nil && next.UI.LinkOwner == "" {
		next.UI.LinkOwner = u.Username
	}
	return s.ctl.Apply(ctx, &next)
}

// ServiceLinkPath is where the service publishes its interface link when
// nothing else was chosen: beside the configuration it runs, in a directory
// the person who installed it already owns.
//
// The application looks here to find the service it handed the engine to, so
// both sides have to agree on it.
func ServiceLinkPath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "service-link")
}

// defaultServiceListen is the port the service serves its interface on. It is
// fixed rather than chosen at random because the application finds the service
// through the link file, and a person without one can still guess this.
const defaultServiceListen = "127.0.0.1:8645"

// postServiceUninstall stops the service and removes it, leaving the
// configuration where it is.
func (s *Server) postServiceUninstall(w http.ResponseWriter, r *http.Request) {
	st := s.serviceState()
	if !st.Supported {
		writeErr(w, http.StatusBadRequest, helper.ErrUnsupported.Error())
		return
	}
	if !st.Installed {
		writeJSON(w, http.StatusOK, st)
		return
	}

	// The service's own interface is the one someone attached to the service
	// is looking at, so this is usually the service removing itself. It cannot
	// both finish the removal and answer afterwards: stopping the job
	// terminates this process. Answer first, then go.
	if st.Elevated {
		st.Installed, st.Running, st.PID = false, false, 0
		writeJSON(w, http.StatusOK, st)
		go func() {
			// Long enough for the answer to reach the page it came from.
			time.Sleep(500 * time.Millisecond)
			if err := helper.Uninstall(); err != nil {
				s.log.Error("could not remove the background service", "error", err)
			}
		}()
		return
	}

	if err := helper.Uninstall(); err != nil {
		if errors.Is(err, helper.ErrCancelled) {
			writeJSON(w, http.StatusOK, s.serviceState())
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.log.Info("removed the background service")
	writeJSON(w, http.StatusOK, s.serviceState())
}
