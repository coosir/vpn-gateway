package ui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os/user"
	"path/filepath"
	"sync"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/client"
	"github.com/vpn-gateway/vpn-gateway/internal/client/helper"
	"github.com/vpn-gateway/vpn-gateway/internal/version"
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
	// Link is the full interface URL of the running background service.
	Link string `json:"link,omitempty"`
	// Reachable is true when the running service is actually serving that
	// link. A job launchd reports as running has not necessarily opened its
	// port yet, and pointing a window at one that has not is the blank error
	// page this exists to avoid.
	Reachable bool `json:"reachable"`
	// AppLink is where the desktop application publishes its own interface.
	// It is empty unless there is one, and unless it answers.
	AppLink string `json:"app_link,omitempty"`
	// Delegate is where installing or removing the service has to be carried
	// out instead of here. A service cannot replace or stop the executable
	// that is serving this page without the page dying with it; the
	// application outlives all of it, so that is where the work belongs.
	Delegate string `json:"delegate,omitempty"`
	// Managed is true when an application owns the window this interface is
	// shown in and moves it itself. The page then leaves the moving alone.
	Managed bool `json:"managed"`
	// AppVersion is the version of this client application.
	AppVersion string `json:"app_version"`
	// Outdated is true when the installed service executable is not the one
	// that would be installed now -- a different version, or one whose
	// version cannot be read at all, which is not a service anybody can call
	// current.
	Outdated bool `json:"outdated"`
}

func (s *Server) serviceOptions() helper.Options {
	return helper.Options{ConfigPath: s.configPath}
}

func (s *Server) serviceState() serviceStatus {
	hStatus := helper.Inspect(s.serviceOptions())
	linkPath := s.ctl.Settings().UI.LinkFile
	if linkPath == "" {
		linkPath = ServiceLinkPath(s.configPath)
	}
	link, _ := ReadLink(linkPath)
	if link == "" && hStatus.Running {
		listen := s.ctl.Settings().UI.Listen
		if listen == "" {
			listen = defaultServiceListen
		}
		stateDir := s.ctl.Settings().UI.StateDir
		if stateDir == "" {
			stateDir = filepath.Dir(s.configPath)
		}
		if tok, err := ReadToken(stateDir); err == nil && tok != "" {
			link = fmt.Sprintf("http://%s/?token=%s", listen, tok)
		}
	}

	st := serviceStatus{
		Status:     hStatus,
		Ready:      s.ctl.Status().Phase != client.PhaseSetup,
		LinkFile:   linkPath,
		Link:       link,
		Managed:    s.managed,
		AppVersion: version.Full(),
	}
	if hStatus.Running && link != "" {
		st.Reachable = reachable(link)
	}
	// A root process serving this page is the service itself, and nothing it
	// does to its own executable leaves this interface alive. Where the
	// application is running, that is where the page can be sent.
	if hStatus.Elevated {
		st.AppLink = s.appLink()
	}
	// Answered in the order the steps have to happen in: being told to find an
	// executable, when the first thing missing is a server to connect to, is
	// an answer to a question nobody has reached yet.
	if !st.Ready {
		st.Blocker = "import a server bundle first; a service with nothing to connect to would only be restarted in a loop"
	}
	st.Outdated = outdated(st.Installed, st.InstalledVersion, s.replacementVersion(st.AppLink))
	return st
}

// outdated says whether the installed service is not the one that would be
// installed now.
//
// A version that could not be read counts. Saying nothing is not saying "up to
// date", and an update that reinstalls the same executable costs a prompt and
// a restart; never offering one leaves a machine on an old service with no way
// to notice.
func outdated(installed bool, installedVersion, replacement string) bool {
	if !installed {
		return false
	}
	return installedVersion != replacement
}

// replacementVersion is the version of whatever would replace the installed
// service if it were updated now: the application driving this interface when
// there is one, and this process otherwise.
//
// It is the whole reason an old service can notice that it is old. The service
// serves this page from the very executable it installed, so asking whether
// that executable is current by comparing it against this process always
// answers yes, however much newer the application asking happens to be. Once
// attaching to the service worked reliably, that was every time anybody
// looked, and the update was never offered again.
func (s *Server) replacementVersion(appLink string) string {
	if appLink != "" {
		if v := linkVersion(appLink); v != "" {
			return v
		}
	}
	return version.Full()
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
	s.busy.Add(1)
	defer s.busy.Add(-1)

	st := s.serviceState()
	if !st.Supported {
		writeErr(w, http.StatusBadRequest, helper.ErrUnsupported.Error())
		return
	}
	if st.AppLink != "" {
		// Installing over a running service stops it first, and this page is
		// served by the process being stopped: the script doing the replacing
		// would be killed halfway through it. The application outlives all of
		// that, so the answer is where to go rather than a result.
		st.Delegate = st.AppLink
		writeJSON(w, http.StatusOK, st)
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
	// The answer is what the page hands the window to, so it waits for an
	// interface rather than for a job: launchd reports a service as running
	// the moment it has started the process, which is well before that
	// process has opened its port. A window pointed at it then is the blank
	// error page this whole handover exists to avoid.
	writeJSON(w, http.StatusOK, s.awaitService(r.Context()))
}

// awaitService waits for the installed service to answer on its own
// interface, and gives up saying so rather than waiting forever: a service
// that never comes up is something the page has to be able to report.
func (s *Server) awaitService(ctx context.Context) serviceStatus {
	deadline := time.Now().Add(serviceReadyWait)
	for {
		st := s.serviceState()
		if st.Running && st.Reachable {
			return st
		}
		if time.Now().After(deadline) {
			s.log.Warn("the background service is installed but has not opened its interface yet")
			return st
		}
		select {
		case <-ctx.Done():
			return st
		case <-time.After(serviceReadyPoll):
		}
	}
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
	s.busy.Add(1)
	defer s.busy.Add(-1)

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
		st.Installed, st.Running, st.PID, st.Reachable = false, false, 0, false
		// Where there is an application, the answer also says where the page
		// should be by the time this interface is gone. Removing itself is
		// the one thing a root service can do without asking anybody for a
		// password, so it is done here rather than handed over.
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

// How long an install waits for the service it started to answer, and how
// often it asks. Long enough for a cold start on a slow machine, short enough
// that a service which is never coming up is reported rather than waited for.
const (
	serviceReadyWait = 20 * time.Second
	serviceReadyPoll = 500 * time.Millisecond
)

// AppLinkPath is where the desktop application publishes its own interface
// link, beside the configuration it edits.
//
// It is what the service reads to find the application: a privileged service
// cannot install over itself or stop itself while serving the page that asked
// it to, and the application is the process that survives both.
func AppLinkPath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "app-link")
}

// appLink returns the application's interface link, empty when there is no
// application to hand work to.
//
// A link this server wrote itself is not one to send anybody to, and neither
// is one left behind by an application that has since quit, so both are
// answered as no link at all.
func (s *Server) appLink() string {
	link, err := ReadLink(AppLinkPath(s.configPath))
	if err != nil || link == "" {
		return ""
	}
	if u, err := url.Parse(link); err == nil && u.Query().Get("token") == s.token {
		return ""
	}
	if !reachable(link) {
		return ""
	}
	return link
}

// Probing an interface is one loopback request, but the page asks for service
// state on every update, so the answer is held briefly rather than asked for
// again on each one.
const (
	probeTTL     = time.Second
	probeTimeout = 900 * time.Millisecond
	probeMemory  = 32
)

var probes sync.Map // link -> *probeResult

type probeResult struct {
	mu sync.Mutex
	at time.Time
	// got is whether the interface answered, and version is what it said it
	// was. They come from one request because they are one question: what, if
	// anything, is running there.
	got     bool
	version string
}

// reachable answers whether an interface link is being served right now.
func reachable(link string) bool {
	p := probed(link)
	return p.got
}

// linkVersion is the version of the client serving a link, empty when nothing
// is serving it.
func linkVersion(link string) string {
	p := probed(link)
	return p.version
}

func probed(link string) probeResult {
	forgetStaleProbes()
	v, _ := probes.LoadOrStore(link, &probeResult{})
	p := v.(*probeResult)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.at.IsZero() || time.Since(p.at) >= probeTTL {
		p.version, p.got = probe(link)
		p.at = time.Now()
	}
	return probeResult{at: p.at, got: p.got, version: p.version}
}

// forgetStaleProbes keeps what is remembered here to a size a machine could
// plausibly be running. Every restart of an application publishes a link of
// its own, and none of the old ones will be asked about again.
func forgetStaleProbes() {
	n := 0
	probes.Range(func(any, any) bool {
		n++
		return n <= probeMemory
	})
	if n > probeMemory {
		probes.Clear()
	}
}

// probe asks an interface for its state, and reports what version answered.
// Anything but an answer -- a refused connection, a timeout, a token the other
// side does not accept -- means there is nothing there to send a window to.
func probe(link string) (version string, ok bool) {
	u, err := url.Parse(link)
	if err != nil || u.Host == "" {
		return "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.Scheme+"://"+u.Host+"/api/state", nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("Authorization", "Bearer "+u.Query().Get("token"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	var st State
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		// It answered, which is the part the window depends on.
		return "", true
	}
	return st.Version, true
}
