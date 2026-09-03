package ui

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vpn-gateway/vpn-gateway/internal/client"
)

func TestServiceStatusNeedsTheToken(t *testing.T) {
	// The service endpoints install and remove something that runs as root.
	_, _, _, srv := testServer(t)
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/service"},
		{http.MethodPost, "/api/service/install"},
		{http.MethodPost, "/api/service/uninstall"},
	} {
		if resp := do(t, srv, c.method, c.path, "", ""); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s without a token returned %d, want 401", c.method, c.path, resp.StatusCode)
		}
	}
}

func TestInstallingIsRefusedBeforeThereIsABundle(t *testing.T) {
	// A service installed with nothing to connect to would start, fail and be
	// restarted by launchd for as long as that stayed true. The refusal says
	// what to do first, and nothing is installed.
	_, ctl, _, srv := testServer(t)
	ctl.mu.Lock()
	ctl.phase = client.PhaseSetup
	ctl.mu.Unlock()

	resp := do(t, srv, http.MethodGet, "/api/service", "tok", "")
	defer resp.Body.Close()
	var st serviceStatus
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if st.Ready {
		t.Error("a session with no bundle was reported ready for a service")
	}
	if !strings.Contains(st.Blocker, "bundle") {
		t.Errorf("the blocker does not say what is missing: %q", st.Blocker)
	}

	resp = do(t, srv, http.MethodPost, "/api/service/install", "tok", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("installing with no bundle returned %d, want 400", resp.StatusCode)
	}
	if len(ctl.applied) != 0 {
		t.Error("the configuration was changed for an install that was refused")
	}
}

func TestPreparingForTheServiceOpensAnInterfaceItCanPublish(t *testing.T) {
	// The service has to serve an interface, say where it is, and give that
	// link to the person who asked for the install. None of it can be
	// arranged afterwards by an application that no longer runs the engine.
	s, ctl, path, _ := testServer(t)

	if err := s.prepareForService(t.Context()); err != nil {
		t.Fatal(err)
	}

	cfg := ctl.Settings()
	if !cfg.UI.Enabled {
		t.Error("the service was installed without an interface")
	}
	if cfg.UI.Listen != defaultServiceListen {
		t.Errorf("ui.listen = %q", cfg.UI.Listen)
	}
	if want := ServiceLinkPath(path); cfg.UI.LinkFile != want {
		t.Errorf("ui.link_file = %q, want %q", cfg.UI.LinkFile, want)
	}
	// Root writes that file, and a file owned by root is one the desktop
	// session cannot read.
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UI.LinkOwner != me.Username {
		t.Errorf("ui.link_owner = %q, want %q", cfg.UI.LinkOwner, me.Username)
	}
	// Everything else is left as it was configured.
	if !cfg.Proxy.Enabled {
		t.Error("preparing for the service changed how traffic enters")
	}
}

func TestPreparingForTheServiceKeepsAChosenLink(t *testing.T) {
	// An operator who named a path in the file meant it.
	s, ctl, _, _ := testServer(t)
	ctl.mu.Lock()
	ctl.cfg.UI.LinkFile = "/tmp/somewhere-else"
	ctl.cfg.UI.LinkOwner = "someone"
	ctl.mu.Unlock()

	if err := s.prepareForService(t.Context()); err != nil {
		t.Fatal(err)
	}
	cfg := ctl.Settings()
	if cfg.UI.LinkFile != "/tmp/somewhere-else" || cfg.UI.LinkOwner != "someone" {
		t.Errorf("a chosen link file was replaced: %+v", cfg.UI)
	}
}

func TestServiceLinkPathSitsBesideTheConfiguration(t *testing.T) {
	// The application looks here for the service it handed the engine to, so
	// both sides have to work it out the same way.
	got := ServiceLinkPath("/Users/someone/Library/Application Support/vpn-gateway/client.yaml")
	want := filepath.Join("/Users/someone/Library/Application Support/vpn-gateway", "service-link")
	if got != want {
		t.Errorf("link path = %q, want %q", got, want)
	}
}

func TestAppLinkPathSitsBesideTheConfiguration(t *testing.T) {
	// The service reads this file to find the application, so both sides have
	// to work the path out the same way.
	got := AppLinkPath("/Users/someone/Library/Application Support/vpn-gateway/client.yaml")
	want := filepath.Join("/Users/someone/Library/Application Support/vpn-gateway", "app-link")
	if got != want {
		t.Errorf("app link path = %q, want %q", got, want)
	}
}

func TestTheApplicationIsNotSentToItsOwnInterface(t *testing.T) {
	// Every client publishes an interface, including the application reading
	// this file. Handing work to itself would be a page sent in a circle.
	s, _, path, srv := testServer(t)
	if err := os.WriteFile(AppLinkPath(path), []byte(srv.URL+"/?token=tok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if link := s.appLink(); link != "" {
		t.Errorf("the application was offered its own interface: %q", link)
	}
}

func TestAnApplicationThatHasQuitIsNotOfferedAsSomewhereToGo(t *testing.T) {
	// A link left behind by an application that is gone points at a refused
	// connection, which is the error page all of this exists to prevent.
	s, _, path, _ := testServer(t)
	dead := "http://127.0.0.1:1/?token=other"
	if err := os.WriteFile(AppLinkPath(path), []byte(dead+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if link := s.appLink(); link != "" {
		t.Errorf("a dead link was offered as somewhere to go: %q", link)
	}
}

func TestARunningApplicationIsWhereTheWorkIsSent(t *testing.T) {
	s, _, path, _ := testServer(t)

	other := &fakeController{cfg: s.ctl.Settings(), phase: client.PhaseIdle, configPath: path}
	app := httptest.NewServer(New(other, path, "app-token", slog.New(slog.DiscardHandler)).Handler())
	defer app.Close()

	link := app.URL + "/?token=app-token"
	if err := os.WriteFile(AppLinkPath(path), []byte(link+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := s.appLink(); got != link {
		t.Errorf("app link = %q, want %q", got, link)
	}
}

func TestAnInterfaceThatRefusesTheTokenIsNotReachable(t *testing.T) {
	// Reachable means an interface answered, not that something is listening:
	// a client running a different configuration has its own token and is not
	// this one's to attach to.
	s, _, path, _ := testServer(t)
	fake := &fakeController{cfg: s.ctl.Settings(), phase: client.PhaseIdle, configPath: path}
	other := httptest.NewServer(New(fake, path, "right", slog.New(slog.DiscardHandler)).Handler())
	defer other.Close()

	if reachable(other.URL + "/?token=wrong") {
		t.Error("an interface that refused the token was reported as reachable")
	}
	if !reachable(other.URL + "/?token=right") {
		t.Error("an interface that answered was not reported as reachable")
	}
}
