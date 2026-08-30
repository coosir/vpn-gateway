package ui

import (
	"encoding/json"
	"net/http"
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
