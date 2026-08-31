package client

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const bundleJSON = `{
  "version": 1,
  "server": {"address": "vpn.example:443", "server_name": "vpn.example", "api_url": "http://vpn.example:8642"},
  "api_token": "tok",
  "tunnels": [{"name": "office", "password": "pw"}]
}`

func newSession(t *testing.T) (*Session, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "client.yaml")
	return NewSession(path, slog.New(slog.DiscardHandler)), path
}

func TestSessionStartsInSetupWithNothingConfigured(t *testing.T) {
	// This is what someone opening the application for the first time sees.
	// Refusing to start would leave them with nothing and nowhere to say so.
	s, _ := newSession(t)
	st := s.Status()
	if st.Phase != PhaseSetup {
		t.Errorf("phase = %q, want setup", st.Phase)
	}
	// And it still has usable defaults, so the interface has something to show.
	cfg := s.Settings()
	if !cfg.TUN.Enabled {
		t.Error("the default should have TUN enabled")
	}
}

func TestImportingABundleLeavesSetup(t *testing.T) {
	s, path := newSession(t)
	if err := s.ImportBundle([]byte(bundleJSON)); err != nil {
		t.Fatal(err)
	}

	st := s.Status()
	if st.Phase != PhaseIdle {
		t.Errorf("phase = %q, want idle", st.Phase)
	}
	if st.Server != "vpn.example:443" || st.TunnelCount != 1 {
		t.Errorf("status = %+v", st)
	}

	// The configuration is written so the next start finds it.
	if _, err := os.Stat(path); err != nil {
		t.Errorf("no configuration was written: %v", err)
	}
	saved := filepath.Join(filepath.Dir(path), "client.json")
	info, err := os.Stat(saved)
	if err != nil {
		t.Fatalf("the bundle was not saved: %v", err)
	}
	// It carries one password per tunnel.
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("the bundle is mode %o, want 600", perm)
	}
}

func TestABadBundleDoesNotReplaceAGoodOne(t *testing.T) {
	s, _ := newSession(t)
	if err := s.ImportBundle([]byte(bundleJSON)); err != nil {
		t.Fatal(err)
	}

	for _, bad := range []string{
		`not json`,
		`{"version":1}`,
		`{"version":1,"server":{"address":"a:1"},"api_token":"t"}`,
		`{"version":1,"server":{"address":"a:1"},"tunnels":[{"name":"x"}]}`,
	} {
		if err := s.ImportBundle([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if st := s.Status(); st.TunnelCount != 1 {
		t.Errorf("the working bundle was replaced: %+v", st)
	}
}

func TestSessionReloadsWhatWasSaved(t *testing.T) {
	s, path := newSession(t)
	if err := s.ImportBundle([]byte(bundleJSON)); err != nil {
		t.Fatal(err)
	}

	// A second session over the same paths picks up where the first left off.
	again := NewSession(path, slog.New(slog.DiscardHandler))
	if st := again.Status(); st.Phase != PhaseIdle || st.TunnelCount != 1 {
		t.Errorf("a restarted session came back as %+v", st)
	}
}

func TestConnectingNeedsABundle(t *testing.T) {
	s, _ := newSession(t)
	err := s.Connect(t.Context())
	if err == nil {
		t.Fatal("connecting was allowed with nothing to connect to")
	}
	if !strings.Contains(err.Error(), "bundle") {
		t.Errorf("the error does not say what is missing: %v", err)
	}
}

func TestApplyRejectsAnInvalidConfiguration(t *testing.T) {
	// Saving an invalid configuration would leave a file the next start
	// refuses, with settings that were never in effect.
	s, path := newSession(t)
	if err := s.ImportBundle([]byte(bundleJSON)); err != nil {
		t.Fatal(err)
	}

	bad := *s.Settings()
	bad.Proxy.Enabled = false
	bad.TUN.Enabled = false // no way in at all
	if err := s.Apply(t.Context(), &bad); err == nil {
		t.Fatal("a configuration with no ingress was accepted")
	}

	reloaded, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.Proxy.Enabled {
		t.Error("the rejected configuration was written anyway")
	}
}

func TestApplySwitchingToTUNFillsInTheDefaults(t *testing.T) {
	// The interface sends only the ingress choice, so a TUN interface arrives
	// with no address, MTU or stack. Rejecting that would make the switch
	// impossible from the interface.
	s, path := newSession(t)
	if err := s.ImportBundle([]byte(bundleJSON)); err != nil {
		t.Fatal(err)
	}

	next := *s.Settings()
	next.TUN = TUNConfig{Enabled: true, AutoRoute: true}
	next.Proxy.Enabled = false
	if err := s.Apply(t.Context(), &next); err != nil {
		t.Fatalf("switching to TUN was refused: %v", err)
	}

	reloaded, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.TUN.Enabled {
		t.Error("the saved configuration does not have TUN on")
	}
	if reloaded.TUN.Stack == "" || reloaded.TUN.Address == "" || reloaded.TUN.MTU == 0 {
		t.Errorf("the interface was saved incomplete: %+v", reloaded.TUN)
	}
}

func TestApplyKeepsComments(t *testing.T) {
	s, path := newSession(t)
	if err := s.ImportBundle([]byte(bundleJSON)); err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	annotated := "# my own note\n" + string(body)
	if err := os.WriteFile(path, []byte(annotated), 0o600); err != nil {
		t.Fatal(err)
	}

	next := *s.Settings()
	next.OnFailure = TargetBlock
	if err := s.Apply(t.Context(), &next); err != nil {
		t.Fatal(err)
	}

	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(saved), "# my own note") {
		t.Errorf("a hand-written comment was lost:\n%s", saved)
	}
	reloaded, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.OnFailure != TargetBlock {
		t.Errorf("on_failure = %q", reloaded.OnFailure)
	}
}

func TestDisconnectingWhenIdleIsHarmless(t *testing.T) {
	s, _ := newSession(t)
	if err := s.Disconnect(); err != nil {
		t.Errorf("disconnecting an idle session failed: %v", err)
	}
}

func TestConnectingNeedsCredentials(t *testing.T) {
	s, _ := newSession(t)
	if err := s.ImportBundle([]byte(bundleJSON)); err != nil {
		t.Fatal(err)
	}
	err := s.Connect(t.Context())
	if err == nil {
		t.Fatal("connecting should fail without username and password")
	}
	if !strings.Contains(err.Error(), "authentication required") && !strings.Contains(err.Error(), "username and password") {
		t.Errorf("error = %v, want authentication required", err)
	}
}
