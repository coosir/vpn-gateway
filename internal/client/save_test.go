package client

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const annotated = `# The bundle produced on the server.
bundle: /etc/vpn-gateway/client.json

proxy:
  enabled: true
  # Loopback only: anything else would expose the tunnels.
  listen: 127.0.0.1:1080

on_failure: direct

# Explicit rules come first, before anything derived.
rules:
  - domain_suffix: [old.example.com]
    tunnel: office

log_level: warn
`

func TestSaveRulesKeepsTheRestOfTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.yaml")
	if err := os.WriteFile(path, []byte(annotated), 0o600); err != nil {
		t.Fatal(err)
	}

	err := SaveRules(path, []Rule{
		{DomainSuffix: []string{"new.example.com"}, Tunnel: "lab"},
		{IPCIDR: []string{"10.1.0.0/16"}, Tunnel: TargetDirect},
	})
	if err != nil {
		t.Fatalf("SaveRules: %v", err)
	}

	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)

	// A configuration whose comments vanish the first time someone uses the
	// interface is one nobody will annotate again.
	for _, comment := range []string{
		"# The bundle produced on the server.",
		"# Loopback only: anything else would expose the tunnels.",
		"# Explicit rules come first, before anything derived.",
	} {
		if !strings.Contains(text, comment) {
			t.Errorf("the comment %q was lost:\n%s", comment, text)
		}
	}
	if !strings.Contains(text, "new.example.com") || !strings.Contains(text, "10.1.0.0/16") {
		t.Errorf("the new rules are missing:\n%s", text)
	}
	if strings.Contains(text, "old.example.com") {
		t.Errorf("the replaced rule is still there:\n%s", text)
	}

	// And the result still loads.
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("the saved file no longer loads: %v", err)
	}
	if len(cfg.Rules) != 2 || cfg.Rules[0].Tunnel != "lab" {
		t.Errorf("rules round-tripped as %+v", cfg.Rules)
	}
	if cfg.Proxy.Listen != "127.0.0.1:1080" || cfg.OnFailure != TargetDirect {
		t.Errorf("other settings changed: %+v", cfg)
	}
}

func TestSaveRulesAddsTheSectionWhenAbsent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.yaml")
	body := "bundle: /etc/vpn-gateway/client.json\nproxy: {enabled: true}\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := SaveRules(path, []Rule{{Domain: []string{"a.example.com"}, Tunnel: "office"}}); err != nil {
		t.Fatalf("SaveRules: %v", err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Rules) != 1 {
		t.Errorf("got %d rules, want 1", len(cfg.Rules))
	}
}

func TestSaveRulesKeepsTheKeyWhenEmptied(t *testing.T) {
	// Removing the last rule must leave the section visible, so it does not
	// look like the file never had one.
	path := filepath.Join(t.TempDir(), "client.yaml")
	if err := os.WriteFile(path, []byte(annotated), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SaveRules(path, nil); err != nil {
		t.Fatalf("SaveRules: %v", err)
	}
	out, _ := os.ReadFile(path)
	if !strings.Contains(string(out), "rules:") {
		t.Errorf("the rules key disappeared:\n%s", out)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Rules) != 0 {
		t.Errorf("got %d rules, want none", len(cfg.Rules))
	}
}

func TestSaveRulesPreservesFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.yaml")
	if err := os.WriteFile(path, []byte(annotated), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SaveRules(path, []Rule{{Domain: []string{"a"}, Tunnel: "office"}}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// The file names a bundle full of tunnel passwords.
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode is %o after saving, want 600", perm)
	}
}

func TestSaveRulesAndDisabledAuto(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.yaml")
	if err := os.WriteFile(path, []byte(annotated), 0o600); err != nil {
		t.Fatal(err)
	}

	err := SaveRulesAndDisabledAuto(path,
		[]Rule{{DomainSuffix: []string{"new.corp"}, Tunnel: "office", Disabled: true}},
		[]string{"office:ip_cidr:10.10.0.0/16"},
	)
	if err != nil {
		t.Fatalf("SaveRulesAndDisabledAuto: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Rules) != 1 || !cfg.Rules[0].Disabled {
		t.Errorf("rules = %+v", cfg.Rules)
	}
	if len(cfg.DisabledAutoRules) != 1 || cfg.DisabledAutoRules[0] != "office:ip_cidr:10.10.0.0/16" {
		t.Errorf("disabled_auto_rules = %+v", cfg.DisabledAutoRules)
	}
}

func TestSaveSettingsWithAuth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.yaml")
	if err := os.WriteFile(path, []byte(annotated), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Auth = AuthConfig{Username: "alice", Password: "secretpassword"}

	if err := SaveSettings(path, cfg); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}

	reloaded, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if reloaded.Auth.Username != "alice" || reloaded.Auth.Password != "secretpassword" {
		t.Errorf("auth = %+v", reloaded.Auth)
	}
}

func TestSaveSettingsToggleAndClearDisabledAutoRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.yaml")
	if err := os.WriteFile(path, []byte(annotated), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Disable an auto rule
	cfg.DisabledAutoRules = []string{"office:domain_suffix:internal.corp"}
	if err := SaveSettings(path, cfg); err != nil {
		t.Fatalf("SaveSettings disable: %v", err)
	}

	reloaded, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig after disable: %v", err)
	}
	if len(reloaded.DisabledAutoRules) != 1 || reloaded.DisabledAutoRules[0] != "office:domain_suffix:internal.corp" {
		t.Fatalf("expected 1 disabled auto rule, got: %+v", reloaded.DisabledAutoRules)
	}

	// 2. Re-enable the auto rule (clear DisabledAutoRules)
	reloaded.DisabledAutoRules = []string{}
	if err := SaveSettings(path, reloaded); err != nil {
		t.Fatalf("SaveSettings re-enable: %v", err)
	}

	reloaded2, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig after re-enable: %v", err)
	}
	if len(reloaded2.DisabledAutoRules) != 0 {
		t.Fatalf("expected 0 disabled auto rules after re-enabling, got: %+v", reloaded2.DisabledAutoRules)
	}
}
