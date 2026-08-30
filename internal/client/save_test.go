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
