package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfigAssignsStablePorts(t *testing.T) {
	// Ports are allocated in name order, not file order, so that reordering
	// the file does not silently move every container's ports.
	path := writeConfig(t, `
port_base: 30000
tunnels:
  - {name: zulu,  provider: mock, image: img}
  - {name: alpha, provider: mock, image: img}
  - {name: mike,  provider: mock, image: img}
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	want := map[string][2]int{
		"alpha": {30000, 30001},
		"mike":  {30002, 30003},
		"zulu":  {30004, 30005},
	}
	for _, tun := range cfg.Tunnels {
		w, ok := want[tun.Name]
		if !ok {
			t.Fatalf("unexpected tunnel %q", tun.Name)
		}
		if tun.DataPort != w[0] || tun.ControlPort != w[1] {
			t.Errorf("%s: got ports %d/%d, want %d/%d", tun.Name, tun.DataPort, tun.ControlPort, w[0], w[1])
		}
	}
}

func TestLoadConfigHonoursPinnedPorts(t *testing.T) {
	path := writeConfig(t, `
port_base: 30000
tunnels:
  - {name: alpha, provider: mock, image: img, data_port: 40000, control_port: 40001}
  - {name: bravo, provider: mock, image: img}
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Tunnels[0].DataPort != 40000 || cfg.Tunnels[0].ControlPort != 40001 {
		t.Errorf("pinned ports were overwritten: %+v", cfg.Tunnels[0])
	}
	if cfg.Tunnels[1].DataPort == 0 {
		t.Error("bravo was left without a data port")
	}
}

func TestLoadConfigRejectsUnknownKeys(t *testing.T) {
	// A typo in a key must fail loudly. Silently ignoring "provder" would
	// leave a tunnel that never starts and no explanation why.
	path := writeConfig(t, `
tunnels:
  - {name: alpha, provder: mock, image: img}
`)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected an error for an unknown key")
	}
}

func TestValidateReportsEveryProblem(t *testing.T) {
	path := writeConfig(t, `
runtime: kubernetes
port_base: 80
tunnels:
  - {name: "Bad Name", provider: mock, image: img}
  - {name: dup, image: img}
  - {name: dup, provider: mock, image: img}
  - {name: creds, provider: mock, image: img, password: a, password_env: B}
`)
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected validation to fail")
	}
	msg := err.Error()
	for _, want := range []string{
		"runtime", "port_base", "name must be", "duplicate name",
		"provider is required", "at most one of password",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error is missing %q; got:\n%s", want, msg)
		}
	}
}

func TestResolvePassword(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "pw")
	// A trailing newline from an editor must not become part of the password.
	if err := os.WriteFile(file, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VG_TEST_PW", "from-env")

	tests := []struct {
		name string
		cfg  TunnelConfig
		want string
	}{
		{"inline", TunnelConfig{Password: "inline"}, "inline"},
		{"env", TunnelConfig{PasswordEnv: "VG_TEST_PW"}, "from-env"},
		{"file", TunnelConfig{PasswordFile: file}, "from-file"},
		{"unset", TunnelConfig{}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.cfg.ResolvePassword()
			if err != nil {
				t.Fatalf("ResolvePassword: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResolvePasswordMissingEnvIsAnError(t *testing.T) {
	// Falling back to an empty password would send a doomed login attempt to
	// a corporate gateway, which can lock the account.
	cfg := TunnelConfig{Name: "x", PasswordEnv: "VG_DEFINITELY_UNSET"}
	if _, err := cfg.ResolvePassword(); err == nil {
		t.Fatal("expected an error when the environment variable is unset")
	}
}
