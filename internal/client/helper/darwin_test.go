//go:build darwin

package helper

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocateBinaryChecksWhatItWasGiven(t *testing.T) {
	dir := t.TempDir()

	good := filepath.Join(dir, "vpn-gateway")
	if err := os.WriteFile(good, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := locateBinary(good); err != nil || got != good {
		t.Errorf("locateBinary(%q) = %q, %v", good, got, err)
	}

	// A configuration file where an executable should be would be installed
	// as one and produce a launchd job that fails at every boot.
	plain := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(plain, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := locateBinary(plain); err == nil {
		t.Error("a file with no execute bit was accepted as the client")
	}
	if _, err := locateBinary(filepath.Join(dir, "missing")); err == nil {
		t.Error("a path that does not exist was accepted")
	}
	if _, err := locateBinary(dir); err == nil {
		t.Error("a directory was accepted as the client")
	}
}

func TestInspectSaysWhatIsMissing(t *testing.T) {
	// Answered before anyone presses the button, so nobody is asked for a
	// password only to be told afterwards that there was nothing to install.
	st := Inspect(Options{ConfigPath: "", Binary: "/nonexistent/vpn-gateway"})
	if !st.Supported {
		t.Fatal("macOS reported no support for a background service")
	}
	if !strings.Contains(st.Blocker, "configuration") {
		t.Errorf("with no configuration the blocker was %q", st.Blocker)
	}

	st = Inspect(Options{ConfigPath: "/tmp/client.yaml", Binary: "/nonexistent/vpn-gateway"})
	if st.Blocker == "" {
		t.Error("a missing executable was not reported before the install")
	}
}

func TestInstallRefusesAConfigurationThatIsNotThere(t *testing.T) {
	// Nothing is elevated to find this out: a job pointed at a file that does
	// not exist would be restarted by launchd for as long as that stayed true.
	err := Install(Options{
		ConfigPath: filepath.Join(t.TempDir(), "missing.yaml"),
		Binary:     "/bin/sh",
	})
	if err == nil {
		t.Fatal("installing against a missing configuration was allowed")
	}
	if !strings.Contains(err.Error(), "not readable") {
		t.Errorf("error = %v", err)
	}
}
