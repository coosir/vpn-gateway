package helper

import (
	"encoding/base64"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

func TestRenderPlistNamesTheConfiguration(t *testing.T) {
	out := renderPlist("/Library/PrivilegedHelperTools/x", "/Users/someone/Library/Application Support/vpn-gateway/client.yaml")

	for _, want := range []string{
		"<string>" + Label + "</string>",
		"<string>-config</string>",
		"<string>/Users/someone/Library/Application Support/vpn-gateway/client.yaml</string>",
		"<string>run</string>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the job description does not contain %q:\n%s", want, out)
		}
	}
}

func TestRenderPlistEscapesPaths(t *testing.T) {
	// A home directory can contain almost anything; an unescaped ampersand
	// would produce a plist launchd refuses to load, and the service would
	// simply never start.
	out := renderPlist("/bin/x", "/Users/a&b/<c>/client.yaml")
	if strings.Contains(out, "a&b") || strings.Contains(out, "<c>") {
		t.Errorf("the path was not escaped for XML:\n%s", out)
	}
	if !strings.Contains(out, "a&amp;b") || !strings.Contains(out, "&lt;c&gt;") {
		t.Errorf("the escaped path is missing:\n%s", out)
	}
}

func TestRenderPlistIsValid(t *testing.T) {
	if _, err := exec.LookPath("plutil"); err != nil {
		t.Skip("plutil is only on macOS")
	}
	cmd := exec.Command("plutil", "-lint", "-")
	cmd.Stdin = strings.NewReader(renderPlist("/bin/x", "/tmp/client.yaml"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the generated job description is not a valid plist: %v\n%s", err, out)
	}
}

func TestShellQuoteSurvivesAQuote(t *testing.T) {
	// A path with a quote in it would otherwise end the argument early and
	// leave the rest of it running as root as its own command.
	path := "/Users/o'brien/client.yaml"
	script := "printf %s " + shellQuote(path)
	out, err := exec.Command("/bin/sh", "-c", script).Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != path {
		t.Errorf("the shell saw %q, want %q", out, path)
	}
}

func TestInstallScriptBootstrapsAfterWriting(t *testing.T) {
	script := installScript("/tmp/vpn-gateway", "/tmp/client.yaml")

	write := strings.Index(script, "cat > ")
	bootstrap := strings.Index(script, "bootstrap")
	bootout := strings.Index(script, "bootout")
	if write < 0 || bootstrap < 0 || bootout < 0 {
		t.Fatalf("the script is missing a step:\n%s", script)
	}
	if !(write < bootout && bootout < bootstrap) {
		t.Errorf("the steps are out of order:\n%s", script)
	}
	if !strings.HasPrefix(script, "set -e\n") {
		t.Errorf("the script does not stop at the first failure:\n%s", script)
	}
	// A half-installed service is worse than none, so the executable has to be
	// in place before launchd is told to run it.
	if strings.Index(script, BinaryPath) > bootstrap {
		t.Errorf("the executable is installed after the job is started:\n%s", script)
	}
}

func TestUninstallLeavesTheConfiguration(t *testing.T) {
	script := uninstallScript()
	if !strings.Contains(script, PlistPath) || !strings.Contains(script, BinaryPath) {
		t.Errorf("the script does not remove what was installed:\n%s", script)
	}
	if strings.Contains(script, "client.yaml") || strings.Contains(script, ".json") {
		t.Errorf("removing the service must not touch anyone's configuration:\n%s", script)
	}
	// Removing the service from its own interface means this script is a child
	// of the process the bootout terminates. Anything after it may not run, so
	// the files have to be gone first or the job returns at the next boot.
	if strings.Index(script, "bootout") < strings.LastIndex(script, "rm -f") {
		t.Errorf("the job is stopped before its files are removed:\n%s", script)
	}
}

func TestElevateCommandCarriesTheScriptIntact(t *testing.T) {
	script := installScript("/tmp/vpn-gateway", `/tmp/a "b" \c/client.yaml`)
	args := elevateCommand(script, `say "hello"`)

	if len(args) != 2 || args[0] != "-e" {
		t.Fatalf("unexpected osascript arguments: %q", args)
	}
	// The AppleScript source must not contain a bare quote or backslash from
	// the script; either would end the string early and change the command
	// that runs as root.
	body := strings.TrimPrefix(args[1], "do shell script ")
	if !strings.HasPrefix(body, `"`) {
		t.Fatalf("the command is not a quoted string: %s", args[1])
	}
	if !regexp.MustCompile(`^do shell script "echo [A-Za-z0-9+/=]+ \| /usr/bin/base64 -D \| /bin/sh"`).MatchString(args[1]) {
		t.Errorf("the encoded command is not the shape it should be: %s", args[1])
	}

	encoded := regexp.MustCompile(`echo ([A-Za-z0-9+/=]+) `).FindStringSubmatch(args[1])
	if encoded == nil {
		t.Fatalf("no encoded script in: %s", args[1])
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded[1])
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != script {
		t.Errorf("the script did not survive encoding:\n%s", decoded)
	}
	if !strings.Contains(args[1], `\"hello\"`) {
		t.Errorf("the prompt was not escaped for AppleScript: %s", args[1])
	}
}

func TestElevateCommandIsAcceptedByAppleScript(t *testing.T) {
	if _, err := exec.LookPath("osascript"); err != nil {
		t.Skip("osascript is only on macOS")
	}
	// Compiling checks the quoting without running anything or asking for a
	// password: a syntax error here would only ever show up as a failed
	// install on someone else's machine.
	args := elevateCommand(installScript("/tmp/vpn-gateway", `/tmp/a "b" \c.yaml`), `it's "fine"`)
	source := "on run\n" + args[1] + "\nend run\n"
	cmd := exec.Command("osacompile", "-o", t.TempDir()+"/t.scpt")
	cmd.Stdin = strings.NewReader(source)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("AppleScript would not compile the command: %v\n%s\n%s", err, out, source)
	}
}

func TestParseJobPID(t *testing.T) {
	out := `system/org.vpn-gateway.client = {
	active count = 1
	path = /Library/LaunchDaemons/org.vpn-gateway.client.plist
	state = running

	program = /Library/PrivilegedHelperTools/org.vpn-gateway.client
	pid = 4271
	immediate reason = speculative
}`
	pid, running := parseJobPID(out)
	if !running || pid != 4271 {
		t.Errorf("pid = %d running = %t, want 4271 true", pid, running)
	}
}

func TestParseJobPIDWhenLoadedButNotRunning(t *testing.T) {
	// launchd keeps the job without a process between restarts; reporting it
	// as running would show a green light over a service that is down.
	out := `system/org.vpn-gateway.client = {
	active count = 0
	state = not running
	last exit code = 1
}`
	if pid, running := parseJobPID(out); running || pid != 0 {
		t.Errorf("pid = %d running = %t, want 0 false", pid, running)
	}
}

func TestConfigFromPlist(t *testing.T) {
	in := []byte(`{"Label":"x","ProgramArguments":["/bin/x","-config","/tmp/client.yaml","run"]}`)
	if got := configFromPlist(in); got != "/tmp/client.yaml" {
		t.Errorf("config = %q", got)
	}
	if got := configFromPlist([]byte(`{"ProgramArguments":["/bin/x","run"]}`)); got != "" {
		t.Errorf("a job with no -config reported %q", got)
	}
	if got := configFromPlist([]byte("not json")); got != "" {
		t.Errorf("unreadable output reported %q", got)
	}
}
