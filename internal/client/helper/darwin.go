//go:build darwin

package helper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// cliName is the executable the service runs. The application ships it inside
// its own bundle so installing the service needs nothing else on the machine.
const cliName = "vpn-gateway"

// inspectTimeout bounds the commands that only read state. They are quick;
// this is only so a wedged launchctl cannot hang the interface.
const inspectTimeout = 10 * time.Second

// Inspect reports what is installed and whether installing would work.
func Inspect(opt Options) Status {
	st := Status{
		Supported:  true,
		Elevated:   os.Geteuid() == 0,
		PlistPath:  PlistPath,
		BinaryPath: BinaryPath,
	}

	if _, err := os.Stat(PlistPath); err == nil {
		st.Installed = true
		st.ConfigPath = installedConfigPath()
		st.PID, st.Running = jobState()
	}

	st.Blocker = blocker(opt)
	return st
}

// blocker answers why an install would not work, before anyone is asked for a
// password.
func blocker(opt Options) string {
	if opt.ConfigPath == "" {
		return "there is no configuration file to hand to the service yet"
	}
	if _, err := locateBinary(opt.Binary); err != nil {
		return err.Error()
	}
	return ""
}

// Install puts the service in place and starts it.
func Install(opt Options) error {
	if opt.ConfigPath == "" {
		return errors.New("the service needs a configuration file to run")
	}
	abs, err := filepath.Abs(opt.ConfigPath)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", opt.ConfigPath, err)
	}
	if _, err := os.Stat(abs); err != nil {
		return fmt.Errorf("the configuration the service would run is not readable: %w", err)
	}
	binary, err := locateBinary(opt.Binary)
	if err != nil {
		return err
	}
	return runPrivileged(installScript(binary, abs),
		"vpn-gateway needs administrator privileges to install its background service.")
}

// Uninstall stops the service and removes it. The configuration stays.
func Uninstall() error {
	return runPrivileged(uninstallScript(),
		"vpn-gateway needs administrator privileges to remove its background service.")
}

// runPrivileged runs a script as root, asking for a password unless this
// process already is root. A client that serves its own interface as root
// removes itself without a prompt: whoever can reach that interface is
// already driving a root process.
func runPrivileged(script, prompt string) error {
	if os.Geteuid() == 0 {
		out, err := exec.Command("/bin/sh", "-c", script).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}

	// No timeout: this waits for a person to type a password.
	cmd := exec.Command("/usr/bin/osascript", elevateCommand(script, prompt)...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	text := strings.TrimSpace(string(out))
	// -128 is what AppleScript reports when the prompt is dismissed. Nothing
	// went wrong, so it must not be shown as though something did.
	if strings.Contains(text, "User canceled") || strings.Contains(text, "-128") {
		return ErrCancelled
	}
	if text == "" {
		return err
	}
	return errors.New(text)
}

// jobState asks launchd whether it has the job, and whether it is up.
func jobState() (pid int, running bool) {
	ctx, cancel := context.WithTimeout(context.Background(), inspectTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/bin/launchctl", "print", "system/"+Label).Output()
	if err != nil {
		// launchctl exits non-zero when the label is not loaded, which is a
		// state rather than a failure.
		return 0, false
	}
	return parseJobPID(string(out))
}

// installedConfigPath reads the configuration out of the installed job.
func installedConfigPath() string {
	ctx, cancel := context.WithTimeout(context.Background(), inspectTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/bin/plutil", "-convert", "json", "-o", "-", PlistPath).Output()
	if err != nil {
		return ""
	}
	return configFromPlist(out)
}

// locateBinary finds the client executable to install.
//
// Beside this one first: an application bundle carries its own copy, so what
// gets installed is the version that was shipped with it rather than whatever
// an unrelated install left on PATH years ago.
func locateBinary(explicit string) (string, error) {
	if explicit != "" {
		if err := executable(explicit); err != nil {
			return "", err
		}
		return explicit, nil
	}

	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		// The command line client can install itself.
		if filepath.Base(exe) == cliName {
			return exe, nil
		}
		beside := filepath.Join(filepath.Dir(exe), cliName)
		if executable(beside) == nil {
			return beside, nil
		}
	}

	if found, err := exec.LookPath(cliName); err == nil {
		return found, nil
	}
	return "", fmt.Errorf("no %s executable was found to install; build it with `make build` and put it beside the application", cliName)
}

func executable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s cannot be read: %w", path, err)
	}
	if info.IsDir() || info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("%s is not an executable file", path)
	}
	return nil
}
