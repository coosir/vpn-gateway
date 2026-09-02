// Package helper installs, inspects and removes the background service that
// runs the vpn-gateway client with the privileges a TUN interface needs.
//
// Creating a utun interface and installing routes cannot be done by a desktop
// application running as the person sitting at the machine. Splitting the
// client into a privileged helper and an unprivileged front end is the shape
// Apple designed for, but SMAppService wants a signed bundle and a developer
// identity this project does not have. What is left is the older arrangement:
// a launchd daemon that runs the ordinary client as root, installed once with
// an authorisation prompt.
//
// The service runs the *same* configuration file the application edits. One
// file means the two can never disagree about what is configured, which is
// worth more here than the isolation a private copy would buy: the file lives
// in the home directory of whoever authorised the install, and that person can
// already reroute this machine's traffic by definition. The executable is a
// different matter and is copied somewhere only root can write, so nothing a
// user can overwrite is ever run with privileges.
package helper

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrUnsupported is returned on platforms with no service to install.
var ErrUnsupported = errors.New("installing a background service is only supported on macOS")

// ErrCancelled is returned when the authorisation prompt was dismissed. It is
// not a failure: the interface says nothing happened rather than showing an
// error nobody caused.
var ErrCancelled = errors.New("the authorisation prompt was dismissed")

// Names and locations of the pieces the install puts in place.
const (
	// Label is the launchd job name.
	Label = "org.vpn-gateway.client"
	// PlistPath is where launchd looks for system daemons.
	PlistPath = "/Library/LaunchDaemons/" + Label + ".plist"
	// BinaryPath is where the client executable is copied to. It is the
	// directory macOS reserves for exactly this, and unlike /usr/local/bin it
	// is not writable by anything but root: a daemon that runs a binary its
	// own user could replace is a root shell with extra steps.
	BinaryPath = "/Library/PrivilegedHelperTools/" + Label
	// LogPath is where the service's output goes.
	LogPath = "/var/log/vpn-gateway.log"
)

// Status is what the interface shows about the service.
type Status struct {
	// Supported is false on platforms with nothing to install.
	Supported bool `json:"supported"`
	// Installed means the launchd job is in place.
	Installed bool `json:"installed"`
	// Running means launchd currently has it up.
	Running bool `json:"running"`
	PID     int  `json:"pid,omitempty"`

	// Elevated means this process is already root, so installing or removing
	// the service asks for nothing.
	Elevated bool `json:"elevated"`

	PlistPath  string `json:"plist_path,omitempty"`
	BinaryPath string `json:"binary_path,omitempty"`
	// ConfigPath is the configuration the *installed* service runs, read back
	// from the job itself. It is how the interface notices that the service
	// was installed for a different account.
	ConfigPath string `json:"config_path,omitempty"`

	// Blocker says why installing would fail right now, and is empty when it
	// would work. It is answered before anyone presses the button, so nobody
	// is asked for a password only to be told afterwards.
	Blocker string `json:"blocker,omitempty"`

	// InstalledVersion is the version reported by the installed service executable.
	InstalledVersion string `json:"installed_version,omitempty"`
}

// Options say what the service should be installed to run.
type Options struct {
	// ConfigPath is the client configuration the service runs. It is the same
	// file the application edits.
	ConfigPath string
	// Binary is the vpn-gateway executable to copy into place. Empty means
	// find it: beside this executable first, then on PATH.
	Binary string
}

// renderPlist builds the launchd job description.
//
// KeepAlive brings it back if it dies, but not if it was stopped on purpose,
// which is what SuccessfulExit false means: `launchctl bootout` stays booted
// out. NetworkState waits for an interface to exist, so the first connection
// is not attempted before there is anything to connect over.
func renderPlist(binary, configPath string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!--` + "\n")
	b.WriteString("  Installed by the vpn-gateway application. Remove it from there, or with\n")
	b.WriteString("  launchctl bootout system/" + Label + " and rm of this file.\n")
	b.WriteString(`-->` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString(`<plist version="1.0">` + "\n<dict>\n")
	b.WriteString("    <key>Label</key>\n    <string>" + xmlEscape(Label) + "</string>\n")
	b.WriteString("    <key>ProgramArguments</key>\n    <array>\n")
	for _, arg := range []string{binary, "-config", configPath, "run"} {
		b.WriteString("        <string>" + xmlEscape(arg) + "</string>\n")
	}
	b.WriteString("    </array>\n")
	b.WriteString("    <key>RunAtLoad</key>\n    <true/>\n")
	b.WriteString("    <key>KeepAlive</key>\n    <dict>\n")
	b.WriteString("        <key>SuccessfulExit</key>\n        <false/>\n")
	b.WriteString("        <key>NetworkState</key>\n        <true/>\n")
	b.WriteString("    </dict>\n")
	b.WriteString("    <key>StandardOutPath</key>\n    <string>" + xmlEscape(LogPath) + "</string>\n")
	b.WriteString("    <key>StandardErrorPath</key>\n    <string>" + xmlEscape(LogPath) + "</string>\n")
	b.WriteString("    <key>ProcessType</key>\n    <string>Interactive</string>\n")
	b.WriteString("</dict>\n</plist>\n")
	return b.String()
}

func xmlEscape(s string) string {
	return strings.NewReplacer(
		"&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;",
	).Replace(s)
}

// shellQuote wraps a string so /bin/sh sees it exactly as given. Single quotes
// stop every expansion there is, so only a single quote itself needs work.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// installScript is what runs as root. It is deliberately one script rather
// than a series of elevated commands: each one would be its own password
// prompt, and a half-finished install is worse than none.
func installScript(binary, configPath string) string {
	plist := renderPlist(BinaryPath, configPath)
	var b strings.Builder
	b.WriteString("set -e\n")
	b.WriteString("/usr/bin/install -d -o root -g wheel -m 0755 " + shellQuote(dirOf(BinaryPath)) + "\n")
	b.WriteString("/usr/bin/install -o root -g wheel -m 0755 " + shellQuote(binary) + " " + shellQuote(BinaryPath) + "\n")
	// The heredoc is quoted, so nothing in the plist is expanded.
	b.WriteString("cat > " + shellQuote(PlistPath) + " <<'VPN_GATEWAY_PLIST'\n")
	b.WriteString(plist)
	b.WriteString("VPN_GATEWAY_PLIST\n")
	b.WriteString("/usr/sbin/chown root:wheel " + shellQuote(PlistPath) + "\n")
	b.WriteString("/bin/chmod 0644 " + shellQuote(PlistPath) + "\n")
	// Replacing an install has to unload the old job first; launchctl refuses
	// to bootstrap a label that is already there.
	b.WriteString("/bin/launchctl bootout system/" + Label + " 2>/dev/null || true\n")
	b.WriteString("/bin/launchctl bootstrap system " + shellQuote(PlistPath) + "\n")
	return b.String()
}

// uninstallScript removes the job and the copied executable. The configuration
// is left alone: it is the application's own file, and the person removing a
// background service did not ask to lose their rules.
//
// The files go before the job is stopped, which looks backwards and is not.
// The service can be removed from its own interface, and then this script is a
// child of the process launchctl is about to terminate; anything after the
// bootout may never run. Stopping last means the worst case is a stopped
// service with nothing left on disk, rather than a job that quietly comes back
// at the next boot.
func uninstallScript() string {
	var b strings.Builder
	b.WriteString("/bin/rm -f " + shellQuote(PlistPath) + "\n")
	b.WriteString("/bin/rm -f " + shellQuote(BinaryPath) + "\n")
	b.WriteString("/bin/launchctl bootout system/" + Label + " 2>/dev/null || true\n")
	return b.String()
}

func dirOf(path string) string {
	if i := strings.LastIndex(path, "/"); i > 0 {
		return path[:i]
	}
	return "/"
}

// elevateCommand builds the osascript that asks for a password and runs the
// script as root.
//
// The script is passed base64-encoded. AppleScript strings and /bin/sh have
// different ideas about quoting and the script contains XML, newlines and
// paths from the file system; encoding it means neither layer has anything to
// misread, and the command line stays a fixed shape whatever is in the script.
func elevateCommand(script, prompt string) []string {
	encoded := base64.StdEncoding.EncodeToString([]byte(script))
	shell := "echo " + encoded + " | /usr/bin/base64 -D | /bin/sh"
	return []string{"-e", fmt.Sprintf(
		"do shell script %s with administrator privileges with prompt %s",
		appleScriptString(shell), appleScriptString(prompt))}
}

// appleScriptString quotes a string for AppleScript source.
func appleScriptString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}

// parseJobPID reads the process id out of `launchctl print`. The whole record
// is dozens of lines of nested state; the only questions here are whether
// launchd knows the job and whether it currently has it up.
func parseJobPID(out string) (pid int, running bool) {
	for _, line := range strings.Split(out, "\n") {
		field, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.TrimSpace(field) != "pid" {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			continue
		}
		return n, true
	}
	return 0, false
}

// configFromPlist reads the -config argument back out of an installed job, so
// the interface can say which configuration the service is actually running.
// The plist is read through plutil rather than parsed here: it is Apple's
// format and their tool always agrees with launchd about it.
func configFromPlist(plutilJSON []byte) string {
	var doc struct {
		ProgramArguments []string `json:"ProgramArguments"`
	}
	if err := json.Unmarshal(plutilJSON, &doc); err != nil {
		return ""
	}
	for i, arg := range doc.ProgramArguments {
		if arg == "-config" && i+1 < len(doc.ProgramArguments) {
			return doc.ProgramArguments[i+1]
		}
	}
	return ""
}

var (
	verCacheMu    sync.Mutex
	verCachePath  string
	verCacheMTime time.Time
	verCacheSize  int64
	verCacheVal   string
)

// cachedBinaryVersion avoids spawning a subprocess on every inspect tick
// if the binary on disk hasn't been modified.
func cachedBinaryVersion(path string, runVersion func(string) (string, error)) string {
	fi, err := os.Stat(path)
	if err != nil {
		return ""
	}
	verCacheMu.Lock()
	if verCachePath == path && verCacheMTime.Equal(fi.ModTime()) && verCacheSize == fi.Size() && verCacheVal != "" {
		v := verCacheVal
		verCacheMu.Unlock()
		return v
	}
	verCacheMu.Unlock()

	out, err := runVersion(path)
	if err != nil {
		return ""
	}
	ver := strings.TrimSpace(out)
	if ver != "" {
		verCacheMu.Lock()
		verCachePath = path
		verCacheMTime = fi.ModTime()
		verCacheSize = fi.Size()
		verCacheVal = ver
		verCacheMu.Unlock()
	}
	return ver
}

// InvalidateVersionCache clears the cached binary version.
func InvalidateVersionCache() {
	verCacheMu.Lock()
	verCachePath = ""
	verCacheVal = ""
	verCacheMTime = time.Time{}
	verCacheSize = 0
	verCacheMu.Unlock()
}
