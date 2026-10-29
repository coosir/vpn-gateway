//go:build windows

package helper

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/vpn-gateway/vpn-gateway/internal/clientbin"
)

const (
	ServiceName    = "VPNGatewayClient"
	cliName        = "vpn-gateway.exe"
	inspectTimeout = 8 * time.Second
)

// hideWindow prevents spawning a black CMD/console window on Windows when executing helper commands.
func hideWindow(cmd *exec.Cmd) *exec.Cmd {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
	cmd.SysProcAttr.CreationFlags |= 0x08000000 // CREATE_NO_WINDOW
	return cmd
}

// utf16LEBase64 converts a string into a UTF-16LE Base64 string for PowerShell's -EncodedCommand parameter.
// This completely eliminates any quoting, newline, path space, or encoding/character corruption issues.
func utf16LEBase64(s string) string {
	runes := utf16.Encode([]rune(s))
	buf := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(buf[i*2:], r)
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// Inspect reports what is installed and whether installing would work on Windows.
func Inspect(opt Options) Status {
	st := Status{
		Supported:  true,
		Elevated:   isElevated(),
		BinaryPath: filepath.Join(os.Getenv("ProgramFiles"), "VPNGateway", cliName),
	}

	pid, running, installed, configPath := queryWindowsService()
	st.Installed = installed
	st.Running = running
	st.PID = pid
	st.ConfigPath = configPath
	if st.Installed {
		st.InstalledVersion = InstalledBinaryVersion(st.BinaryPath)
	}

	st.Blocker = blocker(opt)
	return st
}

// InstalledBinaryVersion runs the installed helper binary on Windows to report its version.
func InstalledBinaryVersion(binaryPath string) string {
	if binaryPath == "" {
		binaryPath = filepath.Join(os.Getenv("ProgramFiles"), "VPNGateway", cliName)
	}
	return cachedBinaryVersion(binaryPath, func(bin string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), inspectTimeout)
		defer cancel()
		out, err := hideWindow(exec.CommandContext(ctx, bin, "version")).Output()
		return string(out), err
	})
}

func blocker(opt Options) string {
	if opt.ConfigPath == "" {
		return "there is no configuration file to hand to the service yet"
	}
	if _, _, err := locateBinary(opt.Binary, false); err != nil {
		return err.Error()
	}
	return ""
}

// isElevated checks if current process has administrative privileges.
//
// Read off this process's own token rather than by running "net session" and
// seeing whether it fails: that spawned a process on every look, and on a
// machine still scanning a freshly downloaded executable the window waited
// for it.
func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// queryWindowsService asks the service manager about VPNGatewayClient.
//
// It talks to the service manager directly, with only the rights to look,
// which every user has. Running sc.exe three times did the same and cost
// three processes and up to eight seconds each.
func queryWindowsService() (pid int, running bool, installed bool, configPath string) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, false, false, ""
	}
	defer windows.CloseServiceHandle(scm)
	h, err := windows.OpenService(scm, windows.StringToUTF16Ptr(ServiceName),
		windows.SERVICE_QUERY_STATUS|windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return 0, false, false, ""
	}
	service := &mgr.Service{Name: ServiceName, Handle: h}
	defer service.Close()
	installed = true

	if st, err := service.Query(); err == nil {
		running = st.State == svc.Running
		pid = int(st.ProcessId)
	}
	if cfg, err := service.Config(); err == nil {
		configPath = configFromCommandLine(cfg.BinaryPathName)
	}
	return pid, running, installed, configPath
}

var configArgRE = regexp.MustCompile(`-config\s+("([^"]+)"|([^\s]+))`)

// configFromCommandLine reads -config back out of the service's command line.
func configFromCommandLine(cmdline string) string {
	m := configArgRE.FindStringSubmatch(cmdline)
	if len(m) < 4 {
		return ""
	}
	if m[2] != "" {
		return m[2]
	}
	return m[3]
}

// serviceSDDL is who may do what to the service. It is Windows' default with
// one change: a signed-in user (IU) may also start and stop it (RP, WP).
//
// The service only exists because that user installed it, it runs the
// configuration in their own profile, and starting or stopping it changes
// nothing they could not already change from the application. Without this a
// service that did not come back after a reboot could only be started by
// someone answering an administrator prompt -- which in practice meant
// uninstalling and installing it again.
const serviceSDDL = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"

// Start brings an installed service back up.
//
// A service installed by this version can be started by the user directly.
// One installed by an earlier version cannot, so that takes one administrator
// prompt, which also grants the right so it is the last.
func Start() error {
	err := startDirect()
	if err == nil || !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return err
	}
	logFile := filepath.Join(os.TempDir(), "vpngateway-start.log")
	script := fmt.Sprintf(`$ErrorActionPreference = 'Stop';
$logPath = '%s';
$svcName = '%s';
try {
    & sc.exe sdset $svcName "%s" 2>&1 | Out-Null
    & sc.exe failureflag $svcName 1 2>&1 | Out-Null
    $startOut = & sc.exe start $svcName 2>&1
    if ($LASTEXITCODE -ne 0 -and ($startOut -notmatch '1056')) {
        throw "sc.exe start failed: $startOut"
    }
    Set-Content -Path $logPath -Value "SUCCESS" -Encoding UTF8 -Force
} catch {
    Set-Content -Path $logPath -Value "ERROR: $($_.Exception.Message)" -Encoding UTF8 -Force
    exit 1
}`, logFile, ServiceName, serviceSDDL)
	if err := runElevatedPowerShell(script, logFile); err != nil {
		return err
	}
	return waitRunning()
}

// startDirect starts the service with the user's own rights.
func startDirect() error {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(scm)
	h, err := windows.OpenService(scm, windows.StringToUTF16Ptr(ServiceName),
		windows.SERVICE_START|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(h)
	if err := windows.StartService(h, 0, nil); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return err
	}
	return waitRunning()
}

// waitRunning waits for the service to report itself running, and says what
// its log says when it does not.
func waitRunning() error {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, running, _, _ := queryWindowsService(); running {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	if tail := LogTail(8); tail != "" {
		return fmt.Errorf("the service did not start; the end of %s reads:\n%s", ServiceLogPath(), tail)
	}
	return errors.New("the service did not start")
}

// ServiceLogPath is where the service writes what it does. It runs as SYSTEM with
// nowhere to print, so without this a service that failed at boot left no
// trace of why.
func ServiceLogPath() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "VPNGateway", "service.log")
}

// LogTail returns the last n lines of the service's log.
func LogTail(n int) string {
	b, err := os.ReadFile(ServiceLogPath())
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(b), "\r\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// Install puts the Windows Service in place and starts it.
func Install(opt Options) error {
	if opt.ConfigPath == "" {
		return errors.New("the service needs a configuration file to run")
	}
	absConfig, err := filepath.Abs(opt.ConfigPath)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", opt.ConfigPath, err)
	}
	if _, err := os.Stat(absConfig); err != nil {
		return fmt.Errorf("the configuration the service would run is not readable: %w", err)
	}

	srcBinary, sum, err := locateBinary(opt.Binary, true)
	if err != nil {
		return err
	}
	absSrc, err := filepath.Abs(srcBinary)
	if err != nil {
		return err
	}
	if sum != "" {
		// Written out just now, and about to be copied by a process running
		// as administrator. Nothing else should be able to get between those
		// two steps, but the check costs one hash and closes the question.
		defer os.Remove(absSrc)
	}

	binDir := filepath.Join(os.Getenv("ProgramFiles"), "VPNGateway")
	targetExe := filepath.Join(binDir, cliName)
	logFile := filepath.Join(os.TempDir(), "vpngateway-install.log")

	script := fmt.Sprintf(`$ErrorActionPreference = 'Stop';
$logPath = '%s';
$binDir = '%s';
$targetExe = '%s';
$srcExe = '%s';
$srcSum = '%s';
$absConfig = '%s';
$svcName = '%s';

try {
    if ($srcSum -ne '') {
        $actual = (Get-FileHash -Path $srcExe -Algorithm SHA256).Hash
        if ($actual -ne $srcSum.ToUpper()) {
            throw "the client executable changed after it was written out"
        }
    }

    if (!(Test-Path $binDir)) {
        New-Item -ItemType Directory -Path $binDir -Force | Out-Null
    }

    & sc.exe stop $svcName 2>&1 | Out-Null
    Start-Sleep -Milliseconds 500
    & sc.exe delete $svcName 2>&1 | Out-Null
    Start-Sleep -Milliseconds 500

    if ($srcExe -ne $targetExe) {
        Copy-Item -Path $srcExe -Destination $targetExe -Force
    }

    $binPath = '\"' + $targetExe + '\" -config \"' + $absConfig + '\" run'
    $createOut = & sc.exe create $svcName binPath= $binPath start= auto DisplayName= "VPN Gateway Service" 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe create failed: $createOut"
    }

    & sc.exe description $svcName "VPN Gateway background privileged TUN helper service" 2>&1 | Out-Null
    & sc.exe failure $svcName reset= 86400 actions= restart/5000/restart/10000/restart/20000 2>&1 | Out-Null
    # Without this the actions above only follow a crash. A service that
    # stops itself with an error -- the usual way one fails at boot -- would
    # otherwise stay down until somebody reinstalled it.
    & sc.exe failureflag $svcName 1 2>&1 | Out-Null
    & sc.exe sdset $svcName "%s" 2>&1 | Out-Null

    $startOut = & sc.exe start $svcName 2>&1
    if ($LASTEXITCODE -ne 0 -and ($startOut -notmatch '1056')) {
        throw "sc.exe start failed: $startOut"
    }

    for ($i = 0; $i -lt 10; $i++) {
        Start-Sleep -Milliseconds 300
        $query = & sc.exe query $svcName
        if ($query -match 'RUNNING') { break }
    }

    Set-Content -Path $logPath -Value "SUCCESS" -Encoding UTF8 -Force
} catch {
    Set-Content -Path $logPath -Value "ERROR: $($_.Exception.Message)" -Encoding UTF8 -Force
    exit 1
}`,
		logFile, binDir, targetExe, absSrc, sum, absConfig, ServiceName, serviceSDDL)

	InvalidateVersionCache()
	err = runElevatedPowerShell(script, logFile)
	if err == nil {
		InvalidateVersionCache()
	}
	return err
}

// Uninstall stops the Windows Service and removes it.
func Uninstall() error {
	InvalidateVersionCache()
	logFile := filepath.Join(os.TempDir(), "vpngateway-uninstall.log")
	script := fmt.Sprintf(`$ErrorActionPreference = 'SilentlyContinue';
$logPath = '%s';
$svcName = '%s';
try {
    & sc.exe stop $svcName 2>&1 | Out-Null
    Start-Sleep -Milliseconds 500
    & sc.exe delete $svcName 2>&1 | Out-Null
    Set-Content -Path $logPath -Value "SUCCESS" -Encoding UTF8 -Force
} catch {
    Set-Content -Path $logPath -Value "ERROR: $($_.Exception.Message)" -Encoding UTF8 -Force
}`, logFile, ServiceName)

	return runElevatedPowerShell(script, logFile)
}

func runElevatedPowerShell(psScript string, logPath string) error {
	_ = os.Remove(logPath)
	encoded := utf16LEBase64(psScript)

	if isElevated() {
		cmd := hideWindow(exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded))
		_ = cmd.Run()
	} else {
		elevateScript := fmt.Sprintf(`Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand','%s' -Wait`, encoded)
		elevateEncoded := utf16LEBase64(elevateScript)
		cmd := hideWindow(exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", elevateEncoded))
		_ = cmd.Run()
	}

	// Read log file
	data, err := os.ReadFile(logPath)
	if err != nil {
		// Log file was not created, which means UAC was cancelled by user
		return ErrCancelled
	}
	defer os.Remove(logPath)

	content := strings.TrimSpace(string(data))
	if strings.HasPrefix(content, "ERROR:") {
		return errors.New(strings.TrimSpace(strings.TrimPrefix(content, "ERROR:")))
	}
	return nil
}

// locateBinary finds the client executable to install as the service.
//
// It is never the running application. What the service manager starts runs
// as SYSTEM, and an application carries a window it would never open; the
// client executable is the whole engine and nothing else, and it is already
// what a service manager knows how to start.
//
// Returned second is the digest of an executable this call wrote out, empty
// for one that was already on disk. Only a file written here can be checked
// against what is copied into place; one that was already there is whatever
// the person who put it there put there.
func locateBinary(explicit string, unpack bool) (path, sum string, err error) {
	if explicit != "" {
		if err := checkFileExists(explicit); err != nil {
			return "", "", err
		}
		return explicit, "", nil
	}

	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		if strings.EqualFold(filepath.Base(exe), cliName) {
			return exe, "", nil
		}
		// Beside the application: a build tree, or an installation that put
		// both files down.
		beside := filepath.Join(filepath.Dir(exe), cliName)
		if checkFileExists(beside) == nil {
			return beside, "", nil
		}
	}

	// A single downloaded file carries the client inside it. Asking whether
	// an install would work is not a reason to write sixteen megabytes out,
	// so that only happens when one is actually being done.
	if clientbin.Available() {
		if !unpack {
			return packedBinary, "", nil
		}
		dir := unpackDir()
		path, sum, err := clientbin.Unpack(dir, cliName)
		if err != nil {
			return "", "", err
		}
		return path, sum, nil
	}

	if found, err := exec.LookPath(cliName); err == nil {
		return found, "", nil
	}
	return "", "", fmt.Errorf("no %s executable was found to install", cliName)
}

// packedBinary is what locateBinary answers when the executable to install is
// the one this application carries and nothing has been written out yet. It
// is never a path anything opens: only whether there is something to install.
const packedBinary = "(the client carried inside this application)"

// unpackDir is where the carried executable is written before an elevated
// process copies it into place: a directory belonging to whoever is running
// the application, since that is who is about to authorise the install.
func unpackDir() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "VPNGateway")
}

func checkFileExists(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s cannot be read: %w", path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory, not an executable", path)
	}
	return nil
}
