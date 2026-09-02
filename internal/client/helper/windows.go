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
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
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
	if _, err := locateBinary(opt.Binary); err != nil {
		return err.Error()
	}
	return ""
}

// isElevated checks if current process has administrative privileges.
func isElevated() bool {
	cmd := hideWindow(exec.Command("net", "session"))
	return cmd.Run() == nil
}

// queryWindowsService queries sc.exe for VPNGatewayClient state.
func queryWindowsService() (pid int, running bool, installed bool, configPath string) {
	ctx, cancel := context.WithTimeout(context.Background(), inspectTimeout)
	defer cancel()

	// 1. Query service status
	out, err := hideWindow(exec.CommandContext(ctx, "sc.exe", "query", ServiceName)).Output()
	if err != nil || !strings.Contains(string(out), ServiceName) {
		return 0, false, false, ""
	}
	installed = true
	if strings.Contains(string(out), "RUNNING") {
		running = true
	}

	// 2. Query PID via queryex
	if exOut, err := hideWindow(exec.CommandContext(ctx, "sc.exe", "queryex", ServiceName)).Output(); err == nil {
		re := regexp.MustCompile(`PID\s*:\s*(\d+)`)
		if matches := re.FindStringSubmatch(string(exOut)); len(matches) > 1 {
			pid, _ = strconv.Atoi(matches[1])
		}
	}

	// 3. Query config path via qc
	if qcOut, err := hideWindow(exec.CommandContext(ctx, "sc.exe", "qc", ServiceName)).Output(); err == nil {
		re := regexp.MustCompile(`-config\s+("([^"]+)"|([^\s]+))`)
		if matches := re.FindStringSubmatch(string(qcOut)); len(matches) > 1 {
			if matches[2] != "" {
				configPath = matches[2]
			} else if matches[3] != "" {
				configPath = matches[3]
			}
		}
	}

	return pid, running, installed, configPath
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

	srcBinary, err := locateBinary(opt.Binary)
	if err != nil {
		return err
	}
	absSrc, err := filepath.Abs(srcBinary)
	if err != nil {
		return err
	}

	binDir := filepath.Join(os.Getenv("ProgramFiles"), "VPNGateway")
	targetExe := filepath.Join(binDir, cliName)
	logFile := filepath.Join(os.TempDir(), "vpngateway-install.log")

	script := fmt.Sprintf(`$ErrorActionPreference = 'Stop';
$logPath = '%s';
$binDir = '%s';
$targetExe = '%s';
$srcExe = '%s';
$absConfig = '%s';
$svcName = '%s';

try {
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
		logFile, binDir, targetExe, absSrc, absConfig, ServiceName)

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

func locateBinary(explicit string) (string, error) {
	if explicit != "" {
		if err := checkFileExists(explicit); err != nil {
			return "", err
		}
		return explicit, nil
	}

	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		if strings.EqualFold(filepath.Base(exe), cliName) {
			return exe, nil
		}
		beside := filepath.Join(filepath.Dir(exe), cliName)
		if checkFileExists(beside) == nil {
			return beside, nil
		}
		// Also check without .exe
		besideNoExt := filepath.Join(filepath.Dir(exe), "vpn-gateway")
		if checkFileExists(besideNoExt) == nil {
			return besideNoExt, nil
		}
		// Single-executable distribution: if running as desktop executable (e.g. vpn-gateway-desktop.exe),
		// use the running executable itself.
		if checkFileExists(exe) == nil {
			return exe, nil
		}
	}

	if found, err := exec.LookPath(cliName); err == nil {
		return found, nil
	}
	return "", fmt.Errorf("no %s executable was found to install", cliName)
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

