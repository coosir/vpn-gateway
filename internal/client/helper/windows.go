//go:build windows

package helper

import (
	"bytes"
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

	st.Blocker = blocker(opt)
	return st
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

	script := fmt.Sprintf(`$ErrorActionPreference = 'Stop';
$binDir = '%s';
if (!(Test-Path $binDir)) { New-Item -ItemType Directory -Path $binDir -Force | Out-Null };
Copy-Item -Path '%s' -Destination '%s' -Force;
& sc.exe create %s binPath= "\"%s\" -config \"%s\" run" start= auto DisplayName= "VPN Gateway Service";
& sc.exe description %s "VPN Gateway background privileged TUN helper service";
& sc.exe failure %s reset= 86400 actions= restart/5000/restart/10000/restart/20000;
& sc.exe start %s;`,
		binDir, absSrc, targetExe, ServiceName, targetExe, absConfig, ServiceName, ServiceName, ServiceName)

	return runElevatedPowerShell(script)
}

// Uninstall stops the Windows Service and removes it.
func Uninstall() error {
	script := fmt.Sprintf(`$ErrorActionPreference = 'SilentlyContinue';
& sc.exe stop %s;
& sc.exe delete %s;`, ServiceName, ServiceName)

	return runElevatedPowerShell(script)
}

func runElevatedPowerShell(psScript string) error {
	encoded := utf16LEBase64(psScript)
	if isElevated() {
		cmd := hideWindow(exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded))
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}

	// Trigger Windows UAC elevation via Start-Process -Verb RunAs with -EncodedCommand
	elevateScript := fmt.Sprintf(`Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand','%s' -Wait`, encoded)
	elevateEncoded := utf16LEBase64(elevateScript)
	cmd := hideWindow(exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", elevateEncoded))

	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	out, err := cmd.Output()
	if err != nil {
		combined := strings.TrimSpace(errBuf.String() + " " + string(out))
		if strings.Contains(combined, "canceled by the user") || strings.Contains(combined, "0x800704C7") || strings.Contains(combined, "1223") {
			return ErrCancelled
		}
		if combined != "" {
			return errors.New(combined)
		}
		return err
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

