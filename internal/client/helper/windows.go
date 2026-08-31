//go:build windows

package helper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	ServiceName = "VPNGatewayClient"
	cliName     = "vpn-gateway.exe"
	inspectTimeout = 8 * time.Second
)

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
	cmd := exec.Command("net", "session")
	return cmd.Run() == nil
}

// queryWindowsService queries sc.exe for VPNGatewayClient state.
func queryWindowsService() (pid int, running bool, installed bool, configPath string) {
	ctx, cancel := context.WithTimeout(context.Background(), inspectTimeout)
	defer cancel()

	// 1. Query service status
	out, err := exec.CommandContext(ctx, "sc.exe", "query", ServiceName).Output()
	if err != nil || !strings.Contains(string(out), ServiceName) {
		return 0, false, false, ""
	}
	installed = true
	if strings.Contains(string(out), "RUNNING") {
		running = true
	}

	// 2. Query PID via queryex
	if exOut, err := exec.CommandContext(ctx, "sc.exe", "queryex", ServiceName).Output(); err == nil {
		re := regexp.MustCompile(`PID\s*:\s*(\d+)`)
		if matches := re.FindStringSubmatch(string(exOut)); len(matches) > 1 {
			pid, _ = strconv.Atoi(matches[1])
		}
	}

	// 3. Query config path via qc
	if qcOut, err := exec.CommandContext(ctx, "sc.exe", "qc", ServiceName).Output(); err == nil {
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
	if isElevated() {
		cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psScript)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}

	// Trigger Windows UAC elevation via Start-Process -Verb RunAs
	encoded := strings.ReplaceAll(psScript, `"`, `\"`)
	arg := fmt.Sprintf("-NoProfile -ExecutionPolicy Bypass -Command \"%s\"", encoded)
	cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
		fmt.Sprintf("Start-Process powershell.exe -Verb RunAs -ArgumentList '%s' -Wait", arg))

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
	}

	if found, err := exec.LookPath(cliName); err == nil {
		return found, nil
	}
	return "", fmt.Errorf("no %s executable was found to install; build it and put it beside the application", cliName)
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
