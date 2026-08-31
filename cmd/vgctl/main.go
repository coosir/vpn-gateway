// Command vgctl inspects a vpn-gateway server and produces the configuration
// its clients need.
//
// It reads the server's configuration and state directory directly, so it
// runs on the server itself rather than over the network.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/vpn-gateway/vpn-gateway/internal/clientbox"
	"github.com/vpn-gateway/vpn-gateway/internal/server"
	"github.com/vpn-gateway/vpn-gateway/internal/server/certs"
	"github.com/vpn-gateway/vpn-gateway/internal/server/clientcfg"
)

const usage = `vgctl inspects a vpn-gateway server and emits client configuration.

Usage:
  vgctl [-config path] <command> [args]

Commands:
  client-config   print the bundle a client needs, as JSON
  outbounds       print sing-box trojan outbounds, one per tunnel
  fingerprint     print the TLS certificate fingerprint to verify out of band
  tunnels         list configured tunnels and their ports
  verify          connect through every tunnel and report what works
  hash-password   hash a plaintext password with bcrypt for server config

verify sends one request through each tunnel and reports the address it came
out of. -probe names where: the default is unreachable from some countries,
and a probe nothing can reach reports every tunnel as broken.
`

func main() {
	configPath := flag.String("config", "/etc/vpn-gateway/config.yaml", "path to the server configuration")
	host := flag.String("host", "", "hostname clients use to reach the server (default: trojan.server_name)")
	probe := flag.String("probe", defaultProbeURL, "URL verify fetches through each tunnel; it must answer with the caller's address")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*configPath, *host, *probe, flag.Arg(0), flag.Args()[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "vgctl:", err)
		os.Exit(1)
	}
}

func run(configPath, host, probe, command string, args []string) error {
	if command == "hash-password" || command == "password-hash" {
		if len(args) == 0 {
			return errors.New("usage: vgctl hash-password <password>")
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(args[0]), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		fmt.Println(string(hash))
		return nil
	}

	cfg, err := server.LoadConfig(configPath)
	if err != nil {
		return err
	}

	switch command {
	case "user", "users":
		return handleUserCommand(cfg, args)
	case "user-list":
		return handleUserCommand(cfg, []string{"list"})
	case "user-add":
		return handleUserCommand(cfg, append([]string{"add"}, args...))
	case "user-del", "user-delete":
		return handleUserCommand(cfg, append([]string{"del"}, args...))
	case "user-passwd", "user-update":
		return handleUserCommand(cfg, append([]string{"passwd"}, args...))
	case "tunnels":
		return listTunnels(cfg)
	case "fingerprint":
		mat, err := loadTLS(cfg)
		if err != nil {
			return err
		}
		if !mat.SelfSigned {
			fmt.Println("the certificate is not self-signed; clients verify it normally and need no pin")
			return nil
		}
		fmt.Println(mat.Fingerprint)
		return nil
	case "verify":
		bundle, err := buildBundle(cfg, host)
		if err != nil {
			return err
		}
		return verify(cfg, bundle, probe)
	case "client-config", "outbounds":
		bundle, err := buildBundle(cfg, host)
		if err != nil {
			return err
		}
		var out []byte
		if command == "outbounds" {
			out, err = bundle.SingBoxOutbounds()
		} else {
			out, err = bundle.JSON()
		}
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

func listTunnels(cfg *server.Config) error {
	fmt.Printf("%-20s %-14s %-9s %-8s %s\n", "NAME", "PROVIDER", "STATE", "DATA", "CONTROL")
	for _, t := range cfg.Tunnels {
		state := "enabled"
		if t.Disabled {
			state = "disabled"
		}
		if t.IsDirect() {
			fmt.Printf("%-20s %-14s %-9s %-8s %s\n", t.Name, t.Provider, state, "-", "-")
		} else {
			fmt.Printf("%-20s %-14s %-9s %-8d %d\n", t.Name, t.Provider, state, t.DataPort, t.ControlPort)
		}
	}
	return nil
}

func buildBundle(cfg *server.Config, host string) (*clientcfg.Bundle, error) {
	if cfg.Trojan.Disabled {
		return nil, errors.New("the trojan listener is disabled, so there is nothing for a client to connect to")
	}
	mat, err := loadTLS(cfg)
	if err != nil {
		return nil, err
	}

	if host == "" {
		host = cfg.Trojan.ServerName
	}
	if host == "" {
		return nil, errors.New("clients need a hostname: set trojan.server_name or pass -host")
	}
	_, port, found := strings.Cut(cfg.Trojan.Listen, ":")
	if !found {
		return nil, fmt.Errorf("trojan.listen %q has no port", cfg.Trojan.Listen)
	}

	token, err := readToken(cfg.StateDir)
	if err != nil {
		return nil, err
	}

	var tunnels []clientcfg.Tunnel
	for _, t := range cfg.Tunnels {
		if t.Disabled {
			continue
		}
		password, err := readSecret(cfg.StateDir, t.Name+".trojan")
		if err != nil {
			return nil, fmt.Errorf("tunnel %q has no trojan password yet; start the server once to generate it: %w", t.Name, err)
		}
		tunnels = append(tunnels, clientcfg.Tunnel{Name: t.Name, Password: password, Provider: t.Provider})
	}
	if len(tunnels) == 0 {
		return nil, errors.New("no tunnel is enabled")
	}

	// The API is bound to loopback on the server, so clients reach it through
	// the same hostname as the listener; exposing it is the operator's
	// decision, not something to assume here.
	_, apiPort, _ := strings.Cut(cfg.APIListen, ":")
	apiURL := fmt.Sprintf("http://%s:%s", host, apiPort)
	bundle := clientcfg.Build(host+":"+port, apiURL, mat, token, tunnels)
	bundle.RequiresAuth = true
	return bundle, nil
}

// verify connects through every tunnel the way a real client would, so a
// setup can be checked from the server before any device is configured.
func verify(cfg *server.Config, bundle *clientcfg.Bundle, probe string) error {
	// The API is on loopback from here, whatever hostname clients use.
	apiURL := "http://" + cfg.APIListen

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	fmt.Printf("server %s (sni %s)\n", bundle.Server.Address, bundle.Server.ServerName)
	if bundle.Server.Fingerprint != "" {
		fmt.Printf("  certificate is self-signed; clients pin %s\n", bundle.Server.Fingerprint)
	}
	fmt.Println()

	failed := 0
	var reasons []string
	for _, t := range bundle.Tunnels {
		state, uptime := tunnelState(ctx, apiURL, bundle.APIToken, t.Name)
		egress, err := probeEgress(ctx, bundle, t.Name, probe)

		status := "ok"
		detail := egress
		if err != nil {
			status = "FAILED"
			detail = err.Error()
			reasons = append(reasons, detail)
			failed++
		}
		fmt.Printf("  %-20s %-8s tunnel=%-13s uptime=%-8s %s\n",
			t.Name, status, state, uptime, detail)
	}

	fmt.Println()
	if failed > 0 {
		// Several tunnels failing for one identical reason says more about
		// the probe than about the tunnels: an address this server cannot
		// reach at all fails the same way through every one of them. One
		// tunnel failing says nothing of the sort, so it is left alone.
		if failed == len(bundle.Tunnels) && len(reasons) > 1 && allSame(reasons) {
			fmt.Printf("every tunnel failed for the same reason; check that %s is reachable from this server, or name another with -probe\n\n", probe)
		}
		return fmt.Errorf("%d of %d tunnels did not carry traffic", failed, len(bundle.Tunnels))
	}
	fmt.Printf("all %d tunnels carried traffic\n", len(bundle.Tunnels))
	return nil
}

// allSame reports whether every reason is the identical string. It is only
// asked of more than one.
func allSame(reasons []string) bool {
	for _, r := range reasons[1:] {
		if r != reasons[0] {
			return false
		}
	}
	return true
}

// tunnelState asks the control API what the container reports, so a failure
// can be attributed to the tunnel rather than to the trojan hop.
func tunnelState(ctx context.Context, apiURL, token, name string) (state, uptime string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+"/api/v1/tunnels/"+name, nil)
	if err != nil {
		return "unknown", "-"
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return "unreachable", "-"
	}
	defer resp.Body.Close()

	var snap struct {
		Reachable bool `json:"reachable"`
		Status    struct {
			State         string `json:"state"`
			UptimeSeconds int64  `json:"uptime_seconds"`
		} `json:"status"`
	}
	if json.NewDecoder(resp.Body).Decode(&snap) != nil {
		return "unreadable", "-"
	}
	// A snapshot keeps the last known status when the container stops
	// answering, so reporting State alone would show a dead tunnel as "up".
	if !snap.Reachable {
		return "unreachable", "-"
	}
	return snap.Status.State, (time.Duration(snap.Status.UptimeSeconds) * time.Second).String()
}

// defaultProbeURL is what verify fetches through a tunnel when nothing else
// is named. It is a reasonable default and a bad one to depend on: it is
// unreachable from mainland China, where a server on the near side of a
// domestic VPN gateway is exactly where this tends to run. There it reports
// every tunnel as failing, including the ones that work, which is why the
// address is a flag rather than a constant.
const defaultProbeURL = "https://api.ipify.org"

// probeEgress sends one request through the tunnel and reports the address it
// came out of, which is the only real proof the path works end to end.
func probeEgress(ctx context.Context, bundle *clientcfg.Bundle, name, probe string) (string, error) {
	sess, err := clientbox.Open(ctx, bundle, name)
	if err != nil {
		return "", err
	}
	defer sess.Close()

	client := &http.Client{
		Transport: &http.Transport{DialContext: sess.Dial},
		Timeout:   20 * time.Second,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probe, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return "", err
	}
	return "egress=" + strings.TrimSpace(string(body)), nil
}

func loadTLS(cfg *server.Config) (*certs.Material, error) {
	if cfg.Trojan.TLSMode == "files" {
		return certs.Load(cfg.Trojan.CertFile, cfg.Trojan.KeyFile, cfg.Trojan.ServerName)
	}
	dir := filepath.Join(cfg.StateDir, "tls")
	mat, err := certs.Load(filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"), cfg.Trojan.ServerName)
	if err != nil {
		return nil, fmt.Errorf("no certificate yet; start the server once to generate it: %w", err)
	}
	mat.SelfSigned = true
	return mat, nil
}

func readToken(stateDir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(stateDir, "api-token"))
	if err != nil {
		return "", fmt.Errorf("no API token yet; start the server once to generate it: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

func readSecret(stateDir, name string) (string, error) {
	b, err := os.ReadFile(filepath.Join(stateDir, "secrets", name))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
