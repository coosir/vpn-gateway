// Command vpn-gateway is the desktop client. It brings up one TUN interface
// (or a local proxy port) and routes traffic by rule: to the enterprise
// gateway's tunnels first, then to proxy nodes, and directly otherwise.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"text/tabwriter"

	"github.com/vpn-gateway/vpn-gateway/internal/client"
	"github.com/vpn-gateway/vpn-gateway/internal/client/ui"
	"github.com/vpn-gateway/vpn-gateway/internal/version"
)

// openBrowser opens the interface. Failing to is not worth stopping for: the
// link has already been printed.
func openBrowser(link string, log *slog.Logger) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", link)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", link)
	default:
		cmd = exec.Command("xdg-open", link)
	}
	if err := cmd.Start(); err != nil {
		log.Warn("could not open a browser; use the printed link", "error", err)
	}
}

const usage = `vpn-gateway is a sing-box client that can also route traffic to
several VPNs at once through an enterprise gateway.

Usage:
  vpn-gateway [-config path] <command>

Commands:
  run      bring up routing and keep it in step with the gateway
  status   show what the gateway reports for each tunnel
  config   print the generated sing-box configuration and exit
  check    validate the configuration and the bundle, then exit
  auth     answer interactive login prompts as tunnels raise them
  version  print the client version and exit

Set ui.enabled to serve a local interface while the client runs: tunnel
state, the rule editor, container logs and login prompts.

Bringing up a TUN interface needs elevated privileges. Set proxy.enabled to
use a local SOCKS5 and HTTP port instead, which does not.
`

func main() {
	configPath := flag.String("config", "/etc/vpn-gateway/client.yaml", "path to the client configuration")
	logLevel := flag.String("log-level", "info", "debug, info, warn or error")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()

	if isWindowsService() {
		if err := runWindowsService(*configPath, *logLevel); err != nil {
			os.Exit(1)
		}
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	if flag.Arg(0) == "version" {
		fmt.Println(version.Full())
		return
	}
	if err := run(ctx, *configPath, *logLevel, flag.Arg(0)); err != nil {
		fmt.Fprintln(os.Stderr, "vpn-gateway:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, configPath, logLevel, command string) error {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(logLevel)); err != nil {
		return fmt.Errorf("bad log level %q: %w", logLevel, err)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))

	cfg, err := client.LoadConfig(configPath)
	if err != nil {
		return err
	}

	if command == "check" {
		return printCheck(cfg)
	}

	session := client.NewSession(configPath, log)
	defer session.Close()

	// Connect immediately for one-shot commands or headless runs (without UI).
	// When running with UI enabled (desktop application / background service),
	// start in idle state and wait for the user to manually initiate the connection.
	if command != "run" || !cfg.UI.Enabled {
		if err := session.Connect(ctx); err != nil {
			return err
		}
	}
	c := session.Client()

	switch command {
	case "config":
		raw, err := c.Config()
		if err != nil {
			return err
		}
		fmt.Println(string(raw))
		return nil

	case "status":
		return printStatus(c)

	case "auth":
		if c.API() == nil {
			return errors.New("the enterprise gateway is not connected; check gateway_disabled, the bundle and the credentials")
		}
		fmt.Println("waiting for tunnels that need a verification code; press ctrl-c to stop")
		err := client.WatchChallenges(ctx, c.API(), &client.TerminalPrompter{In: os.Stdin, Out: os.Stdout})
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err

	case "run":
		// Challenges go to whichever is listening: the interface when it is
		// running, the terminal otherwise. Either way a tunnel that needs a
		// code after reconnecting does not require a second command.
		prompter := client.Prompter(&client.TerminalPrompter{In: os.Stdin, Out: os.Stdout})
		if cfg.UI.Enabled {
			token, err := ui.LoadOrCreateToken(cfg.UI.StateDir)
			if err != nil {
				return err
			}
			srv := ui.New(session, configPath, token, log)
			addr, err := ui.Serve(ctx, cfg.UI.Listen, srv.Handler(), log)
			if err != nil {
				return err
			}
			link := fmt.Sprintf("http://%s/?token=%s", addr, token)
			fmt.Printf("interface: %s\n", link)
			linkPath := cfg.UI.LinkFile
			if linkPath == "" {
				linkPath = ui.ServiceLinkPath(configPath)
			}
			if err := ui.WriteLink(linkPath, addr, token, cfg.UI.LinkOwner); err != nil {
				log.Warn("could not record the interface link", "path", linkPath, "error", err)
			} else {
				log.Info("recorded the interface link", "path", linkPath)
			}
			if cfg.UI.Open {
				openBrowser(link, log)
			}
			prompter = srv.Prompter()
		}
		go client.FollowChallenges(ctx, session.CurrentAPI, prompter)

		<-ctx.Done()
		log.Info("shutting down")
		// Closing tears down the TUN interface and the system routes that
		// point at it; leaving them behind would take the machine offline.
		return session.Close()

	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

// printCheck describes a configuration that loaded, the gateway part only
// when there is one.
func printCheck(cfg *client.Config) error {
	fmt.Printf("configuration is valid\n")
	fmt.Printf("  mode       %s, %d proxy rules\n", cfg.EffectiveMode(), len(cfg.ProxyRules))
	fmt.Printf("  nodes      %d (%d custom, %d subscriptions)\n",
		len(cfg.AllNodes()), len(cfg.CustomNodes), len(cfg.Subscriptions))
	fmt.Printf("  ingress    tun=%t proxy=%t\n", cfg.TUN.Enabled, cfg.Proxy.Enabled)

	if !cfg.GatewayConfigured() {
		fmt.Printf("  gateway    not configured\n")
		return nil
	}
	bundle, err := client.LoadBundle(cfg.Bundle)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Printf("  gateway    no bundle imported yet (%s)\n", cfg.Bundle)
		return nil
	}
	if err != nil {
		return err
	}
	state := "on"
	if cfg.GatewayDisabled {
		state = "switched off"
	}
	fmt.Printf("  gateway    %s\n", state)
	fmt.Printf("  server     %s (sni %s)\n", bundle.Server.Address, bundle.Server.ServerName)
	fmt.Printf("  api        %s\n", bundle.Server.APIURL)
	if len(bundle.Tunnels) > 0 {
		fmt.Printf("  tunnels    %d in bundle (dynamic sync enabled)\n", len(bundle.Tunnels))
	} else {
		fmt.Printf("  tunnels    dynamic from server API\n")
	}
	fmt.Printf("  rules      %d explicit, auto_routes=%t auto_domains=%t\n",
		len(cfg.Rules), cfg.AutoRoutes, cfg.AutoDomains)
	fmt.Printf("  on_failure %s\n", cfg.OnFailure)
	return nil
}

func printStatus(c *client.Client) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TUNNEL\tSTATE\tROUTES\tDNS\tUDP")
	for _, t := range c.Tunnels() {
		state := "down"
		if t.Up {
			state = "up"
		}
		dns := "-"
		if len(t.DNS) > 0 {
			dns = t.DNS[0]
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%t\n", t.Name, state, len(t.Routes), dns, t.UDP)
	}
	return w.Flush()
}
