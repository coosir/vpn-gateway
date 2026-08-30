//go:build desktop

// Command vpn-gateway-desktop is the tray and window around a running
// vpn-gateway client.
//
// It attaches to a client rather than starting one. Creating a TUN interface
// needs elevated privileges, so the client runs as a service; a tray that
// claimed to start it would be lying about what it can do. What it does is
// show what that client is doing and open its interface.
//
// The window runs as a child process. A tray and a webview each want the
// process's main run loop, and on macOS they cannot share one.
//
// This binary needs CGO and the platform's webview libraries, so it is behind
// a build tag: a headless server must still build everything else.
//
//	go build -tags desktop ./cmd/vpn-gateway-desktop
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vpn-gateway/vpn-gateway/internal/client"
	"github.com/vpn-gateway/vpn-gateway/internal/client/ui"
)

const usage = `vpn-gateway-desktop shows a running vpn-gateway client in the tray.

Usage:
  vpn-gateway-desktop [-config path]
  vpn-gateway-desktop -url <the link the client printed>

The client has to be running. It prints its interface link on startup; pass
that with -url, or point -config at the same configuration file the client is
using and the link will be worked out from it.
`

func main() {
	var (
		configPath = flag.String("config", defaultConfigPath(), "the client's configuration file")
		link       = flag.String("url", "", "the interface link the client printed")
		window     = flag.String("window", "", "internal: open a window on this address")
		lang       = flag.String("lang", "", "zh or en; defaults to the system language")
	)
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()

	// The window mode is what the tray re-executes to get a second main run
	// loop; it is not meant to be run by hand.
	if *window != "" {
		runWindow(*window, pickLanguage(*lang))
		return
	}

	target, err := resolveLink(*link, *configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "vpn-gateway-desktop:", err)
		os.Exit(1)
	}
	runTray(target, pickLanguage(*lang))
}

// resolveLink works out where the interface is and how to authenticate to it.
func resolveLink(link, configPath string) (string, error) {
	if link != "" {
		return link, nil
	}

	cfg, err := client.LoadConfig(configPath)
	if err != nil {
		return "", fmt.Errorf("%w\n\nEither start the client and pass the link it prints with -url, "+
			"or point -config at the file it is using", err)
	}
	if !cfg.UI.Enabled {
		return "", fmt.Errorf("the interface is turned off in %s; set ui.enabled and restart the client", configPath)
	}

	token, err := ui.ReadToken(cfg.UI.StateDir)
	if err != nil {
		// The client usually runs elevated, so its state directory is often
		// unreadable to whoever is looking at the tray. Say so rather than
		// reporting a bare permission error.
		return "", fmt.Errorf("cannot read the interface token from %s: %w\n\n"+
			"The client keeps it private, so pass the link it printed instead:\n"+
			"  vpn-gateway-desktop -url 'http://127.0.0.1:8645/?token=…'", cfg.UI.StateDir, err)
	}
	return fmt.Sprintf("http://%s/?token=%s", cfg.UI.Listen, token), nil
}

func defaultConfigPath() string {
	if p := os.Getenv("VPN_GATEWAY_CONFIG"); p != "" {
		return p
	}
	return "/etc/vpn-gateway/client.yaml"
}

// pickLanguage honours an explicit choice, then the environment, and falls
// back to Chinese, which is what the interface itself defaults to.
func pickLanguage(explicit string) string {
	if explicit == "zh" || explicit == "en" {
		return explicit
	}
	for _, key := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		v := strings.ToLower(os.Getenv(key))
		if v == "" {
			continue
		}
		if strings.HasPrefix(v, "zh") {
			return "zh"
		}
		return "en"
	}
	return "zh"
}

// selfPath is the binary to re-execute for the window.
func selfPath() string {
	exe, err := os.Executable()
	if err != nil {
		return filepath.Base(os.Args[0])
	}
	return exe
}
