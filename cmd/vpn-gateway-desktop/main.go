//go:build desktop

// Command vpn-gateway-desktop is the tray and window around a running
// vpn-gateway client.
//
// It attaches to a client rather than starting one. Creating a TUN interface
// needs elevated privileges, so the client runs as a service; a tray that
// claimed to start it would be lying about what it can do. What it does is
// show what that client is doing, and open its interface in a window.
//
// It needs the platform's webview libraries, so it is behind a build tag: a
// headless server must still build everything else.
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
		lang       = flag.String("lang", "", "zh or en; defaults to the system language")
		iconset    = flag.String("write-iconset", "", "internal: write launcher icons into this directory and exit")
	)
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()

	// Packaging calls this to produce the launcher icon, so the drawing lives
	// in one place rather than as a binary blob checked in beside it.
	if *iconset != "" {
		if err := writeIconset(*iconset); err != nil {
			fmt.Fprintln(os.Stderr, "vpn-gateway-desktop:", err)
			os.Exit(1)
		}
		return
	}

	target, err := resolveLink(*link, *configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "vpn-gateway-desktop:", err)
		os.Exit(1)
	}
	if err := run(target, pickLanguage(*lang)); err != nil {
		fmt.Fprintln(os.Stderr, "vpn-gateway-desktop:", err)
		os.Exit(1)
	}
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

// writeIconset writes the sizes macOS asks for in an .iconset directory.
func writeIconset(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, size := range []int{16, 32, 64, 128, 256, 512, 1024} {
		name := fmt.Sprintf("icon_%dx%d.png", size, size)
		if err := os.WriteFile(filepath.Join(dir, name), appIcon(size), 0o644); err != nil {
			return err
		}
		// The 2x variants are the same pixels at the next size up.
		if size >= 32 {
			retina := fmt.Sprintf("icon_%dx%d@2x.png", size/2, size/2)
			if err := os.WriteFile(filepath.Join(dir, retina), appIcon(size), 0o644); err != nil {
				return err
			}
		}
	}
	return nil
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
