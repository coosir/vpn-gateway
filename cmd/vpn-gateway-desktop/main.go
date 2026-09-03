//go:build desktop

// Command vpn-gateway-desktop is the vpn-gateway client with a tray and a
// window around it.
//
// It runs the client itself rather than attaching to one. Opening an
// application passes no arguments and shows no terminal, so anything it needs
// has to be asked for in the interface: it opens on a setup screen, takes the
// bundle the server produced, and connects when told to.
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

	"github.com/vpn-gateway/vpn-gateway/internal/version"
)

const usage = `vpn-gateway-desktop runs the vpn-gateway client with a tray and a window.

Usage:
  vpn-gateway-desktop [-config path] [-lang zh|en] [version]

Everything it needs is configured in the interface, so it takes no arguments
in normal use. Opening it is enough.

Bringing up a TUN interface needs elevated privileges. Without them the client
still runs as a local proxy, which is what it starts as. The background
service that has them runs vpn-gateway, not this: a window is not something a
service manager should be starting.
`

func main() {
	// Fast path for version queries before anything else initializes.
	for _, arg := range os.Args[1:] {
		if arg == "version" || arg == "-v" || arg == "--version" || arg == "-version" {
			fmt.Println(version.Full())
			return
		}
	}

	var (
		configPath = flag.String("config", defaultConfigPath(), "where to keep the configuration")
		lang       = flag.String("lang", "", "zh or en; defaults to the system language")
		iconset    = flag.String("write-iconset", "", "internal: write launcher icons into this directory and exit")
		icoFile    = flag.String("write-ico", "", "internal: write Windows .ico launcher icon to this file and exit")
	)
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()

	if len(flag.Args()) > 0 && flag.Arg(0) == "version" {
		fmt.Println(version.Full())
		return
	}

	// Packaging calls this to produce the launcher icon, so the drawing lives
	// in one place rather than as a binary blob checked in beside it.
	if *iconset != "" {
		if err := writeIconset(*iconset); err != nil {
			fmt.Fprintln(os.Stderr, "vpn-gateway-desktop:", err)
			os.Exit(1)
		}
		return
	}
	if *icoFile != "" {
		if err := os.WriteFile(*icoFile, appIconICO(), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "vpn-gateway-desktop:", err)
			os.Exit(1)
		}
		return
	}

	if err := run(*configPath, pickLanguage(*lang)); err != nil {
		dir := filepath.Dir(*configPath)
		_ = os.MkdirAll(dir, 0o755)
		_ = os.WriteFile(filepath.Join(dir, "desktop.log"), []byte(err.Error()+"\n"), 0o644)
		fmt.Fprintln(os.Stderr, "vpn-gateway-desktop:", err)
		os.Exit(1)
	}
}

// defaultConfigPath is under the user's own configuration directory, not
// /etc: this is opened by whoever is sitting at the machine, and it has to be
// able to write what it is told without being elevated first.
func defaultConfigPath() string {
	if p := os.Getenv("VPN_GATEWAY_CONFIG"); p != "" {
		return p
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "vpn-gateway-client.yaml"
	}
	return filepath.Join(dir, "vpn-gateway", "client.yaml")
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
