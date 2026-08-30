//go:build desktop

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/client"
	"github.com/vpn-gateway/vpn-gateway/internal/client/ui"
)

// findLink works out where the interface is and how to authenticate to it.
//
// The order matters. Double-clicking passes no arguments at all, so a link
// that worked once has to keep working without them: an application that only
// starts from a command line is not an application.
func findLink(explicit, configPath string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if link, err := ui.ReadLink(cachePath()); err == nil {
		return link, nil
	}

	cfg, err := client.LoadConfig(configPath)
	if err != nil {
		return "", fmt.Errorf("no interface link was found.\n\n"+
			"Start the client and run this once with the link it prints:\n"+
			"  vpn-gateway-desktop -url 'http://127.0.0.1:8645/?token=…'\n\n"+
			"It is remembered afterwards, so opening the application is enough from then on.\n\n"+
			"(%s could not be read: %v)", configPath, err)
	}
	if !cfg.UI.Enabled {
		return "", fmt.Errorf("the interface is turned off in %s.\n\n"+
			"Set ui.enabled and restart the client.", configPath)
	}

	// The client records the link here when ui.link_file is set, which is the
	// path that survives the client running as a different user.
	if cfg.UI.LinkFile != "" {
		if link, err := ui.ReadLink(cfg.UI.LinkFile); err == nil {
			return link, nil
		}
	}

	token, err := ui.ReadToken(cfg.UI.StateDir)
	if err != nil {
		return "", fmt.Errorf("the client keeps its token in %s, which this session cannot read.\n\n"+
			"Either set ui.link_file in %s to somewhere your user can read,\n"+
			"or run this once with the link the client printed:\n"+
			"  vpn-gateway-desktop -url 'http://127.0.0.1:8645/?token=…'",
			cfg.UI.StateDir, configPath)
	}
	return fmt.Sprintf("http://%s/?token=%s", cfg.UI.Listen, token), nil
}

// cachePath is where a working link is remembered, under the user's own
// configuration directory rather than the client's.
func cachePath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "vpn-gateway", "link")
}

// rememberLink saves a link that has been shown to work, so the application
// opens by itself next time.
func rememberLink(link string) error {
	path := cachePath()
	if path == "" {
		return errors.New("no user configuration directory")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// It carries a token that can drive the interface, so it is no more
	// readable than the client's own copy.
	return os.WriteFile(path, []byte(link+"\n"), 0o600)
}

// checkLink reports whether a link actually reaches a client.
//
// A link is only remembered once it has worked, so a mistyped one fails now
// with an explanation rather than being cached and failing silently on every
// later launch.
func checkLink(link string) error {
	base, token, err := splitLink(link)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/state", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("nothing is listening at %s.\n\nIs the client running?", base)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("%s rejected the token in this link.\n\n"+
			"The client generates a new one if its state directory is cleared;\n"+
			"use the link it printed most recently.", base)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %d", base, resp.StatusCode)
	}
	return nil
}
