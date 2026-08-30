//go:build !windows

package client

import (
	"fmt"
	"os"
	"syscall"
)

// preserveOwner hands a replacement file to whoever owned the original.
//
// The background service runs as root over the same configuration file the
// application writes. Replacing a file means creating a new one, and a new
// file created by root belongs to root: without this, the first setting
// changed through the service would leave a configuration its owner could no
// longer edit, and the application would start failing to save with a
// permission error nobody did anything to cause.
func preserveOwner(f *os.File, original string) error {
	info, err := os.Stat(original)
	if err != nil {
		// Nothing to preserve: this is a file being created.
		return nil
	}
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	uid, gid := int(sys.Uid), int(sys.Gid)
	if uid == os.Getuid() && gid == os.Getgid() {
		return nil
	}
	if err := f.Chown(uid, gid); err != nil {
		// Only root can give a file away, and only root ever needs to: an
		// unprivileged process rewriting its own file already owns it.
		if os.Geteuid() != 0 {
			return nil
		}
		return fmt.Errorf("keep %s owned by %d:%d: %w", original, uid, gid, err)
	}
	return nil
}
