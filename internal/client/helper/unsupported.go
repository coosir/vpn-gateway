//go:build !darwin && !windows

package helper

// Everywhere else the client is started by the platform's own service
// manager: a systemd unit on Linux, which grants CAP_NET_ADMIN instead of
// running as root, and a service on Windows. Those are installed by whoever
// deploys the machine, not by an application asking for a password, so there
// is nothing here for the interface to offer.

// Inspect reports that there is nothing to install.
func Inspect(Options) Status { return Status{} }

// Install is not available.
func Install(Options) error { return ErrUnsupported }

// Uninstall is not available.
func Uninstall() error { return ErrUnsupported }
