// Package runtime drives a container engine. Only Linux engines are
// supported, because vpn-gateway containers run on the server, never on the
// client -- that is what keeps the client free of any container dependency.
package runtime

import "context"

// Spec describes a container to run. It is the whole surface the tunnel
// manager needs; anything image-specific belongs in the image.
type Spec struct {
	Name    string
	Image   string
	Network string

	// Hostname configures a stable container hostname.
	Hostname string

	// MacAddress configures a stable container MAC address.
	MacAddress string

	// Volumes mounts host directories into the container ("hostPath:containerPath").
	Volumes []string

	// EnvFile holds the container's environment, including credentials. It is
	// a file rather than inline values so secrets never appear in the
	// engine's command line or in the host process list.
	EnvFile string

	// Ports maps a host loopback port to a container port. Nothing is ever
	// published on a non-loopback address: an open SOCKS5 that tunnels into a
	// corporate network would be a serious hole.
	Ports []PortMap

	CapAdd  []string
	Devices []string
	Labels  map[string]string
}

// PortMap publishes ContainerPort on 127.0.0.1:HostPort.
type PortMap struct {
	HostPort      int
	ContainerPort int
}

// Status is what the engine reports about a container.
type Status struct {
	Exists   bool
	Running  bool
	ExitCode int
	// Image is the image reference the container was created from, used to
	// detect that the spec drifted from the running container.
	Image string
	// ConfigHash is the value of the vpn-gateway config-hash label recorded
	// when the container was created.
	ConfigHash string
}

// Engine is a container runtime. Implementations shell out to the engine's
// CLI: it is the one interface both docker and podman agree on, and it keeps
// the server free of a large SDK dependency tree.
type Engine interface {
	// Name reports the engine binary, "docker" or "podman".
	Name() string
	// EnsureNetwork creates the named bridge network if it is absent.
	EnsureNetwork(ctx context.Context, name string) error
	// Inspect reports the container's current status.
	Inspect(ctx context.Context, name string) (Status, error)
	// Create makes the container without starting it.
	Create(ctx context.Context, spec Spec) error
	// Start starts an existing container.
	Start(ctx context.Context, name string) error
	// Stop stops a running container, waiting up to timeoutSeconds for it to
	// exit before killing it.
	Stop(ctx context.Context, name string, timeoutSeconds int) error
	// Remove deletes a container, stopping it first if needed.
	Remove(ctx context.Context, name string) error
	// Logs returns the last n lines of container output.
	Logs(ctx context.Context, name string, tail int) (string, error)
	// HasImage reports whether the image is already present locally.
	HasImage(ctx context.Context, image string) (bool, error)
	// Pull fetches the image from its registry.
	Pull(ctx context.Context, image string) error
}
