package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// LabelManaged marks containers this server owns, so cleanup can find them
// without guessing from names.
const LabelManaged = "io.vpn-gateway.managed"

// LabelConfigHash records the tunnel configuration a container was created
// from. When it stops matching, the container is recreated.
const LabelConfigHash = "io.vpn-gateway.config-hash"

// cliTimeout bounds an individual engine command. Pull is exempt.
const cliTimeout = 60 * time.Second

// CLI drives docker or podman through its command line.
type CLI struct{ bin string }

// Detect returns an engine for the requested name, or the first available one
// when name is "auto".
func Detect(name string) (Engine, error) {
	switch name {
	case "docker", "podman":
		if _, err := exec.LookPath(name); err != nil {
			return nil, fmt.Errorf("container runtime %q is not installed: %w", name, err)
		}
		return &CLI{bin: name}, nil
	case "", "auto":
		for _, cand := range []string{"docker", "podman"} {
			if _, err := exec.LookPath(cand); err == nil {
				return &CLI{bin: cand}, nil
			}
		}
		return nil, errors.New("no container runtime found: install docker or podman")
	default:
		return nil, fmt.Errorf("unsupported runtime %q", name)
	}
}

func (c *CLI) Name() string { return c.bin }

func (c *CLI) run(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, cliTimeout)
	defer cancel()
	return c.runNoTimeout(ctx, args...)
}

func (c *CLI) runNoTimeout(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, c.bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return stdout.String(), fmt.Errorf("%s %s: %s", c.bin, strings.Join(args, " "), msg)
	}
	return stdout.String(), nil
}

func (c *CLI) EnsureNetwork(ctx context.Context, name string) error {
	if _, err := c.run(ctx, "network", "inspect", name); err == nil {
		return nil
	}
	// A concurrent create is benign; treat "already exists" as success.
	if _, err := c.run(ctx, "network", "create", name); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			return nil
		}
		return err
	}
	return nil
}

// inspectResult is the subset of the engine's inspect output we rely on.
// Both docker and podman emit these fields with the same shape.
type inspectResult struct {
	State struct {
		Running  bool `json:"Running"`
		ExitCode int  `json:"ExitCode"`
	} `json:"State"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
}

func (c *CLI) Inspect(ctx context.Context, name string) (Status, error) {
	out, err := c.run(ctx, "inspect", name)
	if err != nil {
		// Absence is a normal state, not a failure: the tunnel manager uses
		// it to decide to create the container.
		if isNotFound(err) {
			return Status{}, nil
		}
		return Status{}, err
	}
	var results []inspectResult
	if err := json.Unmarshal([]byte(out), &results); err != nil {
		return Status{}, fmt.Errorf("parse inspect output for %s: %w", name, err)
	}
	if len(results) == 0 {
		return Status{}, nil
	}
	r := results[0]
	return Status{
		Exists:     true,
		Running:    r.State.Running,
		ExitCode:   r.State.ExitCode,
		Image:      r.Config.Image,
		ConfigHash: r.Config.Labels[LabelConfigHash],
	}, nil
}

func (c *CLI) Create(ctx context.Context, spec Spec) error {
	args := []string{
		"create",
		"--name", spec.Name,
		// The server supervises restarts itself with backoff and reports the
		// reason to clients, so the engine must not race it.
		"--restart", "no",
		"--network", spec.Network,
	}
	if spec.EnvFile != "" {
		args = append(args, "--env-file", spec.EnvFile)
	}
	for _, p := range spec.Ports {
		args = append(args, "-p", fmt.Sprintf("127.0.0.1:%d:%d", p.HostPort, p.ContainerPort))
	}
	for _, cap := range spec.CapAdd {
		args = append(args, "--cap-add", cap)
	}
	for _, dev := range spec.Devices {
		args = append(args, "--device", dev)
	}
	args = append(args, "--label", LabelManaged+"=true")
	for k, v := range spec.Labels {
		args = append(args, "--label", k+"="+v)
	}
	args = append(args, spec.Image)

	_, err := c.run(ctx, args...)
	return err
}

func (c *CLI) Start(ctx context.Context, name string) error {
	_, err := c.run(ctx, "start", name)
	return err
}

func (c *CLI) Stop(ctx context.Context, name string, timeoutSeconds int) error {
	_, err := c.run(ctx, "stop", "-t", strconv.Itoa(timeoutSeconds), name)
	if err != nil && isNotFound(err) {
		return nil
	}
	return err
}

func (c *CLI) Remove(ctx context.Context, name string) error {
	_, err := c.run(ctx, "rm", "-f", name)
	if err != nil && isNotFound(err) {
		return nil
	}
	return err
}

func (c *CLI) Logs(ctx context.Context, name string, tail int) (string, error) {
	// Container logs carry both streams; the agent writes structured lines to
	// stderr, so both are wanted.
	out, err := c.run(ctx, "logs", "--tail", strconv.Itoa(tail), name)
	if err != nil && isNotFound(err) {
		return "", nil
	}
	return out, err
}

func (c *CLI) Pull(ctx context.Context, image string) error {
	// Pulling a large vendor image over a home connection can take minutes,
	// so this one command is not subject to cliTimeout.
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	_, err := c.runNoTimeout(ctx, "pull", image)
	return err
}

func isNotFound(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "no such container") ||
		strings.Contains(s, "no such object") ||
		strings.Contains(s, "not found")
}
