package tunnel

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/vpn-gateway/vpn-gateway/internal/server"
	"github.com/vpn-gateway/vpn-gateway/internal/server/runtime"
)

// fakeEngine records what was asked of the container engine.
type fakeEngine struct {
	present  bool
	pulls    []string
	pullErr  error
	existErr error
}

func (f *fakeEngine) Name() string { return "fake" }
func (f *fakeEngine) HasImage(ctx context.Context, image string) (bool, error) {
	return f.present, f.existErr
}
func (f *fakeEngine) Pull(ctx context.Context, image string) error {
	if f.pullErr != nil {
		return f.pullErr
	}
	f.pulls = append(f.pulls, image)
	f.present = true
	return nil
}
func (f *fakeEngine) EnsureNetwork(context.Context, string) error { return nil }
func (f *fakeEngine) Inspect(context.Context, string) (runtime.Status, error) {
	return runtime.Status{}, nil
}
func (f *fakeEngine) Create(context.Context, runtime.Spec) error        { return nil }
func (f *fakeEngine) Start(context.Context, string) error               { return nil }
func (f *fakeEngine) Stop(context.Context, string, int) error           { return nil }
func (f *fakeEngine) Remove(context.Context, string) error              { return nil }
func (f *fakeEngine) Logs(context.Context, string, int) (string, error) { return "", nil }

func tunnelWith(policy string, engine runtime.Engine) *Tunnel {
	return &Tunnel{
		cfg:        server.TunnelConfig{Name: "office", Image: "coosir/vg-mock:latest"},
		engine:     engine,
		pullPolicy: policy,
		log:        slog.New(slog.DiscardHandler),
	}
}

func TestAMissingImageIsFetched(t *testing.T) {
	// Images are built elsewhere and pushed, so a server that has never run
	// this tunnel does not have one. Without fetching it, creating the
	// container fails with the engine's own message about an unknown image,
	// which says nothing about where it was meant to come from.
	e := &fakeEngine{present: false}
	if err := tunnelWith("missing", e).ensureImage(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(e.pulls) != 1 || e.pulls[0] != "coosir/vg-mock:latest" {
		t.Errorf("fetched %v", e.pulls)
	}
}

func TestAnImageAlreadyHereIsNotFetchedAgain(t *testing.T) {
	e := &fakeEngine{present: true}
	if err := tunnelWith("missing", e).ensureImage(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(e.pulls) != 0 {
		t.Errorf("fetched an image that was already here: %v", e.pulls)
	}
}

func TestAlwaysFetchesEvenWhenPresent(t *testing.T) {
	// A tag that moves, such as latest, only changes on the server when
	// something goes and looks.
	e := &fakeEngine{present: true}
	if err := tunnelWith("always", e).ensureImage(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(e.pulls) != 1 {
		t.Errorf("fetched %d times, want 1", len(e.pulls))
	}
}

func TestNeverExplainsWhatToDo(t *testing.T) {
	e := &fakeEngine{present: false}
	err := tunnelWith("never", e).ensureImage(context.Background())
	if err == nil {
		t.Fatal("a missing image was accepted with pull_policy never")
	}
	if len(e.pulls) != 0 {
		t.Errorf("something was fetched despite the policy: %v", e.pulls)
	}
	for _, want := range []string{"coosir/vg-mock:latest", "push it"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the message does not mention %q: %v", want, err)
		}
	}
}

func TestNeverAcceptsAnImageThatIsHere(t *testing.T) {
	e := &fakeEngine{present: true}
	if err := tunnelWith("never", e).ensureImage(context.Background()); err != nil {
		t.Errorf("an image that is present was refused: %v", err)
	}
}

func TestAFailedFetchSaysWhichImage(t *testing.T) {
	e := &fakeEngine{present: false, pullErr: errors.New("no route to host")}
	err := tunnelWith("missing", e).ensureImage(context.Background())
	if err == nil {
		t.Fatal("a failed fetch was reported as success")
	}
	if !strings.Contains(err.Error(), "coosir/vg-mock:latest") {
		t.Errorf("the error does not name the image: %v", err)
	}
}

// TestManagerPassesThePullPolicyThrough covers a wiring mistake that has no
// symptom until a server without the image tries to start: the field was
// declared and read but never assigned, so every tunnel silently used the
// default whatever the configuration said.
func TestManagerPassesThePullPolicyThrough(t *testing.T) {
	dir := t.TempDir()
	cfg := &server.Config{
		StateDir:   dir,
		PullPolicy: "never",
		Tunnels: []server.TunnelConfig{
			{Name: "office", Provider: "mock", Image: "coosir/vg-mock:latest",
				DataPort: 21000, ControlPort: 21001},
		},
	}

	m, err := NewManager(cfg, &fakeEngine{}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if got := m.tunnels[0].pullPolicy; got != "never" {
		t.Errorf("the tunnel was built with pull policy %q, want never", got)
	}
}
