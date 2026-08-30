package ui

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/client"
	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

// fakeController stands in for the running client.
type fakeController struct {
	mu        sync.Mutex
	cfg       *client.Config
	tunnels   []client.TunnelState
	reloads   [][]client.Rule
	reloadErr error
}

func (f *fakeController) Tunnels() []client.TunnelState {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tunnels
}
func (f *fakeController) Settings() *client.Config {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cfg
}
func (f *fakeController) Config() ([]byte, error) { return []byte(`{"route":{"final":"direct"}}`), nil }
func (f *fakeController) API() *client.API        { return client.NewAPI("http://127.0.0.1:1", "t") }
func (f *fakeController) Reload(ctx context.Context, cfg *client.Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.reloadErr != nil {
		return f.reloadErr
	}
	f.reloads = append(f.reloads, cfg.Rules)
	f.cfg = cfg
	return nil
}

const uiConfig = `# kept
bundle: /dev/null
proxy: {enabled: true}
# rules below
rules:
  - domain_suffix: [old.example.com]
    tunnel: office
`

func testServer(t *testing.T) (*Server, *fakeController, string, *httptest.Server) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "client.yaml")
	if err := os.WriteFile(path, []byte(uiConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := client.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	ctl := &fakeController{
		cfg: cfg,
		tunnels: []client.TunnelState{
			{Name: "office", Up: true, Routes: []string{"10.10.0.0/16"}, DNS: []string{"10.10.0.53"}},
			{Name: "lab", Up: false},
		},
	}
	s := New(ctl, path, "tok", slog.New(slog.DiscardHandler))
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return s, ctl, path, srv
}

func do(t *testing.T, srv *httptest.Server, method, path, token, body string) *http.Response {
	t.Helper()
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	var req *http.Request
	var err error
	if rdr != nil {
		req, err = http.NewRequest(method, srv.URL+path, rdr)
	} else {
		req, err = http.NewRequest(method, srv.URL+path, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestEverythingButThePageNeedsTheToken(t *testing.T) {
	// Loopback is not enough on its own: any other process on the machine
	// could otherwise reroute this machine's traffic just by connecting.
	_, _, _, srv := testServer(t)

	for _, path := range []string{"/api/state", "/api/rules", "/api/generated-config"} {
		if resp := do(t, srv, http.MethodGet, path, "", ""); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s without a token returned %d, want 401", path, resp.StatusCode)
		}
		if resp := do(t, srv, http.MethodGet, path, "wrong", ""); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s with the wrong token returned %d, want 401", path, resp.StatusCode)
		}
		if resp := do(t, srv, http.MethodGet, path, "tok", ""); resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s with the token returned %d, want 200", path, resp.StatusCode)
		}
	}

	// The page carries no data and asks for the token before fetching, so it
	// is served unauthenticated.
	if resp := do(t, srv, http.MethodGet, "/", "", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("GET / returned %d, want 200", resp.StatusCode)
	}
}

func TestStateDescribesTheTunnels(t *testing.T) {
	_, _, _, srv := testServer(t)
	resp := do(t, srv, http.MethodGet, "/api/state", "tok", "")
	defer resp.Body.Close()

	var st State
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if len(st.Tunnels) != 2 || st.Tunnels[0].Name != "office" || !st.Tunnels[0].Up {
		t.Errorf("tunnels = %+v", st.Tunnels)
	}
	if st.Tunnels[1].Up {
		t.Error("a tunnel that is down was reported as up")
	}
	if len(st.Rules) != 1 || st.Rules[0].Tunnel != "office" {
		t.Errorf("rules = %+v", st.Rules)
	}
	if !st.Client.Proxy || st.Client.OnFailure != client.TargetDirect {
		t.Errorf("client view = %+v", st.Client)
	}
}

func TestRulesAreAppliedThenSaved(t *testing.T) {
	_, ctl, path, srv := testServer(t)

	body := `[{"domain_suffix":["new.example.com"],"tunnel":"lab"}]`
	resp := do(t, srv, http.MethodPut, "/api/rules", "tok", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /api/rules returned %d", resp.StatusCode)
	}

	if len(ctl.reloads) != 1 || ctl.reloads[0][0].Tunnel != "lab" {
		t.Fatalf("the client was reloaded with %+v", ctl.reloads)
	}

	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(saved), "new.example.com") {
		t.Errorf("the new rule was not saved:\n%s", saved)
	}
	if !strings.Contains(string(saved), "# kept") {
		t.Errorf("the file's comments were lost:\n%s", saved)
	}
}

func TestRejectedRulesAreNotSaved(t *testing.T) {
	// Saving first would leave a file the running client refused, so the next
	// start would fail with rules that were never in effect.
	_, ctl, path, srv := testServer(t)
	ctl.reloadErr = errRejected

	resp := do(t, srv, http.MethodPut, "/api/rules", "tok",
		`[{"domain_suffix":["x.example.com"],"tunnel":"nope"}]`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("PUT with rejected rules returned %d, want 400", resp.StatusCode)
	}

	saved, _ := os.ReadFile(path)
	if strings.Contains(string(saved), "x.example.com") {
		t.Errorf("rules the client rejected were written to disk:\n%s", saved)
	}
	if !strings.Contains(string(saved), "old.example.com") {
		t.Errorf("the previous rules were lost:\n%s", saved)
	}
}

func TestPromptIsShownAndAnswered(t *testing.T) {
	s, _, _, srv := testServer(t)

	answered := make(chan string, 1)
	go func() {
		v, err := s.Prompter().Ask(context.Background(), "corp", contract.Challenge{
			ID: "sms-1", Type: contract.ChallengeSMS, Prompt: "Enter the code",
			ExpiresAt: time.Now().Add(time.Minute),
		})
		if err == nil {
			answered <- v
		}
	}()

	// The prompt appears in the state the interface polls.
	var id string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp := do(t, srv, http.MethodGet, "/api/state", "tok", "")
		var st State
		json.NewDecoder(resp.Body).Decode(&st)
		resp.Body.Close()
		if len(st.Prompts) == 1 {
			if st.Prompts[0].Tunnel != "corp" || st.Prompts[0].Type != "sms" {
				t.Fatalf("prompt = %+v", st.Prompts[0])
			}
			id = st.Prompts[0].ID
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if id == "" {
		t.Fatal("the challenge never appeared in the state")
	}

	resp := do(t, srv, http.MethodPost, "/api/prompts/"+id, "tok", `{"value":"482915"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("answering returned %d", resp.StatusCode)
	}

	select {
	case v := <-answered:
		if v != "482915" {
			t.Errorf("the provider received %q", v)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the answer never reached whoever was waiting")
	}
}

func TestAnsweringAnUnknownPromptFails(t *testing.T) {
	_, _, _, srv := testServer(t)
	resp := do(t, srv, http.MethodPost, "/api/prompts/corp:gone", "tok", `{"value":"1"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("answering a prompt nobody is waiting for returned %d, want 409", resp.StatusCode)
	}
}

func TestPromptIDsAreScopedToTheirTunnel(t *testing.T) {
	// A gateway's challenge ids are only unique to itself, and two tunnels can
	// be waiting for codes at once.
	s, _, _, srv := testServer(t)

	for _, tunnel := range []string{"office", "lab"} {
		go s.Prompter().Ask(context.Background(), tunnel, contract.Challenge{
			ID: "same-id", Type: contract.ChallengeSMS, ExpiresAt: time.Now().Add(time.Minute),
		})
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		resp := do(t, srv, http.MethodGet, "/api/state", "tok", "")
		var st State
		json.NewDecoder(resp.Body).Decode(&st)
		resp.Body.Close()
		if len(st.Prompts) == 2 {
			ids := map[string]bool{}
			for _, p := range st.Prompts {
				ids[p.ID] = true
			}
			if len(ids) != 2 {
				t.Errorf("two tunnels produced one id: %v", ids)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("both challenges never appeared at once")
}

func TestServeRefusesANonLoopbackAddress(t *testing.T) {
	// Reachable from the network, this interface would let a stranger reroute
	// the machine's traffic.
	_, err := Serve(context.Background(), "0.0.0.0:0", http.NotFoundHandler(), slog.New(slog.DiscardHandler))
	if err == nil {
		t.Fatal("a non-loopback address was accepted")
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Errorf("the error does not explain why: %v", err)
	}
}

func TestTokenIsStableAcrossRestarts(t *testing.T) {
	// The link the client prints has to keep working.
	dir := t.TempDir()
	first, err := LoadOrCreateToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Errorf("the token changed between runs: %q then %q", first, second)
	}
	info, err := os.Stat(filepath.Join(dir, "ui-token"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("the token file mode is %o, want 600", perm)
	}
}

func TestPageIsSelfContained(t *testing.T) {
	// The interface is most needed when the tunnels are down, which is when
	// there is no network to fetch anything from.
	_, _, _, srv := testServer(t)
	resp := do(t, srv, http.MethodGet, "/", "", "")
	defer resp.Body.Close()
	buf := make([]byte, 1<<20)
	n, _ := resp.Body.Read(buf)
	page := string(buf[:n])

	for _, forbidden := range []string{"https://fonts.", "cdn.", "unpkg", "jsdelivr", "@import url("} {
		if strings.Contains(page, forbidden) {
			t.Errorf("the page reaches out to %q", forbidden)
		}
	}
}

type rejected struct{}

func (rejected) Error() string { return "rules reference unknown tunnels: nope" }

var errRejected = rejected{}
