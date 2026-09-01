package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
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

// fakeController stands in for a session.
type fakeController struct {
	mu         sync.Mutex
	cfg        *client.Config
	phase      client.Phase
	configPath string

	applied  [][]client.Rule
	bundles  [][]byte
	connects int

	applyErr  error
	importErr error
	connErr   error
}

func (f *fakeController) Status() client.SessionStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return client.SessionStatus{Phase: f.phase, ConfigPath: f.configPath, TunnelCount: 1}
}

func (f *fakeController) Settings() *client.Config {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cfg
}

// Client is nil throughout: these tests cover the interface, not a routing
// engine, and every handler has to cope with nothing being connected.
func (f *fakeController) Client() *client.Client { return nil }

func (f *fakeController) ImportBundle(raw []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.importErr != nil {
		return f.importErr
	}
	f.bundles = append(f.bundles, raw)
	f.phase = client.PhaseIdle
	return nil
}

func (f *fakeController) Connect(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.connErr != nil {
		return f.connErr
	}
	f.connects++
	f.phase = client.PhaseConnected
	return nil
}

func (f *fakeController) Disconnect() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.phase = client.PhaseIdle
	return nil
}

func (f *fakeController) Apply(ctx context.Context, cfg *client.Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.applyErr != nil {
		return f.applyErr
	}
	f.applied = append(f.applied, cfg.Rules)
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
	ctl := &fakeController{cfg: cfg, phase: client.PhaseIdle, configPath: path}
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

	for _, path := range []string{"/api/state", "/api/rules"} {
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

func TestStateDescribesTheSession(t *testing.T) {
	_, _, _, srv := testServer(t)
	resp := do(t, srv, http.MethodGet, "/api/state", "tok", "")
	defer resp.Body.Close()

	var st State
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if st.Session.Phase != client.PhaseIdle {
		t.Errorf("phase = %q", st.Session.Phase)
	}
	// Nothing is connected, so there are no tunnels -- and the field still
	// has to be a list rather than null, or the interface cannot iterate it.
	if st.Tunnels == nil {
		t.Error("tunnels is null; the interface expects a list")
	}
	if len(st.Rules) != 1 || st.Rules[0].Tunnel != "office" {
		t.Errorf("rules = %+v", st.Rules)
	}
	if !st.Client.Proxy || st.Client.OnFailure != client.TargetDirect {
		t.Errorf("client view = %+v", st.Client)
	}
}

func TestRulesAreNeverNullOnTheWire(t *testing.T) {
	// A configuration with no rules holds a nil slice. Sent as null, it broke
	// the rules editor outright: "add rule" threw before it could add one, so
	// the button did nothing on exactly the fresh install that needs it most.
	_, ctl, _, srv := testServer(t)
	ctl.mu.Lock()
	ctl.cfg.Rules = nil
	ctl.mu.Unlock()

	for _, path := range []string{"/api/state", "/api/rules"} {
		resp := do(t, srv, http.MethodGet, path, "tok", "")
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(body, []byte(`"rules":null`)) || bytes.Equal(bytes.TrimSpace(body), []byte("null")) {
			t.Errorf("%s sent null rules; the interface iterates them: %s", path, body)
		}
	}
}

func TestBundleImportMovesOutOfSetup(t *testing.T) {
	_, ctl, _, srv := testServer(t)
	ctl.mu.Lock()
	ctl.phase = client.PhaseSetup
	ctl.mu.Unlock()

	resp := do(t, srv, http.MethodPost, "/api/bundle", "tok", `{"version":1}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/bundle returned %d", resp.StatusCode)
	}
	if len(ctl.bundles) != 1 {
		t.Fatalf("the controller was given %d bundles", len(ctl.bundles))
	}

	var st State
	json.NewDecoder(resp.Body).Decode(&st)
	if st.Session.Phase != client.PhaseIdle {
		t.Errorf("phase after importing = %q", st.Session.Phase)
	}
}

func TestARejectedBundleIsReported(t *testing.T) {
	_, ctl, _, srv := testServer(t)
	ctl.importErr = errRejected

	resp := do(t, srv, http.MethodPost, "/api/bundle", "tok", `not json`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestConnectAndDisconnect(t *testing.T) {
	_, ctl, _, srv := testServer(t)

	resp := do(t, srv, http.MethodPost, "/api/connect", "tok", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || ctl.connects != 1 {
		t.Fatalf("connect returned %d after %d calls", resp.StatusCode, ctl.connects)
	}

	resp = do(t, srv, http.MethodPost, "/api/disconnect", "tok", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("disconnect returned %d", resp.StatusCode)
	}
	if ctl.Status().Phase != client.PhaseIdle {
		t.Errorf("phase after disconnecting = %q", ctl.Status().Phase)
	}
}

func TestSettingsChangeWhatIsApplied(t *testing.T) {
	_, ctl, _, srv := testServer(t)

	resp := do(t, srv, http.MethodPut, "/api/settings", "tok",
		`{"on_failure":"block","auto_routes":false}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /api/settings returned %d", resp.StatusCode)
	}
	got := ctl.Settings()
	if got.OnFailure != client.TargetBlock {
		t.Errorf("on_failure = %q", got.OnFailure)
	}
	if got.AutoRoutes {
		t.Error("auto_routes was not turned off")
	}
	// Fields that were not sent must keep their values.
	if !got.Proxy.Enabled {
		t.Error("an unrelated setting was reset")
	}
}

func TestHandlersSayWhenNothingIsConnected(t *testing.T) {
	// Every one of these needs a routing engine, and the interface is usable
	// before there is one.
	_, _, _, srv := testServer(t)
	for _, path := range []string{
		"/api/generated-config", "/api/tunnels/office/logs",
	} {
		resp := do(t, srv, http.MethodGet, path, "tok", "")
		resp.Body.Close()
		if resp.StatusCode != http.StatusConflict {
			t.Errorf("GET %s returned %d, want 409", path, resp.StatusCode)
		}
	}
	resp := do(t, srv, http.MethodPost, "/api/tunnels/office/reconnect", "tok", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("reconnect returned %d, want 409", resp.StatusCode)
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

	if len(ctl.applied) != 1 || ctl.applied[0][0].Tunnel != "lab" {
		t.Fatalf("the session was given %+v", ctl.applied)
	}
	_ = path
}

func TestRejectedRulesAreReported(t *testing.T) {
	// Applying validates and saves together, so a rejection leaves both the
	// running engine and the file on disk exactly as they were.
	_, ctl, path, srv := testServer(t)
	ctl.applyErr = errRejected

	resp := do(t, srv, http.MethodPut, "/api/rules", "tok",
		`[{"domain_suffix":["x.example.com"],"tunnel":"nope"}]`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("PUT with rejected rules returned %d, want 400", resp.StatusCode)
	}

	saved, _ := os.ReadFile(path)
	if strings.Contains(string(saved), "x.example.com") {
		t.Errorf("rules the session rejected were written to disk:\n%s", saved)
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

func TestLinkFileRoundTrip(t *testing.T) {
	// The tray reads this to find a client whose own state directory it
	// cannot open.
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "link")

	if err := WriteLink(path, "127.0.0.1:8645", "tok123", ""); err != nil {
		t.Fatal(err)
	}
	got, err := ReadLink(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != "http://127.0.0.1:8645/?token=tok123" {
		t.Errorf("link = %q", got)
	}

	// It carries a token that can reroute this machine's traffic.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("the link file is mode %o, want 600", perm)
	}
}

func TestReadLinkRejectsAnEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "link")
	if err := os.WriteFile(path, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLink(path); err == nil {
		t.Fatal("an empty link file was accepted")
	}
}

func TestNodesAPI(t *testing.T) {
	_, ctl, _, srv := testServer(t)
	token := "tok"

	// 1. Add node via Trojan URL
	body := `{"url": "trojan://mypass@hk.example.com:443?sni=hk.example.com&allowInsecure=1#HK-Node"}`
	resp := do(t, srv, http.MethodPost, "/api/nodes", token, body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/nodes: %d", resp.StatusCode)
	}
	var st State
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if len(st.CustomNodes) != 1 {
		t.Fatalf("expected 1 custom node, got %d", len(st.CustomNodes))
	}
	node := st.CustomNodes[0]
	if node.Name != "HK-Node" || node.Server != "hk.example.com" || node.Port != 443 || node.Password != "mypass" {
		t.Errorf("unexpected node properties: %+v", node)
	}

	// 2. Select node
	selectBody := `{"id": "` + node.ID + `"}`
	resp = do(t, srv, http.MethodPost, "/api/nodes/select", token, selectBody)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/nodes/select: %d", resp.StatusCode)
	}
	resp.Body.Close()

	if ctl.Settings().SelectedNode != "node-"+node.ID {
		t.Errorf("SelectedNode = %q, want %q", ctl.Settings().SelectedNode, "node-"+node.ID)
	}

	// 3. Update node
	updateBody := `{"name": "HK-Node-Updated", "port": 8443}`
	resp = do(t, srv, http.MethodPut, "/api/nodes/"+node.ID, token, updateBody)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /api/nodes/%s: %d", node.ID, resp.StatusCode)
	}
	var updateSt State
	json.NewDecoder(resp.Body).Decode(&updateSt)
	resp.Body.Close()

	if len(updateSt.CustomNodes) != 1 || updateSt.CustomNodes[0].Name != "HK-Node-Updated" || updateSt.CustomNodes[0].Port != 8443 {
		t.Errorf("unexpected updated node: %+v", updateSt.CustomNodes)
	}

	// 4. Delete node
	resp = do(t, srv, http.MethodDelete, "/api/nodes/"+node.ID, token, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE /api/nodes/%s: %d", node.ID, resp.StatusCode)
	}
	var deleteSt State
	json.NewDecoder(resp.Body).Decode(&deleteSt)
	resp.Body.Close()

	if len(deleteSt.CustomNodes) != 0 {
		t.Errorf("expected 0 custom nodes after delete, got %d", len(deleteSt.CustomNodes))
	}
}

func TestSubscriptionsAPI(t *testing.T) {
	// Serve a mock subscription endpoint
	subServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("trojan://pass1@sub1.com:443#SubNode1\ntrojan://pass2@sub2.com:443#SubNode2\n"))
	}))
	defer subServer.Close()

	_, _, _, srv := testServer(t)
	token := "tok"

	// Add subscription
	body := `{"name": "Test Sub", "url": "` + subServer.URL + `"}`
	resp := do(t, srv, http.MethodPost, "/api/subscriptions", token, body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/subscriptions: %d", resp.StatusCode)
	}
	var st State
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if len(st.Subscriptions) != 1 {
		t.Fatalf("expected 1 subscription, got %d", len(st.Subscriptions))
	}
	sub := st.Subscriptions[0]
	if sub.Name != "Test Sub" || len(sub.Nodes) != 2 {
		t.Errorf("unexpected subscription: %+v", sub)
	}
	if len(st.AllNodes) != 2 {
		t.Errorf("expected 2 all_nodes, got %d", len(st.AllNodes))
	}

	// Delete subscription
	resp = do(t, srv, http.MethodDelete, "/api/subscriptions/"+sub.ID, token, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE /api/subscriptions: %d", resp.StatusCode)
	}
	var delSt State
	json.NewDecoder(resp.Body).Decode(&delSt)
	resp.Body.Close()

	if len(delSt.Subscriptions) != 0 {
		t.Errorf("expected 0 subscriptions, got %d", len(delSt.Subscriptions))
	}
}
