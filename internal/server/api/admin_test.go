package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/vpn-gateway/vpn-gateway/internal/server"
	"github.com/vpn-gateway/vpn-gateway/internal/server/tunnel"
)

type memStore struct {
	mu sync.Mutex
	m  map[string]server.TunnelConfig
}

func (s *memStore) PutTunnel(t server.TunnelConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[t.Name] = t
	return nil
}

func (s *memStore) DeleteTunnel(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[name]; !ok {
		return errors.New("not found")
	}
	delete(s.m, name)
	return nil
}

func adminServer(t *testing.T, tunnels ...server.TunnelConfig) (*httptest.Server, *memStore, *tunnel.Manager) {
	t.Helper()
	cfg := &server.Config{StateDir: t.TempDir(), PortBase: 21000, Tunnels: tunnels}
	mgr, err := tunnel.NewManager(cfg, nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	st := &memStore{m: map[string]server.TunnelConfig{}}
	for _, tc := range tunnels {
		st.m[tc.Name] = tc
	}
	srv := New(mgr, "tok", nil, slog.New(slog.DiscardHandler))
	srv.SetTunnelStore(st, cfg.PortBase)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, st, mgr
}

func call(t *testing.T, ts *httptest.Server, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, ts.URL+path, rdr)
	req.Header.Set("Authorization", "Bearer tok")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func TestAdminAddsATunnelThatIsLiveAtOnce(t *testing.T) {
	ts, st, mgr := adminServer(t, server.TunnelConfig{Name: "taken", Provider: "mock", Image: "i", DataPort: 21000, ControlPort: 21001})

	code, out := call(t, ts, "POST", "/api/v1/admin/tunnels", map[string]any{
		"name": "office", "provider": "anyconnect", "image": "coosir/vg-openconnect:latest",
		"server": "vpn.example", "username": "alice", "password": "s3cret",
		"extra": map[string]string{"routes": "10.0.0.0/8", "totp_secret": "SEED"},
	})
	if code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, out)
	}
	// Credentials do not come back out.
	if out["password"] != Unchanged || out["extra"].(map[string]any)["totp_secret"] != Unchanged {
		t.Errorf("credentials in the reply: %v", out)
	}
	// It is managed now, with ports nobody else has.
	got, ok := mgr.Config("office")
	if !ok {
		t.Fatal("the manager does not have the new tunnel")
	}
	if got.DataPort != 21002 || got.ControlPort != 21003 {
		t.Errorf("ports = %d/%d, want 21002/21003 (21000-1 are taken)", got.DataPort, got.ControlPort)
	}
	if st.m["office"].Password != "s3cret" {
		t.Error("the stored tunnel lost its password")
	}

	// Saved again with the placeholders: nothing secret changes.
	code, out = call(t, ts, "PUT", "/api/v1/admin/tunnels/office", map[string]any{
		"name": "office", "provider": "anyconnect", "image": "coosir/vg-openconnect:latest",
		"server": "vpn2.example", "username": "alice", "password": Unchanged,
		"extra": map[string]string{"routes": "10.0.0.0/8", "totp_secret": Unchanged},
	})
	if code != http.StatusOK {
		t.Fatalf("update: %d %v", code, out)
	}
	got, _ = mgr.Config("office")
	if got.Server != "vpn2.example" || got.Password != "s3cret" || got.Extra["totp_secret"] != "SEED" {
		t.Errorf("after update: %+v", got)
	}
	if got.DataPort != 21002 {
		t.Errorf("an update moved the tunnel's ports to %d", got.DataPort)
	}

	// Deleted.
	if code, out := call(t, ts, "DELETE", "/api/v1/admin/tunnels/office", nil); code != http.StatusOK {
		t.Fatalf("delete: %d %v", code, out)
	}
	if _, ok := mgr.Config("office"); ok {
		t.Error("a deleted tunnel is still managed")
	}
	if _, ok := st.m["office"]; ok {
		t.Error("a deleted tunnel is still stored")
	}
}

func TestAdminRefusesWhatWouldNotRun(t *testing.T) {
	ts, _, _ := adminServer(t, server.TunnelConfig{Name: "lan", Provider: "direct"})
	cases := []struct {
		method, path string
		body         map[string]any
		code         int
		want         string
	}{
		{"POST", "/api/v1/admin/tunnels", map[string]any{"name": "lan", "provider": "direct"}, http.StatusConflict, "already exists"},
		{"POST", "/api/v1/admin/tunnels", map[string]any{"name": "Bad_Name", "provider": "direct"}, http.StatusBadRequest, "name must be"},
		{"POST", "/api/v1/admin/tunnels", map[string]any{"name": "x", "provider": "anyconnect"}, http.StatusBadRequest, "image is required"},
		{"POST", "/api/v1/admin/tunnels", map[string]any{"name": "x", "provider": "direct", "nonsense": 1}, http.StatusBadRequest, "unknown field"},
		{"PUT", "/api/v1/admin/tunnels/lan", map[string]any{"name": "lan2", "provider": "direct"}, http.StatusBadRequest, "renamed"},
		{"PUT", "/api/v1/admin/tunnels/nope", map[string]any{"name": "nope", "provider": "direct"}, http.StatusNotFound, ""},
	}
	for _, c := range cases {
		code, out := call(t, ts, c.method, c.path, c.body)
		msg, _ := out["error"].(string)
		if code != c.code || !strings.Contains(msg, c.want) {
			t.Errorf("%s %s %v: %d %q, want %d containing %q", c.method, c.path, c.body, code, msg, c.code, c.want)
		}
	}
}

func TestAdminPageIsServed(t *testing.T) {
	ts, _, _ := adminServer(t)
	res, err := http.Get(ts.URL + "/admin/")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("GET /admin/: %d %s", res.StatusCode, res.Header.Get("Content-Type"))
	}
	if res.Header.Get("Content-Security-Policy") == "" {
		t.Error("the admin page has no content security policy")
	}
}
