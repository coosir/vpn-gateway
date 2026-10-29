package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/vpn-gateway/vpn-gateway/internal/server"
	"github.com/vpn-gateway/vpn-gateway/internal/server/tunnel"
	"github.com/vpn-gateway/vpn-gateway/internal/server/users"
)

// TestAUserSeesOnlyTheTunnelsTheyMayUse is per-user access from the user's
// side: what they are listed, and what they are refused.
func TestAUserSeesOnlyTheTunnelsTheyMayUse(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.DiscardHandler)
	cfg := &server.Config{StateDir: dir, Tunnels: []server.TunnelConfig{
		{Name: "office", Provider: "direct"},
		{Name: "lab", Provider: "direct"},
	}}
	mgr, err := tunnel.NewManager(cfg, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	um, err := users.NewManager(dir, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	srv := New(mgr, "tok", um, log)
	st := &memStore{m: map[string]server.TunnelConfig{}}
	for _, tc := range cfg.Tunnels {
		st.m[tc.Name] = tc
	}
	srv.SetTunnelStore(st, 21000)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	do := func(token, method, path string, body any) (int, []byte) {
		t.Helper()
		var b []byte
		if body != nil {
			b, _ = json.Marshal(body)
		}
		req, _ := http.NewRequest(method, ts.URL+path, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var buf bytes.Buffer
		buf.ReadFrom(res.Body)
		return res.StatusCode, buf.Bytes()
	}
	listed := func(token string) []string {
		t.Helper()
		code, body := do(token, "GET", "/api/v1/tunnels", nil)
		if code != http.StatusOK {
			t.Fatalf("list: %d %s", code, body)
		}
		var snaps []tunnel.Snapshot
		json.Unmarshal(body, &snaps)
		var names []string
		for _, s := range snaps {
			names = append(names, s.Name)
		}
		return names
	}

	// Created limited to one tunnel.
	if code, body := do("tok", "POST", "/api/v1/users", map[string]any{
		"username": "bob", "password": "bobpass", "restricted": true, "tunnels": []string{"office"},
	}); code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, body)
	}
	if code, _ := do("tok", "POST", "/api/v1/users", map[string]any{
		"username": "eve", "password": "evepass", "tunnels": []string{"nowhere"},
	}); code != http.StatusBadRequest {
		t.Errorf("a grant of a tunnel that does not exist was taken: %d", code)
	}
	bob, _, err := um.Authenticate("bob", "bobpass")
	if err != nil {
		t.Fatal(err)
	}

	if got := listed(bob); !slices.Equal(got, []string{"office"}) {
		t.Errorf("bob is listed %v, want [office]", got)
	}
	if code, _ := do(bob, "GET", "/api/v1/tunnels/lab", nil); code != http.StatusNotFound {
		t.Errorf("bob fetched lab: %d", code)
	}
	if code, _ := do(bob, "POST", "/api/v1/tunnels/lab/auth", map[string]string{"id": "x", "value": "y"}); code != http.StatusNotFound {
		t.Errorf("bob answered for lab: %d", code)
	}
	if code, _ := do(bob, "GET", "/api/v1/tunnels/office", nil); code != http.StatusOK {
		t.Errorf("bob could not fetch office: %d", code)
	}
	// The administrator sees everything regardless.
	if got := listed("tok"); len(got) != 2 {
		t.Errorf("the administrator is listed %v", got)
	}

	// Changed: takes effect on the next request, no new login needed.
	if code, body := do("tok", "PUT", "/api/v1/users/bob", map[string]any{"tunnels": []string{"lab"}}); code != http.StatusOK {
		t.Fatalf("change: %d %s", code, body)
	}
	if got := listed(bob); !slices.Equal(got, []string{"lab"}) {
		t.Errorf("after the change bob is listed %v, want [lab]", got)
	}
	// Opened up to everything.
	if code, _ := do("tok", "PUT", "/api/v1/users/bob", map[string]any{"restricted": false}); code != http.StatusOK {
		t.Fatal("unrestrict failed")
	}
	if got := listed(bob); len(got) != 2 {
		t.Errorf("unrestricted bob is listed %v", got)
	}

	// A deleted tunnel leaves nobody's list, so a new one with its name is
	// not handed to whoever had the old one.
	do("tok", "PUT", "/api/v1/users/bob", map[string]any{"tunnels": []string{"lab"}})
	if code, body := do("tok", "DELETE", "/api/v1/admin/tunnels/lab", nil); code != http.StatusOK {
		t.Fatalf("delete: %d %s", code, body)
	}
	for _, u := range um.List() {
		if u.Username == "bob" && len(u.Tunnels) != 0 {
			t.Errorf("bob still holds %v after lab was deleted", u.Tunnels)
		}
	}
}
