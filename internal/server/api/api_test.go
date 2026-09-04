package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/server"
	"github.com/vpn-gateway/vpn-gateway/internal/server/tunnel"
	"github.com/vpn-gateway/vpn-gateway/internal/server/users"
)

func TestAPIUserManagementAndRevocation(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := &server.Config{
		StateDir: dir,
		Runtime:  "auto",
		Tunnels: []server.TunnelConfig{
			{Name: "mock", Provider: "direct"},
		},
	}

	mgr, err := tunnel.NewManager(cfg, nil, log)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	usersMgr, err := users.NewManager(dir, nil, log)
	if err != nil {
		t.Fatalf("NewManager users: %v", err)
	}

	adminToken := "admin-secret-token"
	apiServer := New(mgr, adminToken, usersMgr, log)
	handler := apiServer.Handler()

	ts := httptest.NewServer(handler)
	defer ts.Close()

	// 1. Create a user via Admin API
	addUserBody, _ := json.Marshal(map[string]string{
		"username": "bob",
		"password": "bobpassword123",
	})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/users", bytes.NewReader(addUserBody))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /api/v1/users: %v", err)
	}
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201 Created", res.StatusCode)
	}
	res.Body.Close()

	// 2. List users
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/v1/users", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/v1/users: %v", err)
	}
	var userList []users.UserSummary
	json.NewDecoder(res.Body).Decode(&userList)
	res.Body.Close()
	if len(userList) != 1 || userList[0].Username != "bob" {
		t.Fatalf("userList = %+v, want [bob]", userList)
	}

	// 3. Login as bob
	loginBody, _ := json.Marshal(map[string]string{
		"username": "bob",
		"password": "bobpassword123",
	})
	res, err = http.Post(ts.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("login bob: %v", err)
	}
	var loginResp LoginResponse
	json.NewDecoder(res.Body).Decode(&loginResp)
	res.Body.Close()
	if !loginResp.OK || loginResp.Token == "" {
		t.Fatalf("login failed: %+v", loginResp)
	}
	bobToken := loginResp.Token

	// 4. Access authenticated endpoint with bob's session token
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/v1/tunnels", nil)
	req.Header.Set("Authorization", "Bearer "+bobToken)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/v1/tunnels: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 OK", res.StatusCode)
	}
	res.Body.Close()

	// 4b. Bob (non-admin) trying to start tunnel should get 403 Forbidden
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/v1/tunnels/mock/start", nil)
	req.Header.Set("Authorization", "Bearer "+bobToken)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /api/v1/tunnels/mock/start: %v", err)
	}
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin start tunnel status = %d, want 403 Forbidden", res.StatusCode)
	}
	res.Body.Close()

	// 5. Open SSE stream for bob
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/v1/events", nil)
	req.Header.Set("Authorization", "Bearer "+bobToken)
	req.Header.Set("Accept", "text/event-stream")
	sseRes, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/v1/events: %v", err)
	}
	if sseRes.StatusCode != http.StatusOK {
		t.Fatalf("SSE status = %d, want 200 OK", sseRes.StatusCode)
	}

	sseClosed := make(chan struct{})
	go func() {
		defer close(sseClosed)
		buf := make([]byte, 1024)
		for {
			_, err := sseRes.Body.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	// 6. Delete user bob via Admin API -> must close bob's active SSE stream immediately
	req, _ = http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/users/bob", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE /api/v1/users/bob: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 OK", res.StatusCode)
	}
	res.Body.Close()

	select {
	case <-sseClosed:
	case <-time.After(3 * time.Second):
		t.Fatal("bob's active SSE stream was not terminated after user deletion")
	}

	// 7. Requesting /api/v1/tunnels with old bob token should now return 401 Unauthorized
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/v1/tunnels", nil)
	req.Header.Set("Authorization", "Bearer "+bobToken)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/v1/tunnels: %v", err)
	}
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 Unauthorized after deletion", res.StatusCode)
	}
	res.Body.Close()
}

type mockTrojanAuth struct {
	mu        sync.Mutex
	passwords map[string]string
	revoked   []string
}

func (m *mockTrojanAuth) GetOrCreatePassword(token, username, tunnelName string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.passwords == nil {
		m.passwords = make(map[string]string)
	}
	key := token + ":" + tunnelName
	if p, ok := m.passwords[key]; ok {
		return p
	}
	p := "dynpass_" + token + "_" + tunnelName
	m.passwords[key] = p
	return p
}

func (m *mockTrojanAuth) RevokeSession(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revoked = append(m.revoked, token)
}

func (m *mockTrojanAuth) RevokeUser(username string) {}

func TestAPIDynamicTrojanPasswordAndLogout(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := &server.Config{
		StateDir: dir,
		Runtime:  "auto",
		Tunnels: []server.TunnelConfig{
			{Name: "mock", Provider: "direct"},
		},
	}

	mgr, err := tunnel.NewManager(cfg, nil, log)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	usersMgr, err := users.NewManager(dir, nil, log)
	if err != nil {
		t.Fatalf("NewManager users: %v", err)
	}

	trojanAuth := &mockTrojanAuth{}
	apiServer := New(mgr, "admin-token", usersMgr, log, trojanAuth)
	ts := httptest.NewServer(apiServer.Handler())
	defer ts.Close()

	if err := usersMgr.Add("charlie", "password123", false); err != nil {
		t.Fatalf("Add charlie: %v", err)
	}

	token, _, err := usersMgr.Authenticate("charlie", "password123")
	if err != nil {
		t.Fatalf("Authenticate charlie: %v", err)
	}

	// 1. GET /api/v1/tunnels should return dynamic TrojanPassword
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/tunnels", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/v1/tunnels: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/tunnels status = %d, want 200", res.StatusCode)
	}
	var snaps []tunnel.Snapshot
	json.NewDecoder(res.Body).Decode(&snaps)
	res.Body.Close()

	if len(snaps) != 1 {
		t.Fatalf("expected 1 snapshot, got %d", len(snaps))
	}
	expectedPass := "dynpass_" + token + "_mock"
	if snaps[0].TrojanPassword != expectedPass {
		t.Fatalf("TrojanPassword = %q, want %q", snaps[0].TrojanPassword, expectedPass)
	}

	// 2. POST /api/v1/auth/logout should revoke session
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /api/v1/auth/logout: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("logout status = %d, want 200", res.StatusCode)
	}
	res.Body.Close()

	trojanAuth.mu.Lock()
	if len(trojanAuth.revoked) != 1 || trojanAuth.revoked[0] != token {
		t.Fatalf("trojanAuth.revoked = %v, want [%s]", trojanAuth.revoked, token)
	}
	trojanAuth.mu.Unlock()

	// 3. Subsequent request with token must be rejected with 401 Unauthorized
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/v1/tunnels", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/v1/tunnels after logout: %v", err)
	}
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 Unauthorized after logout", res.StatusCode)
	}
	res.Body.Close()
}
