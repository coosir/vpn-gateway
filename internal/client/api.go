package client

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/vpn-gateway/vpn-gateway/pkg/contract"
)

// Snapshot mirrors one entry of the server's GET /api/v1/tunnels.
//
// It is declared here rather than imported from the server so the client
// depends on the wire format, not on the server's internals.
type Snapshot struct {
	Name      string `json:"name"`
	Provider  string `json:"provider"`
	Disabled  bool   `json:"disabled"`
	Reachable bool   `json:"reachable"`
	LastError string `json:"last_error"`

	// Wanted is whether this tunnel has been asked to dial. One that has not
	// is stopped on purpose rather than broken.
	Wanted bool `json:"wanted"`

	TrojanPassword string `json:"trojan_password,omitempty"`
	Password       string `json:"password,omitempty"`

	Status  contract.Status  `json:"status"`
	Network contract.Network `json:"network"`
	// Challenge is the interactive prompt the tunnel is blocked on, if any.
	Challenge *contract.Challenge `json:"challenge,omitempty"`
}

// Up reports whether this tunnel can carry traffic right now. Both conditions
// matter: a snapshot keeps the last known status when the container stops
// answering, so State alone would report a dead tunnel as up.
func (s Snapshot) Up() bool {
	return s.Reachable && s.Status.State == contract.StateUp
}

// API talks to a vpn-gateway server's control API.
type API struct {
	BaseURL string
	Token   string
	IsAdmin bool
	HTTP    *http.Client
}

// NewAPI builds a client for the server at baseURL.
func NewAPI(baseURL, token string) *API {
	return &API{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		HTTP:    &http.Client{Timeout: 10 * time.Second},
	}
}

// Login authenticates with username and password against the server.
func (a *API) Login(ctx context.Context, username, password string) error {
	body, err := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.BaseURL+"/api/v1/auth/login", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := a.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusUnauthorized {
		return errors.New("authentication failed: invalid username or password")
	}
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		return fmt.Errorf("login failed (status %d): %s", res.StatusCode, strings.TrimSpace(string(b)))
	}
	var reply struct {
		OK      bool   `json:"ok"`
		Token   string `json:"token"`
		IsAdmin bool   `json:"is_admin"`
		Error   string `json:"error"`
	}
	if err := json.NewDecoder(res.Body).Decode(&reply); err == nil && reply.Token != "" {
		a.Token = reply.Token
		a.IsAdmin = reply.IsAdmin
	}
	return nil
}

// Tunnels fetches every tunnel the server manages.
func (a *API) Tunnels(ctx context.Context) ([]Snapshot, error) {
	var out []Snapshot
	if err := a.get(ctx, "/api/v1/tunnels", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Challenge fetches a tunnel's pending interactive authentication prompt, or
// nil when none is pending.
func (a *API) Challenge(ctx context.Context, tunnel string) (*contract.Challenge, error) {
	var ch contract.Challenge
	if err := a.get(ctx, "/api/v1/tunnels/"+tunnel+"/challenge", &ch); err != nil {
		return nil, err
	}
	if ch.ID == "" {
		return nil, nil
	}
	return &ch, nil
}

// Answer submits a response to a pending challenge.
func (a *API) Answer(ctx context.Context, tunnel string, ans contract.AuthAnswer) error {
	body, err := json.Marshal(ans)
	if err != nil {
		return err
	}
	req, err := a.request(ctx, http.MethodPost, "/api/v1/tunnels/"+tunnel+"/auth", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return a.do(req, nil)
}

// Logs returns recent output from a tunnel's container.
func (a *API) Logs(ctx context.Context, tunnel string, tail int) (string, error) {
	req, err := a.request(ctx, http.MethodGet,
		fmt.Sprintf("/api/v1/tunnels/%s/logs?tail=%d", tunnel, tail), nil)
	if err != nil {
		return "", err
	}
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET tunnel logs: unexpected status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return string(body), err
}

// StartTunnel asks the server to dial one tunnel.
func (a *API) StartTunnel(ctx context.Context, tunnel string) error {
	req, err := a.request(ctx, http.MethodPost, "/api/v1/tunnels/"+tunnel+"/start", nil)
	if err != nil {
		return err
	}
	return a.do(req, nil)
}

// StopTunnel takes one tunnel down and leaves it down.
func (a *API) StopTunnel(ctx context.Context, tunnel string) error {
	req, err := a.request(ctx, http.MethodPost, "/api/v1/tunnels/"+tunnel+"/stop", nil)
	if err != nil {
		return err
	}
	return a.do(req, nil)
}

// Reconnect asks the server to redial a tunnel.
func (a *API) Reconnect(ctx context.Context, tunnel string) error {
	req, err := a.request(ctx, http.MethodPost, "/api/v1/tunnels/"+tunnel+"/reconnect", nil)
	if err != nil {
		return err
	}
	return a.do(req, nil)
}

func (a *API) get(ctx context.Context, path string, out any) error {
	req, err := a.request(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	return a.do(req, out)
}

func (a *API) request(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, a.BaseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.Token)
	return req, nil
}

// ErrUnauthorized is returned when the server rejects authentication (invalid or revoked session).
var ErrUnauthorized = errors.New("the server rejected the authorization: session expired or revoked")

func (a *API) do(req *http.Request, out any) error {
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("%s %s: %w", req.Method, req.URL.Path, ErrUnauthorized)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr contract.APIError
		if json.NewDecoder(io.LimitReader(resp.Body, 8<<10)).Decode(&apiErr) == nil && apiErr.Message != "" {
			return fmt.Errorf("%s %s: %s (%d)", req.Method, req.URL.Path, apiErr.Message, resp.StatusCode)
		}
		return fmt.Errorf("%s %s: unexpected status %d", req.Method, req.URL.Path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out)
}

// Event mirrors one entry of the server's GET /api/v1/events stream.
type Event struct {
	At     time.Time `json:"at"`
	Tunnel Snapshot  `json:"tunnel"`
}

// Events streams tunnel state changes until ctx is cancelled or the
// connection drops, calling fn for each one. The first events always describe
// the current state, so a client that connects late does not also have to
// poll.
//
// It always returns a non-nil error; a clean shutdown reports ctx.Err().
// Callers are expected to reconnect with backoff.
func (a *API) Events(ctx context.Context, fn func(Event)) error {
	req, err := a.request(ctx, http.MethodGet, "/api/v1/events", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")

	// The stream is long-lived, so it must not inherit the request timeout.
	stream := &http.Client{Transport: a.HTTP.Transport}
	resp, err := stream.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("GET /api/v1/events: %w", ErrUnauthorized)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET /api/v1/events: unexpected status %d", resp.StatusCode)
	}

	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 4<<10), 1<<20)
	for sc.Scan() {
		data, ok := strings.CutPrefix(sc.Text(), "data:")
		if !ok {
			continue // a comment, an event name, or the blank record separator
		}
		var ev Event
		if json.Unmarshal([]byte(strings.TrimSpace(data)), &ev) != nil {
			continue // a malformed event must not end the stream
		}
		fn(ev)
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return io.EOF
}
