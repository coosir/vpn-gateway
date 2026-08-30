package client

import (
	"context"
	"encoding/json"
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

	Status  contract.Status  `json:"status"`
	Network contract.Network `json:"network"`
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

func (a *API) do(req *http.Request, out any) error {
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("%s %s: the server rejected the API token", req.Method, req.URL.Path)
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
