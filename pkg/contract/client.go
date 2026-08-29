package contract

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client talks the control plane of one container. It is safe for concurrent
// use.
type Client struct {
	// BaseURL is the container's control plane root, e.g.
	// "http://127.0.0.1:21081". No trailing slash.
	BaseURL string
	HTTP    *http.Client
	// Secret is the tunnel's shared secret, sent as a bearer token. It must
	// match the container's VG_AGENT_SECRET.
	Secret string
}

// NewClient returns a Client for a control plane reachable at addr
// ("host:port"). Timeouts are short: the control plane is loopback-local from
// the server's point of view, so a slow reply means the container is wedged.
func NewClient(addr, secret string) *Client {
	return &Client{
		BaseURL: "http://" + addr,
		HTTP:    &http.Client{Timeout: 5 * time.Second},
		Secret:  secret,
	}
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode %s body: %w", path, err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+c.Secret)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr APIError
		if json.NewDecoder(io.LimitReader(resp.Body, 8<<10)).Decode(&apiErr) == nil && apiErr.Message != "" {
			return fmt.Errorf("%s %s: %s (%d)", method, path, apiErr.Message, resp.StatusCode)
		}
		return fmt.Errorf("%s %s: unexpected status %d", method, path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

// Status fetches the tunnel's current state, uptime and traffic counters.
func (c *Client) Status(ctx context.Context) (Status, error) {
	var s Status
	err := c.do(ctx, http.MethodGet, PathStatus, nil, &s)
	return s, err
}

// Network fetches the routes and DNS servers the VPN pushed. Fields are empty
// until the tunnel is up.
func (c *Client) Network(ctx context.Context) (Network, error) {
	var n Network
	err := c.do(ctx, http.MethodGet, PathNetwork, nil, &n)
	return n, err
}

// Challenge fetches the pending interactive authentication prompt. It returns
// a nil Challenge and no error when nothing is pending.
func (c *Client) Challenge(ctx context.Context) (*Challenge, error) {
	var ch Challenge
	err := c.do(ctx, http.MethodGet, PathChallenge, nil, &ch)
	if err != nil {
		return nil, err
	}
	if ch.ID == "" {
		return nil, nil
	}
	return &ch, nil
}

// Answer submits a response to a pending challenge.
func (c *Client) Answer(ctx context.Context, a AuthAnswer) error {
	return c.do(ctx, http.MethodPost, PathAuth, a, nil)
}

// Reconnect asks the provider to tear down and redial.
func (c *Client) Reconnect(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, PathReconnect, nil, nil)
}

// Events streams server-sent events until ctx is cancelled or the connection
// drops, invoking fn for each event. It always returns a non-nil error; a
// clean shutdown reports ctx.Err(). Callers are expected to reconnect with
// backoff.
func (c *Client) Events(ctx context.Context, fn func(Event)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+PathEvents, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Authorization", "Bearer "+c.Secret)

	// The event stream is long-lived, so it must not inherit c.HTTP's
	// request timeout.
	stream := &http.Client{Transport: c.HTTP.Transport}
	resp, err := stream.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: unexpected status %d", PathEvents, resp.StatusCode)
	}

	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 4<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		data, ok := strings.CutPrefix(line, "data:")
		if !ok {
			continue // comment, event name, or the blank record separator
		}
		var ev Event
		if err := json.Unmarshal([]byte(strings.TrimSpace(data)), &ev); err != nil {
			continue // a malformed event must not kill the stream
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
