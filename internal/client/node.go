package client

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// CustomNode represents a user-defined proxy node (e.g., Trojan).
type CustomNode struct {
	ID             string `yaml:"id" json:"id"`
	Name           string `yaml:"name" json:"name"`
	Type           string `yaml:"type" json:"type"` // "trojan"
	Server         string `yaml:"server" json:"server"`
	Port           int    `yaml:"port" json:"port"`
	Password       string `yaml:"password" json:"password"`
	SNI            string `yaml:"sni,omitempty" json:"sni,omitempty"`
	AllowInsecure  bool   `yaml:"allow_insecure,omitempty" json:"allow_insecure,omitempty"`
	SubscriptionID string `yaml:"subscription_id,omitempty" json:"subscription_id,omitempty"`
}

// OutboundTag returns the sing-box outbound tag for this custom node.
func (n CustomNode) OutboundTag() string {
	return "node-" + n.ID
}

// Subscription holds configuration and cached nodes for a remote subscription.
type Subscription struct {
	ID         string       `yaml:"id" json:"id"`
	Name       string       `yaml:"name" json:"name"`
	URL        string       `yaml:"url" json:"url"`
	AutoUpdate bool         `yaml:"auto_update,omitempty" json:"auto_update,omitempty"`
	UpdatedAt  string       `yaml:"updated_at,omitempty" json:"updated_at,omitempty"`
	Nodes      []CustomNode `yaml:"nodes,omitempty" json:"nodes,omitempty"`
}

// GenerateNodeID generates a short random ID for a node.
func GenerateNodeID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())[:8]
	}
	return hex.EncodeToString(b)
}

// ParseTrojanURL parses a trojan:// link into a CustomNode.
//
// Format: trojan://password@host:port?sni=...&allowInsecure=1#NodeName
func ParseTrojanURL(raw string) (*CustomNode, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(strings.ToLower(raw), "trojan://") {
		return nil, errors.New("not a trojan:// URL")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid trojan URL: %w", err)
	}

	password := ""
	if u.User != nil {
		password = u.User.Username()
		if password == "" {
			password = u.User.String()
		}
	}
	if password == "" {
		return nil, errors.New("trojan URL has no password")
	}

	host := u.Hostname()
	if host == "" {
		return nil, errors.New("trojan URL has no host")
	}

	port := 443
	if portStr := u.Port(); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p <= 65535 {
			port = p
		}
	}

	name := u.Fragment
	if unescaped, err := url.QueryUnescape(name); err == nil && unescaped != "" {
		name = unescaped
	}
	if name == "" {
		name = fmt.Sprintf("%s:%d", host, port)
	}

	q := u.Query()
	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("peer")
	}
	if sni == "" {
		sni = host
	}

	allowInsecure := q.Get("allowInsecure") == "1" ||
		q.Get("insecure") == "1" ||
		q.Get("allow_insecure") == "1"

	return &CustomNode{
		ID:            GenerateNodeID(),
		Name:          name,
		Type:          "trojan",
		Server:        host,
		Port:          port,
		Password:      password,
		SNI:           sni,
		AllowInsecure: allowInsecure,
	}, nil
}

// ParseSubscription parses subscription data (base64 trojan links or Clash YAML).
func ParseSubscription(data []byte) ([]CustomNode, error) {
	str := strings.TrimSpace(string(data))
	if str == "" {
		return nil, errors.New("subscription content is empty")
	}

	// 1. Try Clash YAML
	if strings.Contains(str, "proxies:") {
		nodes, err := parseClashYAML(data)
		if err == nil && len(nodes) > 0 {
			return nodes, nil
		}
	}

	// 2. Try Base64 decoding
	decoded, err := tryBase64Decode(str)
	if err == nil && len(decoded) > 0 {
		str = string(decoded)
	}

	// 3. Line by line parsing
	var nodes []CustomNode
	lines := strings.Split(str, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if node, err := ParseTrojanURL(line); err == nil {
			nodes = append(nodes, *node)
		}
	}

	if len(nodes) == 0 {
		return nil, errors.New("no valid trojan nodes found in subscription")
	}
	return nodes, nil
}

func tryBase64Decode(s string) ([]byte, error) {
	// Strip whitespaces
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, " ", "")

	// Pad if needed
	if rem := len(s) % 4; rem != 0 {
		s += strings.Repeat("=", 4-rem)
	}

	// Try standard
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	// Try URL encoding
	return base64.URLEncoding.DecodeString(s)
}

type clashProxyConfig struct {
	Name           string `yaml:"name"`
	Type           string `yaml:"type"`
	Server         string `yaml:"server"`
	Port           int    `yaml:"port"`
	Password       string `yaml:"password"`
	SNI            string `yaml:"sni"`
	SkipCertVerify bool   `yaml:"skip-cert-verify"`
}

type clashConfig struct {
	Proxies []clashProxyConfig `yaml:"proxies"`
}

func parseClashYAML(data []byte) ([]CustomNode, error) {
	var clash clashConfig
	if err := yaml.Unmarshal(data, &clash); err != nil {
		return nil, err
	}
	var nodes []CustomNode
	for _, p := range clash.Proxies {
		if strings.ToLower(p.Type) != "trojan" {
			continue
		}
		if p.Server == "" || p.Port <= 0 || p.Password == "" {
			continue
		}
		sni := p.SNI
		if sni == "" {
			sni = p.Server
		}
		name := p.Name
		if name == "" {
			name = fmt.Sprintf("%s:%d", p.Server, p.Port)
		}
		nodes = append(nodes, CustomNode{
			ID:            GenerateNodeID(),
			Name:          name,
			Type:          "trojan",
			Server:        p.Server,
			Port:          p.Port,
			Password:      p.Password,
			SNI:           sni,
			AllowInsecure: p.SkipCertVerify,
		})
	}
	return nodes, nil
}

// FetchSubscription downloads and parses a subscription from the provided URL.
func FetchSubscription(ctx context.Context, subURL string) ([]CustomNode, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, subURL, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid subscription URL: %w", err)
	}
	req.Header.Set("User-Agent", "vpn-gateway/1.0 (sing-box; Clash)")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download subscription failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("subscription returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read subscription body: %w", err)
	}

	return ParseSubscription(body)
}

// PingNode measures TCP + TLS handshake latency to a node.
func PingNode(ctx context.Context, node CustomNode) (time.Duration, error) {
	addr := net.JoinHostPort(node.Server, strconv.Itoa(node.Port))
	dialer := &net.Dialer{Timeout: 3 * time.Second}

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, fmt.Errorf("TCP dial: %w", err)
	}
	defer conn.Close()

	tlsConfig := &tls.Config{
		ServerName:         node.SNI,
		InsecureSkipVerify: node.AllowInsecure,
	}
	if tlsConfig.ServerName == "" {
		tlsConfig.ServerName = node.Server
	}

	tlsConn := tls.Client(conn, tlsConfig)
	defer tlsConn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = tlsConn.SetDeadline(deadline)
	} else {
		_ = tlsConn.SetDeadline(time.Now().Add(3 * time.Second))
	}

	if err := tlsConn.Handshake(); err != nil {
		return 0, fmt.Errorf("TLS handshake: %w", err)
	}

	return time.Since(start), nil
}
