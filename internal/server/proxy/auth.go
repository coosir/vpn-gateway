package proxy

import (
	"fmt"
	"log/slog"
	"net"
	"slices"
	"sync"

	"github.com/sagernet/sing-box/transport/trojan"
)

// AuthResult represents the authenticated tunnel and user identity for a Trojan connection.
type AuthResult struct {
	TunnelName string
	Username   string
	Token      string
}

// Authenticator validates Trojan handshake keys and tracks active connections.
type Authenticator interface {
	ValidateTrojanKey(key [56]byte) (AuthResult, bool)
	TrackConnection(username, token string, conn net.Conn) func()
}

// SessionValidator checks whether a session token is currently valid.
type SessionValidator interface {
	Validate(token string) (username string, isAdmin bool, valid bool)
}

// TrojanSession holds metadata for a registered Trojan authentication key.
type TrojanSession struct {
	Username   string
	Token      string
	TunnelName string
}

// DynamicAuthenticator manages dynamic Trojan credentials bound to active user sessions.
type DynamicAuthenticator struct {
	mu         sync.RWMutex
	validator  SessionValidator
	log        *slog.Logger
	keys       map[[56]byte]TrojanSession
	tokenKeys  map[string][][56]byte
	userTokens map[string][]string

	connsMu sync.Mutex
	conns   map[string]map[uint64]net.Conn
	nextID  uint64
}

// NewDynamicAuthenticator builds a dynamic Trojan authenticator.
func NewDynamicAuthenticator(validator SessionValidator, log *slog.Logger) *DynamicAuthenticator {
	return &DynamicAuthenticator{
		validator:  validator,
		log:        log,
		keys:       make(map[[56]byte]TrojanSession),
		tokenKeys:  make(map[string][][56]byte),
		userTokens: make(map[string][]string),
		conns:      make(map[string]map[uint64]net.Conn),
	}
}

// GetOrCreatePassword returns the dynamic Trojan password for the specified session and tunnel.
func (d *DynamicAuthenticator) GetOrCreatePassword(token, username, tunnelName string) string {
	if token == "" || tunnelName == "" {
		return ""
	}
	pass := fmt.Sprintf("vpngw_%s_%s", token, tunnelName)
	key := trojan.Key(pass)

	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.keys[key]; !exists {
		d.keys[key] = TrojanSession{
			Username:   username,
			Token:      token,
			TunnelName: tunnelName,
		}
		d.tokenKeys[token] = append(d.tokenKeys[token], key)
		if !slices.Contains(d.userTokens[username], token) {
			d.userTokens[username] = append(d.userTokens[username], token)
		}
	}
	return pass
}

// ValidateTrojanKey verifies that a Trojan key matches a valid, active user session.
func (d *DynamicAuthenticator) ValidateTrojanKey(key [56]byte) (AuthResult, bool) {
	d.mu.RLock()
	sess, ok := d.keys[key]
	d.mu.RUnlock()
	if !ok {
		return AuthResult{}, false
	}

	if d.validator != nil {
		uname, _, valid := d.validator.Validate(sess.Token)
		if !valid || uname != sess.Username {
			// Session was revoked or deleted. Clean up asynchronously.
			go d.RevokeSession(sess.Token)
			return AuthResult{}, false
		}
	}
	return AuthResult{
		TunnelName: sess.TunnelName,
		Username:   sess.Username,
		Token:      sess.Token,
	}, true
}

// TrackConnection records an active connection under a session token for immediate severance upon revocation.
func (d *DynamicAuthenticator) TrackConnection(username, token string, conn net.Conn) func() {
	d.connsMu.Lock()
	id := d.nextID
	d.nextID++
	if d.conns[token] == nil {
		d.conns[token] = make(map[uint64]net.Conn)
	}
	d.conns[token][id] = conn
	d.connsMu.Unlock()

	return func() {
		d.connsMu.Lock()
		if m, ok := d.conns[token]; ok {
			delete(m, id)
			if len(m) == 0 {
				delete(d.conns, token)
			}
		}
		d.connsMu.Unlock()
	}
}

// RevokeSession invalidates all Trojan credentials for a session and forcibly closes active connections.
func (d *DynamicAuthenticator) RevokeSession(token string) {
	if token == "" {
		return
	}
	d.connsMu.Lock()
	conns := make([]net.Conn, 0, len(d.conns[token]))
	for _, c := range d.conns[token] {
		conns = append(conns, c)
	}
	delete(d.conns, token)
	d.connsMu.Unlock()

	for _, c := range conns {
		_ = c.Close()
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	for _, k := range d.tokenKeys[token] {
		delete(d.keys, k)
	}
	delete(d.tokenKeys, token)

	for u, toks := range d.userTokens {
		filtered := toks[:0]
		for _, t := range toks {
			if t != token {
				filtered = append(filtered, t)
			}
		}
		if len(filtered) == 0 {
			delete(d.userTokens, u)
		} else {
			d.userTokens[u] = filtered
		}
	}

	if len(conns) > 0 && d.log != nil {
		d.log.Info("revoked session and closed active trojan connections", "token", token, "closed_connections", len(conns))
	}
}

// RevokeUser invalidates all sessions and closes active connections for a user.
func (d *DynamicAuthenticator) RevokeUser(username string) {
	if username == "" {
		return
	}
	d.mu.Lock()
	toks := append([]string(nil), d.userTokens[username]...)
	d.mu.Unlock()

	for _, tok := range toks {
		d.RevokeSession(tok)
	}
}

// StaticAuthenticator provides backward-compatible authentication against static passwords.
type StaticAuthenticator struct {
	keys map[[56]byte]AuthResult
}

// NewStaticAuthenticator builds an authenticator based on static route passwords.
func NewStaticAuthenticator(routes []Route) *StaticAuthenticator {
	m := make(map[[56]byte]AuthResult)
	for _, r := range routes {
		if r.Name != "" && r.TrojanPassword != "" {
			m[trojan.Key(r.TrojanPassword)] = AuthResult{
				TunnelName: r.Name,
				Username:   r.Name,
			}
		}
	}
	return &StaticAuthenticator{keys: m}
}

// ValidateTrojanKey looks up the static key.
func (s *StaticAuthenticator) ValidateTrojanKey(key [56]byte) (AuthResult, bool) {
	res, ok := s.keys[key]
	return res, ok
}

// TrackConnection is a no-op for static authenticator.
func (s *StaticAuthenticator) TrackConnection(username, token string, conn net.Conn) func() {
	return func() {}
}
