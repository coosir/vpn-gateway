package users

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/server"
	"golang.org/x/crypto/bcrypt"
)

var usernameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,31}$`)

// User represents a registered user.
type User struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	IsAdmin      bool   `json:"is_admin"`
	// Restricted limits the user to Tunnels. Off, the user may use every
	// tunnel, which is what every user could before access was configurable,
	// so a user nobody has restricted keeps working as they did.
	Restricted bool      `json:"restricted,omitempty"`
	Tunnels    []string  `json:"tunnels,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// UserSummary is a safe representation of a user without sensitive hashes.
type UserSummary struct {
	Username   string    `json:"username"`
	IsAdmin    bool      `json:"is_admin"`
	Restricted bool      `json:"restricted"`
	Tunnels    []string  `json:"tunnels"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Session represents an active authenticated user session.
type Session struct {
	Username  string    `json:"username"`
	Token     string    `json:"token"`
	IsAdmin   bool      `json:"is_admin"`
	CreatedAt time.Time `json:"created_at"`
}

// Persister is where the user list is kept between runs.
type Persister interface {
	// LoadUsers returns the saved users.
	LoadUsers() ([]User, error)
	// SaveUsers replaces the saved users with these.
	SaveUsers([]User) error
}

// Manager manages dynamic users, password verification, and active sessions.
type Manager struct {
	persist         Persister
	mu              sync.RWMutex
	users           map[string]User
	sessions        map[string]Session
	cancels         map[string][]contextCancel
	onRevokeUser    func(username string)
	onRevokeSession func(token string)
	onAccessChange  func(username string)
	log             *slog.Logger
}

type contextCancel struct {
	id     int
	cancel func()
}

// NewManager loads or initializes user data from stateDir/users.json.
func NewManager(stateDir string, initialUsers []server.UserConfig, log *slog.Logger) (*Manager, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("users: prepare state dir: %w", err)
	}
	f := &jsonFile{path: filepath.Join(stateDir, "users.json")}
	if _, err := os.Stat(f.path); errors.Is(err, os.ErrNotExist) {
		// First boot: whoever the configuration names becomes the first
		// set of users. After that the file is the truth.
		if err := f.SaveUsers(FromConfig(initialUsers)); err != nil {
			return nil, err
		}
	}
	return NewManagerWith(f, log)
}

// NewManagerWith loads users from p, which keeps them from then on.
func NewManagerWith(p Persister, log *slog.Logger) (*Manager, error) {
	list, err := p.LoadUsers()
	if err != nil {
		return nil, fmt.Errorf("users: %w", err)
	}
	m := &Manager{
		persist:  p,
		users:    make(map[string]User),
		sessions: make(map[string]Session),
		cancels:  make(map[string][]contextCancel),
		log:      log,
	}
	for _, u := range list {
		m.users[u.Username] = u
	}
	return m, nil
}

// FromConfig turns the users named in a configuration file into users.
func FromConfig(initial []server.UserConfig) []User {
	now := time.Now().UTC()
	var out []User
	for _, u := range initial {
		if u.Username != "" {
			out = append(out, User{
				Username:     u.Username,
				PasswordHash: u.PasswordHash,
				IsAdmin:      u.IsAdmin,
				CreatedAt:    now,
				UpdatedAt:    now,
			})
		}
	}
	return out
}

// LoadJSONFile reads a users.json written by an earlier server, reporting
// false when there is none.
func LoadJSONFile(stateDir string) ([]User, bool, error) {
	f := &jsonFile{path: filepath.Join(stateDir, "users.json")}
	if _, err := os.Stat(f.path); errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	list, err := f.LoadUsers()
	return list, err == nil, err
}

func (m *Manager) saveLocked() error {
	list := make([]User, 0, len(m.users))
	for _, u := range m.users {
		list = append(list, u)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Username < list[j].Username })
	return m.persist.SaveUsers(list)
}

// jsonFile keeps users in stateDir/users.json, as servers before the
// database did.
type jsonFile struct{ path string }

func (f *jsonFile) LoadUsers() ([]User, error) {
	data, err := os.ReadFile(f.path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", f.path, err)
	}
	var list []User
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("parse %s: %w", f.path, err)
	}
	return list, nil
}

func (f *jsonFile) SaveUsers(list []User) error {
	if list == nil {
		list = []User{}
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("users: write tmp file: %w", err)
	}
	if err := os.Rename(tmp, f.path); err != nil {
		return fmt.Errorf("users: atomic replace %s: %w", f.path, err)
	}
	return nil
}

// Add creates a new user with optional administrator role.
func (m *Manager) Add(username, password string, isAdmin bool) error {
	username = strings.TrimSpace(username)
	if !usernameRE.MatchString(username) {
		return fmt.Errorf("invalid username %q: must be 1-32 alphanumeric characters, dot, underscore or hyphen", username)
	}
	if len(password) < 4 {
		return errors.New("password must be at least 4 characters")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.users[username]; exists {
		return fmt.Errorf("user %q already exists", username)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	now := time.Now().UTC()
	m.users[username] = User{
		Username:     username,
		PasswordHash: string(hash),
		IsAdmin:      isAdmin,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := m.saveLocked(); err != nil {
		delete(m.users, username)
		return err
	}
	m.log.Info("created user", "username", username, "is_admin", isAdmin)
	return nil
}

// SetAdmin updates whether a user has administrator privileges.
func (m *Manager) SetAdmin(username string, isAdmin bool) error {
	username = strings.TrimSpace(username)
	m.mu.Lock()
	defer m.mu.Unlock()

	user, exists := m.users[username]
	if !exists {
		return fmt.Errorf("user %q does not exist", username)
	}

	user.IsAdmin = isAdmin
	user.UpdatedAt = time.Now().UTC()
	m.users[username] = user

	for tok, sess := range m.sessions {
		if sess.Username == username {
			sess.IsAdmin = isAdmin
			m.sessions[tok] = sess
		}
	}

	if err := m.saveLocked(); err != nil {
		return err
	}

	// No longer an administrator, the user may be left with fewer tunnels
	// than they are connected to.
	m.accessChangedLocked(username)
	m.log.Info("updated admin status for user", "username", username, "is_admin", isAdmin)
	return nil
}

// SetAccess decides which tunnels a user may use: every one, or only those
// named. Connections to a tunnel the user may no longer use are closed.
func (m *Manager) SetAccess(username string, restricted bool, tunnels []string) error {
	username = strings.TrimSpace(username)
	m.mu.Lock()
	defer m.mu.Unlock()

	user, exists := m.users[username]
	if !exists {
		return fmt.Errorf("user %q does not exist", username)
	}
	user.Restricted = restricted
	user.Tunnels = nil
	if restricted {
		user.Tunnels = normalizeNames(tunnels)
	}
	user.UpdatedAt = time.Now().UTC()
	m.users[username] = user
	if err := m.saveLocked(); err != nil {
		return err
	}
	m.accessChangedLocked(username)
	m.log.Info("updated tunnel access for user", "username", username, "restricted", restricted, "tunnels", user.Tunnels)
	return nil
}

// ForgetTunnel takes a deleted tunnel out of every user's list, so a tunnel
// added later under the same name is not handed to whoever had the old one.
func (m *Manager) ForgetTunnel(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	changed := false
	for k, u := range m.users {
		if slices.Contains(u.Tunnels, name) {
			u.Tunnels = slices.DeleteFunc(slices.Clone(u.Tunnels), func(t string) bool { return t == name })
			m.users[k] = u
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return m.saveLocked()
}

// CanUse reports whether a user may use a tunnel.
func (m *Manager) CanUse(username, tunnel string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.users[username]
	if !ok {
		return false
	}
	return u.IsAdmin || !u.Restricted || slices.Contains(u.Tunnels, tunnel)
}

// SetAccessHook sets what is called when a user's access may have narrowed.
func (m *Manager) SetAccessHook(fn func(username string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onAccessChange = fn
}

// accessChangedLocked tells the listener to drop what the user may no longer
// use, and ends the user's event streams so their clients list the tunnels
// again rather than go on showing ones that now refuse them.
func (m *Manager) accessChangedLocked(username string) {
	if list, ok := m.cancels[username]; ok {
		for _, c := range list {
			if c.cancel != nil {
				go c.cancel()
			}
		}
		delete(m.cancels, username)
	}
	if m.onAccessChange != nil {
		go m.onAccessChange(username)
	}
}

func normalizeNames(in []string) []string {
	out := []string{}
	for _, n := range in {
		if n = strings.TrimSpace(n); n != "" && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// UpdatePassword updates an existing user's password and revokes all their active sessions.
func (m *Manager) UpdatePassword(username, newPassword string) error {
	username = strings.TrimSpace(username)
	if len(newPassword) < 4 {
		return errors.New("password must be at least 4 characters")
	}

	m.mu.Lock()
	user, exists := m.users[username]
	if !exists {
		m.mu.Unlock()
		return fmt.Errorf("user %q does not exist", username)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		m.mu.Unlock()
		return fmt.Errorf("hash password: %w", err)
	}

	user.PasswordHash = string(hash)
	user.UpdatedAt = time.Now().UTC()
	m.users[username] = user

	if err := m.saveLocked(); err != nil {
		m.mu.Unlock()
		return err
	}

	// Revoke sessions and cancel active connections
	m.revokeUserLocked(username)
	m.mu.Unlock()

	m.log.Info("updated password for user and revoked active sessions", "username", username)
	return nil
}

// Delete removes an existing user and revokes all their active connections immediately.
func (m *Manager) Delete(username string) error {
	username = strings.TrimSpace(username)

	m.mu.Lock()
	if _, exists := m.users[username]; !exists {
		m.mu.Unlock()
		return fmt.Errorf("user %q does not exist", username)
	}

	delete(m.users, username)
	if err := m.saveLocked(); err != nil {
		m.mu.Unlock()
		return err
	}

	// Revoke sessions and cancel active connections
	m.revokeUserLocked(username)
	m.mu.Unlock()

	m.log.Info("deleted user and terminated active sessions", "username", username)
	return nil
}

// List returns a sorted list of all registered users.
func (m *Manager) List() []UserSummary {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]UserSummary, 0, len(m.users))
	for _, u := range m.users {
		out = append(out, UserSummary{
			Username:   u.Username,
			IsAdmin:    u.IsAdmin,
			Restricted: u.Restricted,
			Tunnels:    append([]string{}, u.Tunnels...),
			CreatedAt:  u.CreatedAt,
			UpdatedAt:  u.UpdatedAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

// Count returns the number of registered users.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.users)
}

// Authenticate verifies user credentials and generates a new session token, returning (token, isAdmin, error).
func (m *Manager) Authenticate(username, password string) (string, bool, error) {
	username = strings.TrimSpace(username)
	m.mu.Lock()
	defer m.mu.Unlock()

	user, exists := m.users[username]
	if !exists {
		return "", false, errors.New("invalid username or password")
	}

	if !verifyPassword(user.PasswordHash, password) {
		return "", false, errors.New("invalid username or password")
	}

	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", false, fmt.Errorf("generate session token: %w", err)
	}
	token := "sess_" + hex.EncodeToString(raw)

	m.sessions[token] = Session{
		Username:  username,
		Token:     token,
		IsAdmin:   user.IsAdmin,
		CreatedAt: time.Now().UTC(),
	}

	return token, user.IsAdmin, nil
}

// Validate checks if a session token is valid and belongs to an active user, returning (username, isAdmin, valid).
func (m *Manager) Validate(token string) (string, bool, bool) {
	if token == "" {
		return "", false, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	sess, exists := m.sessions[token]
	if !exists {
		return "", false, false
	}
	user, userExists := m.users[sess.Username]
	if !userExists {
		return "", false, false
	}
	return sess.Username, user.IsAdmin, true
}

// IsAdmin checks if a username belongs to an active administrator user.
func (m *Manager) IsAdmin(username string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if u, ok := m.users[username]; ok {
		return u.IsAdmin
	}
	return false
}

// RegisterCancel registers a context cancel function for an active user connection.
// Returns an unregister cleanup function.
func (m *Manager) RegisterCancel(username string, cancel func()) func() {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := int(time.Now().UnixNano())
	m.cancels[username] = append(m.cancels[username], contextCancel{id: id, cancel: cancel})

	return func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		list := m.cancels[username]
		for i, c := range list {
			if c.id == id {
				m.cancels[username] = append(list[:i], list[i+1:]...)
				break
			}
		}
	}
}

// SetRevokeHooks sets callbacks invoked when a user or session is revoked.
func (m *Manager) SetRevokeHooks(onRevokeUser func(username string), onRevokeSession func(token string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onRevokeUser = onRevokeUser
	m.onRevokeSession = onRevokeSession
}

// RevokeSession explicitly revokes a single session token (e.g. upon user logout).
func (m *Manager) RevokeSession(token string) {
	m.mu.Lock()
	sess, exists := m.sessions[token]
	if !exists {
		m.mu.Unlock()
		return
	}
	delete(m.sessions, token)

	// Check if user still has other active sessions
	hasOther := false
	for _, s := range m.sessions {
		if s.Username == sess.Username {
			hasOther = true
			break
		}
	}
	if !hasOther {
		if list, ok := m.cancels[sess.Username]; ok {
			for _, c := range list {
				if c.cancel != nil {
					go c.cancel()
				}
			}
			delete(m.cancels, sess.Username)
		}
	}
	onRevoke := m.onRevokeSession
	m.mu.Unlock()

	if onRevoke != nil {
		onRevoke(token)
	}
	m.log.Info("revoked user session", "username", sess.Username, "token", token)
}

// revokeUserLocked cancels all active sessions and triggers cancels for a user.
func (m *Manager) revokeUserLocked(username string) {
	// 1. Remove all session tokens for this user
	for tok, sess := range m.sessions {
		if sess.Username == username {
			delete(m.sessions, tok)
			if m.onRevokeSession != nil {
				go m.onRevokeSession(tok)
			}
		}
	}

	// 2. Trigger active cancel callbacks
	if list, ok := m.cancels[username]; ok {
		for _, c := range list {
			if c.cancel != nil {
				go c.cancel()
			}
		}
		delete(m.cancels, username)
	}

	if m.onRevokeUser != nil {
		go m.onRevokeUser(username)
	}
}

func verifyPassword(hash, password string) bool {
	if hash == "" {
		return false
	}
	if strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2b$") || strings.HasPrefix(hash, "$2y$") {
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	}
	if strings.HasPrefix(hash, "sha256:") {
		h := sha256.Sum256([]byte(password))
		expected := strings.TrimPrefix(hash, "sha256:")
		return subtle.ConstantTimeCompare([]byte(hex.EncodeToString(h[:])), []byte(expected)) == 1
	}
	if len(hash) == 64 {
		h := sha256.Sum256([]byte(password))
		return subtle.ConstantTimeCompare([]byte(hex.EncodeToString(h[:])), []byte(hash)) == 1
	}
	return subtle.ConstantTimeCompare([]byte(hash), []byte(password)) == 1
}
