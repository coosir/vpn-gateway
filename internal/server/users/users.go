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
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	IsAdmin      bool      `json:"is_admin"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// UserSummary is a safe representation of a user without sensitive hashes.
type UserSummary struct {
	Username  string    `json:"username"`
	IsAdmin   bool      `json:"is_admin"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Session represents an active authenticated user session.
type Session struct {
	Username  string    `json:"username"`
	Token     string    `json:"token"`
	IsAdmin   bool      `json:"is_admin"`
	CreatedAt time.Time `json:"created_at"`
}

// Manager manages dynamic users, password verification, and active sessions.
type Manager struct {
	path     string
	mu       sync.RWMutex
	users    map[string]User
	sessions map[string]Session
	cancels  map[string][]contextCancel
	log      *slog.Logger
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

	path := filepath.Join(stateDir, "users.json")
	m := &Manager{
		path:     path,
		users:    make(map[string]User),
		sessions: make(map[string]Session),
		cancels:  make(map[string][]contextCancel),
		log:      log,
	}

	if err := m.load(initialUsers); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) load(initialUsers []server.UserConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.path)
	if err == nil {
		var list []User
		if err := json.Unmarshal(data, &list); err != nil {
			return fmt.Errorf("users: parse %s: %w", m.path, err)
		}
		for _, u := range list {
			m.users[u.Username] = u
		}
		return nil
	}

	if !os.IsNotExist(err) {
		return fmt.Errorf("users: read %s: %w", m.path, err)
	}

	// Initialize from initialUsers only if users.json does not exist (first boot / initial migration)
	now := time.Now().UTC()
	for _, u := range initialUsers {
		if u.Username != "" {
			m.users[u.Username] = User{
				Username:     u.Username,
				PasswordHash: u.PasswordHash,
				IsAdmin:      u.IsAdmin,
				CreatedAt:    now,
				UpdatedAt:    now,
			}
		}
	}
	return m.saveLocked()
}

func (m *Manager) saveLocked() error {
	list := make([]User, 0, len(m.users))
	for _, u := range m.users {
		list = append(list, u)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Username < list[j].Username })

	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}

	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("users: write tmp file: %w", err)
	}
	if err := os.Rename(tmp, m.path); err != nil {
		return fmt.Errorf("users: atomic replace %s: %w", m.path, err)
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

	m.log.Info("updated admin status for user", "username", username, "is_admin", isAdmin)
	return nil
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
			Username:  u.Username,
			IsAdmin:   u.IsAdmin,
			CreatedAt: u.CreatedAt,
			UpdatedAt: u.UpdatedAt,
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

// revokeUserLocked cancels all active sessions and triggers cancels for a user.
func (m *Manager) revokeUserLocked(username string) {
	// 1. Remove all session tokens for this user
	for tok, sess := range m.sessions {
		if sess.Username == username {
			delete(m.sessions, tok)
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
