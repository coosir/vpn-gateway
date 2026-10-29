// Package store keeps what the admin page edits -- tunnels and users -- in a
// SQLite database under the server's state directory.
//
// The configuration file still describes the server itself: where it listens,
// its certificate, where alerts go. What changes while it runs lives here
// instead, because a file the server rewrites is a file that loses whatever
// its owner wrote in it, and a database is something the admin page can change
// one row at a time.
//
// The driver is pure Go, so the server still cross-compiles without cgo.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"github.com/vpn-gateway/vpn-gateway/internal/server"
	"github.com/vpn-gateway/vpn-gateway/internal/server/users"
)

// FileName is the database's name inside the state directory.
const FileName = "vpn-gateway.db"

// ErrNotFound is returned for a tunnel that does not exist.
var ErrNotFound = errors.New("not found")

// migrations bring a database up to date, one schema version each. They are
// only ever appended to: a database already at version n runs from n onwards.
var migrations = []string{
	// 1: tunnels and users.
	`CREATE TABLE meta (
		key   TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);
	CREATE TABLE tunnels (
		name       TEXT PRIMARY KEY,
		config     TEXT NOT NULL,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	);
	CREATE TABLE users (
		username      TEXT PRIMARY KEY,
		password_hash TEXT NOT NULL,
		is_admin      INTEGER NOT NULL DEFAULT 0,
		created_at    TEXT NOT NULL,
		updated_at    TEXT NOT NULL
	);`,
	// 2: which tunnels each user may use. Existing users stay unrestricted.
	`ALTER TABLE users ADD COLUMN restricted INTEGER NOT NULL DEFAULT 0;
	CREATE TABLE user_tunnels (
		username TEXT NOT NULL,
		tunnel   TEXT NOT NULL,
		PRIMARY KEY (username, tunnel)
	);`,
}

// Store is the server's database.
type Store struct {
	db *sql.DB
}

// Open opens, creating if need be, the database in stateDir.
func Open(stateDir string) (*Store, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("store: prepare state dir: %w", err)
	}
	path := filepath.Join(stateDir, FileName)
	// Tunnel passwords are in here, so it is created private rather than
	// tightened afterwards.
	if f, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE, 0o600); err == nil {
		f.Close()
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	// One writer at a time is all SQLite has anyway, and a single
	// connection keeps the pragmas above in force for every statement.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: %s: %w", path, err)
	}
	return s, nil
}

// OpenSeeded opens the database for a tool other than the server, reporting
// false -- and creating nothing -- when the server has not filled one yet.
// Until it has, the configuration file is still where tunnels are.
func OpenSeeded(stateDir string) (*Store, bool, error) {
	if _, err := os.Stat(filepath.Join(stateDir, FileName)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	s, err := Open(stateDir)
	if err != nil {
		return nil, false, err
	}
	seeded, err := s.Seeded()
	if err != nil || !seeded {
		s.Close()
		return nil, false, err
	}
	return s, true, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	var version int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	for i := version; i < len(migrations); i++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migrate to version %d: %w", i+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Seeded reports whether the database has been filled from the configuration
// file once. After that the file's tunnels are no longer read.
func (s *Store) Seeded() (bool, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM meta WHERE key = 'seeded'`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// Seed imports tunnels and users and marks the database as seeded, all at
// once: a server stopped half way through must not come back with half its
// tunnels and nothing left to import them from.
func (s *Store) Seed(tunnels []server.TunnelConfig, us []users.User) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, t := range tunnels {
		if err := putTunnel(tx, t); err != nil {
			return err
		}
	}
	if err := putUsers(tx, us); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO meta (key, value) VALUES ('seeded', ?)`, now()); err != nil {
		return err
	}
	return tx.Commit()
}

// Tunnels returns every tunnel, in name order.
func (s *Store) Tunnels() ([]server.TunnelConfig, error) {
	rows, err := s.db.Query(`SELECT name, config FROM tunnels ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []server.TunnelConfig
	for rows.Next() {
		var name, raw string
		if err := rows.Scan(&name, &raw); err != nil {
			return nil, err
		}
		var t server.TunnelConfig
		if err := json.Unmarshal([]byte(raw), &t); err != nil {
			return nil, fmt.Errorf("tunnel %q: %w", name, err)
		}
		t.Name = name
		out = append(out, t)
	}
	return out, rows.Err()
}

// PutTunnel creates or replaces a tunnel.
func (s *Store) PutTunnel(t server.TunnelConfig) error { return putTunnel(s.db, t) }

// DeleteTunnel removes a tunnel.
func (s *Store) DeleteTunnel(name string) error {
	res, err := s.db.Exec(`DELETE FROM tunnels WHERE name = ?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// LoadUsers implements users.Persister.
func (s *Store) LoadUsers() ([]users.User, error) {
	grants := map[string][]string{}
	rows, err := s.db.Query(`SELECT username, tunnel FROM user_tunnels ORDER BY username, tunnel`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var u, t string
		if err := rows.Scan(&u, &t); err != nil {
			rows.Close()
			return nil, err
		}
		grants[u] = append(grants[u], t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = s.db.Query(`SELECT username, password_hash, is_admin, restricted, created_at, updated_at FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []users.User
	for rows.Next() {
		var u users.User
		var created, updated string
		if err := rows.Scan(&u.Username, &u.PasswordHash, &u.IsAdmin, &u.Restricted, &created, &updated); err != nil {
			return nil, err
		}
		u.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		u.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
		u.Tunnels = grants[u.Username]
		out = append(out, u)
	}
	return out, rows.Err()
}

// SaveUsers implements users.Persister. The whole set is written at once,
// which is how the user manager keeps it.
func (s *Store) SaveUsers(us []users.User) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM users`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM user_tunnels`); err != nil {
		return err
	}
	if err := putUsers(tx, us); err != nil {
		return err
	}
	return tx.Commit()
}

type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func putTunnel(db execer, t server.TunnelConfig) error {
	raw, err := json.Marshal(t)
	if err != nil {
		return err
	}
	ts := now()
	_, err = db.Exec(`INSERT INTO tunnels (name, config, created_at, updated_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET config = excluded.config, updated_at = excluded.updated_at`,
		t.Name, string(raw), ts, ts)
	return err
}

func putUsers(db execer, us []users.User) error {
	for _, u := range us {
		created, updated := u.CreatedAt, u.UpdatedAt
		if created.IsZero() {
			created = time.Now().UTC()
		}
		if updated.IsZero() {
			updated = created
		}
		if _, err := db.Exec(`INSERT INTO users (username, password_hash, is_admin, restricted, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
			u.Username, u.PasswordHash, u.IsAdmin, u.Restricted,
			created.UTC().Format(time.RFC3339Nano), updated.UTC().Format(time.RFC3339Nano)); err != nil {
			return fmt.Errorf("user %q: %w", u.Username, err)
		}
		for _, t := range u.Tunnels {
			if _, err := db.Exec(`INSERT OR IGNORE INTO user_tunnels (username, tunnel) VALUES (?, ?)`, u.Username, t); err != nil {
				return fmt.Errorf("user %q: %w", u.Username, err)
			}
		}
	}
	return nil
}

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }
