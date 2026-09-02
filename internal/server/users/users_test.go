package users

import (
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/vpn-gateway/vpn-gateway/internal/server"
)

func TestUserManager(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	m, err := NewManager(dir, []server.UserConfig{
		{Username: "inituser", PasswordHash: "sha256:fcf730b6d95236ecd3c9fc2d92d7b6b2bb061514961aec041d6c7a7192f592e4"}, // "secret123"
	}, log)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	if m.Count() != 1 {
		t.Fatalf("m.Count() = %d, want 1", m.Count())
	}

	// Add a new user
	if err := m.Add("alice", "alicepassword", false); err != nil {
		t.Fatalf("Add alice: %v", err)
	}
	if m.Count() != 2 {
		t.Fatalf("m.Count() = %d, want 2", m.Count())
	}

	// Duplicate user should fail
	if err := m.Add("alice", "anotherpass", false); err == nil {
		t.Error("Add duplicate user alice should fail")
	}

	// Authenticate alice with wrong password
	if _, _, err := m.Authenticate("alice", "wrong"); err == nil {
		t.Error("Authenticate with wrong password should fail")
	}

	// Authenticate alice with correct password
	tok1, isAdmin, err := m.Authenticate("alice", "alicepassword")
	if err != nil {
		t.Fatalf("Authenticate alice: %v", err)
	}
	if isAdmin {
		t.Fatalf("alice isAdmin = true, want false")
	}
	if user, validAdmin, ok := m.Validate(tok1); !ok || user != "alice" || validAdmin {
		t.Fatalf("Validate tok1: got %q, %v, %v; want alice, false, true", user, validAdmin, ok)
	}

	// Grant admin to alice
	if err := m.SetAdmin("alice", true); err != nil {
		t.Fatalf("SetAdmin alice true: %v", err)
	}
	if !m.IsAdmin("alice") {
		t.Fatalf("m.IsAdmin(alice) = false, want true")
	}
	if user, validAdmin, ok := m.Validate(tok1); !ok || user != "alice" || !validAdmin {
		t.Fatalf("Validate tok1 after SetAdmin: got %q, %v, %v; want alice, true, true", user, validAdmin, ok)
	}

	// Register cancel hook for alice
	var cancelCalled sync.WaitGroup
	cancelCalled.Add(1)
	unreg := m.RegisterCancel("alice", func() {
		cancelCalled.Done()
	})
	_ = unreg

	// Update password for alice
	if err := m.UpdatePassword("alice", "newpassword123"); err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}

	// Cancel callback should be triggered
	done := make(chan struct{})
	go func() {
		cancelCalled.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cancel callback was not called after password update")
	}

	// Old session token should be revoked
	if _, _, ok := m.Validate(tok1); ok {
		t.Error("old session token should be invalid after password update")
	}

	// New login with updated password
	tok2, isAdmin2, err := m.Authenticate("alice", "newpassword123")
	if err != nil {
		t.Fatalf("Authenticate alice with new password: %v", err)
	}
	if !isAdmin2 {
		t.Fatalf("alice isAdmin2 = false, want true")
	}
	if user, validAdmin2, ok := m.Validate(tok2); !ok || user != "alice" || !validAdmin2 {
		t.Fatalf("Validate tok2: got %q, %v, %v; want alice, true, true", user, validAdmin2, ok)
	}

	// Register cancel hook again for deletion test
	var delCancelCalled sync.WaitGroup
	delCancelCalled.Add(1)
	m.RegisterCancel("alice", func() {
		delCancelCalled.Done()
	})

	// Delete user alice
	if err := m.Delete("alice"); err != nil {
		t.Fatalf("Delete alice: %v", err)
	}

	delDone := make(chan struct{})
	go func() {
		delCancelCalled.Wait()
		close(delDone)
	}()
	select {
	case <-delDone:
	case <-time.After(2 * time.Second):
		t.Fatal("cancel callback was not called after user delete")
	}

	// Session tok2 should now be invalid
	if _, _, ok := m.Validate(tok2); ok {
		t.Error("session token should be invalid after user deletion")
	}

	// Reload manager from disk to verify persistence
	m2, err := NewManager(dir, nil, log)
	if err != nil {
		t.Fatalf("NewManager reload: %v", err)
	}
	if m2.Count() != 1 {
		t.Fatalf("m2.Count() = %d, want 1 (inituser)", m2.Count())
	}
	list := m2.List()
	if len(list) != 1 || list[0].Username != "inituser" {
		t.Fatalf("m2.List() = %+v, want [inituser]", list)
	}
}
