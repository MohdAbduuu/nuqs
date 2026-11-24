// Tests the SQLite AuthStore: setup persistence and races, role guards, reset codes, sessions and StartedBy persistence.

package store

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSetupPersistenceAndRace(t *testing.T) {
	st, dir := open(t)
	if st.Dir() != dir {
		t.Fatalf("Dir() = %q, want %q", st.Dir(), dir)
	}
	if n, err := st.CountUsers(); err != nil || n != 0 {
		t.Fatalf("empty count = %d, %v", n, err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	if err := st.ReplaceSetupCode("hash-1", now); err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceSetupCode("hash-2", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CompleteSetup("hash-1", User{Username: "alice", PasswordHash: "h"}, now); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("old setup code should fail, got %v", err)
	}

	// Only one concurrent CompleteSetup caller may succeed.
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := st.CompleteSetup("hash-2", User{Username: "Alice", PasswordHash: "pw"}, now); err == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("expected exactly 1 setup win, got %d", wins.Load())
	}

	// Reopen from disk to verify persistence across restarts.
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.ReplaceSetupCode("hash-3", now); !errors.Is(err, ErrSetupClosed) {
		t.Fatalf("setup should be closed, got %v", err)
	}
	if _, err := reopened.CompleteSetup("hash-2", User{Username: "bob", PasswordHash: "pw"}, now); !errors.Is(err, ErrSetupClosed) {
		t.Fatalf("second setup should fail, got %v", err)
	}
	u, err := reopened.GetUserByUsername("ALICE")
	if err != nil {
		t.Fatal(err)
	}
	if u.Username != "alice" || u.Role != RoleAdmin || u.PasswordHash != "pw" {
		t.Fatalf("unexpected user: %+v", u)
	}
	if _, err := reopened.GetUserByID(u.ID); err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
}

func TestUsersRolesAndLastAdminGuard(t *testing.T) {
	st, _ := open(t)
	now := time.Now().UTC()
	admin, err := st.CreateUser(User{Username: "admin", Role: RoleAdmin, PasswordHash: "h1", CreatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser(User{Username: "ADMIN", Role: RoleUser, PasswordHash: "h2"}); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate username should return ErrExists, got %v", err)
	}
	if _, err := st.UpdateUserRole(admin.ID, RoleUser, now); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demoting last admin: %v", err)
	}
	if err := st.DeleteUser(admin.ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("deleting last admin: %v", err)
	}

	bob, err := st.CreateUserWithResetCode(User{Username: "bob", Role: RoleUser, CreatedAt: now.Add(time.Second)}, "invite-hash", now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := st.HasActiveResetCode(bob.ID, now); err != nil || !ok {
		t.Fatalf("expected active reset code, got %v %v", ok, err)
	}
	if _, err := st.UpdateUserRole(bob.ID, RoleAdmin, now); err != nil {
		t.Fatal(err)
	}
	// A pending-password admin cannot satisfy the active-admin requirement yet.
	if _, err := st.UpdateUserRole(admin.ID, RoleUser, now); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demote with only pending second admin: %v", err)
	}
	// Once bob sets a password, admin can be demoted because bob can sign in.
	if err := st.UpdatePassword(bob.ID, "bob-hash", now); err != nil {
		t.Fatal(err)
	}
	if u, err := st.UpdateUserRole(admin.ID, RoleUser, now); err != nil || u.Role != RoleUser {
		t.Fatalf("demote with second active admin: %+v %v", u, err)
	}
	if err := st.UpdatePassword(admin.ID, "new-hash", now); err != nil {
		t.Fatal(err)
	}
	// RotatePassword checks expectedHash and swaps sessions atomically.
	if err := st.RotatePassword("stale-hash", "rot-hash", Session{TokenHash: "rot-tok", UserID: admin.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); !errors.Is(err, ErrPasswordChanged) {
		t.Fatalf("RotatePassword stale hash = %v, want ErrPasswordChanged", err)
	}
	if err := st.RotatePassword("new-hash", "rot-hash", Session{TokenHash: "rot-tok", UserID: admin.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatalf("RotatePassword: %v", err)
	}
	users, activeResets, err := st.ListUsersWithResetStatus(now)
	if err != nil || len(users) != 2 || users[0].Username != "admin" || users[1].Username != "bob" || !activeResets[bob.ID] {
		t.Fatalf("ListUsersWithResetStatus = %+v, %+v, %v", users, activeResets, err)
	}

	if err := st.CreateSession(Session{TokenHash: "tok-a", UserID: admin.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteUser(admin.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.GetSession("tok-a", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted user's session should be gone, got %v", err)
	}
}

func TestResetCodesAndCrossProcessVisibility(t *testing.T) {
	serverStore, dir := open(t)
	cliStore, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cliStore.Close() })

	now := time.Now().UTC()
	u, err := serverStore.CreateUser(User{Username: "alice", Role: RoleAdmin, PasswordHash: "old"})
	if err != nil {
		t.Fatal(err)
	}
	if err := serverStore.CreateSession(Session{TokenHash: "sess-1", UserID: u.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}

	// Separate CLI store handle saves reset code while serverStore is alive.
	if err := cliStore.SaveResetCode(u.ID, "reset-hash", now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Server immediately sees revoked session and active reset code via SQLite WAL.
	if _, _, err := serverStore.GetSession("sess-1", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("session should be revoked after reset code, got %v", err)
	}
	if ok, err := serverStore.HasActiveResetCode(u.ID, now); err != nil || !ok {
		t.Fatalf("HasActiveResetCode = %v, %v", ok, err)
	}
	if _, err := serverStore.ConsumeResetCode("alice", "wrong-hash", "new", now); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("wrong reset code: %v", err)
	}
	updated, err := serverStore.ConsumeResetCode("ALICE", "reset-hash", "new-pw-hash", now.Add(time.Minute))
	if err != nil || updated.PasswordHash != "new-pw-hash" {
		t.Fatalf("ConsumeResetCode: %+v %v", updated, err)
	}
	// Code cannot be reused.
	if _, err := serverStore.ConsumeResetCode("alice", "reset-hash", "again", now.Add(2*time.Minute)); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("reused code should fail: %v", err)
	}
	// Expired code fails with ErrCodeExpired.
	if err := cliStore.SaveResetCode(u.ID, "exp-hash", now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := serverStore.ConsumeResetCode("alice", "exp-hash", "pw", now.Add(2*time.Minute)); !errors.Is(err, ErrCodeExpired) {
		t.Fatalf("expired code: %v", err)
	}
}

func TestSessionsAndAuthEdgeCases(t *testing.T) {
	st, _ := open(t)
	now := time.Now().UTC()
	u, err := st.CreateUser(User{Username: "alice", Role: RoleAdmin, PasswordHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSession(Session{TokenHash: "expired", UserID: u.ID, CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSession(Session{TokenHash: "valid", UserID: u.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.GetSession("expired", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired session: %v", err)
	}
	sess, gotU, err := st.GetSession("valid", now)
	if err != nil || sess.UserID != u.ID || gotU.Username != "alice" {
		t.Fatalf("valid session: %+v %+v %v", sess, gotU, err)
	}
	if err := st.DeleteSession("valid"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.GetSession("valid", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted session: %v", err)
	}

	if err := st.CreateSession(Session{TokenHash: "s1", UserID: u.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteUserSessions(u.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.GetSession("s1", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteUserSessions: %v", err)
	}

	// Missing user queries.
	if _, err := st.GetUserByID("missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetUserByID missing: %v", err)
	}
	if _, err := st.GetUserByUsername("missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetUserByUsername missing: %v", err)
	}
	if _, err := st.UpdateUserRole("missing", RoleUser, now); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateUserRole missing: %v", err)
	}
	if err := st.UpdatePassword("missing", "hash", now); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdatePassword missing: %v", err)
	}
	if err := st.DeleteUser("missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteUser missing: %v", err)
	}
	if has, err := st.HasActiveResetCode("missing", now); err != nil || has {
		t.Errorf("HasActiveResetCode missing: %v %v", has, err)
	}
	if err := st.SaveResetCode("missing", "hash", now, now.Add(time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Errorf("SaveResetCode missing: %v", err)
	}
	if _, err := st.CreateUserWithResetCode(User{Username: "alice", Role: RoleUser}, "hash", now, now.Add(time.Hour)); !errors.Is(err, ErrExists) {
		t.Errorf("CreateUserWithResetCode duplicate: %v", err)
	}
	if _, err := st.ConsumeResetCode("missing", "code", "new-pw", now); !errors.Is(err, ErrInvalidCode) {
		t.Errorf("ConsumeResetCode missing user: %v", err)
	}

	// StartedBy persists on runs and summaries.
	r := Run{Name: "Attributed", Kind: "full", StartedBy: "alice", Targets: []string{"127.0.0.1"}, Status: Completed, Started: now}
	if err := st.Save(&r); err != nil {
		t.Fatal(err)
	}
	gotRun, err := st.Run(r.ID)
	if err != nil || gotRun.StartedBy != "alice" {
		t.Fatalf("Run StartedBy = %q, %v", gotRun.StartedBy, err)
	}
	sums, err := st.Runs(10)
	if err != nil || len(sums) != 1 || sums[0].StartedBy != "alice" {
		t.Fatalf("Runs StartedBy = %+v, %v", sums, err)
	}

	// Role helpers.
	if !RoleAdmin.Valid() || !RoleUser.Valid() || Role("bogus").Valid() {
		t.Error("role helpers wrong")
	}
}
