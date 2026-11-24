// SQLite-backed persistence for accounts, sessions and one-time recovery codes in nuqs.db.

package store

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Role controls what a signed-in user may do in the web UI and API.
type Role string

// Supported account roles.
const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
)

// Valid reports whether r is one of the recognized roles.
func (r Role) Valid() bool {
	return r == RoleAdmin || r == RoleUser
}

// CodePurpose distinguishes initial setup codes from password reset codes.
type CodePurpose string

// Supported one-time code purposes.
const (
	CodeSetup CodePurpose = "setup"
	CodeReset CodePurpose = "reset"
)

// Sentinel errors returned by account, session and recovery code operations.
var (
	ErrExists          = errors.New("already exists")
	ErrLastAdmin       = errors.New("cannot remove or demote the last admin")
	ErrInvalidCode     = errors.New("invalid one-time code")
	ErrCodeExpired     = errors.New("one-time code has expired")
	ErrSetupClosed     = errors.New("initial setup is already complete")
	ErrPasswordChanged = errors.New("password was changed concurrently")
)

// User is a persisted Nuqs account.
type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	Role         Role      `json:"role"`
	PasswordHash string    `json:"password_hash,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Session is an active authenticated browser session stored as a token hash.
type Session struct {
	TokenHash string    `json:"token_hash"`
	UserID    string    `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// CanonicalUsername normalizes a username for case-insensitive matching.
func CanonicalUsername(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// CountUsers returns the number of registered accounts.
func (s *Store) CountUsers() (int, error) {
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return n, nil
}

// ListUsersWithResetStatus returns accounts and their active reset-code flags
// from one consistent database transaction.
func (s *Store) ListUsersWithResetStatus(now time.Time) ([]User, map[string]bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, nil, fmt.Errorf("list users: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.Query(`SELECT id, username, role, password_hash, created_at, updated_at
		FROM users ORDER BY created_at ASC, canonical_username ASC`)
	if err != nil {
		return nil, nil, fmt.Errorf("list users: %w", err)
	}
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			_ = rows.Close()
			return nil, nil, fmt.Errorf("list users: %w", err)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, nil, fmt.Errorf("list users: %w", err)
	}
	_ = rows.Close()

	active := map[string]bool{}
	if !now.IsZero() {
		crows, err := tx.Query(`SELECT DISTINCT user_id FROM one_time_codes
			WHERE purpose = ? AND (expires_at = 0 OR expires_at >= ?)`, string(CodeReset), unix(now.UTC()))
		if err != nil {
			return nil, nil, fmt.Errorf("list reset codes: %w", err)
		}
		for crows.Next() {
			var uid string
			if err := crows.Scan(&uid); err != nil {
				_ = crows.Close()
				return nil, nil, fmt.Errorf("list reset codes: %w", err)
			}
			active[uid] = true
		}
		if err := crows.Err(); err != nil {
			_ = crows.Close()
			return nil, nil, fmt.Errorf("list reset codes: %w", err)
		}
		_ = crows.Close()
	}
	return out, active, nil
}

// GetUserByID finds an account by its unique ID.
func (s *Store) GetUserByID(id string) (User, error) {
	u, err := scanUser(s.db.QueryRow(`SELECT id, username, role, password_hash, created_at, updated_at
		FROM users WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("load user %q: %w", id, err)
	}
	return u, nil
}

// GetUserByUsername finds an account by username (case-insensitive).
func (s *Store) GetUserByUsername(username string) (User, error) {
	canon := CanonicalUsername(username)
	u, err := scanUser(s.db.QueryRow(`SELECT id, username, role, password_hash, created_at, updated_at
		FROM users WHERE canonical_username = ?`, canon))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("load user %q: %w", canon, err)
	}
	return u, nil
}

// CreateUserWithResetCode atomically creates a user and stores an initial one-time code.
func (s *Store) CreateUserWithResetCode(user User, codeHash string, now, expiresAt time.Time) (User, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return User{}, fmt.Errorf("create user: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	created, err := insertUserTx(tx, user)
	if err != nil {
		return User{}, err
	}
	if _, err := tx.Exec(`DELETE FROM one_time_codes WHERE purpose = ? AND user_id = ?`, string(CodeReset), created.ID); err != nil {
		return User{}, fmt.Errorf("save invite code: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO one_time_codes (purpose, user_id, code_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
		string(CodeReset), created.ID, codeHash, unix(now.UTC()), unix(expiresAt.UTC())); err != nil {
		return User{}, fmt.Errorf("save invite code: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return User{}, fmt.Errorf("create user: %w", err)
	}
	return created, nil
}

// UpdateUserRole changes a user's role while refusing to demote the last admin.
func (s *Store) UpdateUserRole(id string, role Role, now time.Time) (User, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return User{}, fmt.Errorf("update role: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	u, err := scanUser(tx.QueryRow(`SELECT id, username, role, password_hash, created_at, updated_at FROM users WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("update role: %w", err)
	}
	if u.Role == RoleAdmin && u.PasswordHash != "" && role != RoleAdmin {
		admins, err := countAdminsTx(tx)
		if err != nil {
			return User{}, err
		}
		if admins <= 1 {
			return User{}, ErrLastAdmin
		}
	}
	u.Role = role
	u.UpdatedAt = now.UTC()
	if _, err := tx.Exec(`UPDATE users SET role = ?, updated_at = ? WHERE id = ?`, string(role), unix(u.UpdatedAt), id); err != nil {
		return User{}, fmt.Errorf("update role: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return User{}, fmt.Errorf("update role: %w", err)
	}
	return u, nil
}

// RotatePassword atomically verifies expectedHash, updates the password hash,
// revokes older sessions and inserts the replacement session in one transaction.
func (s *Store) RotatePassword(expectedHash, newHash string, session Session) error {
	now := session.CreatedAt.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("rotate password: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var currentHash string
	err = tx.QueryRow(`SELECT password_hash FROM users WHERE id = ?`, session.UserID).Scan(&currentHash)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("rotate password: %w", err)
	}
	if !constantEqual(currentHash, expectedHash) {
		return ErrPasswordChanged
	}
	if _, err := tx.Exec(`UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?`, newHash, unix(now), session.UserID); err != nil {
		return fmt.Errorf("rotate password: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM sessions WHERE user_id = ? OR expires_at <= ?`, session.UserID, unix(now)); err != nil {
		return fmt.Errorf("rotate password: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		session.TokenHash, session.UserID, unix(now), unix(session.ExpiresAt.UTC())); err != nil {
		return fmt.Errorf("rotate password: %w", err)
	}
	return tx.Commit()
}

// DeleteUser removes a user, its sessions and its reset codes while guarding the last active admin.
func (s *Store) DeleteUser(id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var role, passwordHash string
	err = tx.QueryRow(`SELECT role, password_hash FROM users WHERE id = ?`, id).Scan(&role, &passwordHash)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	if Role(role) == RoleAdmin && passwordHash != "" {
		admins, err := countAdminsTx(tx)
		if err != nil {
			return err
		}
		if admins <= 1 {
			return ErrLastAdmin
		}
	}
	if _, err := tx.Exec(`DELETE FROM one_time_codes WHERE user_id = ?`, id); err != nil {
		return fmt.Errorf("delete user codes: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM users WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	return tx.Commit()
}

// ReplaceSetupCode stores a fresh initial setup code hash if zero users exist.
func (s *Store) ReplaceSetupCode(codeHash string, now time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("replace setup code: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM users`).Scan(&n); err != nil {
		return fmt.Errorf("replace setup code: %w", err)
	}
	if n > 0 {
		return ErrSetupClosed
	}
	if _, err := tx.Exec(`DELETE FROM one_time_codes WHERE purpose = ?`, string(CodeSetup)); err != nil {
		return fmt.Errorf("replace setup code: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO one_time_codes (purpose, user_id, code_hash, created_at, expires_at) VALUES (?, '', ?, ?, 0)`,
		string(CodeSetup), codeHash, unix(now.UTC())); err != nil {
		return fmt.Errorf("replace setup code: %w", err)
	}
	return tx.Commit()
}

// CompleteSetup atomically verifies the setup code, creates the first admin
// account and permanently clears all setup codes.
func (s *Store) CompleteSetup(codeHash string, admin User, now time.Time) (User, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return User{}, fmt.Errorf("complete setup: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM users`).Scan(&n); err != nil {
		return User{}, fmt.Errorf("complete setup: %w", err)
	}
	if n > 0 {
		return User{}, ErrSetupClosed
	}
	rows, err := tx.Query(`SELECT code_hash FROM one_time_codes WHERE purpose = ?`, string(CodeSetup))
	if err != nil {
		return User{}, fmt.Errorf("complete setup: %w", err)
	}
	matched := false
	for rows.Next() {
		var stored string
		if err := rows.Scan(&stored); err != nil {
			_ = rows.Close()
			return User{}, fmt.Errorf("complete setup: %w", err)
		}
		if constantEqual(stored, codeHash) {
			matched = true
		}
	}
	if err := rows.Close(); err != nil {
		return User{}, fmt.Errorf("complete setup: %w", err)
	}
	if !matched {
		return User{}, ErrInvalidCode
	}
	admin.Role = RoleAdmin
	admin.CreatedAt = now.UTC()
	admin.UpdatedAt = now.UTC()
	created, err := insertUserTx(tx, admin)
	if err != nil {
		return User{}, err
	}
	if _, err := tx.Exec(`DELETE FROM one_time_codes WHERE purpose = ?`, string(CodeSetup)); err != nil {
		return User{}, fmt.Errorf("complete setup: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return User{}, fmt.Errorf("complete setup: %w", err)
	}
	return created, nil
}

// SaveResetCode replaces any active reset code for userID and revokes existing sessions.
func (s *Store) SaveResetCode(userID, codeHash string, now, expiresAt time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("save reset code: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var exists int
	if err := tx.QueryRow(`SELECT count(*) FROM users WHERE id = ?`, userID).Scan(&exists); err != nil {
		return fmt.Errorf("save reset code: %w", err)
	}
	if exists == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(`DELETE FROM one_time_codes WHERE purpose = ? AND user_id = ?`, string(CodeReset), userID); err != nil {
		return fmt.Errorf("save reset code: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO one_time_codes (purpose, user_id, code_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
		string(CodeReset), userID, codeHash, unix(now.UTC()), unix(expiresAt.UTC())); err != nil {
		return fmt.Errorf("save reset code: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM sessions WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("revoke sessions: %w", err)
	}
	return tx.Commit()
}

// ConsumeResetCode atomically validates username's one-time reset code, sets
// newPasswordHash, removes the code and revokes existing sessions.
func (s *Store) ConsumeResetCode(username, codeHash, newPasswordHash string, now time.Time) (User, error) {
	canon := CanonicalUsername(username)
	tx, err := s.db.Begin()
	if err != nil {
		return User{}, fmt.Errorf("consume reset code: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	u, err := scanUser(tx.QueryRow(`SELECT id, username, role, password_hash, created_at, updated_at
		FROM users WHERE canonical_username = ?`, canon))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrInvalidCode
	}
	if err != nil {
		return User{}, fmt.Errorf("consume reset code: %w", err)
	}

	rows, err := tx.Query(`SELECT code_hash, expires_at FROM one_time_codes WHERE purpose = ? AND user_id = ?`, string(CodeReset), u.ID)
	if err != nil {
		return User{}, fmt.Errorf("consume reset code: %w", err)
	}
	var matched bool
	var matchedExp int64
	for rows.Next() {
		var stored string
		var exp int64
		if err := rows.Scan(&stored, &exp); err != nil {
			_ = rows.Close()
			return User{}, fmt.Errorf("consume reset code: %w", err)
		}
		if constantEqual(stored, codeHash) {
			matched = true
			matchedExp = exp
		}
	}
	if err := rows.Close(); err != nil {
		return User{}, fmt.Errorf("consume reset code: %w", err)
	}
	if !matched {
		return User{}, ErrInvalidCode
	}
	exp := fromUnix(matchedExp)
	if !exp.IsZero() && exp.Before(now) {
		_, _ = tx.Exec(`DELETE FROM one_time_codes WHERE purpose = ? AND user_id = ?`, string(CodeReset), u.ID)
		_ = tx.Commit()
		return User{}, ErrCodeExpired
	}

	u.PasswordHash = newPasswordHash
	u.UpdatedAt = now.UTC()
	if _, err := tx.Exec(`UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?`, newPasswordHash, unix(u.UpdatedAt), u.ID); err != nil {
		return User{}, fmt.Errorf("consume reset code: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM one_time_codes WHERE purpose = ? AND user_id = ?`, string(CodeReset), u.ID); err != nil {
		return User{}, fmt.Errorf("consume reset code: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM sessions WHERE user_id = ?`, u.ID); err != nil {
		return User{}, fmt.Errorf("consume reset code: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return User{}, fmt.Errorf("consume reset code: %w", err)
	}
	return u, nil
}

// HasActiveResetCode reports whether userID has an unexpired reset code.
func (s *Store) HasActiveResetCode(userID string, now time.Time) (bool, error) {
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM one_time_codes
		WHERE purpose = ? AND user_id = ? AND (expires_at = 0 OR expires_at > ?)`,
		string(CodeReset), userID, unix(now.UTC())).Scan(&n); err != nil {
		return false, fmt.Errorf("check reset code: %w", err)
	}
	return n > 0, nil
}

// CreateSession persists a hashed session token and prunes expired sessions.
func (s *Store) CreateSession(session Session) error {
	now := session.CreatedAt.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`DELETE FROM sessions WHERE expires_at <= ?`, unix(now)); err != nil {
		return fmt.Errorf("prune sessions: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		session.TokenHash, session.UserID, unix(now), unix(session.ExpiresAt.UTC())); err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return tx.Commit()
}

// GetSession resolves an active session token hash and its owning user.
func (s *Store) GetSession(tokenHash string, now time.Time) (Session, User, error) {
	var sess Session
	var u User
	var role string
	var sCreated, sExpires, uCreated, uUpdated int64
	err := s.db.QueryRow(`SELECT s.token_hash, s.user_id, s.created_at, s.expires_at,
			u.id, u.username, u.role, u.password_hash, u.created_at, u.updated_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = ?`, tokenHash).
		Scan(&sess.TokenHash, &sess.UserID, &sCreated, &sExpires,
			&u.ID, &u.Username, &role, &u.PasswordHash, &uCreated, &uUpdated)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, User{}, ErrNotFound
	}
	if err != nil {
		return Session{}, User{}, fmt.Errorf("load session: %w", err)
	}
	sess.CreatedAt, sess.ExpiresAt = fromUnix(sCreated).UTC(), fromUnix(sExpires).UTC()
	u.Role = Role(role)
	u.CreatedAt, u.UpdatedAt = fromUnix(uCreated).UTC(), fromUnix(uUpdated).UTC()
	if !sess.ExpiresAt.After(now) {
		_, _ = s.db.Exec(`DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
		return Session{}, User{}, ErrNotFound
	}
	return sess, u, nil
}

// DeleteSession revokes a single session token hash.
func (s *Store) DeleteSession(tokenHash string) error {
	if _, err := s.db.Exec(`DELETE FROM sessions WHERE token_hash = ?`, tokenHash); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

type userScanner interface {
	Scan(dest ...any) error
}

func scanUser(row userScanner) (User, error) {
	var u User
	var role string
	var created, updated int64
	if err := row.Scan(&u.ID, &u.Username, &role, &u.PasswordHash, &created, &updated); err != nil {
		return User{}, err
	}
	u.Role = Role(role)
	u.CreatedAt = fromUnix(created).UTC()
	u.UpdatedAt = fromUnix(updated).UTC()
	return u, nil
}

func insertUserTx(tx *sql.Tx, u User) (User, error) {
	canon := CanonicalUsername(u.Username)
	if canon == "" {
		return User{}, errors.New("username is required")
	}
	var exists int
	if err := tx.QueryRow(`SELECT count(*) FROM users WHERE canonical_username = ?`, canon).Scan(&exists); err != nil {
		return User{}, fmt.Errorf("check username: %w", err)
	}
	if exists > 0 {
		return User{}, ErrExists
	}
	if u.ID == "" {
		id, err := randomID()
		if err != nil {
			return User{}, err
		}
		u.ID = id
	}
	u.Username = canon
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now().UTC()
	} else {
		u.CreatedAt = u.CreatedAt.UTC()
	}
	if u.UpdatedAt.IsZero() {
		u.UpdatedAt = u.CreatedAt
	} else {
		u.UpdatedAt = u.UpdatedAt.UTC()
	}
	if _, err := tx.Exec(`INSERT INTO users (id, username, canonical_username, role, password_hash, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Username, canon, string(u.Role), u.PasswordHash, unix(u.CreatedAt), unix(u.UpdatedAt)); err != nil {
		return User{}, fmt.Errorf("insert user: %w", err)
	}
	return u, nil
}

func countAdminsTx(tx *sql.Tx) (int, error) {
	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM users WHERE role = ? AND password_hash != ''`, string(RoleAdmin)).Scan(&n); err != nil {
		return 0, fmt.Errorf("count admins: %w", err)
	}
	return n, nil
}

func constantEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func randomID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
