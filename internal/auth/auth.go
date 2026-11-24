// Package auth implements Nuqs user accounts, PBKDF2 password hashing,
// one-time setup and password-reset codes, sessions, rate limiting and RBAC.
package auth

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nuqs-org/nuqs/internal/store"
)

const (
	// DefaultSessionTTL is how long a signed-in browser session remains valid.
	DefaultSessionTTL = 7 * 24 * time.Hour
	// DefaultInviteCodeTTL is how long a one-time teammate invite code stays valid.
	DefaultInviteCodeTTL = 24 * time.Hour
	// DefaultResetCodeTTL is how long a one-time password reset code stays valid.
	DefaultResetCodeTTL = time.Hour
	minPasswordLen      = 10
	maxPasswordLen      = 128
	minUsernameLen      = 2
	maxUsernameLen      = 32
)

// Auth errors returned by Service methods.
var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrRateLimited        = errors.New("too many failed attempts; try again later")
	ErrUnauthorized       = errors.New("authentication required")
	ErrForbidden          = errors.New("you do not have permission for this action")
	ErrSelfDelete         = errors.New("you cannot delete your own account")
)

// ValidationError reports user-supplied input that failed account validation.
type ValidationError struct {
	Message string
}

// Error returns the user-facing validation message.
func (e *ValidationError) Error() string {
	return e.Message
}

// Principal identifies the authenticated user attached to an HTTP request.
type Principal struct {
	UserID   string
	Username string
	Role     store.Role
}

// IsAdmin reports whether the principal has administrator privileges.
func (p Principal) IsAdmin() bool {
	return p.Role == store.RoleAdmin
}

// UserView is a safe, public projection of an account (never containing hashes).
type UserView struct {
	ID              string     `json:"id"`
	Username        string     `json:"username"`
	Role            store.Role `json:"role"`
	PendingPassword bool       `json:"pending_password"`
	HasResetCode    bool       `json:"has_reset_code"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// ResetCodeResult holds a freshly issued one-time recovery code shown once.
type ResetCodeResult struct {
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	Code      string    `json:"reset_code"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Service coordinates account storage, cryptography, sessions and rate limiting.
type Service struct {
	Store         *store.Store
	HTTPS         bool
	Iterations    int
	SessionTTL    time.Duration
	InviteCodeTTL time.Duration
	ResetCodeTTL  time.Duration
	Now           func() time.Time
	Limiter       *RateLimiter
}

// NewService constructs a Service backed by st with production defaults.
func NewService(st *store.Store) *Service {
	s := &Service{
		Store:         st,
		Iterations:    DefaultPBKDF2Iterations,
		SessionTTL:    DefaultSessionTTL,
		InviteCodeTTL: DefaultInviteCodeTTL,
		ResetCodeTTL:  DefaultResetCodeTTL,
		Now:           time.Now,
		Limiter:       NewRateLimiter(),
	}
	s.Limiter.Now = s.now
	return s
}

// NeedsSetup reports whether zero accounts exist and first-run setup is required.
func (s *Service) NeedsSetup() (bool, error) {
	n, err := s.Store.CountUsers()
	if err != nil {
		return false, err
	}
	return n == 0, nil
}

// EnsureSetupCode creates and stores a fresh one-time setup code whenever no
// users exist yet. The plaintext code is returned once for terminal display.
func (s *Service) EnsureSetupCode() (string, bool, error) {
	needed, err := s.NeedsSetup()
	if err != nil || !needed {
		return "", false, err
	}
	code, err := GenerateCode()
	if err != nil {
		return "", false, err
	}
	if err := s.Store.ReplaceSetupCode(HashCode(code), s.now()); err != nil {
		if errors.Is(err, store.ErrSetupClosed) {
			return "", false, nil
		}
		return "", false, err
	}
	return code, true, nil
}

// CompleteSetup validates the terminal setup code, creates the initial admin
// account, invalidates the code and opens an authenticated session.
func (s *Service) CompleteSetup(ip, setupCode, username, password string) (store.User, string, time.Duration, error) {
	if ok, wait := s.Limiter.Allow(ip, "setup"); !ok {
		return store.User{}, "", wait, ErrRateLimited
	}
	if NormalizeCode(setupCode) == "" {
		return store.User{}, "", 0, &ValidationError{Message: "Enter the one-time setup code printed in the terminal."}
	}
	cleanUser, err := ValidateUsername(username)
	if err != nil {
		return store.User{}, "", 0, err
	}
	if err := ValidatePassword(password); err != nil {
		return store.User{}, "", 0, err
	}
	hash, err := HashPassword(password, s.Iterations)
	if err != nil {
		return store.User{}, "", 0, err
	}
	now := s.now()
	u, err := s.Store.CompleteSetup(HashCode(setupCode), store.User{
		Username:     cleanUser,
		Role:         store.RoleAdmin,
		PasswordHash: hash,
		CreatedAt:    now,
		UpdatedAt:    now,
	}, now)
	if err != nil {
		return store.User{}, "", 0, err
	}
	s.Limiter.RecordSuccess(ip, "setup")
	token, err := s.newSession(u.ID)
	if err != nil {
		return store.User{}, "", 0, err
	}
	return u, token, 0, nil
}

// Login authenticates username and password with rate limiting and constant-time
// PBKDF2 verification, returning the user and a fresh session token.
func (s *Service) Login(ip, username, password string) (store.User, string, time.Duration, error) {
	canon := store.CanonicalUsername(username)
	if ok, wait := s.Limiter.Allow(ip, canon); !ok {
		return store.User{}, "", wait, ErrRateLimited
	}
	if canon == "" || password == "" {
		dummyVerify(password, s.Iterations)
		return store.User{}, "", 0, ErrInvalidCredentials
	}
	u, err := s.Store.GetUserByUsername(canon)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			dummyVerify(password, s.Iterations)
			return store.User{}, "", 0, ErrInvalidCredentials
		}
		return store.User{}, "", 0, err
	}
	if u.PasswordHash == "" {
		dummyVerify(password, s.Iterations)
		return store.User{}, "", 0, ErrInvalidCredentials
	}
	if !VerifyPassword(password, u.PasswordHash) {
		return store.User{}, "", 0, ErrInvalidCredentials
	}
	s.Limiter.RecordSuccess(ip, canon)
	token, err := s.newSession(u.ID)
	if err != nil {
		return store.User{}, "", 0, err
	}
	return u, token, 0, nil
}

// Logout revokes the session associated with rawToken.
func (s *Service) Logout(rawToken string) error {
	if strings.TrimSpace(rawToken) == "" {
		return nil
	}
	return s.Store.DeleteSession(HashSecret(rawToken))
}

// ResolveSession validates a raw session cookie token and returns its Principal.
func (s *Service) ResolveSession(rawToken string) (Principal, bool, error) {
	if strings.TrimSpace(rawToken) == "" {
		return Principal{}, false, nil
	}
	_, u, err := s.Store.GetSession(HashSecret(rawToken), s.now())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Principal{}, false, nil
		}
		return Principal{}, false, err
	}
	return Principal{UserID: u.ID, Username: u.Username, Role: u.Role}, true, nil
}

// ListUsers returns safe user views for the admin users page and API.
func (s *Service) ListUsers() ([]UserView, error) {
	users, activeResets, err := s.Store.ListUsersWithResetStatus(s.now())
	if err != nil {
		return nil, err
	}
	out := make([]UserView, 0, len(users))
	for _, u := range users {
		out = append(out, UserView{
			ID:              u.ID,
			Username:        u.Username,
			Role:            u.Role,
			PendingPassword: u.PasswordHash == "",
			HasResetCode:    activeResets[u.ID],
			CreatedAt:       u.CreatedAt,
			UpdatedAt:       u.UpdatedAt,
		})
	}
	return out, nil
}

// CreateUser creates a teammate account with a one-time invite/reset code so
// the teammate picks their own password at /reset-password.
func (s *Service) CreateUser(username string, role store.Role) (UserView, ResetCodeResult, error) {
	cleanUser, err := ValidateUsername(username)
	if err != nil {
		return UserView{}, ResetCodeResult{}, err
	}
	if !role.Valid() {
		return UserView{}, ResetCodeResult{}, &ValidationError{Message: "Choose a valid role: admin or user."}
	}
	code, err := GenerateCode()
	if err != nil {
		return UserView{}, ResetCodeResult{}, err
	}
	now := s.now()
	exp := now.Add(s.InviteCodeTTL)
	u, err := s.Store.CreateUserWithResetCode(store.User{
		Username:  cleanUser,
		Role:      role,
		CreatedAt: now,
		UpdatedAt: now,
	}, HashCode(code), now, exp)
	if err != nil {
		if errors.Is(err, store.ErrExists) {
			return UserView{}, ResetCodeResult{}, &ValidationError{Message: fmt.Sprintf("An account named %q already exists.", cleanUser)}
		}
		return UserView{}, ResetCodeResult{}, err
	}
	view := UserView{
		ID:              u.ID,
		Username:        u.Username,
		Role:            u.Role,
		PendingPassword: true,
		HasResetCode:    true,
		CreatedAt:       u.CreatedAt,
		UpdatedAt:       u.UpdatedAt,
	}
	return view, ResetCodeResult{UserID: u.ID, Username: u.Username, Code: code, ExpiresAt: exp}, nil
}

// UpdateRole updates an existing account's role, preserving the last-admin guard.
func (s *Service) UpdateRole(userID string, role store.Role) (UserView, error) {
	if !role.Valid() {
		return UserView{}, &ValidationError{Message: "Choose a valid role: admin or user."}
	}
	u, err := s.Store.UpdateUserRole(userID, role, s.now())
	if err != nil {
		return UserView{}, err
	}
	hasReset, err := s.Store.HasActiveResetCode(u.ID, s.now())
	if err != nil {
		return UserView{}, err
	}
	return UserView{
		ID:              u.ID,
		Username:        u.Username,
		Role:            u.Role,
		PendingPassword: u.PasswordHash == "",
		HasResetCode:    hasReset,
		CreatedAt:       u.CreatedAt,
		UpdatedAt:       u.UpdatedAt,
	}, nil
}

// DeleteUser removes targetID if actorID is not deleting themselves and at
// least one admin account remains.
func (s *Service) DeleteUser(actorID, targetID string) error {
	if actorID != "" && actorID == targetID {
		return ErrSelfDelete
	}
	return s.Store.DeleteUser(targetID)
}

// IssueResetCode creates a one-time password reset code for userID and revokes
// all of that user's active sessions.
func (s *Service) IssueResetCode(userID string) (ResetCodeResult, error) {
	u, err := s.Store.GetUserByID(userID)
	if err != nil {
		return ResetCodeResult{}, err
	}
	return s.saveResetForUser(u)
}

// IssueResetCodeByUsername creates a one-time password reset code for username
// (used by "nuqs user reset-password <name>") and revokes active sessions.
func (s *Service) IssueResetCodeByUsername(username string) (ResetCodeResult, error) {
	canon := store.CanonicalUsername(username)
	if canon == "" {
		return ResetCodeResult{}, &ValidationError{Message: "Enter a username."}
	}
	u, err := s.Store.GetUserByUsername(canon)
	if err != nil {
		return ResetCodeResult{}, err
	}
	return s.saveResetForUser(u)
}

func (s *Service) saveResetForUser(u store.User) (ResetCodeResult, error) {
	code, err := GenerateCode()
	if err != nil {
		return ResetCodeResult{}, err
	}
	now := s.now()
	exp := now.Add(s.ResetCodeTTL)
	if err := s.Store.SaveResetCode(u.ID, HashCode(code), now, exp); err != nil {
		return ResetCodeResult{}, err
	}
	return ResetCodeResult{
		UserID:    u.ID,
		Username:  u.Username,
		Code:      code,
		ExpiresAt: exp,
	}, nil
}

// CompletePasswordReset validates a one-time reset code, sets the user's new
// password and invalidates the code and any existing sessions.
func (s *Service) CompletePasswordReset(ip, username, code, newPassword string) (store.User, time.Duration, error) {
	canon := store.CanonicalUsername(username)
	if ok, wait := s.Limiter.Allow(ip, canon); !ok {
		return store.User{}, wait, ErrRateLimited
	}
	if canon == "" || NormalizeCode(code) == "" {
		return store.User{}, 0, &ValidationError{Message: "Enter both your username and one-time reset code."}
	}
	if err := ValidatePassword(newPassword); err != nil {
		return store.User{}, 0, err
	}
	hash, err := HashPassword(newPassword, s.Iterations)
	if err != nil {
		return store.User{}, 0, err
	}
	u, err := s.Store.ConsumeResetCode(canon, HashCode(code), hash, s.now())
	if err != nil {
		return store.User{}, 0, err
	}
	s.Limiter.RecordSuccess(ip, canon)
	return u, 0, nil
}

// ChangePassword verifies currentPassword for userID, updates the password
// hash, revokes previous sessions and returns a rotated session token.
func (s *Service) ChangePassword(userID, currentPassword, newPassword string) (string, error) {
	u, err := s.Store.GetUserByID(userID)
	if err != nil {
		return "", err
	}
	if u.PasswordHash == "" || !VerifyPassword(currentPassword, u.PasswordHash) {
		return "", ErrInvalidCredentials
	}
	if err := ValidatePassword(newPassword); err != nil {
		return "", err
	}
	hash, err := HashPassword(newPassword, s.Iterations)
	if err != nil {
		return "", err
	}
	token, session, err := s.sessionFor(u.ID)
	if err != nil {
		return "", err
	}
	if err := s.Store.RotatePassword(u.PasswordHash, hash, session); err != nil {
		if errors.Is(err, store.ErrPasswordChanged) {
			return "", ErrInvalidCredentials
		}
		return "", err
	}
	return token, nil
}

// ValidateUsername checks and canonicalizes an account username.
func ValidateUsername(raw string) (string, error) {
	canon := store.CanonicalUsername(raw)
	if len(canon) < minUsernameLen || len(canon) > maxUsernameLen {
		return "", &ValidationError{Message: fmt.Sprintf("Username must be between %d and %d characters.", minUsernameLen, maxUsernameLen)}
	}
	for i := 0; i < len(canon); i++ {
		c := canon[i]
		alnum := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		extra := c == '.' || c == '_' || c == '-'
		if i == 0 && !alnum {
			return "", &ValidationError{Message: "Username must start with a letter or number."}
		}
		if !alnum && !extra {
			return "", &ValidationError{Message: "Username can only use letters, numbers, dots, hyphens and underscores."}
		}
	}
	return canon, nil
}

// ValidatePassword checks minimum and maximum password length constraints.
func ValidatePassword(password string) error {
	if len(password) < minPasswordLen {
		return &ValidationError{Message: fmt.Sprintf("Password must be at least %d characters.", minPasswordLen)}
	}
	if len(password) > maxPasswordLen {
		return &ValidationError{Message: fmt.Sprintf("Password must be %d characters or fewer.", maxPasswordLen)}
	}
	return nil
}

func (s *Service) newSession(userID string) (string, error) {
	raw, session, err := s.sessionFor(userID)
	if err != nil {
		return "", err
	}
	if err := s.Store.CreateSession(session); err != nil {
		return "", err
	}
	return raw, nil
}

func (s *Service) sessionFor(userID string) (string, store.Session, error) {
	raw, err := GenerateSessionToken()
	if err != nil {
		return "", store.Session{}, err
	}
	now := s.now()
	return raw, store.Session{TokenHash: HashSecret(raw), UserID: userID, CreatedAt: now, ExpiresAt: now.Add(s.SessionTTL)}, nil
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}
