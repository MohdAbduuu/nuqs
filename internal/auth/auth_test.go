// Tests PBKDF2 password hashing, one-time codes, rate limiting, sessions, RBAC and middleware.

package auth

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nuqs-org/nuqs/internal/store"
)

func newTestService(t *testing.T) (*Service, *time.Time) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	clock := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	svc := NewService(st)
	svc.Iterations = 1000 // fast in tests; production default is checked separately
	svc.Now = func() time.Time { return clock }
	return svc, &clock
}

func TestPasswordHashing(t *testing.T) {
	if DefaultPBKDF2Iterations < 600_000 {
		t.Fatalf("DefaultPBKDF2Iterations = %d, want >= 600000", DefaultPBKDF2Iterations)
	}
	h1, err := HashPassword("correct horse battery staple", 1000)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := HashPassword("correct horse battery staple", 1000)
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h2 {
		t.Error("salts must be unique per hash")
	}
	if !strings.HasPrefix(h1, "pbkdf2-sha256$1000$") {
		t.Errorf("unexpected hash format %q", h1)
	}
	if !VerifyPassword("correct horse battery staple", h1) {
		t.Error("valid password should verify")
	}
	if VerifyPassword("wrong password", h1) {
		t.Error("wrong password must fail")
	}
	for _, bad := range []string{"", "not-a-hash", "bcrypt$10$a$b", "pbkdf2-sha256$10$a$b", "pbkdf2-sha256$1000$!!!$abc"} {
		if VerifyPassword("anything", bad) {
			t.Errorf("malformed hash %q must not verify", bad)
		}
	}
}

func TestCodesAndValidation(t *testing.T) {
	c1, err := GenerateCode()
	if err != nil {
		t.Fatal(err)
	}
	c2, err := GenerateCode()
	if err != nil {
		t.Fatal(err)
	}
	if c1 == c2 || !strings.Contains(c1, "-") {
		t.Fatalf("unexpected codes: %q %q", c1, c2)
	}
	if HashCode(c1) != HashCode(strings.ToLower(strings.ReplaceAll(c1, "-", " "))) {
		t.Error("code normalization should ignore case, spaces and hyphens")
	}

	if _, err := ValidateUsername("a"); err == nil {
		t.Error("1-char username should fail")
	}
	if _, err := ValidateUsername("-bad"); err == nil {
		t.Error("leading hyphen should fail")
	}
	if _, err := ValidateUsername("bad name!"); err == nil {
		t.Error("special chars should fail")
	}
	if got, err := ValidateUsername(" Alice_01 "); err != nil || got != "alice_01" {
		t.Errorf("ValidateUsername = %q, %v", got, err)
	}
	if err := ValidatePassword("short"); err == nil {
		t.Error("short password should fail")
	}
	if err := ValidatePassword(strings.Repeat("x", 129)); err == nil {
		t.Error("overlong password should fail")
	}
	if err := ValidatePassword("valid-password-123"); err != nil {
		t.Errorf("valid password failed: %v", err)
	}
}

func TestSetupLoginResetAndAccountLifecycle(t *testing.T) {
	svc, clock := newTestService(t)

	code, needed, err := svc.EnsureSetupCode()
	if err != nil || !needed || code == "" {
		t.Fatalf("EnsureSetupCode = %q %v %v", code, needed, err)
	}
	// Wrong setup code fails.
	if _, _, _, err := svc.CompleteSetup("127.0.0.1", "WRONG-CODE", "admin", "strong-password-1"); !errors.Is(err, store.ErrInvalidCode) {
		t.Fatalf("wrong code: %v", err)
	}
	// Valid setup creates admin and disables further setup.
	admin, tok, _, err := svc.CompleteSetup("127.0.0.1", code, "Admin", "strong-password-1")
	if err != nil || admin.Username != "admin" || admin.Role != store.RoleAdmin || tok == "" {
		t.Fatalf("CompleteSetup: %+v %q %v", admin, tok, err)
	}
	if _, needed, err := svc.EnsureSetupCode(); err != nil || needed {
		t.Fatalf("setup should no longer be needed: %v %v", needed, err)
	}
	if p, ok, err := svc.ResolveSession(tok); err != nil || !ok || !p.IsAdmin() {
		t.Fatalf("ResolveSession = %+v %v %v", p, ok, err)
	}

	// Admin creates a teammate with a 24-hour one-time invite code.
	bobView, invite, err := svc.CreateUser("bob", store.RoleUser)
	if err != nil || !bobView.PendingPassword || invite.Code == "" {
		t.Fatalf("CreateUser: %+v %+v %v", bobView, invite, err)
	}
	if gotTTL := invite.ExpiresAt.Sub(*clock); gotTTL != DefaultInviteCodeTTL {
		t.Fatalf("invite TTL = %v, want %v", gotTTL, DefaultInviteCodeTTL)
	}
	// Invite code stays valid past the 1-hour reset window (e.g. 2 hours later).
	*clock = clock.Add(2 * time.Hour)
	// Teammate cannot log in before setting a password.
	if _, _, _, err := svc.Login("10.0.0.2", "bob", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("blank login should fail: %v", err)
	}
	if _, _, _, err := svc.Login("10.0.0.2", "bob", "anything12345"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("pending-password login should fail: %v", err)
	}
	// Teammate sets password with one-time invite code.
	if _, _, err := svc.CompletePasswordReset("10.0.0.2", "bob", invite.Code, "bob-new-password-1"); err != nil {
		t.Fatalf("CompletePasswordReset: %v", err)
	}
	// Invite code expires after 24 hours.
	carolView, carolInvite, err := svc.CreateUser("carol", store.RoleUser)
	if err != nil {
		t.Fatalf("CreateUser carol: %v", err)
	}
	*clock = clock.Add(DefaultInviteCodeTTL + time.Minute)
	if _, _, err := svc.CompletePasswordReset("10.0.0.3", "carol", carolInvite.Code, "too-late-invite-1"); !errors.Is(err, store.ErrCodeExpired) {
		t.Fatalf("expired invite code: %v", err)
	}
	if err := svc.DeleteUser(admin.ID, carolView.ID); err != nil {
		t.Fatalf("DeleteUser carol: %v", err)
	}
	// Code cannot be reused.
	if _, _, err := svc.CompletePasswordReset("10.0.0.2", "bob", invite.Code, "bob-new-password-2"); !errors.Is(err, store.ErrInvalidCode) {
		t.Fatalf("reused code should fail: %v", err)
	}
	// Teammate logs in.
	_, bobTok, _, err := svc.Login("10.0.0.2", "bob", "bob-new-password-1")
	if err != nil || bobTok == "" {
		t.Fatalf("bob Login: %v", err)
	}
	// Bob changes own password -> rotates session and invalidates old session.
	newBobTok, err := svc.ChangePassword(bobView.ID, "bob-new-password-1", "bob-changed-password-2")
	if err != nil || newBobTok == "" || newBobTok == bobTok {
		t.Fatalf("ChangePassword: %q %v", newBobTok, err)
	}
	if _, ok, _ := svc.ResolveSession(bobTok); ok {
		t.Error("old session must be revoked after password change")
	}
	if _, ok, _ := svc.ResolveSession(newBobTok); !ok {
		t.Error("rotated session should be valid")
	}

	// Admin or CLI issues reset code -> revokes active session.
	res, err := svc.IssueResetCodeByUsername("bob")
	if err != nil || res.Code == "" {
		t.Fatalf("IssueResetCodeByUsername: %+v %v", res, err)
	}
	if _, ok, _ := svc.ResolveSession(newBobTok); ok {
		t.Error("session must be revoked when reset code is issued")
	}
	// Reset code expires after TTL.
	*clock = clock.Add(2 * time.Hour)
	if _, _, err := svc.CompletePasswordReset("10.0.0.2", "bob", res.Code, "too-late-password"); !errors.Is(err, store.ErrCodeExpired) {
		t.Fatalf("expired reset code: %v", err)
	}

	// Self-delete and last-admin guards.
	if err := svc.DeleteUser(admin.ID, admin.ID); !errors.Is(err, ErrSelfDelete) {
		t.Fatalf("self-delete: %v", err)
	}
	if _, err := svc.UpdateRole(admin.ID, store.RoleUser); !errors.Is(err, store.ErrLastAdmin) {
		t.Fatalf("demote last admin: %v", err)
	}
	if _, err := svc.UpdateRole(bobView.ID, store.RoleAdmin); err != nil {
		t.Fatalf("promote bob to admin: %v", err)
	}
	users, err := svc.ListUsers()
	if err != nil || len(users) != 2 {
		t.Fatalf("ListUsers: %+v %v", users, err)
	}
	if err := svc.DeleteUser(admin.ID, bobView.ID); err != nil {
		t.Fatalf("DeleteUser bob: %v", err)
	}
	if err := svc.Logout(tok); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := svc.ResolveSession(tok); ok {
		t.Error("logged-out session must not resolve")
	}
}

func TestRateLimiting(t *testing.T) {
	svc, clock := newTestService(t)
	code, _, _ := svc.EnsureSetupCode()
	_, _, _, err := svc.CompleteSetup("127.0.0.1", code, "admin", "strong-password-1")
	if err != nil {
		t.Fatal(err)
	}

	// Repeated valid logins from the same IP clear their counted attempt and
	// never trip the per-IP limit.
	for i := range defaultMaxPerIP + 5 {
		if _, _, _, err := svc.Login("192.168.1.8", "admin", "strong-password-1"); err != nil {
			t.Fatalf("valid login %d failed: %v", i+1, err)
		}
	}

	for i := range defaultMaxPerIPUser {
		if _, _, _, err := svc.Login("192.168.1.9", "admin", "wrong-password"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: got %v, want ErrInvalidCredentials", i+1, err)
		}
	}
	if _, _, wait, err := svc.Login("192.168.1.9", "admin", "strong-password-1"); !errors.Is(err, ErrRateLimited) || wait <= 0 {
		t.Fatalf("expected rate limit with positive wait, got %v %v", err, wait)
	}
	// A different IP is not locked out of the admin account.
	if _, _, _, err := svc.Login("192.168.1.10", "admin", "strong-password-1"); err != nil {
		t.Fatalf("other IP should still be able to sign in: %v", err)
	}
	// After the window elapses, original IP is allowed again.
	*clock = clock.Add(defaultRateWindow + time.Second)
	if _, _, _, err := svc.Login("192.168.1.9", "admin", "strong-password-1"); err != nil {
		t.Fatalf("login after window: %v", err)
	}
}

func TestLoginRateLimitParallelRequests(t *testing.T) {
	svc, _ := newTestService(t)
	// Use enough iterations that parallel requests overlap while PBKDF2 runs.
	svc.Iterations = 10_000
	code, _, err := svc.EnsureSetupCode()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := svc.CompleteSetup("127.0.0.1", code, "admin", "strong-password-1"); err != nil {
		t.Fatal(err)
	}

	const total = 30
	start := make(chan struct{})
	var invalid, limited, other atomic.Int32
	var wg sync.WaitGroup
	for range total {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _, wait, err := svc.Login("192.168.1.50", "admin", "wrong-password")
			switch {
			case errors.Is(err, ErrInvalidCredentials):
				invalid.Add(1)
			case errors.Is(err, ErrRateLimited) && wait > 0:
				limited.Add(1)
			default:
				other.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if invalid.Load() != defaultMaxPerIPUser || limited.Load() != total-defaultMaxPerIPUser || other.Load() != 0 {
		t.Fatalf("parallel wrong logins: invalid=%d limited=%d other=%d, want %d/%d/0",
			invalid.Load(), limited.Load(), other.Load(), defaultMaxPerIPUser, total-defaultMaxPerIPUser)
	}
}

func TestGateMiddlewareAndSameOrigin(t *testing.T) {
	svc, _ := newTestService(t)
	code, _, _ := svc.EnsureSetupCode()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := PrincipalFromContext(r.Context())
		_, _ = w.Write([]byte("ok:" + r.URL.Path + ":" + p.Username))
	})
	h := svc.Gate(inner)

	// While 0 users exist: /static passes, /setup passes, HTML redirects to /setup, /api gets 401.
	for _, c := range []struct {
		path string
		want int
		loc  string
	}{
		{"/static/nuqs.css", http.StatusOK, ""},
		{"/setup", http.StatusOK, ""},
		{"/scans", http.StatusFound, "/setup"},
		{"/api/scans", http.StatusUnauthorized, ""},
	} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://192.168.1.5:9002"+c.path, nil)
		req.TLS = &tls.ConnectionState{}
		h.ServeHTTP(w, req)
		if w.Code != c.want || (c.loc != "" && w.Header().Get("Location") != c.loc) {
			t.Errorf("before setup %s: code=%d loc=%q, want %d %q", c.path, w.Code, w.Header().Get("Location"), c.want, c.loc)
		}
		if w.Header().Get("Strict-Transport-Security") == "" {
			t.Errorf("TLS request should set HSTS on %s", c.path)
		}
	}

	_, tok, _, err := svc.CompleteSetup("127.0.0.1", code, "admin", "strong-password-1")
	if err != nil {
		t.Fatal(err)
	}

	// After setup: /setup is closed, /login & /reset-password allowed, protected HTML redirects with next, API gets 401.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "https://192.168.1.5:9002/setup", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("POST /setup after setup: %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://192.168.1.5:9002/scans/3?tab=vulns", nil))
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/login?next=%2Fscans%2F3%3Ftab%3Dvulns" {
		t.Errorf("unauthenticated deep link: %d %q", w.Code, w.Header().Get("Location"))
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://192.168.1.5:9002/api/status", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated API: %d", w.Code)
	}

	// Authenticated request passes through and /login redirects to /scans.
	req := httptest.NewRequest(http.MethodGet, "https://192.168.1.5:9002/scans", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: tok})
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Body.String() != "ok:/scans:admin" || w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("authenticated /scans: %d %q cc=%q", w.Code, w.Body.String(), w.Header().Get("Cache-Control"))
	}

	// Cookie flags and SameOrigin / SafeNext checks.
	rec := httptest.NewRecorder()
	tlsReq := httptest.NewRequest(http.MethodPost, "https://192.168.1.5:9002/login", nil)
	tlsReq.TLS = &tls.ConnectionState{}
	svc.SetSessionCookie(rec, tlsReq, tok)
	cookies := resultCookies(rec)
	if len(cookies) != 1 || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie flags wrong: %+v", cookies)
	}

	tlsReq.Header.Set("Origin", "https://192.168.1.5:9002")
	if !SameOrigin(tlsReq, true) {
		t.Error("matching HTTPS origin should pass")
	}
	tlsReq.Header.Set("Origin", "http://192.168.1.5:9002")
	if SameOrigin(tlsReq, true) {
		t.Error("HTTP origin on HTTPS server must fail")
	}
	tlsReq.Header.Del("Origin")
	tlsReq.Header.Set("Sec-Fetch-Site", "same-origin")
	if !SameOrigin(tlsReq, true) {
		t.Error("Sec-Fetch-Site: same-origin fallback should pass")
	}
	tlsReq.Header.Set("Origin", "null")
	if !SameOrigin(tlsReq, true) {
		t.Error("Origin: null with Sec-Fetch-Site: same-origin should pass")
	}
	tlsReq.Header.Set("Sec-Fetch-Site", "cross-site")
	if SameOrigin(tlsReq, true) {
		t.Error("Origin: null with cross-site must fail")
	}

	for in, want := range map[string]string{
		"/scans/5":           "/scans/5",
		"//evil.example/x":   "/scans",
		"https://evil.com/x": "/scans",
		"/\\evil.com":        "/scans",
		"/login":             "/scans",
		"/setup":             "/scans",
		"/checks?q=ssh":      "/checks?q=ssh",
	} {
		if got := SafeNext(in); got != want {
			t.Errorf("SafeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAuthEdgeCasesAndBranches(t *testing.T) {
	svc, clock := newTestService(t)
	code, _, err := svc.EnsureSetupCode()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := svc.CompleteSetup("127.0.0.1", "   ", "admin", "strong-password-1"); err == nil {
		t.Error("empty setup code should fail")
	}
	if _, _, _, err := svc.CompleteSetup("127.0.0.1", code, "!", "strong-password-1"); err == nil {
		t.Error("bad username should fail")
	}
	if _, _, _, err := svc.CompleteSetup("127.0.0.1", code, "admin", "short"); err == nil {
		t.Error("short password should fail")
	}
	admin, _, _, err := svc.CompleteSetup("127.0.0.1", code, "admin", "strong-password-1")
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := svc.CreateUser("bob", store.Role("invalid")); err == nil {
		t.Error("invalid role should fail")
	}
	if _, _, err := svc.CreateUser("admin", store.RoleUser); err == nil {
		t.Error("duplicate username should fail")
	}
	if _, err := svc.UpdateRole(admin.ID, store.Role("nope")); err == nil {
		t.Error("UpdateRole invalid role should fail")
	}
	if _, err := svc.IssueResetCode("missing-id"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("IssueResetCode missing: %v", err)
	}
	if _, err := svc.IssueResetCodeByUsername(""); err == nil {
		t.Error("empty username reset should fail")
	}
	if _, err := svc.IssueResetCodeByUsername("ghost"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown username reset: %v", err)
	}
	res, err := svc.IssueResetCode(admin.ID)
	if err != nil || res.Code == "" {
		t.Fatalf("IssueResetCode: %+v %v", res, err)
	}
	if _, _, err := svc.CompletePasswordReset("127.0.0.1", "", "", "new-password-123"); err == nil {
		t.Error("blank reset inputs should fail")
	}
	if _, _, err := svc.CompletePasswordReset("127.0.0.1", "admin", res.Code, "short"); err == nil {
		t.Error("short new password should fail")
	}
	if _, _, err := svc.CompletePasswordReset("127.0.0.1", "admin", res.Code, "admin-reset-pass-1"); err != nil {
		t.Fatalf("CompletePasswordReset: %v", err)
	}
	if _, err := svc.ChangePassword(admin.ID, "wrong-current", "another-pass-123"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("wrong current password: %v", err)
	}
	if _, err := svc.ChangePassword(admin.ID, "admin-reset-pass-1", "short"); err == nil {
		t.Error("short change password should fail")
	}
	if err := svc.Logout(""); err != nil {
		t.Errorf("empty logout: %v", err)
	}
	if _, ok, err := svc.ResolveSession(""); err != nil || ok {
		t.Errorf("empty session resolve: %v %v", ok, err)
	}

	// Gate additional branches: authenticated GET /login redirects, GET /setup redirects, unauth POST returns 401.
	h := svc.Gate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	_, tok, _, err := svc.Login("127.0.0.1", "admin", "admin-reset-pass-1")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9002/login", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: tok})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/scans" {
		t.Errorf("authed GET /login = %d %q", w.Code, w.Header().Get("Location"))
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9002/setup", nil))
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/login" {
		t.Errorf("GET /setup after setup = %d %q", w.Code, w.Header().Get("Location"))
	}
	if w.Header().Get("Content-Security-Policy") == "" || w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("Gate redirect missing security headers: %v", w.Header())
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9002/users", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("unauth POST /users = %d, want 401", w.Code)
	}

	// ClearSessionCookie, ClientIP, SameOrigin empty host, and RateLimiter IP-wide cap.
	rec := httptest.NewRecorder()
	svc.ClearSessionCookie(rec, httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9002/logout", nil))
	if cookies := resultCookies(rec); len(cookies) != 1 || cookies[0].MaxAge != -1 {
		t.Errorf("ClearSessionCookie: %+v", cookies)
	}
	rNoPort := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9002/", nil)
	rNoPort.RemoteAddr = "10.0.0.5"
	if got := ClientIP(rNoPort); got != "10.0.0.5" {
		t.Errorf("ClientIP = %q", got)
	}
	rNoPort.Host = ""
	if SameOrigin(rNoPort, false) {
		t.Error("empty host must fail SameOrigin")
	}
	rl := NewRateLimiter()
	rl.Now = func() time.Time { return *clock }
	for i := range defaultMaxPerIP {
		if ok, _ := rl.Allow("10.1.1.1", "user-"+string(rune('a'+i))); !ok {
			t.Fatalf("attempt %d should be allowed", i+1)
		}
	}
	if ok, wait := rl.Allow("10.1.1.1", "fresh-user"); ok || wait <= 0 {
		t.Errorf("IP-wide rate limit should trigger: ok=%v wait=%v", ok, wait)
	}
	rl.pruneAll(clock.Add(defaultRateWindow+time.Second), defaultRateWindow)
	if ok, _ := rl.Allow("10.1.1.1", "fresh-user"); !ok {
		t.Error("after pruneAll expired IP should be allowed")
	}
}

func resultCookies(w *httptest.ResponseRecorder) []*http.Cookie {
	resp := w.Result()
	defer resp.Body.Close()
	return resp.Cookies()
}
