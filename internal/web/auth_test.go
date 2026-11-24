// Tests first-run setup, login, sessions, password reset, rate limiting, RBAC and /users management in the web UI.

package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nuqs-org/nuqs/internal/auth"
	"github.com/nuqs-org/nuqs/internal/store"
	"github.com/nuqs-org/nuqs/internal/tools"
)

func newAuthedWeb(t *testing.T) (*Handler, *auth.Service, string) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	authSvc := auth.NewService(st)
	authSvc.Iterations = 1000
	code, needed, err := authSvc.EnsureSetupCode()
	if err != nil || !needed {
		t.Fatalf("EnsureSetupCode: %v %v", needed, err)
	}
	h := newTestWeb(t, &fakeRunner{xml: scanXML})
	h.Auth = authSvc
	return h, authSvc, code
}

func postForm(h http.Handler, path string, form url.Values, cookies []*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9002"+path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "http://127.0.0.1:9002")
	r.RemoteAddr = "127.0.0.1:54321"
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func getWithCookies(h http.Handler, path string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9002"+path, nil)
	r.RemoteAddr = "127.0.0.1:54321"
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func resultCookies(w *httptest.ResponseRecorder) []*http.Cookie {
	resp := w.Result()
	defer resp.Body.Close()
	return resp.Cookies()
}

func TestWebSetupLoginUsersResetAndRBACFlow(t *testing.T) {
	h, authSvc, setupCode := newAuthedWeb(t)

	// Before setup: /scans redirects to /setup, and /setup renders the setup form.
	w := getWithCookies(h, "/scans", nil)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/setup" {
		t.Fatalf("before setup /scans: %d %q", w.Code, w.Header().Get("Location"))
	}
	w = getWithCookies(h, "/setup", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "One-time setup code") {
		t.Fatalf("GET /setup: %d", w.Code)
	}

	// Bad setup code rejected.
	w = postForm(h, "/setup", url.Values{
		"code": {"WRONG-CODE"}, "username": {"alice"}, "password": {"alice-secret-123"}, "confirm": {"alice-secret-123"},
	}, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("bad setup code = %d, want 401", w.Code)
	}

	// Valid setup creates admin and sets session cookie.
	w = postForm(h, "/setup", url.Values{
		"code": {setupCode}, "username": {"alice"}, "password": {"alice-secret-123"}, "confirm": {"alice-secret-123"},
	}, nil)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/scans" {
		t.Fatalf("POST /setup: %d %q %s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	adminCookies := resultCookies(w)
	if len(adminCookies) == 0 {
		t.Fatal("expected session cookie after setup")
	}

	// /setup is permanently closed now.
	if w := getWithCookies(h, "/setup", nil); w.Code != http.StatusFound || w.Header().Get("Location") != "/login" {
		t.Fatalf("GET /setup after setup: %d %q", w.Code, w.Header().Get("Location"))
	}

	// Admin sees Users nav item and can add a user teammate.
	w = getWithCookies(h, "/scans", adminCookies)
	mustContain(t, "admin scans", w.Body.String(), `href="/users"`, `href="/scans/new"`, "alice", "admin")

	w = postForm(h, "/users", url.Values{"username": {"bob"}, "role": {"user"}}, adminCookies)
	if w.Code != http.StatusCreated {
		t.Fatalf("POST /users: %d %s", w.Code, w.Body.String())
	}
	mustContain(t, "created teammate", w.Body.String(), "One-time password code", "bob", "pending password")

	// Extract the issued reset code from the rendered code banner.
	body := w.Body.String()
	start := strings.Index(body, `<code class="codeValue">`)
	if start < 0 {
		t.Fatalf("missing codeValue in users page:\n%s", body)
	}
	rest := body[start+len(`<code class="codeValue">`):]
	inviteCode := rest[:strings.Index(rest, "</code>")]

	// User sets password at /reset-password and signs in.
	w = getWithCookies(h, "/reset-password?user=bob", nil)
	mustContain(t, "reset page", w.Body.String(), `value="bob"`, "One-time reset code")

	w = postForm(h, "/reset-password", url.Values{
		"username": {"bob"}, "code": {inviteCode}, "password": {"bob-secret-1234"}, "confirm": {"bob-secret-1234"},
	}, nil)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login?notice=password-reset" {
		t.Fatalf("POST /reset-password: %d %q", w.Code, w.Header().Get("Location"))
	}

	w = getWithCookies(h, "/login?notice=password-reset", nil)
	mustContain(t, "login notice", w.Body.String(), "Password saved. Sign in with your new password.")

	w = postForm(h, "/login", url.Values{"username": {"bob"}, "password": {"bob-secret-1234"}, "next": {"/scans"}}, nil)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/scans" {
		t.Fatalf("bob login: %d %q", w.Code, w.Header().Get("Location"))
	}
	userCookies := resultCookies(w)

	// Regular user can open /scans and /scans/new, but cannot see or access /users.
	w = getWithCookies(h, "/scans", userCookies)
	mustContain(t, "user scans", w.Body.String(), `href="/scans/new"`)
	if strings.Contains(w.Body.String(), `href="/users"`) {
		t.Error("regular user must not see Users link")
	}
	if w := getWithCookies(h, "/scans/new", userCookies); w.Code != http.StatusOK {
		t.Errorf("user GET /scans/new = %d, want 200", w.Code)
	}
	if w := getWithCookies(h, "/users", userCookies); w.Code != http.StatusForbidden {
		t.Errorf("user GET /users = %d, want 403", w.Code)
	}

	// A scan started by alice displays "by alice" on /scans and "Started by" on /scans/{id}.
	s, err := h.Scans.Start(tools.NewScan{Name: "Lab", Kind: "full", StartedBy: "alice", Settings: tools.ScanRequest{Target: "127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	w = getWithCookies(h, "/scans", userCookies)
	mustContain(t, "scans attribution", w.Body.String(), "by alice")
	w = getWithCookies(h, "/scans/"+s.ID, userCookies)
	mustContain(t, "scan details attribution", w.Body.String(), "Started by", "alice")

	// Bob changes own password -> gets rotated session cookie.
	w = postForm(h, "/account/password", url.Values{
		"current_password": {"bob-secret-1234"}, "new_password": {"bob-updated-5678"}, "confirm_password": {"bob-updated-5678"},
	}, userCookies)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/scans?notice=password-updated" {
		t.Fatalf("change password: %d %q", w.Code, w.Header().Get("Location"))
	}
	rotatedCookies := resultCookies(w)

	// Admin promotes bob to admin, issues a reset code, then deletes bob.
	bob, err := authSvc.Store.GetUserByUsername("bob")
	if err != nil {
		t.Fatal(err)
	}
	w = postForm(h, "/users/"+bob.ID+"/role", url.Values{"role": {"admin"}}, adminCookies)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("role update: %d", w.Code)
	}
	w = postForm(h, "/users/"+bob.ID+"/reset", nil, adminCookies)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "One-time password code") {
		t.Fatalf("admin reset: %d", w.Code)
	}
	// Reset revoked bob's rotated session.
	if w := getWithCookies(h, "/scans", rotatedCookies); w.Code != http.StatusFound {
		t.Errorf("revoked session should redirect to login, got %d", w.Code)
	}
	w = postForm(h, "/users/"+bob.ID+"/delete", nil, adminCookies)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("delete bob: %d", w.Code)
	}

	// Admin signs out.
	w = postForm(h, "/logout", nil, adminCookies)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login?notice=signed-out" {
		t.Fatalf("logout: %d %q", w.Code, w.Header().Get("Location"))
	}
}

func TestWebLoginRateLimitAndCSRF(t *testing.T) {
	h, _, setupCode := newAuthedWeb(t)
	_ = postForm(h, "/setup", url.Values{
		"code": {setupCode}, "username": {"alice"}, "password": {"alice-secret-123"}, "confirm": {"alice-secret-123"},
	}, nil)

	// Cross-origin POST is rejected.
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9002/login", strings.NewReader("username=alice&password=bad"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin login = %d, want 403", w.Code)
	}

	// Repeated bad logins hit 429 Too Many Requests with Retry-After.
	for range 5 {
		w := postForm(h, "/login", url.Values{"username": {"alice"}, "password": {"wrong-pass-123"}}, nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("bad login = %d, want 401", w.Code)
		}
	}
	w = postForm(h, "/login", url.Values{"username": {"alice"}, "password": {"alice-secret-123"}}, nil)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("rate-limited login = %d retry=%q", w.Code, w.Header().Get("Retry-After"))
	}
}

func TestWebAuthErrorBranches(t *testing.T) {
	h, authSvc, setupCode := newAuthedWeb(t)

	// Mismatched setup passwords.
	w := postForm(h, "/setup", url.Values{
		"code": {setupCode}, "username": {"alice"}, "password": {"alice-secret-123"}, "confirm": {"different-123"},
	}, nil)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "do not match") {
		t.Fatalf("setup mismatch: %d", w.Code)
	}
	// Complete setup.
	w = postForm(h, "/setup", url.Values{
		"code": {setupCode}, "username": {"alice"}, "password": {"alice-secret-123"}, "confirm": {"alice-secret-123"},
	}, nil)
	adminCookies := resultCookies(w)

	// Change password errors: mismatch and wrong current password.
	w = postForm(h, "/account/password", url.Values{
		"current_password": {"alice-secret-123"}, "new_password": {"new-password-111"}, "confirm_password": {"other-password-2"},
	}, adminCookies)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "do not match") {
		t.Errorf("change pw mismatch = %d", w.Code)
	}
	w = postForm(h, "/account/password", url.Values{
		"current_password": {"wrong-password"}, "new_password": {"new-password-111"}, "confirm_password": {"new-password-111"},
	}, adminCookies)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "Current password is incorrect") {
		t.Errorf("change pw wrong current = %d", w.Code)
	}
	w = postForm(h, "/account/password", url.Values{
		"current_password": {"incorrect-password"}, "new_password": {"new-password-1"}, "confirm_password": {"new-password-1"},
		"return_to": {"/checks?q=telnet"},
	}, adminCookies)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/checks?account_error=current-password&q=telnet" {
		t.Fatalf("password error should return to the original page, got %d %q", w.Code, w.Header().Get("Location"))
	}
	w = getWithCookies(h, w.Header().Get("Location"), adminCookies)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `id="accountError"`) || !strings.Contains(w.Body.String(), "Current password is incorrect") {
		t.Fatalf("missing inline account error: %d", w.Code)
	}

	// Users page errors: duplicate user, self delete, last-admin demote, missing user.
	w = postForm(h, "/users", url.Values{"username": {"alice"}, "role": {"user"}}, adminCookies)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "already exists") {
		t.Errorf("duplicate user = %d", w.Code)
	}
	alice, _ := authSvc.Store.GetUserByUsername("alice")
	w = postForm(h, "/users/"+alice.ID+"/delete", nil, adminCookies)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "cannot remove your own") {
		t.Errorf("self delete = %d", w.Code)
	}
	w = postForm(h, "/users/"+alice.ID+"/role", url.Values{"role": {"user"}}, adminCookies)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "At least one admin") {
		t.Errorf("last admin demote = %d", w.Code)
	}
	w = postForm(h, "/users/missing/reset", nil, adminCookies)
	if w.Code != http.StatusNotFound {
		t.Errorf("missing user reset = %d", w.Code)
	}
	w = postForm(h, "/users/missing/delete", nil, adminCookies)
	if w.Code != http.StatusNotFound {
		t.Errorf("missing user delete = %d", w.Code)
	}

	// Reset password error branches: mismatch and bad code.
	w = postForm(h, "/reset-password", url.Values{
		"username": {"alice"}, "code": {"FAKE-CODE"}, "password": {"new-password-123"}, "confirm": {"other-123"},
	}, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("reset mismatch = %d", w.Code)
	}
	w = postForm(h, "/reset-password", url.Values{
		"username": {"alice"}, "code": {"FAKE-CODE"}, "password": {"new-password-123"}, "confirm": {"new-password-123"},
	}, nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("reset bad code = %d", w.Code)
	}

	// Helpers coverage.
	if userInitials("alice") != "AL" || userInitials("!!!") != "U" {
		t.Errorf("userInitials unexpected")
	}
	if !strings.Contains(rateLimitMessage(60_000_000_000), "1 minute") || !strings.Contains(rateLimitMessage(180_000_000_000), "3 minutes") || !strings.Contains(rateLimitMessage(10_000_000_000), "10 seconds") {
		t.Errorf("rateLimitMessage unexpected")
	}
	if noticeText("unknown") != "" || noticeText("role-updated") == "" || noticeText("user-removed") == "" || noticeText("password-reset") == "" || noticeText("signed-out") == "" || noticeText("password-updated") == "" {
		t.Errorf("noticeText unexpected")
	}
}

func TestWebAuthMoreEdgeCases(t *testing.T) {
	h, authSvc, setupCode := newAuthedWeb(t)

	// Short password in setup.
	w := postForm(h, "/setup", url.Values{
		"code": {setupCode}, "username": {"admin"}, "password": {"short"}, "confirm": {"short"},
	}, nil)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "at least 10 characters") {
		t.Errorf("short password setup = %d", w.Code)
	}

	// Invalid username in setup.
	w = postForm(h, "/setup", url.Values{
		"code": {setupCode}, "username": {"bad name!"}, "password": {"admin-password-123"}, "confirm": {"admin-password-123"},
	}, nil)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "Username") {
		t.Errorf("bad username setup = %d", w.Code)
	}

	// Successful setup.
	w = postForm(h, "/setup", url.Values{
		"code": {setupCode}, "username": {"admin"}, "password": {"admin-password-123"}, "confirm": {"admin-password-123"},
	}, nil)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("setup failed: %d", w.Code)
	}
	adminCookies := resultCookies(w)

	// Setup after completed returns 403 / redirects.
	w = postForm(h, "/setup", url.Values{
		"code": {setupCode}, "username": {"admin2"}, "password": {"admin-password-123"}, "confirm": {"admin-password-123"},
	}, nil)
	if w.Code != http.StatusForbidden {
		t.Errorf("setup after completed = %d, want 403", w.Code)
	}

	// Login with empty credentials.
	w = postForm(h, "/login", url.Values{"username": {""}, "password": {""}}, nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("empty login = %d", w.Code)
	}
	// Login with nonexistent user.
	w = postForm(h, "/login", url.Values{"username": {"nonexistent"}, "password": {"secret-123"}}, nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("nonexistent login = %d", w.Code)
	}

	// Reset with short password.
	w = postForm(h, "/reset-password", url.Values{
		"username": {"admin"}, "code": {"anycode"}, "password": {"short"}, "confirm": {"short"},
	}, nil)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "at least 10 characters") {
		t.Errorf("reset short password = %d", w.Code)
	}

	// Users page: create user with invalid name or invalid role.
	w = postForm(h, "/users", url.Values{"username": {"bad user!"}, "role": {"user"}}, adminCookies)
	if w.Code != http.StatusBadRequest {
		t.Errorf("create user bad name = %d", w.Code)
	}
	w = postForm(h, "/users", url.Values{"username": {"validname"}, "role": {"superhero"}}, adminCookies)
	if w.Code != http.StatusBadRequest {
		t.Errorf("create user bad role = %d", w.Code)
	}

	// Change password with short new password.
	w = postForm(h, "/account/password", url.Values{
		"current_password": {"admin-password-123"}, "new_password": {"short"}, "confirm_password": {"short"},
	}, adminCookies)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "at least 10 characters") {
		t.Errorf("change pw short = %d", w.Code)
	}

	// Update role to invalid role.
	admin, _ := authSvc.Store.GetUserByUsername("admin")
	w = postForm(h, "/users/"+admin.ID+"/role", url.Values{"role": {"bogus"}}, adminCookies)
	if w.Code != http.StatusBadRequest {
		t.Errorf("role bogus = %d", w.Code)
	}

	// Non-admin accessing users POST routes.
	w = postForm(h, "/users", url.Values{"username": {"charlie"}, "role": {"user"}}, nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("unauthed users post = %d", w.Code)
	}

	// Status label and severity rank coverage.
	if severityRank("critical") != 0 || severityRank("nonexistent") <= 0 {
		t.Error("severityRank unexpected")
	}
	runningScan := tools.Scan{Status: tools.ScanRunning, Percent: 45}
	if !strings.Contains(statusLabel(runningScan), "45%") {
		t.Error("statusLabel running unexpected")
	}
	stoppedScan := tools.Scan{Status: tools.ScanStopped}
	if !strings.Contains(statusLabel(stoppedScan), "Stopped") {
		t.Error("statusLabel stopped unexpected")
	}
	failedScan := tools.Scan{Status: tools.ScanFailed}
	if statusLabel(failedScan) != "Failed" {
		t.Error("statusLabel failed unexpected")
	}
	errScan := tools.Scan{Status: tools.ScanCompleted, Error: "timeout"}
	if !strings.Contains(statusLabel(errScan), "errors") {
		t.Error("statusLabel error unexpected")
	}
	if joinInts([]int{80, 443}, ",") != "80,443" {
		t.Error("joinInts failed")
	}
	if formatDuration(-1) != "0.0s" || formatDuration(0.05) != "0.05s" || formatDuration(30) != "30.0s" || formatDuration(90) != "1m 30s" {
		t.Error("formatDuration failed")
	}
	_ = suggestedTarget(h.Service.AllowedScope)
	_ = localNetwork()

	// Direct routes: root redirect, favicon, settings page, and 404
	if w := getWithCookies(h, "/", adminCookies); w.Code != http.StatusFound {
		t.Errorf("GET / = %d", w.Code)
	}
	if w := getWithCookies(h, "/favicon.ico", nil); w.Code != http.StatusMovedPermanently {
		t.Errorf("GET /favicon.ico = %d", w.Code)
	}
	if w := getWithCookies(h, "/scans/new/quick", adminCookies); w.Code != http.StatusOK {
		t.Errorf("GET /scans/new/quick = %d", w.Code)
	}
	if w := getWithCookies(h, "/scans/new/bogus", adminCookies); w.Code != http.StatusNotFound {
		t.Errorf("GET /scans/new/bogus = %d", w.Code)
	}

	// Payload too large for parseLimitedForm
	bigReq := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9002/login", strings.NewReader("big="+strings.Repeat("a", 70000)))
	bigReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	bigReq.Header.Set("Origin", "http://127.0.0.1:9002")
	bigRec := httptest.NewRecorder()
	h.ServeHTTP(bigRec, bigReq)
	if bigRec.Code != http.StatusBadRequest {
		t.Errorf("big body = %d", bigRec.Code)
	}

	// setRetryAfter helper
	retryRec := httptest.NewRecorder()
	setRetryAfter(retryRec, 45*time.Second)
	if retryRec.Header().Get("Retry-After") != "45" {
		t.Errorf("setRetryAfter = %q", retryRec.Header().Get("Retry-After"))
	}

	// Login page with query params
	if w := getWithCookies(h, "/login?notice=signed-out&next=/scans", nil); w.Code != http.StatusOK {
		t.Errorf("login with notice = %d", w.Code)
	}
	if w := getWithCookies(h, "/users?notice=role-updated", adminCookies); w.Code != http.StatusOK || strings.Count(w.Body.String(), "Role updated.") != 1 {
		t.Errorf("users with notice = %d, role-updated count = %d", w.Code, strings.Count(w.Body.String(), "Role updated."))
	}
	if w := getWithCookies(h, "/users?notice=user-removed", adminCookies); w.Code != http.StatusOK || strings.Count(w.Body.String(), "Account removed.") != 1 {
		t.Errorf("users with removed notice = %d, user-removed count = %d", w.Code, strings.Count(w.Body.String(), "Account removed."))
	}
	if w := getWithCookies(h, "/scans?notice=password-updated", adminCookies); w.Code != http.StatusOK {
		t.Errorf("scans with notice = %d", w.Code)
	}

	// Success branch of admin change password
	w = postForm(h, "/account/password", url.Values{
		"current_password": {"admin-password-123"}, "new_password": {"admin-newpassword-999"}, "confirm_password": {"admin-newpassword-999"},
	}, adminCookies)
	if w.Code != http.StatusSeeOther {
		t.Errorf("admin change password success = %d", w.Code)
	}
	adminCookies = resultCookies(w)

	// Handler with Auth disabled helpers
	hNoAuth := newTestWeb(t, &fakeRunner{xml: scanXML})
	req := httptest.NewRequest(http.MethodGet, "/scans", nil)
	if _, ok := hNoAuth.requireAdmin(httptest.NewRecorder(), req); ok {
		t.Error("requireAdmin should fail without auth")
	}
	errRec := httptest.NewRecorder()
	h.renderAuth(errRec, nil, http.StatusOK, "nonexistent.html", authPageData{})
	if errRec.Code != http.StatusInternalServerError {
		t.Errorf("renderAuth missing template = %d", errRec.Code)
	}

	// Partials checks with search filter
	w = getWithCookies(h, "/partials/checks?q=ssh", adminCookies)
	if w.Code != http.StatusOK {
		t.Errorf("partials checks q=ssh = %d", w.Code)
	}
	w = getWithCookies(h, "/checks", adminCookies)
	if w.Code != http.StatusOK {
		t.Errorf("checks page = %d", w.Code)
	}

	// Expired reset code submission.
	alice, _ := authSvc.Store.GetUserByUsername("admin")
	_ = authSvc.Store.SaveResetCode(alice.ID, auth.HashCode("EXPIRED1"), authSvc.Now().Add(-2*time.Hour), authSvc.Now().Add(-time.Hour))
	w = postForm(h, "/reset-password", url.Values{
		"username": {"admin"}, "code": {"EXPIRED1"}, "password": {"new-password-1234"}, "confirm": {"new-password-1234"},
	}, nil)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "expired") {
		t.Errorf("expired reset code = %d, body: %s", w.Code, w.Body.String())
	}
}
