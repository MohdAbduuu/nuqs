// Tests API authentication, admin vs user RBAC, scan attribution and /api/users management.

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nuqs-org/nuqs/internal/auth"
	"github.com/nuqs-org/nuqs/internal/store"
)

func newAuthedScansHandler(t *testing.T) (*Handler, string, string) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	authSvc := auth.NewService(st)
	authSvc.Iterations = 1000
	code, _, err := authSvc.EnsureSetupCode()
	if err != nil {
		t.Fatal(err)
	}
	_, adminTok, _, err := authSvc.CompleteSetup("127.0.0.1", code, "alice", "alice-password-1")
	if err != nil {
		t.Fatal(err)
	}
	_, userInvite, err := authSvc.CreateUser("bob", store.RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := authSvc.CompletePasswordReset("127.0.0.1", "bob", userInvite.Code, "bob-password-123"); err != nil {
		t.Fatal(err)
	}
	_, userTok, _, err := authSvc.Login("127.0.0.1", "bob", "bob-password-123")
	if err != nil {
		t.Fatal(err)
	}

	h := newScansHandler(t, &fakeRunner{xml: []byte(telnetHostXML)})
	h.Auth = authSvc
	return h, adminTok, userTok
}

func doAuthed(h http.Handler, method, url, origin, token, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, url, strings.NewReader(body))
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		r.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: token})
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestAPIRBACAndStartedBy(t *testing.T) {
	h, adminTok, userTok := newAuthedScansHandler(t)
	const base = "http://127.0.0.1:9002"
	scanBody := `{"name":"Lab check","kind":"full","settings":{"target":"127.0.0.1"}}`

	// Unauthenticated requests are rejected with 401.
	if w := doAuthed(h, http.MethodGet, base+"/api/status", "", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauth status = %d, want 401", w.Code)
	}
	if w := doAuthed(h, http.MethodPost, base+"/api/scans", base, "", scanBody); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauth start = %d, want 401", w.Code)
	}

	// Regular user can read status and start scans, and scan records started_by="bob".
	if w := doAuthed(h, http.MethodGet, base+"/api/status", "", userTok, ""); w.Code != http.StatusOK {
		t.Fatalf("user status = %d", w.Code)
	}
	w := doAuthed(h, http.MethodPost, base+"/api/scans", base, userTok, scanBody)
	if w.Code != http.StatusCreated {
		t.Fatalf("user start = %d %s", w.Code, w.Body.String())
	}
	var created ScanSummary
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.StartedBy != "bob" {
		t.Errorf("StartedBy = %q, want bob", created.StartedBy)
	}
	waitDone(t, h, created.ID)

	// Spoofing started_by in JSON is rejected by DisallowUnknownFields.
	if w := doAuthed(h, http.MethodPost, base+"/api/scans", base, userTok, `{"started_by":"alice","kind":"full","settings":{"target":"127.0.0.1"}}`); w.Code != http.StatusBadRequest {
		t.Errorf("spoofed started_by = %d, want 400", w.Code)
	}
	// Regular user cannot manage users.
	if w := doAuthed(h, http.MethodGet, base+"/api/users", "", userTok, ""); w.Code != http.StatusForbidden {
		t.Errorf("user /api/users = %d, want 403", w.Code)
	}

	// Admin manages users via /api/users.
	w = doAuthed(h, http.MethodGet, base+"/api/users", "", adminTok, "")
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "pbkdf2") {
		t.Fatalf("admin list users: %d %s", w.Code, w.Body.String())
	}
	w = doAuthed(h, http.MethodPost, base+"/api/users", base, adminTok, `{"username":"dave","role":"user"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create user = %d %s", w.Code, w.Body.String())
	}
	var added createUserResponse
	if err := json.Unmarshal(w.Body.Bytes(), &added); err != nil || added.ResetCode == "" || added.User.Username != "dave" {
		t.Fatalf("unexpected create response: %+v %v", added, err)
	}
	// Promote role to admin.
	w = doAuthed(h, http.MethodPatch, base+"/api/users/"+added.User.ID, base, adminTok, `{"role":"admin"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"admin"`) {
		t.Fatalf("patch role = %d %s", w.Code, w.Body.String())
	}
	// Reset password.
	w = doAuthed(h, http.MethodPost, base+"/api/users/"+added.User.ID+"/reset-password", base, adminTok, "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"reset_code"`) {
		t.Fatalf("reset password = %d %s", w.Code, w.Body.String())
	}
	// Cannot delete self.
	alice, _ := h.Auth.Store.GetUserByUsername("alice")
	if w := doAuthed(h, http.MethodDelete, base+"/api/users/"+alice.ID, base, adminTok, ""); w.Code != http.StatusBadRequest {
		t.Errorf("self delete = %d, want 400", w.Code)
	}
	// Cannot demote last active admin (dave is pending password).
	if w := doAuthed(h, http.MethodPatch, base+"/api/users/"+alice.ID, base, adminTok, `{"role":"user"}`); w.Code != http.StatusConflict {
		t.Errorf("demote last admin = %d, want 409", w.Code)
	}
	// Foreign origin rejected on user mutations.
	if w := doAuthed(h, http.MethodDelete, base+"/api/users/"+added.User.ID, "http://evil.example", adminTok, ""); w.Code != http.StatusForbidden {
		t.Errorf("foreign origin delete = %d, want 403", w.Code)
	}
	// Delete teammate succeeds.
	if w := doAuthed(h, http.MethodDelete, base+"/api/users/"+added.User.ID, base, adminTok, ""); w.Code != http.StatusNoContent {
		t.Errorf("delete teammate = %d, want 204", w.Code)
	}
	// Error status branches on /api/users.
	if w := doAuthed(h, http.MethodPost, base+"/api/users", base, adminTok, `{"username":"x","role":"user"}`); w.Code != http.StatusBadRequest {
		t.Errorf("short username = %d, want 400", w.Code)
	}
	if w := doAuthed(h, http.MethodPost, base+"/api/users", base, adminTok, `not-json`); w.Code != http.StatusBadRequest {
		t.Errorf("bad json = %d, want 400", w.Code)
	}
	if w := doAuthed(h, http.MethodPatch, base+"/api/users/missing", base, adminTok, `{"role":"user"}`); w.Code != http.StatusNotFound {
		t.Errorf("patch missing = %d, want 404", w.Code)
	}
	if w := doAuthed(h, http.MethodPatch, base+"/api/users/"+alice.ID, base, adminTok, `{"role":"bogus"}`); w.Code != http.StatusBadRequest {
		t.Errorf("patch bad role = %d, want 400", w.Code)
	}
	if w := doAuthed(h, http.MethodPost, base+"/api/users/missing/reset-password", base, adminTok, ""); w.Code != http.StatusNotFound {
		t.Errorf("reset missing = %d, want 404", w.Code)
	}
	if w := doAuthed(h, http.MethodDelete, base+"/api/users/missing", base, adminTok, ""); w.Code != http.StatusNotFound {
		t.Errorf("delete missing = %d, want 404", w.Code)
	}
}
