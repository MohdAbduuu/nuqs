// Tests first-run setup code output, authenticated routes and "nuqs user reset-password".

package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestServeSetupCodeAndAuthenticatedRoutes(t *testing.T) {
	dataDir := t.TempDir()
	r := &fakeRunner{}
	app, out, errOut := newApp(t, r)
	app.DataDir = dataDir
	app.PBKDF2Iterations = 1000
	app.LookPath = func(file string) (string, error) { return "/usr/bin/" + file, nil }

	app.ListenAndServe = func(_ context.Context, _ string, servedHandler http.Handler) error {
		stdout := out.String()
		if !strings.Contains(stdout, "First-time setup required") || !strings.Contains(stdout, "http://127.0.0.1:9123/setup") {
			t.Fatalf("expected setup code instructions in stdout:\n%s", stdout)
		}
		setupCode := extractIndentedCode(t, stdout)

		// Before setup: /scans redirects to /setup, /api/status returns 401.
		rec := httptest.NewRecorder()
		servedHandler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9123/scans", nil))
		if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/setup" {
			t.Fatalf("uninitialized /scans: %d %q", rec.Code, rec.Header().Get("Location"))
		}
		rec = httptest.NewRecorder()
		servedHandler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9123/api/status", nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("uninitialized /api/status: %d", rec.Code)
		}

		// Complete setup through the wired handler.
		form := url.Values{"code": {setupCode}, "username": {"admin"}, "password": {"admin-secret-123"}, "confirm": {"admin-secret-123"}}
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9123/setup", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "http://127.0.0.1:9123")
		rec = httptest.NewRecorder()
		servedHandler.ServeHTTP(rec, req)
		setupCookies := resultCookies(rec)
		if rec.Code != http.StatusSeeOther || len(setupCookies) == 0 {
			t.Fatalf("POST /setup: %d %s", rec.Code, rec.Body.String())
		}
		sessionCookie := setupCookies[0]

		// Authenticated requests reach all routes.
		for _, path := range []string{"/scans", "/scans/new", "/checks", "/users", "/api/status", "/api/checks", "/api/scans", "/api/users", "/partials/checks", "/static/nuqs.css"} {
			req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9123"+path, nil)
			req.AddCookie(sessionCookie)
			rec := httptest.NewRecorder()
			servedHandler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("authenticated GET %s: got %d, want 200", path, rec.Code)
			}
		}

		// Run "nuqs user reset-password" from CLI while the server is still running
		// and verify it revokes the live server's session via SQLite WAL.
		cliApp, cliOut, cliErr := newApp(t, r)
		cliApp.DataDir = dataDir
		cliApp.PBKDF2Iterations = 1000
		if code := cliApp.Run(context.Background(), []string{"user", "reset-password", "admin"}); code != ExitOK {
			t.Fatalf("user reset-password: %d %s", code, cliErr)
		}
		resetCode := extractIndentedCode(t, cliOut.String())
		if resetCode == "" {
			t.Fatalf("missing reset code:\n%s", cliOut.String())
		}
		// Previous session is immediately revoked on the running server handler.
		req = httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9123/api/status", nil)
		req.AddCookie(sessionCookie)
		rec = httptest.NewRecorder()
		servedHandler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("revoked session should fail immediately, got %d", rec.Code)
		}
		// Reset password completes via /reset-password using the CLI code.
		resetForm := url.Values{"username": {"admin"}, "code": {resetCode}, "password": {"new-password-456"}, "confirm": {"new-password-456"}}
		req = httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9123/reset-password", strings.NewReader(resetForm.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "http://127.0.0.1:9123")
		rec = httptest.NewRecorder()
		servedHandler.ServeHTTP(rec, req)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login?notice=password-reset" {
			t.Fatalf("POST /reset-password: %d %q %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
		}
		return nil
	}

	code := app.Run(context.Background(), []string{"serve", "--addr", "127.0.0.1:9123"})
	if code != ExitOK {
		t.Fatalf("exit %d, stderr:\n%s", code, errOut)
	}

	// Restarting nuqs serve with existing users must NOT print a setup code.
	app2, out2, errOut2 := newApp(t, r)
	app2.DataDir = dataDir
	app2.PBKDF2Iterations = 1000
	app2.LookPath = func(file string) (string, error) { return "/usr/bin/" + file, nil }
	app2.ListenAndServe = func(context.Context, string, http.Handler) error { return nil }
	if code := app2.Run(context.Background(), []string{"serve", "--addr", "127.0.0.1:9123"}); code != ExitOK {
		t.Fatalf("restart serve: %d %s", code, errOut2)
	}
	if strings.Contains(out2.String(), "setup code") {
		t.Fatalf("should not print setup code after setup:\n%s", out2.String())
	}
}

func TestUserCommandUsageAndErrors(t *testing.T) {
	for _, c := range []struct {
		args []string
		want int
	}{
		{[]string{"user"}, ExitUsage},
		{[]string{"user", "-h"}, ExitOK},
		{[]string{"user", "bogus"}, ExitUsage},
		{[]string{"user", "reset-password", "-h"}, ExitOK},
		{[]string{"user", "reset-password"}, ExitUsage},
		{[]string{"user", "reset-password", "--bad-flag", "bob"}, ExitUsage},
		{[]string{"user", "reset-password", "nobody"}, ExitError},
	} {
		app, _, _ := newApp(t, &fakeRunner{})
		if got := app.Run(context.Background(), c.args); got != c.want {
			t.Errorf("%v: exit %d, want %d", c.args, got, c.want)
		}
	}
}

func extractIndentedCode(t *testing.T, output string) string {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "  ") {
			return strings.TrimSpace(line)
		}
	}
	t.Fatalf("could not find indented one-time code in:\n%s", output)
	return ""
}

func resultCookies(w *httptest.ResponseRecorder) []*http.Cookie {
	resp := w.Result()
	defer resp.Body.Close()
	return resp.Cookies()
}
