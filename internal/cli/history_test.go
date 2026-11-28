// Tests for saving scans from the CLI, "nuqs history" and "nuqs show".

package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nuqs-org/nuqs/internal/engine"
	"github.com/nuqs-org/nuqs/internal/store"
)

func TestScanIsSavedAndShownAgain(t *testing.T) {
	app, out, errOut := newApp(t, &fakeRunner{})
	if code := app.Run(context.Background(), []string{"scan", "192.168.1.0/30", "-p", "23"}); code != ExitOK {
		t.Fatalf("exit %d:\n%s", code, errOut)
	}
	if !strings.Contains(errOut.String(), "Saved as scan 1. See it again with: nuqs show 1") {
		t.Errorf("stderr should say where the scan went:\n%s", errOut)
	}
	scanned := out.String()

	out.Reset()
	if code := app.Run(context.Background(), []string{"show", "1"}); code != ExitOK {
		t.Fatalf("show exit %d:\n%s", code, errOut)
	}
	if out.String() != scanned {
		t.Errorf("show should print what scan printed:\n got %s\nwant %s", out, scanned)
	}

	out.Reset()
	if code := app.Run(context.Background(), []string{"show", "--json", "1"}); code != ExitOK {
		t.Fatalf("show --json exit %d", code)
	}
	var rep engine.Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil || len(rep.Findings) != 1 {
		t.Errorf("show --json: %v, %+v", err, rep.Findings)
	}

	out.Reset()
	if code := app.Run(context.Background(), []string{"history"}); code != ExitOK {
		t.Fatalf("history exit %d", code)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "ID") || !strings.HasPrefix(lines[1], "1 ") ||
		!strings.Contains(lines[1], "completed") || !strings.HasSuffix(lines[1], "192.168.1.0/30") {
		t.Errorf("history:\n%s", out)
	}
}

func TestHistoryNewestFirstAndLimit(t *testing.T) {
	app, out, _ := newApp(t, &fakeRunner{})
	for _, target := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		if code := app.Run(context.Background(), []string{"scan", target}); code != ExitOK {
			t.Fatal(code)
		}
	}
	out.Reset()
	app.Run(context.Background(), []string{"history", "-n", "2"})
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 || !strings.HasSuffix(lines[1], "10.0.0.3") || !strings.HasSuffix(lines[2], "10.0.0.2") {
		t.Errorf("history -n 2:\n%s", out)
	}
}

func TestNoSave(t *testing.T) {
	app, out, errOut := newApp(t, &fakeRunner{})
	if code := app.Run(context.Background(), []string{"scan", "--no-save", "10.0.0.1"}); code != ExitOK {
		t.Fatal(code)
	}
	if strings.Contains(errOut.String(), "Saved") {
		t.Errorf("--no-save still saved:\n%s", errOut)
	}
	out.Reset()
	app.Run(context.Background(), []string{"history"})
	if !strings.Contains(out.String(), "No saved scans yet") {
		t.Errorf("history after --no-save:\n%s", out)
	}
}

func TestStoppedScanIsSavedAsStopped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	app, out, _ := newApp(t, &fakeRunner{})
	app.Run(ctx, []string{"scan", "10.0.0.1"})
	out.Reset()
	app.Run(context.Background(), []string{"history"})
	if !strings.Contains(out.String(), "stopped") {
		t.Errorf("history:\n%s", out)
	}
}

func TestScanStillWorksWhenSavingFails(t *testing.T) {
	app, out, errOut := newApp(t, &fakeRunner{})
	file := filepath.Join(t.TempDir(), "file")
	os.WriteFile(file, nil, 0o600)
	app.DataDir = filepath.Join(file, "data") // can't make a folder inside a file
	if code := app.Run(context.Background(), []string{"scan", "10.0.0.1"}); code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out.String(), "telnet-open") || !strings.Contains(errOut.String(), "warning: couldn't save this scan") {
		t.Errorf("stdout:\n%s\nstderr:\n%s", out, errOut)
	}
	for _, args := range [][]string{{"history"}, {"show", "1"}} {
		if code := app.Run(context.Background(), args); code != ExitError {
			t.Errorf("%v with a broken data folder: exit %d", args, code)
		}
	}
}

func TestHistoryAndShowUsage(t *testing.T) {
	app, _, errOut := newApp(t, &fakeRunner{})
	cases := []struct {
		args []string
		code int
	}{
		{[]string{"history", "extra"}, ExitUsage},
		{[]string{"history", "-n", "-1"}, ExitUsage},
		{[]string{"history", "--bogus"}, ExitUsage},
		{[]string{"history", "-h"}, ExitOK},
		{[]string{"show"}, ExitUsage},
		{[]string{"show", "abc"}, ExitUsage},
		{[]string{"show", "1", "2"}, ExitUsage},
		{[]string{"show", "--bogus"}, ExitUsage},
		{[]string{"show", "-h"}, ExitOK},
		{[]string{"show", "7"}, ExitError}, // nothing saved yet
	}
	for _, c := range cases {
		if code := app.Run(context.Background(), c.args); code != c.code {
			t.Errorf("%v: exit %d, want %d\n%s", c.args, code, c.code, errOut)
		}
	}
}

func TestShowRunWithoutReport(t *testing.T) {
	app, _, errOut := newApp(t, &fakeRunner{})
	st, err := store.Open(app.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	r := store.Run{Name: "broken", Kind: "quick", Targets: []string{"10.0.0.1"}, Status: store.Failed, Error: "Nmap isn't installed", Started: time.Now()}
	if err := st.Save(&r); err != nil {
		t.Fatal(err)
	}
	st.Close()
	if code := app.Run(context.Background(), []string{"show", "1"}); code != ExitError || !strings.Contains(errOut.String(), "Scan 1 failed without a report: Nmap isn't installed") {
		t.Errorf("exit %d:\n%s", code, errOut)
	}
}

func TestServeShowsScansSavedByTheCLI(t *testing.T) {
	app, out, errOut := newApp(t, &fakeRunner{})
	app.PBKDF2Iterations = 1000
	if code := app.Run(context.Background(), []string{"scan", "10.0.0.1"}); code != ExitOK {
		t.Fatal(code)
	}
	out.Reset()
	app.LookPath = func(file string) (string, error) { return "/usr/bin/" + file, nil }
	app.ListenAndServe = func(_ context.Context, _ string, handler http.Handler) error {
		setupCode := extractIndentedCode(t, out.String())
		form := url.Values{"code": {setupCode}, "username": {"admin"}, "password": {"admin-password-1"}, "confirm": {"admin-password-1"}}
		setupReq := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9124/setup", strings.NewReader(form.Encode()))
		setupReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		setupReq.Header.Set("Origin", "http://127.0.0.1:9124")
		setupRec := httptest.NewRecorder()
		handler.ServeHTTP(setupRec, setupReq)
		cookies := resultCookies(setupRec)
		if setupRec.Code != http.StatusSeeOther || len(cookies) == 0 {
			t.Fatalf("POST /setup: %d %s", setupRec.Code, setupRec.Body.String())
		}
		for path, want := range map[string]string{"/scans": "10.0.0.1", "/scans/1": "Command line scan", "/api/scans/1": `"status":"completed"`} {
			req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9124"+path, nil)
			req.AddCookie(cookies[0])
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), want) {
				t.Errorf("GET %s: %d, missing %q", path, rec.Code, want)
			}
		}
		return nil
	}
	if code := app.Run(context.Background(), []string{"serve", "--addr", "127.0.0.1:9124"}); code != ExitOK {
		t.Fatalf("serve exit %d:\n%s", code, errOut)
	}
}

func TestServeFailsWithoutItsStore(t *testing.T) {
	app, _, errOut := newApp(t, &fakeRunner{})
	app.LookPath = func(file string) (string, error) { return "/usr/bin/" + file, nil }
	file := filepath.Join(t.TempDir(), "file")
	os.WriteFile(file, nil, 0o600)
	app.DataDir = filepath.Join(file, "data")
	if code := app.Run(context.Background(), []string{"serve"}); code != ExitError || !strings.Contains(errOut.String(), "error:") {
		t.Errorf("exit %d:\n%s", code, errOut)
	}
}

func TestDeleteCommand(t *testing.T) {
	app, out, errOut := newApp(t, &fakeRunner{})
	ctx := context.Background()
	for _, target := range []string{"10.0.0.1", "10.0.0.2"} {
		if code := app.Run(ctx, []string{"scan", target}); code != ExitOK {
			t.Fatalf("scan %s exit %d:\n%s", target, code, errOut)
		}
	}

	// Save a running scan directly to verify CLI refuses to delete it.
	st, err := store.Open(app.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	running := store.Run{Name: "still running", Kind: "quick", Targets: []string{"127.0.0.1"}, Started: time.Now()}
	if err := st.Create(&running); err != nil {
		t.Fatal(err)
	}
	st.Close()

	errOut.Reset()
	if code := app.Run(ctx, []string{"delete", "3"}); code != ExitError || !strings.Contains(errOut.String(), "still running") {
		t.Fatalf("delete running: exit %d\n%s", code, errOut)
	}

	out.Reset()
	errOut.Reset()
	if code := app.Run(ctx, []string{"delete", "1"}); code != ExitOK || !strings.Contains(out.String(), "Deleted scan 1.") {
		t.Fatalf("delete 1: exit %d\nout: %s\nerr: %s", code, out, errOut)
	}
	if code := app.Run(ctx, []string{"show", "1"}); code != ExitError {
		t.Errorf("deleted scan still shown: exit %d", code)
	}

	out.Reset()
	if code := app.Run(ctx, []string{"history"}); code != ExitOK {
		t.Fatalf("history exit %d", code)
	}
	if strings.Contains(out.String(), "10.0.0.1") || !strings.Contains(out.String(), "10.0.0.2") {
		t.Errorf("history after delete:\n%s", out)
	}

	for _, c := range []struct {
		args []string
		code int
	}{
		{[]string{"delete"}, ExitUsage},
		{[]string{"delete", "abc"}, ExitUsage},
		{[]string{"delete", "0"}, ExitUsage},
		{[]string{"delete", "-1"}, ExitUsage},
		{[]string{"delete", "1", "2"}, ExitUsage},
		{[]string{"delete", "--bogus"}, ExitUsage},
		{[]string{"delete", "-h"}, ExitOK},
		{[]string{"delete", "99"}, ExitError},
	} {
		if code := app.Run(ctx, c.args); code != c.code {
			t.Errorf("%v: exit %d, want %d", c.args, code, c.code)
		}
	}

	// Broken data folder returns ExitError.
	file := filepath.Join(t.TempDir(), "file")
	os.WriteFile(file, nil, 0o600)
	app.DataDir = filepath.Join(file, "data")
	if code := app.Run(ctx, []string{"delete", "2"}); code != ExitError {
		t.Errorf("broken data dir: exit %d, want ExitError", code)
	}
}

func TestScanRetention(t *testing.T) {
	ctx := context.Background()

	t.Run("CLI --keep deletes oldest after save", func(t *testing.T) {
		app, out, errOut := newApp(t, &fakeRunner{})
		for _, target := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
			if code := app.Run(ctx, []string{"scan", "--keep", "2", target}); code != ExitOK {
				t.Fatalf("scan %s exit %d:\n%s", target, code, errOut)
			}
		}
		if code := app.Run(ctx, []string{"show", "1"}); code != ExitError {
			t.Errorf("pruned scan 1 still exists: exit %d", code)
		}
		out.Reset()
		if code := app.Run(ctx, []string{"history", "-n", "0"}); code != ExitOK {
			t.Fatalf("history exit %d", code)
		}
		if strings.Contains(out.String(), "10.0.0.1") || !strings.Contains(out.String(), "10.0.0.2") || !strings.Contains(out.String(), "10.0.0.3") {
			t.Errorf("history after --keep 2:\n%s", out)
		}

		// --no-save does not prune existing scans.
		if code := app.Run(ctx, []string{"scan", "--no-save", "--keep", "1", "10.0.0.4"}); code != ExitOK {
			t.Fatalf("--no-save exit %d", code)
		}
		out.Reset()
		app.Run(ctx, []string{"history", "-n", "0"})
		if !strings.Contains(out.String(), "10.0.0.2") || !strings.Contains(out.String(), "10.0.0.3") {
			t.Errorf("--no-save should not prune existing scans:\n%s", out)
		}

		// --keep 1 prunes before sinceLastScan so no broken diff suggestion is printed.
		errOut.Reset()
		if code := app.Run(ctx, []string{"scan", "--keep", "1", "10.0.0.3"}); code != ExitOK {
			t.Fatalf("--keep 1 exit %d:\n%s", code, errOut)
		}
		if strings.Contains(errOut.String(), "nuqs diff") {
			t.Errorf("should not suggest diff after pruning the previous scan:\n%s", errOut)
		}
	})

	t.Run("NUQS_KEEP_SCANS env and 0 keeps all", func(t *testing.T) {
		t.Setenv("NUQS_KEEP_SCANS", "2")
		app, out, errOut := newApp(t, &fakeRunner{})
		for _, target := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
			if code := app.Run(ctx, []string{"scan", target}); code != ExitOK {
				t.Fatalf("scan %s exit %d:\n%s", target, code, errOut)
			}
		}
		out.Reset()
		app.Run(ctx, []string{"history", "-n", "0"})
		if strings.Contains(out.String(), "10.0.0.1") || !strings.Contains(out.String(), "10.0.0.3") {
			t.Errorf("NUQS_KEEP_SCANS=2:\n%s", out)
		}

		// --keep 0 after the target still overrides NUQS_KEEP_SCANS and keeps everything going forward.
		if code := app.Run(ctx, []string{"scan", "10.0.0.4", "--keep", "0"}); code != ExitOK {
			t.Fatalf("--keep 0 exit %d:\n%s", code, errOut)
		}
		out.Reset()
		app.Run(ctx, []string{"history", "-n", "0"})
		for _, want := range []string{"10.0.0.2", "10.0.0.3", "10.0.0.4"} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("--keep 0 dropped %s:\n%s", want, out)
			}
		}

		// NUQS_KEEP_SCANS=0 keeps all.
		t.Setenv("NUQS_KEEP_SCANS", "0")
		if code := app.Run(ctx, []string{"scan", "10.0.0.5"}); code != ExitOK {
			t.Fatalf("NUQS_KEEP_SCANS=0 exit %d", code)
		}
		out.Reset()
		app.Run(ctx, []string{"history", "-n", "0"})
		for _, want := range []string{"10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("NUQS_KEEP_SCANS=0 dropped %s:\n%s", want, out)
			}
		}
	})

	t.Run("invalid keep values rejected", func(t *testing.T) {
		app, _, _ := newApp(t, &fakeRunner{})
		if code := app.Run(ctx, []string{"scan", "--keep", "-1", "10.0.0.1"}); code != ExitUsage {
			t.Errorf("scan --keep -1: exit %d, want ExitUsage", code)
		}
		if code := app.Run(ctx, []string{"serve", "--keep", "-1"}); code != ExitUsage {
			t.Errorf("serve --keep -1: exit %d, want ExitUsage", code)
		}
		for _, bad := range []string{"abc", "-2"} {
			t.Setenv("NUQS_KEEP_SCANS", bad)
			if code := app.Run(ctx, []string{"scan", "10.0.0.1"}); code != ExitUsage {
				t.Errorf("scan with NUQS_KEEP_SCANS=%q: exit %d, want ExitUsage", bad, code)
			}
			if code := app.Run(ctx, []string{"serve"}); code != ExitUsage {
				t.Errorf("serve with NUQS_KEEP_SCANS=%q: exit %d, want ExitUsage", bad, code)
			}
			// Help still works even if the env var is invalid.
			if code := app.Run(ctx, []string{"scan", "-h"}); code != ExitOK {
				t.Errorf("scan -h with bad env: exit %d, want ExitOK", code)
			}
			if code := app.Run(ctx, []string{"serve", "-h"}); code != ExitOK {
				t.Errorf("serve -h with bad env: exit %d, want ExitOK", code)
			}
		}
	})

	t.Run("serve --keep prunes oldest scans after save", func(t *testing.T) {
		app, out, errOut := newApp(t, &fakeRunner{})
		app.PBKDF2Iterations = 1000
		app.LookPath = func(file string) (string, error) { return "/usr/bin/" + file, nil }
		app.ListenAndServe = func(_ context.Context, _ string, handler http.Handler) error {
			const base = "http://127.0.0.1:9125"
			setupCode := extractIndentedCode(t, out.String())
			form := url.Values{"code": {setupCode}, "username": {"admin"}, "password": {"admin-password-1"}, "confirm": {"admin-password-1"}}
			setupReq := httptest.NewRequest(http.MethodPost, base+"/setup", strings.NewReader(form.Encode()))
			setupReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			setupReq.Header.Set("Origin", base)
			setupRec := httptest.NewRecorder()
			handler.ServeHTTP(setupRec, setupReq)
			cookie := resultCookies(setupRec)[0]

			startAndWait := func(name string) string {
				body := `{"name":"` + name + `","kind":"quick","settings":{"target":"127.0.0.1"}}`
				req := httptest.NewRequest(http.MethodPost, base+"/api/scans", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Origin", base)
				req.AddCookie(cookie)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != http.StatusCreated {
					t.Fatalf("POST /api/scans (%s): %d %s", name, rec.Code, rec.Body.String())
				}
				var created struct{ ID string }
				if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
					t.Fatal(err)
				}
				deadline := time.Now().Add(5 * time.Second)
				for time.Now().Before(deadline) {
					getReq := httptest.NewRequest(http.MethodGet, base+"/api/scans/"+created.ID, nil)
					getReq.AddCookie(cookie)
					getRec := httptest.NewRecorder()
					handler.ServeHTTP(getRec, getReq)
					var state struct{ Status string }
					if json.Unmarshal(getRec.Body.Bytes(), &state) == nil && state.Status != "running" {
						return created.ID
					}
					time.Sleep(10 * time.Millisecond)
				}
				t.Fatalf("scan %s did not finish", created.ID)
				return ""
			}

			id1 := startAndWait("first")
			id2 := startAndWait("second")
			id3 := startAndWait("third")

			getReq := httptest.NewRequest(http.MethodGet, base+"/api/scans/"+id1, nil)
			getReq.AddCookie(cookie)
			getRec := httptest.NewRecorder()
			handler.ServeHTTP(getRec, getReq)
			if getRec.Code != http.StatusNotFound {
				t.Errorf("pruned scan %s: GET status %d, want 404", id1, getRec.Code)
			}
			for _, id := range []string{id2, id3} {
				req := httptest.NewRequest(http.MethodGet, base+"/api/scans/"+id, nil)
				req.AddCookie(cookie)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					t.Errorf("kept scan %s: GET status %d, want 200", id, rec.Code)
				}
			}
			return nil
		}
		if code := app.Run(ctx, []string{"serve", "--addr", "127.0.0.1:9125", "--keep", "2"}); code != ExitOK {
			t.Fatalf("serve exit %d:\n%s", code, errOut)
		}
	})
}
