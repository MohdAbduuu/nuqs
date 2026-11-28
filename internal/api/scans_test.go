// Tests the /api/scans endpoints and the LocalOnly Host check.

package api

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nuqs-org/nuqs/internal/nmap"
	"github.com/nuqs-org/nuqs/internal/store"
	"github.com/nuqs-org/nuqs/internal/tools"
)

const telnetHostXML = `<nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="23"><state state="open"/><service name="telnet" method="probed"/></port></ports></host></nmaprun>`

// slowRunner waits until released or cancelled.
type slowRunner struct{ release chan struct{} }

func (s *slowRunner) Run(ctx context.Context, _ []string, out io.Writer) error {
	select {
	case <-s.release:
		_, err := io.WriteString(out, telnetHostXML)
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func newScansHandler(t *testing.T, r nmap.Runner) *Handler {
	t.Helper()
	h := newTestHandler(r)
	h.Scans = &tools.Scans{Service: h.Service}
	t.Cleanup(h.Scans.StopAll)
	return h
}

func do(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://127.0.0.1:9002"+path, strings.NewReader(body))
	r.Header.Set("Origin", "http://127.0.0.1:9002")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// waitDone polls until the scan isn't running any more.
func waitDone(t *testing.T, h *Handler, id string) tools.Scan {
	t.Helper()
	for range 500 {
		if s, ok := h.Scans.Get(id); ok && s.Status != tools.ScanRunning {
			return s
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("scan never finished")
	return tools.Scan{}
}

func TestStartListGetDownload(t *testing.T) {
	h := newScansHandler(t, &fakeRunner{xml: []byte(telnetHostXML)})

	w := do(h, http.MethodPost, "/api/scans", `{"name":"Lab","kind":"full","settings":{"target":"127.0.0.1"}}`)
	if w.Code != http.StatusCreated || w.Header().Get("Location") != "/scans/1" {
		t.Fatalf("start: %d %s %s", w.Code, w.Header().Get("Location"), w.Body)
	}
	waitDone(t, h, "1")

	w = do(h, http.MethodGet, "/api/scans", "")
	var list []ScanSummary
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || len(list) != 1 {
		t.Fatalf("list: %v %s", err, w.Body)
	}
	if list[0].Name != "Lab" || list[0].Counts["medium"] != 1 || strings.Contains(w.Body.String(), `"report"`) {
		t.Errorf("list should have counts and no report: %s", w.Body)
	}

	w = do(h, http.MethodGet, "/api/scans/1", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"report"`) {
		t.Errorf("get: %d %s", w.Code, w.Body)
	}
	formats := []struct{ path, ext, contentType, body string }{
		{"/api/scans/1/report", "json", "application/json", `"check_id": "telnet-open"`},
		{"/api/scans/1/report/html", "html", "text/html; charset=utf-8", "Nuqs scan report"},
		{"/api/scans/1/report/csv", "csv", "text/csv; charset=utf-8", "finding_id,severity,confidence"},
	}
	for _, format := range formats {
		w = do(h, http.MethodGet, format.path, "")
		if w.Code != http.StatusOK || w.Header().Get("Content-Type") != format.contentType ||
			!strings.Contains(w.Header().Get("Content-Disposition"), "nuqs-scan-1."+format.ext) ||
			!strings.Contains(w.Body.String(), format.body) || w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("download %s: %d %v", format.ext, w.Code, w.Header())
		}
	}
	if w := do(h, http.MethodGet, "/api/scans/1/report/pdf", ""); w.Code != http.StatusNotFound {
		t.Errorf("unknown report format: %d", w.Code)
	}
	for _, path := range []string{"/api/scans/9", "/api/scans/9/report", "/api/scans/9/events"} {
		if w := do(h, http.MethodGet, path, ""); w.Code != http.StatusNotFound {
			t.Errorf("GET %s: %d", path, w.Code)
		}
	}
}

func TestStartRejects(t *testing.T) {
	h := newScansHandler(t, &slowRunner{release: make(chan struct{})})
	const local = "http://127.0.0.1:9002"
	const jsonType = "application/json"
	scan := func(settings string) string { return `{"kind":"full","settings":` + settings + `}` }
	for _, c := range []struct {
		name, host, origin, media, body string
		want                            int
	}{
		{"foreign origin", "127.0.0.1:9002", "https://example.org", jsonType, scan(`{"target":"127.0.0.1"}`), http.StatusForbidden},
		{"localhost origin on the IP host", "127.0.0.1:9002", "http://localhost:9002", jsonType, scan(`{"target":"127.0.0.1"}`), http.StatusForbidden},
		{"foreign host", "example.org:9002", local, jsonType, scan(`{"target":"127.0.0.1"}`), http.StatusForbidden},
		{"not json", "127.0.0.1:9002", local, "text/plain", `{}`, http.StatusUnsupportedMediaType},
		{"unknown field", "127.0.0.1:9002", local, jsonType, `{"kind":"full","nmap_path":"x"}`, http.StatusBadRequest},
		{"two documents", "127.0.0.1:9002", local, jsonType, scan(`{"target":"127.0.0.1"}`) + `{}`, http.StatusBadRequest},
		{"outside scope", "127.0.0.1:9002", local, jsonType, scan(`{"target":"192.0.2.1"}`), http.StatusBadRequest},
		{"too wide", "127.0.0.1:9002", local, jsonType, scan(`{"target":"127.0.0.1/7","force":true}`), http.StatusBadRequest},
		{"blank target", "127.0.0.1:9002", local, jsonType, scan(`{"target":" "}`), http.StatusBadRequest},
		{"bad timeout", "127.0.0.1:9002", local, jsonType, scan(`{"target":"127.0.0.1","timeout":"later"}`), http.StatusBadRequest},
		{"negative timeout", "127.0.0.1:9002", local, jsonType, scan(`{"target":"127.0.0.1","timeout":"-5s"}`), http.StatusBadRequest},
		{"too many workers", "127.0.0.1:9002", local, jsonType, scan(`{"target":"127.0.0.1","workers":200}`), http.StatusBadRequest},
		{"ports as a flag", "127.0.0.1:9002", local, jsonType, scan(`{"target":"127.0.0.1","ports":"-oN"}`), http.StatusBadRequest},
		{"no kind", "127.0.0.1:9002", local, jsonType, `{"settings":{"target":"127.0.0.1"}}`, http.StatusBadRequest},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "http://"+c.host+"/api/scans", strings.NewReader(c.body))
			r.Header.Set("Origin", c.origin)
			r.Header.Set("Content-Type", c.media)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != c.want {
				t.Errorf("got %d, want %d (%s)", w.Code, c.want, w.Body)
			}
		})
	}

	if w := do(h, http.MethodPost, "/api/scans", `{"kind":"full","settings":{"target":"127.0.0.1"}}`); w.Code != http.StatusCreated {
		t.Fatalf("first: %d", w.Code)
	}
	if w := do(h, http.MethodPost, "/api/scans", `{"kind":"full","settings":{"target":"127.0.0.1"}}`); w.Code != http.StatusConflict {
		t.Errorf("second while running: %d", w.Code)
	}

	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9002/api/scans/1/stop", nil)
	r.Header.Set("Origin", "https://example.org")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("stop from another site: %d", w.Code)
	}
	if w := do(h, http.MethodPost, "/api/scans/9/stop", ""); w.Code != http.StatusNotFound {
		t.Errorf("stop unknown: %d", w.Code)
	}
	if w := do(h, http.MethodPost, "/api/scans/1/stop", ""); w.Code != http.StatusNoContent {
		t.Errorf("stop: %d", w.Code)
	}
	if s := waitDone(t, h, "1"); s.Status != tools.ScanStopped {
		t.Errorf("status %s", s.Status)
	}
}

func TestDeleteScanEndpoint(t *testing.T) {
	runner := &slowRunner{release: make(chan struct{})}
	h := newScansHandler(t, runner)
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	h.Scans.Store = st

	// Cross-origin delete is forbidden.
	r := httptest.NewRequest(http.MethodDelete, "http://127.0.0.1:9002/api/scans/1", nil)
	r.Header.Set("Origin", "https://example.org")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("foreign origin delete: got %d, want 403", w.Code)
	}

	// Missing scan returns 404.
	if w := do(h, http.MethodDelete, "/api/scans/99", ""); w.Code != http.StatusNotFound {
		t.Fatalf("delete unknown: got %d, want 404", w.Code)
	}

	// Start a scan: deleting while running returns 409 Conflict.
	if w := do(h, http.MethodPost, "/api/scans", `{"name":"To delete","kind":"full","settings":{"target":"127.0.0.1"}}`); w.Code != http.StatusCreated {
		t.Fatalf("start: %d %s", w.Code, w.Body)
	}
	if w := do(h, http.MethodDelete, "/api/scans/1", ""); w.Code != http.StatusConflict {
		t.Fatalf("delete running: got %d, want 409 (%s)", w.Code, w.Body)
	}

	// Finish scan, then delete returns 204 and scan disappears from API and store.
	close(runner.release)
	waitDone(t, h, "1")
	if w := do(h, http.MethodDelete, "/api/scans/1", ""); w.Code != http.StatusNoContent {
		t.Fatalf("delete finished: got %d, want 204 (%s)", w.Code, w.Body)
	}
	if w := do(h, http.MethodGet, "/api/scans/1", ""); w.Code != http.StatusNotFound {
		t.Errorf("deleted scan GET: got %d, want 404", w.Code)
	}
	if w := do(h, http.MethodDelete, "/api/scans/1", ""); w.Code != http.StatusNotFound {
		t.Errorf("delete twice: got %d, want 404", w.Code)
	}

	// Closed store returns 500.
	st.Close()
	if w := do(h, http.MethodDelete, "/api/scans/1", ""); w.Code != http.StatusInternalServerError {
		t.Errorf("delete with closed store: got %d, want 500", w.Code)
	}
}

func TestScanEventsStream(t *testing.T) {
	runner := &slowRunner{release: make(chan struct{})}
	h := newScansHandler(t, runner)
	srv := httptest.NewServer(h)
	defer srv.Close()
	h.Addr = strings.TrimPrefix(srv.URL, "http://")

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/scans", strings.NewReader(`{"kind":"quick","settings":{"target":"127.0.0.1"}}`))
	req.Header.Set("Origin", srv.URL)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("start: %v %v", err, resp)
	}
	resp.Body.Close()

	resp, err = http.Get(srv.URL + "/api/scans/1/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("content type %q", resp.Header.Get("Content-Type"))
	}
	lines := bufio.NewScanner(resp.Body)
	var got []Progress
	for lines.Scan() {
		line := lines.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var p Progress
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &p); err != nil {
			t.Fatal(err)
		}
		got = append(got, p)
		if len(got) == 1 {
			if p.Status != tools.ScanRunning {
				t.Errorf("first update should be running, got %+v", p)
			}
			close(runner.release) // let the scan finish
		}
	}
	last := got[len(got)-1]
	if last.Status != tools.ScanCompleted || last.ChecksDone != 1 || last.HostsFound != 1 || last.Percent != 100 {
		t.Errorf("last update %+v", last)
	}
}

func TestLocalOnly(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	h := LocalOnly("127.0.0.1:9002", ok)
	for host, want := range map[string]int{
		"127.0.0.1:9002":      http.StatusTeapot,
		"localhost:9002":      http.StatusTeapot,
		"evil.example:9002":   http.StatusForbidden,
		"127.0.0.1:9003":      http.StatusForbidden,
		"localhost.evil:9002": http.StatusForbidden,
	} {
		r := httptest.NewRequest(http.MethodGet, "http://"+host+"/scans", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("Host %s: got %d, want %d", host, w.Code, want)
		}
	}
}
