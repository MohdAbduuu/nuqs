// Tests the HTTP directory listing check against Apache, nginx, Python and clean servers.

package httpdirlisting

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nuqs-org/nuqs/internal/check"
	"github.com/nuqs-org/nuqs/internal/model"
)

func targetFor(t *testing.T, raw string, svc model.Service) check.Target {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	host, port, _ := net.SplitHostPort(u.Host)
	svc.Port, _ = strconv.Atoi(port)
	svc.Protocol = "tcp"
	if svc.Name == "" {
		svc.Name = "http"
	}
	return check.Target{Host: host, Service: svc}
}

func TestInfo(t *testing.T) {
	in := Check{}.Info()
	if err := check.Validate([]check.Check{Check{}}); err != nil {
		t.Fatal(err)
	}
	if in.ID != "http-directory-listing" || in.Severity != model.Medium {
		t.Fatalf("unexpected info: %+v", in)
	}
	for _, name := range []string{"http", "https", "http-alt", "http-proxy"} {
		if !check.Applies(in, model.Service{Port: 1, Name: name}) {
			t.Errorf("should apply to %q", name)
		}
	}
	if check.Applies(in, model.Service{Port: 80, Name: "ssh"}) {
		t.Error("should not apply by port alone")
	}
}

func TestDetectsServerFormats(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		html    string
		wantAll []string
		forbid  []string
	}{
		{
			name: "nginx autoindex on root",
			path: "/",
			html: `<html>
<head><title>Index of /</title></head>
<body>
<h1>Index of /</h1><hr><pre><a href="../">../</a>
<a href="backup.sql">backup.sql</a>   28-Nov-2026 12:00   128
<a href="notes.txt">notes.txt</a>     28-Nov-2026 12:00    42
<a href="subdir/">subdir/</a>         28-Nov-2026 12:00     -
</pre><hr></body></html>`,
			wantAll: []string{`"Index of /"`, "3 entries", "backup.sql", "notes.txt", "subdir/"},
			forbid:  []string{"../"},
		},
		{
			name: "apache autoindex in /files/",
			path: "/files/",
			html: `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html><head><title>Index of /files</title></head>
<body><h1>Index of /files</h1>
<table>
<tr><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th></tr>
<tr><td><a href="/">Parent Directory</a></td></tr>
<tr><td><a href="config.bak">config.bak</a></td></tr>
<tr><td><a href="very-long-backup-filename-2026.tar.gz">very-long-backup-fil..&gt;</a></td></tr>
</table></body></html>`,
			wantAll: []string{"/files/", `"Index of /files"`, "2 entries", "config.bak", "very-long-backup-filename-2026.tar.gz"},
			forbid:  []string{"Parent Directory", "Last modified", "Name"},
		},
		{
			name: "python http.server listing",
			path: "/",
			html: `<!DOCTYPE HTML>
<html lang="en"><head><meta charset="utf-8"><title>Directory listing for /</title></head>
<body><h1>Directory listing for /</h1><hr>
<ul>
<li><a href="app.py">app.py</a></li>
<li><a href="secrets.env">secrets.env</a></li>
</ul><hr></body></html>`,
			wantAll: []string{`"Directory listing for /"`, "2 entries", "app.py", "secrets.env"},
		},
		{
			name:    "empty directory listing",
			path:    "/uploads/",
			html:    `<html><head><title>Index of /uploads/</title></head><body><h1>Index of /uploads/</h1><hr><pre><a href="../">../</a></pre><hr></body></html>`,
			wantAll: []string{"/uploads/", `"Index of /uploads/"`, "empty directory"},
		},
		{
			name: "many files capped in evidence",
			path: "/",
			html: `<html><head><title>Index of /</title></head><body><h1>Index of /</h1><pre>` +
				`<a href="a.txt">a.txt</a><a href="b.txt">b.txt</a><a href="c.txt">c.txt</a>` +
				`<a href="d.txt">d.txt</a><a href="e.txt">e.txt</a><a href="f.txt">f.txt</a><a href="g.txt">g.txt</a>` +
				`</pre></body></html>`,
			wantAll: []string{"7 entries", "a.txt, b.txt, c.txt, d.txt, e.txt and 2 more"},
			forbid:  []string{"f.txt", "g.txt"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == tc.path {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					w.Write([]byte(tc.html))
					return
				}
				if r.URL.Path == "/" {
					w.Header().Set("Content-Type", "text/html")
					w.Write([]byte("<html><head><title>Welcome</title></head><body>Home</body></html>"))
					return
				}
				http.NotFound(w, r)
			}))
			defer srv.Close()

			res, err := Check{}.Run(context.Background(), targetFor(t, srv.URL, model.Service{}))
			if err != nil || res == nil {
				t.Fatalf("expected finding, got res=%+v err=%v", res, err)
			}
			for _, want := range tc.wantAll {
				if !strings.Contains(res.Evidence, want) {
					t.Errorf("evidence missing %q: %q", want, res.Evidence)
				}
			}
			for _, bad := range tc.forbid {
				if strings.Contains(res.Evidence, bad) {
					t.Errorf("evidence should not contain %q: %q", bad, res.Evidence)
				}
			}
		})
	}
}

func TestHTTPSListing(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><head><title>Index of /</title></head><body><h1>Index of /</h1><pre><a href="db.dump">db.dump</a></pre></body></html>`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	res, err := Check{}.Run(context.Background(), targetFor(t, srv.URL, model.Service{Name: "http", Tunnel: "ssl"}))
	if err != nil || res == nil || !strings.Contains(res.Evidence, "https://") || !strings.Contains(res.Evidence, "1 entry: db.dump") {
		t.Fatalf("expected HTTPS finding, got res=%+v err=%v", res, err)
	}
}

func TestNegativeNoFalsePositives(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"normal website": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><head><title>Nuqs Docs</title></head><body><p>Watch out for Index of / pages.</p></body></html>`))
		},
		"403 forbidden everywhere": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "403 Forbidden", http.StatusForbidden)
		},
		"json response mentioning Index of": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"title":"<title>Index of /</title><h1>Index of /</h1>"}`))
		},
		"title only without file links": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><head><title>Index of / article</title></head><body><p>Just prose.</p><a href="https://example.com">external</a></body></html>`))
		},
	}

	for name, handler := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(handler)
			defer srv.Close()
			res, err := Check{}.Run(context.Background(), targetFor(t, srv.URL, model.Service{}))
			if err != nil || res != nil {
				t.Errorf("%s: expected clean result, got res=%+v err=%v", name, res, err)
			}
		})
	}
}

func TestErrors(t *testing.T) {
	t.Run("unreachable", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := l.Addr().String()
		l.Close()
		res, err := Check{}.Run(context.Background(), targetFor(t, "http://"+addr, model.Service{}))
		if err == nil || res != nil {
			t.Fatalf("expected error on closed port, got res=%+v err=%v", res, err)
		}
	})

	t.Run("respects context timeout", func(t *testing.T) {
		slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-time.After(5 * time.Second):
			case <-r.Context().Done():
			}
		}))
		defer slow.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		start := time.Now()
		res, err := Check{}.Run(ctx, targetFor(t, slow.URL, model.Service{}))
		if err == nil || res != nil || time.Since(start) > 2*time.Second {
			t.Fatalf("expected fast timeout, got res=%+v err=%v after %s", res, err, time.Since(start))
		}
	})
}
