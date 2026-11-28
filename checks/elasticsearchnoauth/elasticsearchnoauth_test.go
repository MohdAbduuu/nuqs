// Tests the Elasticsearch unauthenticated access check against fake HTTP servers.

package elasticsearchnoauth

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

const sampleRoot = `{
  "name": "node-1",
  "cluster_name": "nuqs-lab",
  "cluster_uuid": "abc123",
  "version": {
    "number": "8.17.4",
    "lucene_version": "9.12.0"
  },
  "tagline": "You Know, for Search"
}`

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
	if in.ID != "elasticsearch-no-auth" || in.Severity != model.High {
		t.Fatalf("unexpected info: %+v", in)
	}
	if !check.Applies(in, model.Service{Port: 9200, Name: "wap-wsp"}) {
		t.Error("should apply on port 9200 regardless of service name")
	}
	if !check.Applies(in, model.Service{Port: 19200, Name: "http", Product: "Elasticsearch REST API"}) {
		t.Error("should apply to Elasticsearch REST API detected as http on a non-standard port")
	}
	if check.Applies(in, model.Service{Port: 22, Name: "ssh"}) {
		t.Error("should not apply to ssh")
	}
}

func TestOpenCluster(t *testing.T) {
	cases := []struct {
		name      string
		indices   string
		wantCount string
		forbid    string
	}{
		{
			name:      "multiple text indices",
			indices:   "yellow open secret-customers abc 1 1 50 0 12kb 12kb\ngreen  open logs-2026        def 1 0 10 0  4kb  4kb\n",
			wantCount: "2 indices",
			forbid:    "secret-customers",
		},
		{
			name:      "single index with verbose header",
			indices:   "health status index uuid pri rep docs.count\nyellow open orders xyz 1 1 5 0 1kb\n",
			wantCount: "1 index",
			forbid:    "orders",
		},
		{
			name:      "empty cluster",
			indices:   "",
			wantCount: "0 indices",
		},
		{
			name:      "json indices reply",
			indices:   `[{"index":"alpha"},{"index":"beta"},{"index":"gamma"}]`,
			wantCount: "3 indices",
			forbid:    "alpha",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Elastic-Product", "Elasticsearch")
				switch r.URL.Path {
				case "/":
					w.Header().Set("Content-Type", "application/json")
					w.Write([]byte(sampleRoot))
				case "/_cat/indices":
					w.Write([]byte(tc.indices))
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()

			res, err := Check{}.Run(context.Background(), targetFor(t, srv.URL, model.Service{Product: "Elasticsearch REST API"}))
			if err != nil || res == nil {
				t.Fatalf("expected finding, got res=%+v err=%v", res, err)
			}
			for _, want := range []string{`cluster "nuqs-lab"`, "Elasticsearch 8.17.4", tc.wantCount} {
				if !strings.Contains(res.Evidence, want) {
					t.Errorf("evidence missing %q: %q", want, res.Evidence)
				}
			}
			if tc.forbid != "" && strings.Contains(res.Evidence, tc.forbid) {
				t.Errorf("evidence must not expose index names/data (%q): %q", tc.forbid, res.Evidence)
			}
		})
	}
}

func TestOpenClusterOverHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Write([]byte(sampleRoot))
		case "/_cat/indices":
			w.Write([]byte("green open app-logs 1 1 0 1 0 1kb 1kb\n"))
		}
	}))
	defer srv.Close()

	res, err := Check{}.Run(context.Background(), targetFor(t, srv.URL, model.Service{Name: "http", Tunnel: "ssl", Product: "Elasticsearch REST API"}))
	if err != nil || res == nil || !strings.Contains(res.Evidence, "https://") {
		t.Fatalf("expected HTTPS finding, got res=%+v err=%v", res, err)
	}
}

func TestSecuredCluster(t *testing.T) {
	cases := []struct {
		name       string
		rootStatus int
		idxStatus  int
	}{
		{"401 on root", http.StatusUnauthorized, http.StatusUnauthorized},
		{"403 on root", http.StatusForbidden, http.StatusForbidden},
		{"401 on indices", http.StatusOK, http.StatusUnauthorized},
		{"403 on indices", http.StatusOK, http.StatusForbidden},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					w.WriteHeader(tc.rootStatus)
					if tc.rootStatus == http.StatusOK {
						w.Write([]byte(sampleRoot))
					}
					return
				}
				w.WriteHeader(tc.idxStatus)
			}))
			defer srv.Close()

			res, err := Check{}.Run(context.Background(), targetFor(t, srv.URL, model.Service{Product: "Elasticsearch REST API"}))
			if err != nil || res != nil {
				t.Errorf("secured cluster should be clean, got res=%+v err=%v", res, err)
			}
		})
	}
}

func TestSkipsNonElasticsearchHTTP(t *testing.T) {
	// Normal HTML or non-ES JSON (even when Nmap labeled another product) is clean, no error.
	for _, body := range []string{"<html><body>hello nginx</body></html>", `{"cluster_name":"x","version":{"number":"1.0"}}`, `{"ok":true}`} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte(body))
		}))
		res, err := Check{}.Run(context.Background(), targetFor(t, s.URL, model.Service{Name: "http", Product: "nginx"}))
		s.Close()
		if err != nil || res != nil {
			t.Errorf("non-ES body %q: got res=%+v err=%v", body, res, err)
		}
	}

	// Elasticsearch behind a reverse proxy (Nmap labeled nginx) is still detected.
	proxied := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Write([]byte(sampleRoot))
		case "/_cat/indices":
			w.Write([]byte("green open logs abc 1 0 1 0 1kb 1kb\n"))
		}
	}))
	defer proxied.Close()
	res, err := Check{}.Run(context.Background(), targetFor(t, proxied.URL, model.Service{Name: "http", Product: "nginx"}))
	if err != nil || res == nil || !strings.Contains(res.Evidence, `cluster "nuqs-lab"`) {
		t.Fatalf("proxied Elasticsearch should still be detected: res=%+v err=%v", res, err)
	}

	// Unknown HTTP product returning 404: clean, no error.
	s404 := httptest.NewServer(http.NotFoundHandler())
	defer s404.Close()
	res, err = Check{}.Run(context.Background(), targetFor(t, s404.URL, model.Service{Name: "http"}))
	if err != nil || res != nil {
		t.Errorf("non-ES 404: got res=%+v err=%v", res, err)
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
		res, err := Check{}.Run(context.Background(), targetFor(t, "http://"+addr, model.Service{Product: "Elasticsearch REST API"}))
		if err == nil || res != nil {
			t.Fatalf("expected error on closed port, got res=%+v err=%v", res, err)
		}
	})

	t.Run("unexpected status on elasticsearch root", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer srv.Close()
		res, err := Check{}.Run(context.Background(), targetFor(t, srv.URL, model.Service{Product: "Elasticsearch REST API"}))
		if err == nil || res != nil {
			t.Fatalf("expected error on 503 root, got res=%+v err=%v", res, err)
		}
	})

	t.Run("unexpected status on _cat/indices", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				w.Write([]byte(sampleRoot))
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()
		res, err := Check{}.Run(context.Background(), targetFor(t, srv.URL, model.Service{Product: "Elasticsearch REST API"}))
		if err == nil || res != nil {
			t.Fatalf("expected error on 500 indices, got res=%+v err=%v", res, err)
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
		res, err := Check{}.Run(ctx, targetFor(t, slow.URL, model.Service{Product: "Elasticsearch REST API"}))
		if err == nil || res != nil || time.Since(start) > 2*time.Second {
			t.Fatalf("expected fast timeout, got res=%+v err=%v after %s", res, err, time.Since(start))
		}
	})

	t.Run("truncated large indices reply caps reads", func(t *testing.T) {
		line := "green open idx-0000000000000000000000000000000000000000000 1 1 0 0 1kb 1kb\n"
		huge := strings.Repeat(line, (maxIndicesBody/len(line))+50)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				w.Write([]byte(sampleRoot))
				return
			}
			w.Write([]byte(huge))
		}))
		defer srv.Close()
		res, err := Check{}.Run(context.Background(), targetFor(t, srv.URL, model.Service{Product: "Elasticsearch REST API"}))
		if err != nil || res == nil || !strings.Contains(res.Evidence, "at least ") {
			t.Fatalf("expected truncated count in evidence, got res=%+v err=%v", res, err)
		}
	})
}
