// Tests TLS self-signed generation, loopback HTTPS LocalOnly enforcement and network HTTPS serving.

package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServeHTTPSNetworkModeAndSelfSignedCert(t *testing.T) {
	dataDir := t.TempDir()
	app, out, errOut := newApp(t, &fakeRunner{})
	app.DataDir = dataDir
	app.PBKDF2Iterations = 1000
	app.LookPath = func(file string) (string, error) { return "/usr/bin/" + file, nil }

	var gotAddr, gotCert, gotKey string
	app.ListenAndServeTLS = func(_ context.Context, addr, certFile, keyFile string, gotHandler http.Handler) error {
		gotAddr, gotCert, gotKey = addr, certFile, keyFile
		// Network HTTPS mode accepts LAN Host headers (not blocked by LocalOnly) and sets HSTS.
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://192.168.1.50:9443/setup", nil)
		req.TLS = &tls.ConnectionState{}
		gotHandler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || rec.Header().Get("Strict-Transport-Security") == "" {
			t.Fatalf("LAN HTTPS /setup: code=%d hsts=%q", rec.Code, rec.Header().Get("Strict-Transport-Security"))
		}
		return nil
	}

	code := app.Run(context.Background(), []string{"serve", "--addr", "0.0.0.0:9443", "--tls-self-signed"})
	if code != ExitOK {
		t.Fatalf("serve HTTPS exit %d: %s", code, errOut)
	}
	if gotAddr != "0.0.0.0:9443" || gotCert == "" || gotKey == "" || !strings.Contains(out.String(), "https://127.0.0.1:9443") || !strings.Contains(out.String(), "0.0.0.0:9443") {
		t.Fatalf("unexpected HTTPS bind: addr=%q cert=%q key=%q out=%s", gotAddr, gotCert, gotKey, out)
	}
	cfg, err := BuildTLSConfig(gotCert, gotKey)
	if err != nil || cfg.MinVersion != tls.VersionTLS12 || len(cfg.Certificates) != 1 {
		t.Fatalf("BuildTLSConfig: %+v %v", cfg, err)
	}
	leaf, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	if err != nil || len(leaf.IPAddresses) == 0 || len(leaf.DNSNames) == 0 {
		t.Fatalf("self-signed leaf cert SANs missing: %v", err)
	}
	// Reusing existing self-signed cert leaves the file untouched.
	infoBefore, _ := os.Stat(gotCert)
	cert2, key2, err := EnsureSelfSignedCert(dataDir, "0.0.0.0:9443")
	if err != nil || cert2 != gotCert || key2 != gotKey {
		t.Fatalf("reuse cert: %q %q %v", cert2, key2, err)
	}
	infoAfter, _ := os.Stat(cert2)
	if !infoAfter.ModTime().Equal(infoBefore.ModTime()) {
		t.Error("expected existing valid cert to be reused")
	}

	// Bad TLS flag combinations are rejected.
	for _, bad := range [][]string{
		{"serve", "--tls-cert", gotCert},
		{"serve", "--tls-key", gotKey},
		{"serve", "--tls-self-signed", "--tls-cert", gotCert, "--tls-key", gotKey},
		{"serve", "--addr", "0.0.0.0:9443"},
	} {
		a2, _, _ := newApp(t, &fakeRunner{})
		if c := a2.Run(context.Background(), bad); c != ExitUsage {
			t.Errorf("%v: exit %d, want %d", bad, c, ExitUsage)
		}
	}
}

func TestServeLoopbackHTTPSKeepsLocalOnly(t *testing.T) {
	dataDir := t.TempDir()
	app, _, errOut := newApp(t, &fakeRunner{})
	app.DataDir = dataDir
	app.PBKDF2Iterations = 1000
	app.LookPath = func(file string) (string, error) { return "/usr/bin/" + file, nil }

	app.ListenAndServeTLS = func(_ context.Context, _ string, _, _ string, h http.Handler) error {
		// Valid loopback HTTPS Host succeeds and sets HSTS.
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://127.0.0.1:9443/setup", nil)
		req.TLS = &tls.ConnectionState{}
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || rec.Header().Get("Strict-Transport-Security") == "" {
			t.Fatalf("loopback HTTPS /setup: code=%d hsts=%q", rec.Code, rec.Header().Get("Strict-Transport-Security"))
		}

		// Foreign Host pointed at loopback over HTTPS is still refused by LocalOnly.
		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "https://evil.example:9443/setup", nil)
		req.TLS = &tls.ConnectionState{}
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "https://127.0.0.1:9443") {
			t.Fatalf("foreign Host on loopback HTTPS: code=%d body=%q", rec.Code, rec.Body.String())
		}
		return nil
	}

	if code := app.Run(context.Background(), []string{"serve", "--addr", "127.0.0.1:9443", "--tls-self-signed"}); code != ExitOK {
		t.Fatalf("loopback HTTPS exit %d: %s", code, errOut)
	}
}

func TestTLSAndAddressHelpers(t *testing.T) {
	for _, tc := range []struct {
		addr    string
		wantErr bool
	}{
		{"127.0.0.1:9002", false},
		{"localhost:9002", false},
		{"[::1]:9002", false},
		{"0.0.0.0:9002", true},
		{"192.168.1.1:9002", true},
		{"invalid-addr", true},
	} {
		err := checkLoopback(tc.addr)
		if (err != nil) != tc.wantErr {
			t.Errorf("checkLoopback(%q) = %v, wantErr %v", tc.addr, err, tc.wantErr)
		}
	}

	for _, tc := range []struct {
		addr    string
		wantErr bool
	}{
		{"127.0.0.1:9002", false},
		{"0.0.0.0:443", false},
		{"127.0.0.1", true},
		{"127.0.0.1:abc", true},
		{"127.0.0.1:99999", true},
		{"127.0.0.1:-1", true},
	} {
		_, err := CheckServeAddr(tc.addr)
		if (err != nil) != tc.wantErr {
			t.Errorf("CheckServeAddr(%q) err=%v, wantErr=%v", tc.addr, err, tc.wantErr)
		}
	}

	if got := LocalAccessURL("0.0.0.0:9002", "http"); got != "http://127.0.0.1:9002" {
		t.Errorf("LocalAccessURL: %s", got)
	}
	if got := LocalAccessURL("[::]:9443", "https"); got != "https://127.0.0.1:9443" {
		t.Errorf("LocalAccessURL: %s", got)
	}
	if got := LocalAccessURL("localhost:9002", "http"); got != "http://localhost:9002" {
		t.Errorf("LocalAccessURL: %s", got)
	}
	_ = NetworkHintURL("0.0.0.0:9443", "https")
	_ = NetworkHintURL("127.0.0.1:9002", "http")

	if _, err := BuildTLSConfig("nonexistent-cert.pem", "nonexistent-key.pem"); err == nil {
		t.Error("expected error for nonexistent cert")
	}

	dir := t.TempDir()
	badCert := filepath.Join(dir, "bad.crt")
	badKey := filepath.Join(dir, "bad.key")
	_ = os.WriteFile(badCert, []byte("bad pem content"), 0o600)
	_ = os.WriteFile(badKey, []byte("bad pem content"), 0o600)
	if validExistingCert(badCert, badKey, "127.0.0.1:9443", time.Now()) {
		t.Error("validExistingCert should fail for bad PEM")
	}

	goodCert, goodKey, err := EnsureSelfSignedCert(dir, "127.0.0.1:9443")
	if err != nil {
		t.Fatal(err)
	}
	if !validExistingCert(goodCert, goodKey, "127.0.0.1:9443", time.Now()) {
		t.Error("validExistingCert should succeed for valid cert")
	}
	if validExistingCert(goodCert, goodKey, "127.0.0.1:9443", time.Now().Add(400*24*time.Hour)) {
		t.Error("validExistingCert should fail for expired cert")
	}
	if validExistingCert(goodCert, goodKey, "10.254.254.254:9443", time.Now()) {
		t.Error("validExistingCert should fail for mismatched SAN IP")
	}
}
