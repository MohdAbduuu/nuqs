// Package httpheaders checks web servers for missing security headers.
//
// This is an "active probe" check. It sends one normal GET request to "/"
// and looks at the response headers. It never sends anything harmful.
package httpheaders

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/nuqs-org/nuqs/internal/check"
	"github.com/nuqs-org/nuqs/internal/model"
)

// Check reports web servers that don't send basic security headers.
type Check struct {
	// Client is used for the request. Nil means a default client that doesn't
	// follow redirects and accepts any TLS certificate (we're scanning, not browsing).
	Client *http.Client
}

// Info describes the check.
func (Check) Info() check.Info {
	return check.Info{
		ID:               "http-security-headers",
		Title:            "Web server is missing security headers",
		Description:      "The web server is missing basic security headers that protect people in their browser.\nHeaders like CSP, X-Frame-Options and HSTS stop framing, script injection and plain-HTTP downgrades, so leaving them out makes other site bugs easier to abuse.",
		Severity:         model.Low,
		Fix:              "Configure the web server to send the missing headers. Most servers can add them in one line of config.",
		RemediationTitle: "Add HTTP security headers",
		Services:         []string{"http", "https", "http-alt", "http-proxy", "https-alt"},
		References: []check.Reference{
			{Title: "OWASP HTTP Security Response Headers Cheat Sheet", URL: "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"},
			{Title: "MDN Web Docs: Content-Security-Policy", URL: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"},
			{Title: "RFC 6797: HTTP Strict Transport Security (HSTS)", URL: "https://datatracker.ietf.org/doc/html/rfc6797"},
			{Title: "CWE-693: Protection Mechanism Failure", URL: "https://cwe.mitre.org/data/definitions/693.html"},
		},
	}
}

// header is one header we look for. ok returns true when the response has it.
type header struct {
	name    string
	ok      func(http.Header) bool
	tlsOnly bool
}

var wanted = []header{
	{name: "Content-Security-Policy", ok: has("Content-Security-Policy")},
	{name: "X-Content-Type-Options", ok: func(h http.Header) bool {
		return strings.EqualFold(strings.TrimSpace(h.Get("X-Content-Type-Options")), "nosniff")
	}},
	{name: "X-Frame-Options", ok: func(h http.Header) bool {
		// A CSP frame-ancestors rule does the same job, so either is fine.
		return h.Get("X-Frame-Options") != "" || strings.Contains(strings.ToLower(h.Get("Content-Security-Policy")), "frame-ancestors")
	}},
	{name: "Strict-Transport-Security", ok: has("Strict-Transport-Security"), tlsOnly: true},
}

func has(name string) func(http.Header) bool {
	return func(h http.Header) bool { return strings.TrimSpace(h.Get(name)) != "" }
}

// Run sends GET / and lists any missing headers.
func (c Check) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	useTLS := t.Service.Tunnel == "ssl" || strings.HasPrefix(t.Service.Name, "https")
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s/", scheme, t.Address())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Nuqs scanner")

	client := c.Client
	if client == nil {
		client = defaultClient()
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))

	var missing []string
	for _, w := range wanted {
		if w.tlsOnly && !useTLS {
			continue
		}
		if !w.ok(resp.Header) {
			missing = append(missing, w.name)
		}
	}
	if len(missing) == 0 {
		return nil, nil
	}
	return &check.Result{
		Evidence: fmt.Sprintf("GET %s returned %d without these headers: %s", url, resp.StatusCode, strings.Join(missing, ", ")),
	}, nil
}

func defaultClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // a scanner must talk to servers with self-signed certs
			Proxy:           nil,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
