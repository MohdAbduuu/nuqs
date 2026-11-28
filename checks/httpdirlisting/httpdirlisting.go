// Package httpdirlisting checks web servers for open directory listings.
//
// It sends read-only GET requests to "/" and a few common folders and looks
// for auto-generated index pages such as Apache, nginx ("Index of /...") and
// Python http.server ("Directory listing for /..."). Nothing is modified.
package httpdirlisting

import (
	"context"
	"crypto/tls"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/nuqs-org/nuqs/internal/check"
	"github.com/nuqs-org/nuqs/internal/model"
)

// maxBody caps how much HTML we read from each candidate page.
const maxBody = 256 << 10

// maxEvidenceEntries caps how many filenames are listed in the finding evidence.
const maxEvidenceEntries = 5

// probePaths are the root and common folders checked for open directory listings.
var probePaths = []string{
	"/",
	"/files/",
	"/uploads/",
	"/backup/",
	"/backups/",
	"/static/",
	"/assets/",
	"/pub/",
	"/downloads/",
}

var (
	titlePattern = regexp.MustCompile(`(?is)<title\b[^>]*>(.*?)</title>`)
	h1Pattern    = regexp.MustCompile(`(?is)<h1\b[^>]*>(.*?)</h1>`)
	linkPattern  = regexp.MustCompile(`(?is)<a\b[^>]*href\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>(.*?)</a>`)
	tagPattern   = regexp.MustCompile(`<[^>]+>`)
)

// Check reports web servers exposing open directory listings.
type Check struct {
	// Client is used for the HTTP requests. Nil means a default client that
	// doesn't follow redirects and accepts any TLS certificate.
	Client *http.Client
}

// Info describes the check.
func (Check) Info() check.Info {
	return check.Info{
		ID:               "http-directory-listing",
		Title:            "Web server allows directory listing",
		Description:      "The web server shows the contents of a directory when no index page is present.\nDirectory listings expose backup files, source code, configuration files and internal paths that were not meant to be public.",
		Severity:         model.Medium,
		Fix:              "Disable directory indexing in the web server configuration (for example, autoindex off in nginx or Options -Indexes in Apache) and add an index page where needed.",
		RemediationTitle: "Disable HTTP directory listing",
		Services:         []string{"http", "https", "http-alt", "http-proxy", "https-alt"},
		References: []check.Reference{
			{Title: "OWASP Web Security Testing Guide: Configuration and Deployment Management", URL: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"},
			{Title: "CWE-548: Exposure of Information Through Directory Listing", URL: "https://cwe.mitre.org/data/definitions/548.html"},
		},
	}
}

// Run probes "/" and a few common folders and reports the first open directory listing found.
func (c Check) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	useTLS := t.Service.Tunnel == "ssl" || strings.HasPrefix(strings.ToLower(t.Service.Name), "https")
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	baseURL := fmt.Sprintf("%s://%s", scheme, t.Address())

	client := c.Client
	if client == nil {
		client = defaultClient()
	}

	for _, p := range probePaths {
		targetURL := baseURL + p
		status, contentType, body, err := fetch(ctx, client, targetURL)
		if err != nil {
			return nil, fmt.Errorf("GET %s: %w", targetURL, err)
		}
		if status != http.StatusOK || !isHTML(contentType) {
			continue
		}
		if title, entries, ok := parseListing(body); ok {
			return &check.Result{Evidence: formatEvidence(targetURL, title, entries)}, nil
		}
	}
	return nil, nil
}

func fetch(ctx context.Context, client *http.Client, targetURL string) (int, string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return 0, "", "", err
	}
	req.Header.Set("User-Agent", "Nuqs scanner")

	resp, err := client.Do(req)
	if err != nil {
		return 0, "", "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return 0, "", "", err
	}
	return resp.StatusCode, resp.Header.Get("Content-Type"), string(body), nil
}

func isHTML(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	return ct == "" || strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml+xml")
}

// parseListing recognizes Apache, nginx and Python http.server directory index
// pages and extracts the page title and listed file names.
func parseListing(body string) (string, []string, bool) {
	title := extractText(titlePattern, body)
	heading := extractText(h1Pattern, body)

	titleMatch := isListingTitle(title)
	headingMatch := isListingTitle(heading)
	if !titleMatch && !headingMatch {
		return "", nil, false
	}

	entries := extractEntries(body)
	// Require both title and h1 to match (handles empty directories cleanly),
	// or at least one file link when only one of title/h1 is present.
	if !(titleMatch && headingMatch) && len(entries) == 0 {
		return "", nil, false
	}

	label := title
	if !titleMatch {
		label = heading
	}
	return label, entries, true
}

func extractText(re *regexp.Regexp, body string) string {
	m := re.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	plain := tagPattern.ReplaceAllString(m[1], "")
	return collapseSpace(html.UnescapeString(plain))
}

func isListingTitle(s string) bool {
	low := strings.ToLower(strings.TrimSpace(s))
	return strings.HasPrefix(low, "index of /") || strings.HasPrefix(low, "directory listing for /")
}

func extractEntries(body string) []string {
	matches := linkPattern.FindAllStringSubmatch(body, -1)
	seen := map[string]bool{}
	var entries []string
	for _, m := range matches {
		href := strings.TrimSpace(firstNonEmpty(m[1], m[2], m[3]))
		text := collapseSpace(html.UnescapeString(tagPattern.ReplaceAllString(m[4], "")))
		name, ok := entryName(href, text)
		if !ok || seen[name] {
			continue
		}
		seen[name] = true
		entries = append(entries, name)
	}
	return entries
}

func entryName(href, text string) (string, bool) {
	if href == "" {
		return "", false
	}
	lowHref := strings.ToLower(href)
	if strings.HasPrefix(lowHref, "?") ||
		strings.HasPrefix(lowHref, "#") ||
		strings.HasPrefix(lowHref, "http://") ||
		strings.HasPrefix(lowHref, "https://") ||
		strings.HasPrefix(lowHref, "//") ||
		strings.HasPrefix(lowHref, "mailto:") ||
		strings.HasPrefix(lowHref, "javascript:") {
		return "", false
	}
	if href == "/" || href == "." || href == "./" || href == ".." || href == "../" {
		return "", false
	}
	lowText := strings.ToLower(text)
	if lowText == "parent directory" || lowText == ".." || lowText == "../" || lowText == "to parent directory" {
		return "", false
	}
	// Prefer the decoded href over truncated nginx/Apache display labels ("..>").
	if unescaped, err := url.PathUnescape(href); err == nil && unescaped != "" {
		if text == "" || strings.HasSuffix(text, "..>") {
			return unescaped, true
		}
	}
	if text != "" {
		return text, true
	}
	return href, true
}

func formatEvidence(targetURL, title string, entries []string) string {
	if len(entries) == 0 {
		return fmt.Sprintf("GET %s returned directory listing %q (empty directory)", targetURL, title)
	}
	shown := entries
	extra := ""
	if len(entries) > maxEvidenceEntries {
		shown = entries[:maxEvidenceEntries]
		extra = fmt.Sprintf(" and %d more", len(entries)-maxEvidenceEntries)
	}
	unit := "entries"
	if len(entries) == 1 {
		unit = "entry"
	}
	return fmt.Sprintf("GET %s returned directory listing %q with %d %s: %s%s",
		targetURL, title, len(entries), unit, strings.Join(shown, ", "), extra)
}

func collapseSpace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
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
