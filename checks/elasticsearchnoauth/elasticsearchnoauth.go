// Package elasticsearchnoauth checks if an Elasticsearch HTTP API allows
// unauthenticated access.
//
// It sends harmless read-only GET requests to "/" and "/_cat/indices" without
// credentials. A secured cluster returns 401 or 403. An open cluster answers
// with its cluster metadata and index list. Only the cluster name, version and
// index count are recorded in the evidence, never index names or document data.
package elasticsearchnoauth

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/nuqs-org/nuqs/internal/check"
	"github.com/nuqs-org/nuqs/internal/model"
)

const (
	// maxRootBody caps the JSON response read from GET /.
	maxRootBody = 64 << 10
	// maxIndicesBody caps the response read from GET /_cat/indices.
	maxIndicesBody = 1 << 20
)

// Check reports Elasticsearch clusters whose HTTP API needs no login.
type Check struct {
	// Client is used for the HTTP requests. Nil means a default client that
	// doesn't follow redirects and accepts any TLS certificate.
	Client *http.Client
}

// Info describes the check.
func (Check) Info() check.Info {
	return check.Info{
		ID:               "elasticsearch-no-auth",
		Title:            "Elasticsearch cluster has no authentication",
		Description:      "Anyone who can reach this Elasticsearch port can read, change or delete indices without logging in.\nOpen Elasticsearch clusters often expose application logs, user records and search data to anyone on the network.",
		Severity:         model.High,
		Fix:              "Enable Elasticsearch security (xpack.security.enabled: true in elasticsearch.yml), configure authentication and TLS, or bind Elasticsearch to localhost only.",
		RemediationTitle: "Enable Elasticsearch authentication",
		Ports:            []int{9200},
		Services:         []string{"elasticsearch", "http", "https", "http-alt", "https-alt"},
		References: []check.Reference{
			{Title: "Elastic: Set up minimal security for Elasticsearch", URL: "https://www.elastic.co/guide/en/elasticsearch/reference/current/security-minimal-setup.html"},
			{Title: "CWE-306: Missing Authentication for Critical Function", URL: "https://cwe.mitre.org/data/definitions/306.html"},
		},
	}
}

type rootReply struct {
	Name        string `json:"name"`
	ClusterName string `json:"cluster_name"`
	Tagline     string `json:"tagline"`
	Version     struct {
		Number        string `json:"number"`
		LuceneVersion string `json:"lucene_version"`
	} `json:"version"`
}

// Run sends GET / and GET /_cat/indices and reports a finding if Elasticsearch
// answers both without requiring authentication.
func (c Check) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	isES := t.Service.Port == 9200 ||
		strings.Contains(strings.ToLower(t.Service.Name), "elasticsearch") ||
		strings.Contains(strings.ToLower(t.Service.Product), "elasticsearch")

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

	rootURL := baseURL + "/"
	status, hdr, body, err := fetch(ctx, client, rootURL, maxRootBody)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", rootURL, err)
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return nil, nil // authentication is enforced
	}
	if status != http.StatusOK {
		if isES {
			return nil, fmt.Errorf("GET %s: unexpected status %d", rootURL, status)
		}
		return nil, nil // some other HTTP service on a non-9200 port
	}

	meta, ok := parseRoot(hdr, body)
	if !ok {
		return nil, nil // not an Elasticsearch REST API
	}

	indicesURL := baseURL + "/_cat/indices"
	idxStatus, _, idxBody, err := fetch(ctx, client, indicesURL, maxIndicesBody)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", indicesURL, err)
	}
	if idxStatus == http.StatusUnauthorized || idxStatus == http.StatusForbidden {
		return nil, nil // indices require authentication
	}
	if idxStatus != http.StatusOK {
		return nil, fmt.Errorf("GET %s: unexpected status %d", indicesURL, idxStatus)
	}

	count, truncated := countIndices(idxBody, len(idxBody) >= maxIndicesBody)
	return &check.Result{
		Evidence: formatEvidence(baseURL, meta.ClusterName, meta.Version.Number, count, truncated),
	}, nil
}

func fetch(ctx context.Context, client *http.Client, targetURL string, limit int64) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("User-Agent", "Nuqs scanner")

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return 0, nil, nil, err
	}
	return resp.StatusCode, resp.Header, body, nil
}

// parseRoot verifies that the response body looks like an Elasticsearch GET /
// JSON document and returns its metadata.
func parseRoot(hdr http.Header, body []byte) (rootReply, bool) {
	var r rootReply
	if err := json.Unmarshal(body, &r); err != nil {
		return rootReply{}, false
	}
	if strings.TrimSpace(r.ClusterName) == "" || strings.TrimSpace(r.Version.Number) == "" {
		return rootReply{}, false
	}
	hasSignal := strings.EqualFold(strings.TrimSpace(hdr.Get("X-Elastic-Product")), "Elasticsearch") ||
		strings.TrimSpace(r.Version.LuceneVersion) != "" ||
		strings.Contains(strings.ToLower(r.Tagline), "search")
	if !hasSignal {
		return rootReply{}, false
	}
	return r, true
}

// countIndices counts how many indices GET /_cat/indices returned without
// keeping any index names or contents.
func countIndices(body []byte, hitLimit bool) (int, bool) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return 0, false
	}
	if trimmed[0] == '[' {
		var items []json.RawMessage
		if err := json.Unmarshal(trimmed, &items); err == nil {
			return len(items), hitLimit
		}
		if hitLimit {
			return bytes.Count(trimmed, []byte("{")), true
		}
	}
	lines := strings.Split(string(body), "\n")
	if hitLimit && len(lines) > 1 && !bytes.HasSuffix(body, []byte("\n")) {
		// Drop a potentially partial final line when the read cap was reached.
		lines = lines[:len(lines)-1]
	}
	count := 0
	for i, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		// Skip the optional verbose header line ("health status index ...").
		if i == 0 && strings.EqualFold(fields[0], "health") && len(fields) > 1 && strings.EqualFold(fields[1], "status") {
			continue
		}
		count++
	}
	return count, hitLimit
}

func formatEvidence(baseURL, cluster, version string, count int, truncated bool) string {
	unit := "indices"
	if count == 1 {
		unit = "index"
	}
	countText := fmt.Sprintf("%d %s", count, unit)
	if truncated {
		countText = fmt.Sprintf("at least %d %s", count, unit)
	}
	return fmt.Sprintf("GET %s/ and /_cat/indices answered without login: cluster %q (Elasticsearch %s), %s", baseURL, cluster, version, countText)
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
