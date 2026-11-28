// Package memcachedexposed checks if a Memcached server answers commands
// over TCP without authentication.
//
// It sends one read-only "stats" command and reads the STAT lines until END.
// If Memcached replies with server stats, anyone who can reach the port can
// read, alter or flush cached data. Nothing is modified and no keys are read.
package memcachedexposed

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/nuqs-org/nuqs/internal/check"
	"github.com/nuqs-org/nuqs/internal/model"
)

// maxReply caps how much we read from the server so a hostile server cannot
// exhaust memory. A real Memcached stats reply is roughly 1.5 KiB.
const maxReply = 64 << 10

// Check reports Memcached servers exposed over TCP without authentication.
type Check struct{}

// Info describes the check.
func (Check) Info() check.Info {
	return check.Info{
		ID:               "memcached-exposed",
		Title:            "Memcached server is exposed without authentication",
		Description:      "Anyone who can reach this Memcached port can read cached data, overwrite keys or flush the cache without logging in.\nMemcached has no authentication by default and should only be reachable on localhost or a private network.",
		Severity:         model.High,
		Fix:              "Bind Memcached to localhost (-l 127.0.0.1), restrict port 11211 with a firewall, and disable UDP (-U 0).",
		RemediationTitle: "Restrict Memcached access",
		Ports:            []int{11211},
		Services:         []string{"memcached", "memcache"},
		References: []check.Reference{
			{Title: "Memcached Server Configuration: Networking", URL: "https://github.com/memcached/memcached/wiki/ConfiguringServer#networking"},
			{Title: "CISA Alert: UDP-Based Amplification Attacks (Memcached)", URL: "https://www.cisa.gov/news-events/alerts/2018/03/02/udp-based-amplification-attacks"},
			{Title: "CWE-306: Missing Authentication for Critical Function", URL: "https://cwe.mitre.org/data/definitions/306.html"},
		},
	}
}

// Run sends "stats" over TCP and reports a finding if Memcached replies with stats.
func (Check) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	if t.Service.Tunnel == "ssl" {
		return nil, errors.New("memcached over TLS isn't supported yet")
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", t.Address())
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	}

	// Close the connection if ctx is canceled, unblocking any pending I/O.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	if _, err := conn.Write([]byte("stats\r\n")); err != nil {
		return nil, err
	}

	return parseStats(io.LimitReader(conn, maxReply))
}

func parseStats(r io.Reader) (*check.Result, error) {
	br := bufio.NewReader(r)
	var version, uptime, firstLine string
	statCount := 0
	sawEnd := false

	for {
		line, err := br.ReadString('\n')
		if len(line) > 0 {
			trimmed := strings.TrimRight(line, "\r\n")
			if firstLine == "" {
				firstLine = trimmed
			}
			if trimmed == "END" {
				sawEnd = true
				break
			}
			if strings.HasPrefix(trimmed, "STAT ") {
				parts := strings.SplitN(trimmed, " ", 3)
				if len(parts) == 3 {
					statCount++
					switch parts[1] {
					case "version":
						version = strings.TrimSpace(parts[2])
					case "uptime":
						uptime = strings.TrimSpace(parts[2])
					}
				}
			} else {
				if statCount == 0 && isAuthRejected(trimmed) {
					return nil, nil
				}
				return nil, fmt.Errorf("unexpected Memcached reply: %q", preview(trimmed))
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
	}

	if statCount == 0 || (!sawEnd && version == "" && uptime == "") {
		if firstLine == "" {
			return nil, errors.New("empty reply from Memcached")
		}
		return nil, fmt.Errorf("incomplete Memcached stats reply: %q", preview(firstLine))
	}

	return &check.Result{Evidence: formatEvidence(version, uptime)}, nil
}

func preview(s string) string {
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}

func isAuthRejected(line string) bool {
	low := strings.ToLower(line)
	return strings.HasPrefix(line, "CLIENT_ERROR") &&
		(strings.Contains(low, "auth") || strings.Contains(low, "unauthorized") || strings.Contains(low, "not allowed"))
}

func formatEvidence(version, uptime string) string {
	switch {
	case version != "" && uptime != "":
		return fmt.Sprintf("sent stats and got Memcached %s (uptime %ss)", version, uptime)
	case version != "":
		return fmt.Sprintf("sent stats and got Memcached %s", version)
	case uptime != "":
		return fmt.Sprintf("sent stats and got Memcached stats (uptime %ss)", uptime)
	default:
		return "sent stats and got Memcached stats reply without authentication"
	}
}
