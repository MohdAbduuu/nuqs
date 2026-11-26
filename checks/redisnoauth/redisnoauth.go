// Package redisnoauth checks if a Redis server allows unauthenticated access.
//
// It sends a harmless PING command without credentials. If the server replies
// with +PONG, unauthenticated access is possible. If it replies with -NOAUTH
// or an -ERR containing "authentication required", it needs a password. If it
// replies with -DENIED, it's in protected mode and only allows localhost. Either way, no finding.
package redisnoauth

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/nuqs-org/nuqs/internal/check"
	"github.com/nuqs-org/nuqs/internal/model"
)

// maxReply caps how much we read from the server so hostile servers cannot
// exhaust memory.
const maxReply = 256

// Check reports Redis servers with no password.
type Check struct{}

// Info describes the check.
func (Check) Info() check.Info {
	return check.Info{
		ID:               "redis-no-auth",
		Title:            "Redis server has no password",
		Description:      "Anyone who can reach this Redis port can read or change data without a password.\nAttackers often abuse open Redis servers to steal session tokens, poison app data or write files to the host.",
		Severity:         model.High,
		Fix:              "Set requirepass in redis.conf, or bind Redis to localhost only.",
		RemediationTitle: "Require Redis authentication",
		Ports:            []int{6379},
		Services:         []string{"redis"},
		References: []check.Reference{
			{Title: "Redis Security Documentation", URL: "https://redis.io/docs/latest/operate/oss_and_stack/management/security/"},
			{Title: "Redis Access Control Lists (ACL)", URL: "https://redis.io/docs/latest/operate/oss_and_stack/management/security/acl/"},
			{Title: "CWE-306: Missing Authentication for Critical Function", URL: "https://cwe.mitre.org/data/definitions/306.html"},
		},
	}
}

// Run sends PING and reports a finding if Redis answers with +PONG.
func (Check) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	if t.Service.Tunnel == "ssl" {
		return nil, fmt.Errorf("redis over TLS isn't supported yet")
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

	// Close the connection if ctx is cancelled, which unblocks any pending I/O.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	if _, err := conn.Write([]byte("PING\r\n")); err != nil {
		return nil, err
	}

	r := bufio.NewReader(io.LimitReader(conn, maxReply))
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}

	reply := strings.TrimRight(line, "\r\n")
	if reply == "+PONG" {
		return &check.Result{Evidence: "sent PING without a password and got +PONG"}, nil
	}
	if strings.HasPrefix(reply, "-NOAUTH") || strings.HasPrefix(reply, "-DENIED") || strings.Contains(strings.ToLower(reply), "authentication required") || strings.Contains(strings.ToLower(reply), "protected mode") {
		return nil, nil // password needed or protected mode, no finding
	}

	return nil, fmt.Errorf("unexpected Redis reply: %q", reply)
}
