// Package ftpanon checks if an FTP server lets anyone log in as "anonymous".
//
// This is a "login probe" check. It logs in with the public anonymous
// account, reads the reply and logs out. It doesn't list, read or write files.
package ftpanon

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"time"

	"github.com/nuqs-org/nuqs/internal/check"
	"github.com/nuqs-org/nuqs/internal/model"
)

// maxReply caps how much we read from the server, so a hostile server can't
// make us use lots of memory.
const maxReply = 64 << 10

// Check reports FTP servers that accept anonymous logins.
type Check struct{}

// Info describes the check.
func (Check) Info() check.Info {
	return check.Info{
		ID:               "ftp-anonymous-login",
		Title:            "FTP server allows anonymous login",
		Description:      "Anyone on the network can log in to this FTP server as \"anonymous\" with no password.\nInternal files on port 21 can be read by anyone, and open upload folders can be used to drop files or fill the disk.",
		Severity:         model.Medium,
		Fix:              "Disable anonymous FTP unless you really mean to share files publicly. For vsftpd set anonymous_enable=NO.",
		RemediationTitle: "Disable anonymous FTP",
		Ports:            []int{21},
		Services:         []string{"ftp"},
		References: []check.Reference{
			{Title: "CWE-287: Improper Authentication", URL: "https://cwe.mitre.org/data/definitions/287.html"},
			{Title: "RFC 1635: How to Use Anonymous FTP", URL: "https://datatracker.ietf.org/doc/html/rfc1635"},
			{Title: "vsftpd.conf Manual", URL: "https://security.appspot.com/vsftpd/vsftpd_conf.html"},
		},
	}
}

// Run tries the anonymous login. It returns a finding on reply 230 (logged in)
// and nil when the server says no.
func (Check) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	if t.Service.Tunnel == "ssl" {
		return nil, fmt.Errorf("FTP over TLS isn't supported yet")
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
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	}
	// Close the connection if ctx is cancelled, which unblocks any read.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	r := textproto.NewReader(bufio.NewReader(io.LimitReader(conn, maxReply)))
	w := textproto.NewWriter(bufio.NewWriter(conn))

	if _, _, err := r.ReadResponse(220); err != nil {
		return nil, fmt.Errorf("unexpected FTP greeting: %w", err)
	}

	if err := w.PrintfLine("USER anonymous"); err != nil {
		return nil, err
	}
	code, msg, err := r.ReadResponse(0)
	if err != nil {
		return nil, fmt.Errorf("reading USER reply: %w", err)
	}
	switch {
	case code == 230: // some servers log in right after USER
		quit(w)
		return found(code, msg), nil
	case code != 331:
		return nil, nil // server refused the anonymous user
	}

	if err := w.PrintfLine("PASS nuqs@example.com"); err != nil {
		return nil, err
	}
	code, msg, err = r.ReadResponse(0)
	if err != nil {
		return nil, fmt.Errorf("reading PASS reply: %w", err)
	}
	quit(w)
	if code == 230 {
		return found(code, msg), nil
	}
	return nil, nil
}

func found(code int, msg string) *check.Result {
	return &check.Result{Evidence: fmt.Sprintf("logged in as \"anonymous\", server replied %d %s", code, msg)}
}

func quit(w *textproto.Writer) { _ = w.PrintfLine("QUIT") }
