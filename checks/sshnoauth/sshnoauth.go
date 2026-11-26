// Package sshnoauth checks if an SSH server lets anyone log in with no password or key.
//
// This is a "login probe" check, but it never sends a password. It does the
// SSH key exchange and asks to log in as "nuqs" with no credentials, the
// "none" method. A normal server says no and lists the methods it wants. A
// server that says yes lets anyone in, which is much worse than allowing
// passwords, so it gets its own check.
package sshnoauth

import (
	"context"
	"fmt"

	"github.com/nuqs-org/nuqs/internal/check"
	"github.com/nuqs-org/nuqs/internal/model"
	"github.com/nuqs-org/nuqs/internal/sshprobe"
)

// user is who we ask to log in as. Any name works.
const user = "nuqs"

// Check reports SSH servers that let anyone in without credentials.
type Check struct {
	// Ask asks the server for its login methods. Nil means sshprobe.AuthMethods.
	Ask func(ctx context.Context, addr, user string) (*sshprobe.Auth, error)
}

// Info describes the check.
func (Check) Info() check.Info {
	return check.Info{
		ID:               "ssh-no-auth",
		Title:            "SSH server lets anyone log in without a password",
		Description:      "This SSH server lets anyone log in without a password or key.\nAllowing the SSH \"none\" login method removes authentication completely, so anyone on the network can get a shell or tunnel traffic through the host.",
		Severity:         model.Critical,
		Fix:              "Make the SSH server ask for a key or password for every login (in OpenSSH, set PermitEmptyPasswords no). On a device where you can't change that, update its firmware or turn SSH off.",
		RemediationID:    "ssh-public-key-only",
		RemediationTitle: "Require SSH public-key authentication",
		RemediationFix:   check.SSHKeyOnlyFix,
		Ports:            []int{22},
		Services:         []string{"ssh"},
		References: []check.Reference{
			{Title: "RFC 4252: The Secure Shell (SSH) Authentication Protocol", URL: "https://datatracker.ietf.org/doc/html/rfc4252"},
			{Title: "OpenSSH sshd_config Manual", URL: "https://man.openbsd.org/sshd_config"},
			{Title: "CWE-306: Missing Authentication for Critical Function", URL: "https://cwe.mitre.org/data/definitions/306.html"},
		},
	}
}

// Run tries the "none" login and reports a finding if the server lets us in.
func (c Check) Run(ctx context.Context, t check.Target) (*check.Result, error) {
	ask := c.Ask
	if ask == nil {
		ask = sshprobe.AuthMethods
	}
	a, err := ask(ctx, t.Address(), user)
	if err != nil {
		return nil, err
	}
	if !a.NoAuth {
		return nil, nil
	}
	return &check.Result{Evidence: fmt.Sprintf("%s let us log in as %q with no password or key", a.Banner, user)}, nil
}
