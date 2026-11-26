// Package telnet flags open Telnet services.
//
// This is the simplest kind of check, it needs no network traffic of its own.
// Nmap already told us the service is Telnet, so the check only explains why
// that's a problem.
package telnet

import (
	"context"
	"fmt"
	"strings"

	"github.com/nuqs-org/nuqs/internal/check"
	"github.com/nuqs-org/nuqs/internal/model"
)

// Check reports Telnet servers.
type Check struct{}

// Info describes the check.
func (Check) Info() check.Info {
	return check.Info{
		ID:               "telnet-open",
		Title:            "Unencrypted Telnet server",
		Description:      "Telnet has no encryption, so everything typed in a session crosses the network in the clear.\nSomeone on the same Wi-Fi or LAN can capture logins, see every command and take over the session.",
		Severity:         model.Medium,
		Fix:              "Turn off Telnet and use SSH instead. Telnet sends passwords as plain text, so anyone on the network can read them.",
		RemediationTitle: "Replace Telnet with SSH",
		Services:         []string{"telnet"},
		References: []check.Reference{
			{Title: "CWE-319: Cleartext Transmission of Sensitive Information", URL: "https://cwe.mitre.org/data/definitions/319.html"},
			{Title: "RFC 854: Telnet Protocol Specification", URL: "https://datatracker.ietf.org/doc/html/rfc854"},
			{Title: "RFC 4251: The Secure Shell (SSH) Protocol Architecture", URL: "https://datatracker.ietf.org/doc/html/rfc4251"},
		},
	}
}

// Run explains what Nmap found. It never fails. If Nmap only guessed Telnet
// from the port number, the finding is inferred, not confirmed.
func (Check) Run(_ context.Context, t check.Target) (*check.Result, error) {
	if t.Service.Guessed {
		return &check.Result{
			Evidence:   fmt.Sprintf("port %d/%s is open and Nmap guessed Telnet from the port number only", t.Service.Port, t.Service.Protocol),
			Confidence: model.Inferred,
		}, nil
	}
	what := strings.TrimSpace(t.Service.Product + " " + t.Service.Version)
	if what == "" {
		what = "a Telnet server"
	}
	return &check.Result{
		Evidence: fmt.Sprintf("port %d/%s is open and Nmap identified it as %s", t.Service.Port, t.Service.Protocol, what),
	}, nil
}
