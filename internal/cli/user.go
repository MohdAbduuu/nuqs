// Local CLI commands for managing Nuqs user accounts, including password recovery.

package cli

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/nuqs-org/nuqs/internal/auth"
	"github.com/nuqs-org/nuqs/internal/store"
)

const userUsage = `Usage:
  nuqs user reset-password <username>   issue a one-time password reset code
`

func (a *App) user(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(a.Stderr, userUsage)
		return ExitUsage
	}
	switch args[0] {
	case "reset-password":
		return a.userResetPassword(args[1:])
	case "help", "-h", "--help":
		fmt.Fprint(a.Stdout, userUsage)
		return ExitOK
	default:
		fmt.Fprintf(a.Stderr, "unknown user command %q\n\n%s", args[0], userUsage)
		return ExitUsage
	}
}

func (a *App) userResetPassword(args []string) int {
	fs := flag.NewFlagSet("user reset-password", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(a.Stderr, "Usage: nuqs user reset-password <username>")
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(a.Stderr, "expected exactly one username")
		fs.Usage()
		return ExitUsage
	}
	username := strings.TrimSpace(fs.Arg(0))

	st, err := store.Open(a.dataDir())
	if err != nil {
		fmt.Fprintf(a.Stderr, "error: %v\n", err)
		return ExitError
	}
	defer func() { _ = st.Close() }()
	authSvc := auth.NewService(st)
	if a.PBKDF2Iterations > 0 {
		authSvc.Iterations = a.PBKDF2Iterations
	}
	res, err := authSvc.IssueResetCodeByUsername(username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			fmt.Fprintf(a.Stderr, "error: no account named %q exists\n", username)
			return ExitError
		}
		fmt.Fprintf(a.Stderr, "error: %v\n", err)
		return ExitError
	}

	fmt.Fprintf(a.Stdout, "One-time password reset code for %s (valid for 1 hour):\n  %s\n\nExisting sessions for %s have been signed out.\nOpen /reset-password?user=%s in the web UI to set a new password.\n",
		res.Username, res.Code, res.Username, res.Username)
	return ExitOK
}
