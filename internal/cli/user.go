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
  nuqs user reset-password [--data <dir>] <username>   issue a one-time password reset code
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
	dataDir := fs.String("data", a.dataDir(), "directory containing nuqs.db (default: NUQS_DATA_DIR or user config dir)")
	fs.Usage = func() {
		fmt.Fprintln(a.Stderr, "Usage: nuqs user reset-password [--data <dir>] <username>")
		fs.PrintDefaults()
	}

	// Accept flags before or after the username, just like "nuqs scan".
	var positional []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return ExitOK
			}
			return ExitUsage
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	if len(positional) != 1 {
		fmt.Fprintln(a.Stderr, "expected exactly one username")
		fs.Usage()
		return ExitUsage
	}
	username := strings.TrimSpace(positional[0])

	st, err := store.Open(*dataDir)
	if err != nil {
		fmt.Fprintf(a.Stderr, "error: %v\n", err)
		return ExitError
	}
	defer func() { _ = st.Close() }()
	authSvc := auth.NewService(st, auth.Options{Iterations: a.PBKDF2Iterations})
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
