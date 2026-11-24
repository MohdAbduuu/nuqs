<!-- Design notes for the embedded Nuqs web UI served by nuqs serve. -->
# Scan workspace UI

The embedded web UI in `internal/web/` (backed by `internal/store/`, `internal/auth/`, `internal/api/` and `internal/tools/`)
implements first-run setup, account sign-in, role-based access control, team user management,
the scans list, new scan flow, results and check library described in
[the web UI plan](docs/ui/building.md), served directly from the `nuqs` binary via `nuqs serve`.

The pages follow the usual scanner flow, in our own look and words. Every page has
its own URL, so back, refresh and links all work:

- **First-run setup & sign-in**: the first time `nuqs serve` starts with no accounts, it
  prints a one-time setup code in the terminal. Opening the UI prompts for that code plus
  an admin username and password, then disables setup permanently. After that, users sign
  in with sessions (rate-limited, PBKDF2-hashed passwords persisted in `internal/store/`).
- **Users** (admin only): add teammates with `admin` or `user` roles, change
  roles, issue one-time password reset codes (also available from the server CLI via
  `nuqs user reset-password <name>`) and remove accounts.
- **Scans** (home): every scan with its type, status, operator (`started_by`), real duration and findings.
- **New scan**: scan type cards grouped into Discovery and Vulnerabilities, then a
  settings page with Basic, Discovery and Advanced sections on the left, like System
  Settings. Changing a setting keeps the type and adds a "modified" tag. The target
  field counts addresses and flags mistakes while typing, and asks first when the
  target is over 1,024 addresses.
- **Scan results**: Hosts and Vulnerabilities tabs, a Scan details panel with a
  severity ring, and checks that couldn't finish kept apart from findings. While it
  runs, the page shows live progress over Server-Sent Events and reloads when done.
  Stop keeps what was found so far.
- **Host** and **Vulnerability** pages, each with what we saw and how to fix it.
- **Check library**, searchable with htmx.

Scans run on the server in the background, one at a time, so closing the tab
doesn't stop them. Every scan, account, session and recovery code is saved in
SQLite (`nuqs.db` via `internal/store/`), so history and sign-ins survive restarts.
The browser keeps no copy of any report.

A quiet, Mac-style workspace: a translucent sidebar like Finder that folds down to
icons, a toolbar with the page path and the page's buttons, and cards on a plain
canvas. The sidebar footer shows the signed-in account and role, with an account dialog
for changing passwords and signing out. Appearance follows
the system setting until the user picks light or dark in the toolbar. System fonts
only, nothing to download. Severity colours are used only for severity, and
reduced-motion turns off the spinner and pulse.
