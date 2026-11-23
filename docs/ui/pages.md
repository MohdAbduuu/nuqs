<!-- Every screen in the web UI, what's on it, and the week we build it. -->

# Pages

Every screen in the UI. The week says when it's built, see the [roadmap](../roadmap.md).

Wireframes for each page are made in W1 and saved in `docs/ui/wireframes/`.

## For FYP-I (by 5 Dec)

### Setup, Login & Password Reset (W2)

- **First-run setup (`/setup`):** enter the one-time setup code printed in the terminal when `nuqs serve` starts with no accounts, then choose the first admin username and password. Once claimed, the code stops working permanently.
- **Sign in (`/login`):** username and password with rate limiting and persisted server-side sessions (`HttpOnly`, `SameSite=Strict`, `Secure` on HTTPS).
- **Set or reset password (`/reset-password`):** enter a username and a one-time reset code issued by an admin on `/users` or via `nuqs user reset-password <name>` on the server.

### Users (Admin only)

- Add teammates with a role (`admin` or `user`) and receive a one-time code so they choose their own password
- Change roles, issue password reset codes (revoking existing sessions) and remove accounts (with self-delete protection and a requirement that at least one admin who can sign in remains)

### Scans (W2)

The home page, like the scan list in other scanners:

- Every scan: name, targets, type, status with the real time it took, and findings by severity
- A **New scan** button in the toolbar
- With no scans yet, a **Scan 127.0.0.1** button that just starts one

### New scan (W2)

Two steps, the usual scanner flow:

1. **Pick a scan type** from cards grouped into Discovery and Vulnerabilities: Discover hosts (coming with the discover work), Quick, Full and Custom
2. **Settings** for that type, in sections on the left like System Settings:
   - **Basic:** name, description and targets, with a live address count, a **Use my network** button, and a check before scans over 1,024 addresses
   - **Discovery:** port presets in plain words, ping or not, faster service detection
   - **Advanced:** check timeout and checks at once
   - **Launch** and **Cancel** in the toolbar. Changing a setting keeps the type and adds a **modified** tag
- If the target isn't in the allowed list, it says so before the scan starts, not after

### Scan keyboard shortcuts

- Press **Enter** in a single-line scan settings field to launch the scan.
- Press **Escape** on a running scan page to open the stop confirmation. Open dialogs and text fields keep their own keyboard behavior.

### Scan results (W2)

The main screen. Three tabs:

- **By fix** (default): one row per fix, like "Update OpenSSH to 9.8, fixes 6 findings on 3 hosts", sorted by risk
- **By host:** each host, its open ports and its findings
- **All findings:** a plain table you can sort and filter by severity, host, check and confidence

A short **since last scan** line at the top: "2 new, 3 fixed, 10 still open".

Finished scans can be exported as JSON, a self-contained printable HTML report,
PDF or spreadsheet-ready CSV.

### Finding detail (W2)

- Title, severity and **confirmed** or **inferred**
- **What we saw:** the evidence, exactly as the server sent it
- **How to fix it:** the fix text, and the CVE links if there are any
- First seen and last seen
- A **Check again** button that re-runs just this check on just this host

### History (W2)

Every past scan: when, target, how long it took, findings. Tick any two to compare them.

### Compare (W2)

Two scans side by side: **new**, **fixed** and **still open**, each as its own list.

## For FYP-II

| Page | Week | What it adds |
|---|---|---|
| Live scan | W6 | Hosts filling in as they finish, what's running right now, time left, a stop button |
| Beginner mode | W6 | A **Scan my network** button on Home, finds the local network by itself |
| Checks | W6 | Every check, what it looks for in plain words, and its fix |
| Data feeds | W6 | How fresh each vulnerability source is, an **Update now** button |
| Credentials | W7 | Add SSH logins, with a **Test** button that says exactly what's wrong |
| Verify | W9 | **Verify** and **How do I fix this?** buttons on a finding, every AI step shown |
| Reports | W10 | Download HTML, PDF, CSV or SARIF, summary or technical |
| Schedules and alerts | W10 | Run scans daily or weekly, send email or webhook alerts |
| Windows credentials | W11 | WinRM logins, with the same **Test** button |
| Workers | W12 | Scan workers on other networks, online or offline |
| Audit log | W12 | Audit log of sign-ins, role changes and scans |

## The look

- Clean and quiet, lots of white space, like the logo: dark ink, one teal accent
- Severity colours used only for severity: critical, high, medium, low, info
- Light and dark mode (W6)
- Works on a phone, the tables turn into cards on small screens
- System fonts, nothing to download
