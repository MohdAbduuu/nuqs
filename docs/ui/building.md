<!-- How the web UI is built: the tech, the folders, security and testing. -->

# How we build it

## The short version

Plain HTML pages made by Go on the server, with [htmx](https://htmx.org) for the parts that update without a reload. Everything is embedded in the `nuqs` binary. No npm, no build step, no separate frontend app.

## Why this way

| We picked | Instead of | Because |
|---|---|---|
| A web page served by `nuqs` | A desktop app (Qt) | Works on every OS and from any machine on the network, see [Decisions](../design/decisions.md) |
| HTML from Go templates, plus htmx | React or Vue | No Node toolchain, no build step, one language for the whole team. Go's templates escape everything by default, which matters a lot here (see Security). |
| htmx, one small file (about 14 KB zipped) we keep in the repo | A JS framework | Forms, tabs, filters and live updates with HTML attributes, not hundreds of lines of JS |
| Server-Sent Events for live progress | The browser asking every few seconds | The server pushes only what changed, the fix for Nessus' "are you done?" every 4 seconds |
| Our own small CSS file | A CSS framework | One file, nothing to download, easy to keep looking like Nuqs |

htmx is a JavaScript file, not a Go dependency, so the Go code stays standard library only.

## How it fits in

```
browser ──► nuqs serve (net/http)
              ├── /        HTML pages and fragments   (internal/web)
              └── /api/    JSON plus report downloads for scripts and CI  (internal/api)
                     │
                     ▼
              internal/tools  ← one set of actions: scan, results, diff, history
                     │
              engine, store, checks  (the same code the CLI uses)
```

The UI and the JSON API are two thin layers over the same actions. Neither one has scan logic of its own. So the CLI, the API and the UI always give the same answer.

## Folders

```
internal/web/
  web.go            routes and handlers
  templates/        one .html file per page, plus small parts (finding row, severity badge)
  static/
    nuqs.css        all the styles
    htmx.min.js     htmx itself
    logo.svg
```

Templates and static files are put inside the binary with Go's `embed`, so there's still one file to ship.

## How a page works

1. The browser asks for `/scans/12`.
2. The handler gets the results through `internal/tools`.
3. It fills the `results.html` template and sends the page.
4. Clicking the **By host** tab asks for only that part, and htmx swaps it in. No full reload.

Live progress (W6) works the same way: the page listens on `/scans/12/events`, and each event swaps in the updated part.

## Security

A vulnerability tool shows text that comes from the machines it scans. A hostile server can put HTML or script in its banner, so we're strict about this:

- **Everything is escaped.** We use `html/template`, which escapes by default. Never `template.HTML` on anything that came from a scan.
- **Strict Content-Security-Policy:** scripts only from our own files, no inline scripts. Even if something slips through, it can't run.
- **Accounts & sessions:** first-run setup is gated by a one-time terminal code so nobody can claim the first admin without host access. Passwords are hashed with Go's standard library `crypto/pbkdf2` (PBKDF2-HMAC-SHA256, 600,000 iterations), auth endpoints are rate-limited, and session tokens are stored hashed with `HttpOnly`, `Secure` (on HTTPS) and `SameSite=Strict` cookies.
- **Roles:** `admin` and `user` permissions are enforced server-side on every web and API route.
- **Changes need POST,** and we check the `Origin` header, so other sites can't start scans or modify accounts for you.
- **Allowed targets:** the server refuses to scan anything outside the list in the config, whatever the browser sends.

## Testing

| What | How | When |
|---|---|---|
| Every handler | Go's `httptest`: right page, right status, no token means no access | from W2 |
| Escaping | A fake finding with `<script>` in its evidence must show up as plain text on every page | from W2 |
| Templates | Every template renders with empty data and with lots of data without errors | from W2 |
| The whole flow | Playwright in CI: scan the lab, open a finding, compare two scans | from W6 |
| Accessibility | An automatic check (axe) on every page in the Playwright run | from W6 |

## Who does what

The API and UI owners build `internal/web` and `internal/api`. The core and CLI owner builds `internal/tools` and keeps it stable. If the UI needs something new, it's added to `internal/tools` first, so the CLI gets it too.
