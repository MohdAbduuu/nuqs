// HTTP session cookies, same-origin CSRF checks, context helpers and auth gate middleware.

package auth

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

// SessionCookieName is the HTTP-only cookie carrying the active session token.
const SessionCookieName = "nuqs_session"

type principalKey struct{}

// WithPrincipal returns a copy of ctx carrying p.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFromContext retrieves the authenticated principal from ctx, if any.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

// SetSessionCookie writes the session cookie with strict browser security flags.
func (s *Service) SetSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.HTTPS || r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(s.SessionTTL.Seconds()),
	})
}

// ClearSessionCookie expires the session cookie on the client browser.
func (s *Service) ClearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.HTTPS || r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// SessionToken reads the raw session cookie value from r, or "".
func SessionToken(r *http.Request) string {
	c, err := r.Cookie(SessionCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// SameOrigin verifies that a state-changing request came from this server's
// exact scheme and Host, preventing cross-site request forgery.
func SameOrigin(r *http.Request, https bool) bool {
	if r.Host == "" {
		return false
	}
	scheme := "http"
	if https || r.TLS != nil {
		scheme = "https"
	}
	want := scheme + "://" + r.Host
	origin := r.Header.Get("Origin")
	if origin != "" && origin != "null" {
		return origin == want
	}
	return r.Header.Get("Sec-Fetch-Site") == "same-origin"
}

// SafeNext validates a post-login redirect target as a local relative path so
// open redirects to external origins are impossible.
func SafeNext(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.Contains(raw, "\\") {
		return "/scans"
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return "/scans"
	}
	switch u.Path {
	case "", "/", "/login", "/setup", "/logout", "/reset-password":
		return "/scans"
	}
	return raw
}

// Gate enforces first-run setup gating, session authentication, cache control
// and HSTS across both the web UI and JSON API routes.
func (s *Service) Gate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.HTTPS || r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		path := r.URL.Path
		if strings.HasPrefix(path, "/static/") || path == "/favicon.ico" {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")

		needed, err := s.NeedsSetup()
		if err != nil {
			setGateSecurityHeaders(w)
			http.Error(w, "Auth store error.", http.StatusInternalServerError)
			return
		}
		if needed {
			if path == "/setup" {
				next.ServeHTTP(w, r)
				return
			}
			setGateSecurityHeaders(w)
			if isAPIPath(path) {
				http.Error(w, "Initial setup required. Open /setup in your browser.", http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/setup", http.StatusFound)
			return
		}

		// Setup is complete: permanently close /setup.
		if path == "/setup" {
			setGateSecurityHeaders(w)
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			http.Error(w, "Initial setup is already complete.", http.StatusForbidden)
			return
		}

		// Resolve session if present.
		principal, ok, err := s.ResolveSession(SessionToken(r))
		if err != nil {
			setGateSecurityHeaders(w)
			http.Error(w, "Auth store error.", http.StatusInternalServerError)
			return
		}
		if ok {
			r = r.WithContext(WithPrincipal(r.Context(), principal))
			if path == "/login" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
				setGateSecurityHeaders(w)
				http.Redirect(w, r, "/scans", http.StatusFound)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// Unauthenticated access is allowed only to /login and /reset-password.
		if path == "/login" || path == "/reset-password" {
			next.ServeHTTP(w, r)
			return
		}
		setGateSecurityHeaders(w)
		if isAPIPath(path) {
			http.Error(w, "Authentication required.", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			target := "/login"
			if nextPath := SafeNext(r.URL.RequestURI()); nextPath != "/scans" {
				target = "/login?next=" + url.QueryEscape(nextPath)
			}
			http.Redirect(w, r, target, http.StatusFound)
			return
		}
		http.Error(w, "Authentication required.", http.StatusUnauthorized)
	})
}

func setGateSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "same-origin")
}

func isAPIPath(path string) bool {
	return path == "/api" || strings.HasPrefix(path, "/api/")
}
