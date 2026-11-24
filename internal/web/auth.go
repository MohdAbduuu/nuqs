// Authentication, password recovery, account password change and admin users UI handlers.

package web

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/nuqs-org/nuqs/internal/auth"
	"github.com/nuqs-org/nuqs/internal/store"
	"github.com/nuqs-org/nuqs/internal/tools"
)

type authPageData struct {
	Version  string
	Title    string
	Heading  string
	Subtitle string
	Username string
	Code     string
	Next     string
	Notice   string
	Error    string
}

type userRow struct {
	auth.UserView
	IsSelf      bool
	IsLastAdmin bool
}

type usersData struct {
	Users  []userRow
	Issued *auth.ResetCodeResult
	Notice string
	Error  string
}

func (h *Handler) registerAuth(mux *http.ServeMux) {
	if h.Auth == nil {
		return
	}
	mux.HandleFunc("GET /setup", h.setupGet)
	mux.HandleFunc("POST /setup", h.setupPost)
	mux.HandleFunc("GET /login", h.loginGet)
	mux.HandleFunc("POST /login", h.loginPost)
	mux.HandleFunc("POST /logout", h.logoutPost)
	mux.HandleFunc("GET /reset-password", h.resetGet)
	mux.HandleFunc("POST /reset-password", h.resetPost)
	mux.HandleFunc("POST /account/password", h.changePasswordPost)
	mux.HandleFunc("GET /users", h.usersGet)
	mux.HandleFunc("POST /users", h.usersCreatePost)
	mux.HandleFunc("POST /users/{id}/role", h.usersRolePost)
	mux.HandleFunc("POST /users/{id}/reset", h.usersResetPost)
	mux.HandleFunc("POST /users/{id}/delete", h.usersDeletePost)
}

func (h *Handler) requireAdmin(w http.ResponseWriter, r *http.Request) (auth.Principal, bool) {
	if h.Auth == nil {
		http.NotFound(w, r)
		return auth.Principal{}, false
	}
	p, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		http.Error(w, auth.ErrUnauthorized.Error(), http.StatusUnauthorized)
		return auth.Principal{}, false
	}
	if !p.IsAdmin() {
		http.Error(w, auth.ErrForbidden.Error(), http.StatusForbidden)
		return auth.Principal{}, false
	}
	return p, true
}

func (h *Handler) renderAuth(w http.ResponseWriter, r *http.Request, status int, name string, data authPageData) {
	tmpl, ok := h.authPages[name]
	if !ok || tmpl == nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	data.Version = h.version
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "auth_layout", data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	h.writeHTMLStatus(w, r, status, buf.Bytes())
}

func (h *Handler) sameOrigin(r *http.Request) bool {
	return auth.SameOrigin(r, h.HTTPS || r.TLS != nil)
}

func parseLimitedForm(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data.", http.StatusBadRequest)
		return false
	}
	return true
}

// --- First-run setup ---

func (h *Handler) setupGet(w http.ResponseWriter, r *http.Request) {
	h.renderAuth(w, r, http.StatusOK, "setup.html", authPageData{
		Title:    "Set up Nuqs",
		Heading:  "Set up Nuqs",
		Subtitle: "Enter the one-time setup code from your terminal to create the first admin account.",
	})
}

func (h *Handler) setupPost(w http.ResponseWriter, r *http.Request) {
	if !h.sameOrigin(r) {
		http.Error(w, "Open the setup page on this server.", http.StatusForbidden)
		return
	}
	if !parseLimitedForm(w, r) {
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	confirm := r.FormValue("confirm")

	fail := func(status int, msg string) {
		h.renderAuth(w, r, status, "setup.html", authPageData{
			Title:    "Set up Nuqs",
			Heading:  "Set up Nuqs",
			Subtitle: "Enter the one-time setup code from your terminal to create the first admin account.",
			Code:     code,
			Username: username,
			Error:    msg,
		})
	}
	if password != confirm {
		fail(http.StatusBadRequest, "Passwords do not match.")
		return
	}

	_, token, wait, err := h.Auth.CompleteSetup(auth.ClientIP(r), code, username, password)
	var ve *auth.ValidationError
	switch {
	case errors.Is(err, auth.ErrRateLimited):
		setRetryAfter(w, wait)
		fail(http.StatusTooManyRequests, rateLimitMessage(wait))
		return
	case errors.As(err, &ve):
		fail(http.StatusBadRequest, ve.Message)
		return
	case errors.Is(err, store.ErrInvalidCode):
		fail(http.StatusUnauthorized, "That setup code is not valid. Check the terminal where nuqs serve is running.")
		return
	case errors.Is(err, store.ErrSetupClosed):
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	case err != nil:
		fail(http.StatusInternalServerError, "Could not finish setup. Try again.")
		return
	}

	h.Auth.SetSessionCookie(w, r, token)
	http.Redirect(w, r, "/scans", http.StatusSeeOther)
}

// --- Sign in & sign out ---

func (h *Handler) loginGet(w http.ResponseWriter, r *http.Request) {
	h.renderAuth(w, r, http.StatusOK, "login.html", authPageData{
		Title:    "Sign in",
		Heading:  "Sign in to Nuqs",
		Subtitle: "Use your account to access scans and results.",
		Next:     auth.SafeNext(r.URL.Query().Get("next")),
		Notice:   noticeText(r.URL.Query().Get("notice")),
	})
}

func (h *Handler) loginPost(w http.ResponseWriter, r *http.Request) {
	if !h.sameOrigin(r) {
		http.Error(w, "Open the sign-in page on this server.", http.StatusForbidden)
		return
	}
	if !parseLimitedForm(w, r) {
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	nextPath := auth.SafeNext(r.FormValue("next"))

	fail := func(status int, msg string) {
		h.renderAuth(w, r, status, "login.html", authPageData{
			Title:    "Sign in",
			Heading:  "Sign in to Nuqs",
			Subtitle: "Use your account to access scans and results.",
			Username: username,
			Next:     nextPath,
			Error:    msg,
		})
	}

	_, token, wait, err := h.Auth.Login(auth.ClientIP(r), username, password)
	switch {
	case errors.Is(err, auth.ErrRateLimited):
		setRetryAfter(w, wait)
		fail(http.StatusTooManyRequests, rateLimitMessage(wait))
		return
	case errors.Is(err, auth.ErrInvalidCredentials):
		fail(http.StatusUnauthorized, "Invalid username or password.")
		return
	case err != nil:
		fail(http.StatusInternalServerError, "Could not sign in right now. Try again.")
		return
	}

	h.Auth.SetSessionCookie(w, r, token)
	http.Redirect(w, r, nextPath, http.StatusSeeOther)
}

func (h *Handler) logoutPost(w http.ResponseWriter, r *http.Request) {
	if !h.sameOrigin(r) {
		http.Error(w, "Open Nuqs on this server.", http.StatusForbidden)
		return
	}
	_ = h.Auth.Logout(auth.SessionToken(r))
	h.Auth.ClearSessionCookie(w, r)
	http.Redirect(w, r, "/login?notice=signed-out", http.StatusSeeOther)
}

// --- Password reset / invite code ---

func (h *Handler) resetGet(w http.ResponseWriter, r *http.Request) {
	h.renderAuth(w, r, http.StatusOK, "reset_password.html", authPageData{
		Title:    "Set or reset password",
		Heading:  "Set or reset password",
		Subtitle: "Enter your username and one-time code to choose a new password.",
		Username: strings.TrimSpace(r.URL.Query().Get("user")),
	})
}

func (h *Handler) resetPost(w http.ResponseWriter, r *http.Request) {
	if !h.sameOrigin(r) {
		http.Error(w, "Open this page on this server.", http.StatusForbidden)
		return
	}
	if !parseLimitedForm(w, r) {
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	code := strings.TrimSpace(r.FormValue("code"))
	password := r.FormValue("password")
	confirm := r.FormValue("confirm")

	fail := func(status int, msg string) {
		h.renderAuth(w, r, status, "reset_password.html", authPageData{
			Title:    "Set or reset password",
			Heading:  "Set or reset password",
			Subtitle: "Enter your username and one-time code to choose a new password.",
			Username: username,
			Code:     code,
			Error:    msg,
		})
	}
	if password != confirm {
		fail(http.StatusBadRequest, "Passwords do not match.")
		return
	}

	_, wait, err := h.Auth.CompletePasswordReset(auth.ClientIP(r), username, code, password)
	var ve *auth.ValidationError
	switch {
	case errors.Is(err, auth.ErrRateLimited):
		setRetryAfter(w, wait)
		fail(http.StatusTooManyRequests, rateLimitMessage(wait))
		return
	case errors.As(err, &ve):
		fail(http.StatusBadRequest, ve.Message)
		return
	case errors.Is(err, store.ErrCodeExpired):
		fail(http.StatusBadRequest, "That reset code has expired. Ask an admin or run nuqs user reset-password for a new one.")
		return
	case errors.Is(err, store.ErrInvalidCode):
		fail(http.StatusUnauthorized, "Invalid username or reset code.")
		return
	case err != nil:
		fail(http.StatusInternalServerError, "Could not update password. Try again.")
		return
	}

	http.Redirect(w, r, "/login?notice=password-reset", http.StatusSeeOther)
}

// --- Self-service password change ---

func (h *Handler) changePasswordPost(w http.ResponseWriter, r *http.Request) {
	if !h.sameOrigin(r) {
		http.Error(w, "Open Nuqs on this server.", http.StatusForbidden)
		return
	}
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		http.Error(w, auth.ErrUnauthorized.Error(), http.StatusUnauthorized)
		return
	}
	if !parseLimitedForm(w, r) {
		return
	}
	current := r.FormValue("current_password")
	next := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")

	returnTo := r.FormValue("return_to")
	redirectAccount := func(key, value string) {
		dest, _ := url.Parse(auth.SafeNext(returnTo))
		if dest == nil {
			dest = &url.URL{Path: "/scans"}
		}
		q := dest.Query()
		q.Set(key, value)
		dest.RawQuery = q.Encode()
		http.Redirect(w, r, dest.RequestURI(), http.StatusSeeOther)
	}
	renderErr := func(status int, msg, code string) {
		if returnTo != "" {
			redirectAccount("account_error", code)
			return
		}
		data := scansData{SuggestedTarget: suggestedTarget(h.Service.AllowedScope)}
		for _, s := range h.Scans.List() {
			if s.Status == tools.ScanRunning {
				data.Running = s.ID
			}
			data.Rows = append(data.Rows, scanRow{Scan: s, Label: statusLabel(s), Class: statusClass(s), Counts: countOf(s.Report)})
		}
		h.renderStatus(w, r, status, "scans.html", page{
			Title:      "Scans",
			Nav:        "scans",
			Crumbs:     []crumb{{Label: "Scans"}},
			FlashError: msg,
			Data:       data,
		})
	}
	if next != confirm {
		renderErr(http.StatusBadRequest, "New passwords do not match.", "mismatch")
		return
	}
	token, err := h.Auth.ChangePassword(principal.UserID, current, next)
	var ve *auth.ValidationError
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		renderErr(http.StatusUnauthorized, "Current password is incorrect.", "current-password")
		return
	case errors.As(err, &ve):
		renderErr(http.StatusBadRequest, ve.Message, "invalid-password")
		return
	case err != nil:
		renderErr(http.StatusInternalServerError, "Could not update password.", "update")
		return
	}
	h.Auth.SetSessionCookie(w, r, token)
	redirectAccount("notice", "password-updated")
}

// --- Admin users page ---

func (h *Handler) usersGet(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}
	h.renderUsers(w, r, http.StatusOK, actor, nil, "", "")
}

func (h *Handler) usersCreatePost(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}
	if !h.sameOrigin(r) {
		http.Error(w, "Open the users page on this server.", http.StatusForbidden)
		return
	}
	if !parseLimitedForm(w, r) {
		return
	}
	username := r.FormValue("username")
	role := store.Role(strings.TrimSpace(r.FormValue("role")))
	_, code, err := h.Auth.CreateUser(username, role)
	var ve *auth.ValidationError
	switch {
	case errors.As(err, &ve):
		h.renderUsers(w, r, http.StatusBadRequest, actor, nil, "", ve.Message)
		return
	case err != nil:
		h.renderUsers(w, r, http.StatusInternalServerError, actor, nil, "", "Could not create user.")
		return
	}
	h.renderUsers(w, r, http.StatusCreated, actor, &code, fmt.Sprintf("Created account %q.", code.Username), "")
}

func (h *Handler) usersRolePost(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}
	if !h.sameOrigin(r) {
		http.Error(w, "Open the users page on this server.", http.StatusForbidden)
		return
	}
	if !parseLimitedForm(w, r) {
		return
	}
	role := store.Role(strings.TrimSpace(r.FormValue("role")))
	_, err := h.Auth.UpdateRole(r.PathValue("id"), role)
	var ve *auth.ValidationError
	switch {
	case errors.As(err, &ve):
		h.renderUsers(w, r, http.StatusBadRequest, actor, nil, "", ve.Message)
		return
	case errors.Is(err, store.ErrLastAdmin):
		h.renderUsers(w, r, http.StatusConflict, actor, nil, "", "At least one admin account must remain.")
		return
	case errors.Is(err, store.ErrNotFound):
		h.renderUsers(w, r, http.StatusNotFound, actor, nil, "", "User not found.")
		return
	case err != nil:
		h.renderUsers(w, r, http.StatusInternalServerError, actor, nil, "", "Could not update role.")
		return
	}
	http.Redirect(w, r, "/users?notice=role-updated", http.StatusSeeOther)
}

func (h *Handler) usersResetPost(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}
	if !h.sameOrigin(r) {
		http.Error(w, "Open the users page on this server.", http.StatusForbidden)
		return
	}
	res, err := h.Auth.IssueResetCode(r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		h.renderUsers(w, r, http.StatusNotFound, actor, nil, "", "User not found.")
		return
	case err != nil:
		h.renderUsers(w, r, http.StatusInternalServerError, actor, nil, "", "Could not generate reset code.")
		return
	}
	h.renderUsers(w, r, http.StatusOK, actor, &res, fmt.Sprintf("Existing sessions for %q have been signed out.", res.Username), "")
}

func (h *Handler) usersDeletePost(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.requireAdmin(w, r)
	if !ok {
		return
	}
	if !h.sameOrigin(r) {
		http.Error(w, "Open the users page on this server.", http.StatusForbidden)
		return
	}
	err := h.Auth.DeleteUser(actor.UserID, r.PathValue("id"))
	switch {
	case errors.Is(err, auth.ErrSelfDelete):
		h.renderUsers(w, r, http.StatusBadRequest, actor, nil, "", "You cannot remove your own account.")
		return
	case errors.Is(err, store.ErrLastAdmin):
		h.renderUsers(w, r, http.StatusConflict, actor, nil, "", "At least one admin account must remain.")
		return
	case errors.Is(err, store.ErrNotFound):
		h.renderUsers(w, r, http.StatusNotFound, actor, nil, "", "User not found.")
		return
	case err != nil:
		h.renderUsers(w, r, http.StatusInternalServerError, actor, nil, "", "Could not remove user.")
		return
	}
	http.Redirect(w, r, "/users?notice=user-removed", http.StatusSeeOther)
}

func (h *Handler) renderUsers(w http.ResponseWriter, r *http.Request, status int, actor auth.Principal, issued *auth.ResetCodeResult, notice, errMsg string) {
	list, err := h.Auth.ListUsers()
	if err != nil {
		http.Error(w, "Could not load users.", http.StatusInternalServerError)
		return
	}
	admins := 0
	for _, u := range list {
		if u.Role == store.RoleAdmin && !u.PendingPassword {
			admins++
		}
	}
	rows := make([]userRow, 0, len(list))
	for _, u := range list {
		rows = append(rows, userRow{
			UserView:    u,
			IsSelf:      u.ID == actor.UserID,
			IsLastAdmin: u.Role == store.RoleAdmin && !u.PendingPassword && admins <= 1,
		})
	}
	h.renderStatus(w, r, status, "users.html", page{
		Title:  "Users",
		Nav:    "users",
		Crumbs: []crumb{{Label: "Users"}},
		Data:   usersData{Users: rows, Issued: issued, Notice: notice, Error: errMsg},
	})
}

func setRetryAfter(w http.ResponseWriter, wait time.Duration) {
	secs := int(wait.Round(time.Second).Seconds())
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
}

func rateLimitMessage(wait time.Duration) string {
	mins := int(wait.Minutes())
	if mins >= 1 {
		if mins == 1 {
			return "Too many failed attempts. Try again in about 1 minute."
		}
		return fmt.Sprintf("Too many failed attempts. Try again in about %d minutes.", mins)
	}
	secs := int(wait.Seconds())
	if secs < 1 {
		secs = 1
	}
	return fmt.Sprintf("Too many failed attempts. Try again in %d seconds.", secs)
}

func noticeText(code string) string {
	switch code {
	case "password-reset":
		return "Password saved. Sign in with your new password."
	case "signed-out":
		return "You have been signed out."
	case "password-updated":
		return "Your password has been updated."
	case "role-updated":
		return "Role updated."
	case "user-removed":
		return "Account removed."
	default:
		return ""
	}
}

func userInitials(username string) string {
	var out []rune
	for _, r := range strings.TrimSpace(username) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			out = append(out, unicode.ToUpper(r))
			if len(out) == 2 {
				break
			}
		}
	}
	if len(out) == 0 {
		return "U"
	}
	return string(out)
}
