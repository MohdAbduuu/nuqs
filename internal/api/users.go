// Admin-only /api/users endpoints for creating teammates, changing roles, resetting passwords and deleting accounts.

package api

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/nuqs-org/nuqs/internal/auth"
	"github.com/nuqs-org/nuqs/internal/store"
)

type createUserRequest struct {
	Username string     `json:"username"`
	Role     store.Role `json:"role"`
}

type createUserResponse struct {
	User      auth.UserView `json:"user"`
	ResetCode string        `json:"reset_code"`
}

type updateRoleRequest struct {
	Role store.Role `json:"role"`
}

func (h *Handler) registerUsers(mux *http.ServeMux) {
	if h.Auth == nil {
		return
	}
	mux.HandleFunc("GET /api/users", h.listUsers)
	mux.HandleFunc("POST /api/users", h.createUser)
	mux.HandleFunc("PATCH /api/users/{id}", h.updateUserRole)
	mux.HandleFunc("POST /api/users/{id}/reset-password", h.resetUserPassword)
	mux.HandleFunc("DELETE /api/users/{id}", h.deleteUser)
}

func (h *Handler) requireAdmin(w http.ResponseWriter, r *http.Request) (auth.Principal, bool) {
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

func (h *Handler) listUsers(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}
	users, err := h.Auth.ListUsers()
	if err != nil {
		http.Error(w, "Could not load users.", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (h *Handler) createUser(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}
	if !h.sameOrigin(r) {
		http.Error(w, "Open the users page on this server.", http.StatusForbidden)
		return
	}
	var in createUserRequest
	if !decodeJSONBody(w, r, &in) {
		return
	}
	user, code, err := h.Auth.CreateUser(in.Username, in.Role)
	var ve *auth.ValidationError
	switch {
	case errors.As(err, &ve):
		http.Error(w, ve.Message, http.StatusBadRequest)
		return
	case err != nil:
		http.Error(w, "Could not create user.", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, createUserResponse{User: user, ResetCode: code.Code})
}

func (h *Handler) updateUserRole(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}
	if !h.sameOrigin(r) {
		http.Error(w, "Open the users page on this server.", http.StatusForbidden)
		return
	}
	var in updateRoleRequest
	if !decodeJSONBody(w, r, &in) {
		return
	}
	user, err := h.Auth.UpdateRole(r.PathValue("id"), in.Role)
	var ve *auth.ValidationError
	switch {
	case errors.As(err, &ve):
		http.Error(w, ve.Message, http.StatusBadRequest)
		return
	case errors.Is(err, store.ErrNotFound):
		http.Error(w, "No user with that ID.", http.StatusNotFound)
		return
	case errors.Is(err, store.ErrLastAdmin):
		http.Error(w, "At least one admin account must remain.", http.StatusConflict)
		return
	case err != nil:
		http.Error(w, "Could not update role.", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (h *Handler) resetUserPassword(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdmin(w, r); !ok {
		return
	}
	if !h.sameOrigin(r) {
		http.Error(w, "Open the users page on this server.", http.StatusForbidden)
		return
	}
	res, err := h.Auth.IssueResetCode(r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		http.Error(w, "No user with that ID.", http.StatusNotFound)
		return
	case err != nil:
		http.Error(w, "Could not create password reset code.", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (h *Handler) deleteUser(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, auth.ErrSelfDelete.Error(), http.StatusBadRequest)
		return
	case errors.Is(err, store.ErrLastAdmin):
		http.Error(w, "At least one admin account must remain.", http.StatusConflict)
		return
	case errors.Is(err, store.ErrNotFound):
		http.Error(w, "No user with that ID.", http.StatusNotFound)
		return
	case err != nil:
		http.Error(w, "Could not delete user.", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		http.Error(w, "Expected application/json.", http.StatusUnsupportedMediaType)
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil || !errors.Is(dec.Decode(&struct{}{}), io.EOF) {
		http.Error(w, "Invalid JSON body.", http.StatusBadRequest)
		return false
	}
	return true
}
