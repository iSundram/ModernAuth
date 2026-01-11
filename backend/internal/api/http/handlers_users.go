// Package http provides user management HTTP handlers.
package http

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/auth"
)

// ListUsers handles requests to list all users.
func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	// Parse pagination parameters
	limit := 50
	offset := 0

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if parsed, err := strconv.Atoi(offsetStr); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	result, err := h.authService.ListUsers(r.Context(), limit, offset)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to list users", err)
		return
	}

	users := make([]UserResponse, len(result.Users))
	for i, user := range result.Users {
		users[i] = UserResponse{
			ID:              user.ID.String(),
			Email:           user.Email,
			Username:        user.Username,
			IsEmailVerified: user.IsEmailVerified,
			CreatedAt:       user.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		}
	}

	response := map[string]interface{}{
		"users":    users,
		"total":    result.Total,
		"limit":    result.Limit,
		"offset":   result.Offset,
		"has_more": result.HasMore,
	}

	writeJSON(w, http.StatusOK, response)
}

// CreateUser handles user creation by admin.
func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	result, err := h.authService.Register(r.Context(), &auth.RegisterRequest{
		Email:    req.Email,
		Password: req.Password,
		Username: req.Username,
	})

	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to create user", err)
		return
	}

	response := UserResponse{
		ID:              result.User.ID.String(),
		Email:           result.User.Email,
		Username:        result.User.Username,
		IsEmailVerified: result.User.IsEmailVerified,
		CreatedAt:       result.User.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	writeJSON(w, http.StatusCreated, response)
}

// GetUser handles requests for a specific user.
func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid user ID", err)
		return
	}

	user, err := h.authService.GetUserByID(r.Context(), id)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to get user", err)
		return
	}
	if user == nil {
		h.writeError(w, http.StatusNotFound, "User not found", nil)
		return
	}

	response := UserResponse{
		ID:              user.ID.String(),
		Email:           user.Email,
		Username:        user.Username,
		IsEmailVerified: user.IsEmailVerified,
		CreatedAt:       user.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	writeJSON(w, http.StatusOK, response)
}

// UpdateUser handles user updates.
func (h *Handler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid user ID", err)
		return
	}

	var req UpdateUserHTTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if errors := ValidateStruct(req); errors != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "Validation failed",
			"details": errors,
		})
		return
	}

	user, err := h.authService.UpdateUser(r.Context(), &auth.UpdateUserRequest{
		UserID:   id,
		Email:    req.Email,
		Username: req.Username,
		Phone:    req.Phone,
	})

	if err != nil {
		switch err {
		case auth.ErrUserNotFound:
			h.writeError(w, http.StatusNotFound, "User not found", err)
		case auth.ErrUserExists:
			h.writeError(w, http.StatusConflict, "Email already in use", err)
		default:
			h.writeError(w, http.StatusInternalServerError, "Failed to update user", err)
		}
		return
	}

	response := UserResponse{
		ID:              user.ID.String(),
		Email:           user.Email,
		Username:        user.Username,
		IsEmailVerified: user.IsEmailVerified,
		CreatedAt:       user.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	writeJSON(w, http.StatusOK, response)
}

// DeleteUser handles user deletion.
func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid user ID", err)
		return
	}

	// Get actor ID from context
	actorID, err := getUserIDFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	err = h.authService.DeleteUser(r.Context(), id, &actorID)
	if err != nil {
		switch err {
		case auth.ErrUserNotFound:
			h.writeError(w, http.StatusNotFound, "User not found", err)
		default:
			h.writeError(w, http.StatusInternalServerError, "Failed to delete user", err)
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "User deleted successfully"})
}
