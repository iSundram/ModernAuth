// Package http provides HTTP handlers for ModernAuth API.
// This file contains user impersonation handlers for admin support.
package http

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/auth"
)

// ImpersonateUserRequest represents a request to impersonate a user.
type ImpersonateUserRequest struct {
	Reason string `json:"reason"`
}

// ImpersonateUser handles POST /v1/admin/users/{id}/impersonate
func (h *Handler) ImpersonateUser(w http.ResponseWriter, r *http.Request) {
	// Get admin user ID from context
	adminUserID, err := getUserIDFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required", err)
		return
	}

	// Get target user ID from URL
	targetUserIDStr := chi.URLParam(r, "id")
	targetUserID, err := uuid.Parse(targetUserIDStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid user ID", err)
		return
	}

	// Parse request body
	var req ImpersonateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Reason is optional, so ignore decode errors
		req.Reason = ""
	}

	// Check if impersonation is enabled
	enabled := true
	if setting, err := h.storage.GetSetting(r.Context(), "impersonation_enabled"); err == nil && setting != nil {
		if v, ok := setting.Value.(string); ok && v == "false" {
			enabled = false
		}
	}

	if !enabled {
		h.writeError(w, http.StatusForbidden, "User impersonation is disabled", nil)
		return
	}

	// Get session TTL
	sessionTTL := 30 // Default 30 minutes
	if setting, err := h.storage.GetSetting(r.Context(), "impersonation_session_ttl_minutes"); err == nil && setting != nil {
		if v, ok := setting.Value.(string); ok {
			if parsed, err := parseInt(v); err == nil {
				sessionTTL = parsed
			}
		}
	}

	// Start impersonation
	impersonationReq := &auth.ImpersonationRequest{
		AdminUserID:  adminUserID,
		TargetUserID: targetUserID,
		Reason:       req.Reason,
		IPAddress:    r.RemoteAddr,
		UserAgent:    r.Header.Get("User-Agent"),
	}

	result, err := h.authService.StartImpersonation(r.Context(), impersonationReq, sessionTTL)
	if err != nil {
		switch err {
		case auth.ErrImpersonationNotAllowed:
			h.writeError(w, http.StatusForbidden, "You do not have permission to impersonate users", err)
		case auth.ErrCannotImpersonateAdmin:
			h.writeError(w, http.StatusForbidden, "Cannot impersonate admin users", err)
		case auth.ErrUserNotFound:
			h.writeError(w, http.StatusNotFound, "Target user not found", err)
		case auth.ErrUserInactive:
			h.writeError(w, http.StatusForbidden, "Target user account is deactivated", err)
		default:
			h.writeError(w, http.StatusInternalServerError, "Failed to start impersonation", err)
		}
		return
	}

	h.logger.Info("User impersonation started",
		"admin_user_id", adminUserID,
		"target_user_id", targetUserID,
		"session_id", result.Session.ID)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"session":    result.Session,
		"tokens":     result.TokenPair,
		"message":    "Impersonation session started",
		"expires_at": result.Session.ExpiresAt,
	})
}

// EndImpersonation handles POST /v1/auth/impersonation/end
func (h *Handler) EndImpersonation(w http.ResponseWriter, r *http.Request) {
	// Get session ID from context
	sessionIDStr, ok := r.Context().Value(sessionIDKey).(string)
	if !ok || sessionIDStr == "" {
		h.writeError(w, http.StatusUnauthorized, "Session not found", nil)
		return
	}

	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid session ID", err)
		return
	}

	// Check if this is an impersonation session
	isImpersonation, adminUserID := h.authService.IsImpersonationSession(r.Context(), sessionID)
	if !isImpersonation {
		h.writeError(w, http.StatusBadRequest, "Not an impersonation session", nil)
		return
	}

	// End impersonation
	if err := h.authService.EndImpersonation(r.Context(), sessionID); err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to end impersonation", err)
		return
	}

	h.logger.Info("Impersonation session ended", "session_id", sessionID, "admin_user_id", adminUserID)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Impersonation session ended",
	})
}

// ListImpersonationSessions handles GET /v1/admin/impersonation-sessions
func (h *Handler) ListImpersonationSessions(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	var adminUserID, targetUserID *uuid.UUID

	if adminIDStr := r.URL.Query().Get("admin_user_id"); adminIDStr != "" {
		if id, err := uuid.Parse(adminIDStr); err == nil {
			adminUserID = &id
		}
	}

	if targetIDStr := r.URL.Query().Get("target_user_id"); targetIDStr != "" {
		if id, err := uuid.Parse(targetIDStr); err == nil {
			targetUserID = &id
		}
	}

	limit := 50
	offset := 0

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsed, err := parseInt(limitStr); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}

	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if parsed, err := parseInt(offsetStr); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	sessions, err := h.authService.ListImpersonationSessions(r.Context(), adminUserID, targetUserID, limit, offset)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to list impersonation sessions", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"sessions": sessions,
		"limit":    limit,
		"offset":   offset,
	})
}

// GetImpersonationStatus handles GET /v1/auth/impersonation/status
func (h *Handler) GetImpersonationStatus(w http.ResponseWriter, r *http.Request) {
	sessionIDStr, ok := r.Context().Value(sessionIDKey).(string)
	if !ok || sessionIDStr == "" {
		h.writeError(w, http.StatusUnauthorized, "Session not found", nil)
		return
	}

	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid session ID", err)
		return
	}

	isImpersonation, adminUserID := h.authService.IsImpersonationSession(r.Context(), sessionID)

	response := map[string]interface{}{
		"is_impersonation": isImpersonation,
	}

	if isImpersonation && adminUserID != nil {
		response["admin_user_id"] = adminUserID.String()
		
		// Get admin user details
		if adminUser, err := h.storage.GetUserByID(r.Context(), *adminUserID); err == nil && adminUser != nil {
			response["admin_user_email"] = adminUser.Email
		}
	}

	writeJSON(w, http.StatusOK, response)
}
