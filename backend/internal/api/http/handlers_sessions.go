// Package http provides session management HTTP handlers.
package http

import (
	"context"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/auth"
)

// RevokeAllSessions handles revoking all user sessions.
func (h *Handler) RevokeAllSessions(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	err = h.authService.RevokeAllSessions(r.Context(), &auth.RevokeAllSessionsRequest{
		UserID:    userID,
		IP:        r.RemoteAddr,
		UserAgent: r.UserAgent(),
	})

	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to revoke sessions", err)
		return
	}

	// Send session revoked notification email
	go func() {
		user, err := h.storage.GetUserByID(context.Background(), userID)
		if err != nil || user == nil {
			h.logger.Error("Failed to get user for session revoked email", "error", err, "user_id", userID)
			return
		}
		if err := h.emailService.SendSessionRevokedEmail(context.Background(), user, "All sessions revoked by user request"); err != nil {
			h.logger.Error("Failed to send session revoked email", "error", err, "user_id", userID)
		}
	}()

	writeJSON(w, http.StatusOK, map[string]string{"message": "All sessions revoked successfully"})
}

// ListSessions handles listing active user sessions.
func (h *Handler) ListSessions(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	// Parse pagination
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit := 50
	offset := 0

	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	if offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	sessions, err := h.authService.GetUserSessions(r.Context(), userID, limit, offset)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to get sessions", err)
		return
	}

	response := make([]SessionResponse, len(sessions))
	for i, session := range sessions {
		response[i] = SessionResponse{
			ID:        session.ID.String(),
			UserID:    session.UserID.String(),
			CreatedAt: session.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			ExpiresAt: session.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
			Revoked:   session.Revoked,
			IsCurrent: false, // Would need to check against current session ID
		}
		if session.TenantID != nil {
			id := session.TenantID.String()
			response[i].TenantID = &id
		}
		if session.DeviceID != nil {
			id := session.DeviceID.String()
			response[i].DeviceID = &id
		}
		if session.Fingerprint != nil {
			response[i].Fingerprint = session.Fingerprint
		}
		if session.Metadata != nil {
			response[i].Metadata = session.Metadata
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data":   response,
		"limit":  limit,
		"offset": offset,
		"count":  len(response),
	})
}

// RevokeSession revokes a single session by ID (must belong to current user).
func (h *Handler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	sessionIDStr := chi.URLParam(r, "id")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid session ID", err)
		return
	}

	err = h.authService.RevokeSession(r.Context(), userID, sessionID)
	if err != nil {
		if err == auth.ErrSessionRevoked {
			h.writeError(w, http.StatusNotFound, "Session not found or already revoked", err)
			return
		}
		h.writeError(w, http.StatusInternalServerError, "Failed to revoke session", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Session revoked successfully"})
}
