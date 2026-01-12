// Package http provides session management HTTP handlers.
package http

import (
	"net/http"

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

	writeJSON(w, http.StatusOK, map[string]string{"message": "All sessions revoked successfully"})
}

// ListSessions handles listing user sessions.
// Note: This can be implemented using the device service's GetLoginHistory
// For now, returns a message directing to the sessions endpoint
func (h *Handler) ListSessions(w http.ResponseWriter, r *http.Request) {
	// This endpoint can be enhanced to list active sessions
	// For now, use /v1/sessions/history for login history via device handler
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Use /v1/sessions/history endpoint for login history",
	})
}
