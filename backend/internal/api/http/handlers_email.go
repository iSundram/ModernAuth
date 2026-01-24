// Package http provides email verification HTTP handlers.
package http

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/iSundram/ModernAuth/internal/auth"
	"github.com/iSundram/ModernAuth/internal/email"
)

// VerifyEmail handles email verification.
func (h *Handler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req VerifyEmailHTTPRequest
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

	err := h.authService.VerifyEmail(r.Context(), req.Token)
	if err != nil {
		switch err {
		case auth.ErrTokenNotFound:
			h.writeError(w, http.StatusNotFound, "Invalid verification token", err)
		case auth.ErrTokenExpired:
			h.writeError(w, http.StatusGone, "Verification token has expired", err)
		case auth.ErrTokenUsed:
			h.writeError(w, http.StatusConflict, "Verification token has already been used", err)
		default:
			h.writeError(w, http.StatusInternalServerError, "Email verification failed", err)
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Email verified successfully"})
}

// SendVerificationEmail handles sending verification emails.
func (h *Handler) SendVerificationEmail(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	result, err := h.authService.SendEmailVerification(r.Context(), userID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to send verification email", err)
		return
	}

	// Send email if email service is configured
	if h.emailService != nil {
		user, err := h.storage.GetUserByID(r.Context(), userID)
		if err == nil && user != nil {
			// Build verification URL
			verifyURL := h.getBaseURL(r) + "/verify-email?token=" + result.Token

			// Queue email (async with retry via email queue)
			if err := h.emailService.SendVerificationEmail(r.Context(), user, result.Token, verifyURL); err != nil {
				// Handle rate limit error
				if errors.Is(err, email.ErrRateLimitExceeded) {
					h.writeError(w, http.StatusTooManyRequests, "Too many verification emails requested. Please try again later.", err)
					return
				}
				// Log other errors but don't fail the request (email is queued async)
				h.logger.Error("Failed to queue verification email", "error", err, "user_id", userID)
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Verification email sent",
	})
}
