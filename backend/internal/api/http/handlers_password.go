// Package http provides password management HTTP handlers.
package http

import (
	"encoding/json"
	"net/http"

	"github.com/iSundram/ModernAuth/internal/auth"
)

// ForgotPassword handles password reset requests.
func (h *Handler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req ForgotPasswordRequest
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

	result, err := h.authService.RequestPasswordReset(r.Context(), req.Email)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to process password reset request", err)
		return
	}

	// Always return success to prevent email enumeration
	response := map[string]interface{}{
		"message": "If an account exists with that email, a password reset link has been sent",
	}

	// Send email if token was generated and email service is configured
	if result != nil && h.emailService != nil {
		user, err := h.storage.GetUserByEmail(r.Context(), req.Email)
		if err == nil && user != nil {
			// Build reset URL
			resetURL := h.getBaseURL(r) + "/reset-password?token=" + result.Token
			
			// Send email asynchronously (don't block response)
			go func() {
				if err := h.emailService.SendPasswordResetEmail(r.Context(), user, result.Token, resetURL); err != nil {
					h.logger.Error("Failed to send password reset email", "error", err, "email", req.Email)
				}
			}()
		}
	}

	writeJSON(w, http.StatusOK, response)
}

// ResetPassword handles password reset.
func (h *Handler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req ResetPasswordHTTPRequest
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

	err := h.authService.ResetPassword(r.Context(), &auth.ResetPasswordRequest{
		Token:       req.Token,
		NewPassword: req.NewPassword,
	})

	if err != nil {
		switch err {
		case auth.ErrTokenNotFound:
			h.writeError(w, http.StatusNotFound, "Invalid reset token", err)
		case auth.ErrTokenExpired:
			h.writeError(w, http.StatusGone, "Reset token has expired", err)
		case auth.ErrTokenUsed:
			h.writeError(w, http.StatusConflict, "Reset token has already been used", err)
		default:
			h.writeError(w, http.StatusInternalServerError, "Password reset failed", err)
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Password reset successfully"})
}

// ChangePassword handles password change for authenticated users.
func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	var req ChangePasswordHTTPRequest
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

	err = h.authService.ChangePassword(r.Context(), &auth.ChangePasswordRequest{
		UserID:          userID,
		CurrentPassword: req.CurrentPassword,
		NewPassword:     req.NewPassword,
		IP:              r.RemoteAddr,
		UserAgent:       r.UserAgent(),
	})

	if err != nil {
		switch err {
		case auth.ErrInvalidCredentials:
			h.writeError(w, http.StatusUnauthorized, "Current password is incorrect", err)
		default:
			h.writeError(w, http.StatusInternalServerError, "Failed to change password", err)
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Password changed successfully"})
}
