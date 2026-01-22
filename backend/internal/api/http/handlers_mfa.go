// Package http provides MFA HTTP handlers.
package http

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/auth"
)

// DisableMFARequest represents a request to disable MFA.
type DisableMFARequest struct {
	Code string `json:"code" validate:"required,len=6"`
}

// DisableMFA handles disabling MFA for a user.
func (h *Handler) DisableMFA(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	var req DisableMFARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate request
	if validationErrors := ValidateStruct(req); validationErrors != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "Validation failed",
			"details": validationErrors,
		})
		return
	}

	err = h.authService.DisableMFA(r.Context(), userID, req.Code)
	if err != nil {
		switch err {
		case auth.ErrInvalidMFACode:
			h.writeError(w, http.StatusUnauthorized, "Invalid verification code", err)
		case auth.ErrMFANotSetup:
			h.writeError(w, http.StatusBadRequest, "MFA is not enabled", err)
		default:
			h.writeError(w, http.StatusInternalServerError, "Failed to disable MFA", err)
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "MFA disabled successfully"})
}

// GenerateBackupCodes handles generating new MFA backup codes.
func (h *Handler) GenerateBackupCodes(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	result, err := h.authService.GenerateBackupCodes(r.Context(), userID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to generate backup codes", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"backup_codes": result.BackupCodes,
		"message":      "Store these codes in a safe place. Each code can only be used once.",
	})
}

// GetBackupCodeCount handles getting the count of remaining backup codes.
func (h *Handler) GetBackupCodeCount(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	count, err := h.authService.GetBackupCodeCount(r.Context(), userID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to get backup code count", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"remaining_codes": count,
	})
}

// LoginMFABackupRequest represents a request to login with a backup code.
type LoginMFABackupRequest struct {
	UserID     string `json:"user_id" validate:"required,uuid"`
	BackupCode string `json:"backup_code" validate:"required"`
}

// LoginMFABackup handles MFA verification using a backup code.
func (h *Handler) LoginMFABackup(w http.ResponseWriter, r *http.Request) {
	var req LoginMFABackupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate request
	if validationErrors := ValidateStruct(req); validationErrors != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "Validation failed",
			"details": validationErrors,
		})
		return
	}

	userID, err := parseUUID(req.UserID)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid user ID", err)
		return
	}

	// Check MFA lockout
	if h.mfaLockout != nil {
		locked, remaining, err := h.mfaLockout.IsLocked(r.Context(), "mfa:"+req.UserID)
		if err != nil {
			h.logger.Error("Failed to check MFA lockout", "error", err)
		} else if locked {
			authFailureTotal.WithLabelValues("login_backup", "mfa_locked").Inc()
			writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
				"error":               "MFA temporarily locked",
				"message":             "Too many failed MFA attempts. Please try again later.",
				"retry_after_seconds": int(remaining.Seconds()),
			})
			return
		}
	}

	result, err := h.authService.LoginWithBackupCode(r.Context(), &auth.LoginWithBackupCodeRequest{
		UserID:     userID,
		BackupCode: req.BackupCode,
		IP:         r.RemoteAddr,
		UserAgent:  r.UserAgent(),
	})

	if err != nil {
		// Record failed MFA attempt
		if h.mfaLockout != nil && err == auth.ErrInvalidMFACode {
			locked, lockErr := h.mfaLockout.RecordFailedAttempt(r.Context(), "mfa:"+req.UserID)
			if lockErr != nil {
				h.logger.Error("Failed to record MFA attempt", "error", lockErr)
			}
			if locked {
				authFailureTotal.WithLabelValues("login_backup", "mfa_locked").Inc()
				writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
					"error":   "MFA temporarily locked",
					"message": "Too many failed MFA attempts. Please try again later.",
				})
				return
			}
		}

		switch err {
		case auth.ErrInvalidMFACode:
			authFailureTotal.WithLabelValues("login_backup", "invalid_code").Inc()
			h.writeError(w, http.StatusUnauthorized, "Invalid backup code", err)
		case auth.ErrUserNotFound:
			h.writeError(w, http.StatusNotFound, "User not found", err)
		default:
			h.writeError(w, http.StatusInternalServerError, "Login failed", err)
		}
		return
	}

	// Clear MFA lockout on success
	if h.mfaLockout != nil {
		if err := h.mfaLockout.ClearFailedAttempts(r.Context(), "mfa:"+req.UserID); err != nil {
			h.logger.Error("Failed to clear MFA attempts", "error", err)
		}
	}

	authSuccessTotal.WithLabelValues("login_backup").Inc()
	response := LoginResponse{
		User: h.buildUserResponse(r.Context(), result.User),
		Tokens: TokensResponse{
			AccessToken:  result.TokenPair.AccessToken,
			RefreshToken: result.TokenPair.RefreshToken,
			TokenType:    result.TokenPair.TokenType,
			ExpiresIn:    result.TokenPair.ExpiresIn,
		},
	}

	writeJSON(w, http.StatusOK, response)
}

// parseUUID parses a UUID string.
func parseUUID(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}
