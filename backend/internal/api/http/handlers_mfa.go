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

// MFAStatusResponse represents the MFA status for a user.
type MFAStatusResponse struct {
	IsEnabled            bool     `json:"is_enabled"`
	Methods              []string `json:"methods"`
	PreferredMethod      string   `json:"preferred_method"`
	BackupCodesRemaining int      `json:"backup_codes_remaining"`
	TOTPSetupAt          *string  `json:"totp_setup_at,omitempty"`
	WebAuthnCredentials  int      `json:"webauthn_credentials"`
}

// GetMFAStatus returns the current MFA configuration for a user.
func (h *Handler) GetMFAStatus(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	status, err := h.authService.GetMFAStatus(r.Context(), userID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to get MFA status", err)
		return
	}

	response := MFAStatusResponse{
		IsEnabled:            status.IsEnabled,
		Methods:              status.Methods,
		PreferredMethod:      status.PreferredMethod,
		BackupCodesRemaining: status.BackupCodesRemaining,
		WebAuthnCredentials:  status.WebAuthnCredentials,
	}
	if status.TOTPSetupAt != nil {
		t := status.TOTPSetupAt.Format("2006-01-02T15:04:05Z07:00")
		response.TOTPSetupAt = &t
	}

	writeJSON(w, http.StatusOK, response)
}

// SendEmailMFARequest represents a request to send an email MFA code.
type SendEmailMFARequest struct {
	UserID string `json:"user_id" validate:"required,uuid"`
}

// SendEmailMFA sends an MFA code to the user's email.
func (h *Handler) SendEmailMFA(w http.ResponseWriter, r *http.Request) {
	var req SendEmailMFARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

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

	err = h.authService.SendEmailMFACode(r.Context(), userID)
	if err != nil {
		switch err {
		case auth.ErrUserNotFound:
			h.writeError(w, http.StatusNotFound, "User not found", err)
		case auth.ErrMFANotSetup:
			h.writeError(w, http.StatusBadRequest, "Email MFA is not enabled", err)
		case auth.ErrRateLimited:
			h.writeError(w, http.StatusTooManyRequests, "Too many requests, please wait", err)
		default:
			h.writeError(w, http.StatusInternalServerError, "Failed to send MFA code", err)
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "MFA code sent to email"})
}

// LoginEmailMFARequest represents a request to verify email MFA.
type LoginEmailMFARequest struct {
	UserID string `json:"user_id" validate:"required,uuid"`
	Code   string `json:"code" validate:"required,len=6"`
}

// LoginEmailMFA handles email MFA verification during login.
func (h *Handler) LoginEmailMFA(w http.ResponseWriter, r *http.Request) {
	var req LoginEmailMFARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

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
			authFailureTotal.WithLabelValues("login_email_mfa", "mfa_locked").Inc()
			writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
				"error":               "MFA temporarily locked",
				"message":             "Too many failed MFA attempts. Please try again later.",
				"retry_after_seconds": int(remaining.Seconds()),
			})
			return
		}
	}

	result, err := h.authService.LoginWithEmailMFA(r.Context(), &auth.LoginWithEmailMFARequest{
		UserID:    userID,
		Code:      req.Code,
		IP:        r.RemoteAddr,
		UserAgent: r.UserAgent(),
	})

	if err != nil {
		if h.mfaLockout != nil && err == auth.ErrInvalidMFACode {
			locked, lockErr := h.mfaLockout.RecordFailedAttempt(r.Context(), "mfa:"+req.UserID)
			if lockErr != nil {
				h.logger.Error("Failed to record MFA attempt", "error", lockErr)
			}
			if locked {
				authFailureTotal.WithLabelValues("login_email_mfa", "mfa_locked").Inc()
				writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
					"error":   "MFA temporarily locked",
					"message": "Too many failed MFA attempts. Please try again later.",
				})
				return
			}
		}

		switch err {
		case auth.ErrInvalidMFACode:
			authFailureTotal.WithLabelValues("login_email_mfa", "invalid_code").Inc()
			h.writeError(w, http.StatusUnauthorized, "Invalid or expired code", err)
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

	authSuccessTotal.WithLabelValues("login_email_mfa").Inc()
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

// EnableEmailMFA enables email-based MFA for the authenticated user.
func (h *Handler) EnableEmailMFA(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	err = h.authService.EnableEmailMFA(r.Context(), userID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to enable email MFA", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Email MFA enabled successfully"})
}

// DisableEmailMFA disables email-based MFA for the authenticated user.
func (h *Handler) DisableEmailMFA(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	err = h.authService.DisableEmailMFA(r.Context(), userID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to disable email MFA", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Email MFA disabled successfully"})
}

// TrustDeviceForMFARequest represents a request to trust a device for MFA.
type TrustDeviceForMFARequest struct {
	DeviceFingerprint string `json:"device_fingerprint" validate:"required"`
	TrustDays         int    `json:"trust_days" validate:"omitempty,min=1,max=90"`
}

// TrustDeviceForMFA marks the current device as trusted for MFA.
func (h *Handler) TrustDeviceForMFA(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	var req TrustDeviceForMFARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if validationErrors := ValidateStruct(req); validationErrors != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "Validation failed",
			"details": validationErrors,
		})
		return
	}

	trustDays := req.TrustDays
	if trustDays == 0 {
		trustDays = 30 // Default to 30 days
	}

	err = h.authService.TrustDeviceForMFA(r.Context(), userID, req.DeviceFingerprint, trustDays)
	if err != nil {
		switch err {
		case auth.ErrDeviceNotFound:
			h.writeError(w, http.StatusNotFound, "Device not found", err)
		default:
			h.writeError(w, http.StatusInternalServerError, "Failed to trust device", err)
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":    "Device trusted for MFA",
		"trust_days": trustDays,
	})
}

// RevokeMFATrust revokes MFA trust from a device.
func (h *Handler) RevokeMFATrust(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	var req struct {
		DeviceFingerprint string `json:"device_fingerprint" validate:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	err = h.authService.RevokeMFATrust(r.Context(), userID, req.DeviceFingerprint)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to revoke MFA trust", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "MFA trust revoked"})
}

// SetPreferredMFARequest represents a request to set the preferred MFA method.
type SetPreferredMFARequest struct {
	Method string `json:"method" validate:"required,oneof=totp email webauthn sms"`
}

// SetPreferredMFA sets the user's preferred MFA method.
func (h *Handler) SetPreferredMFA(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	var req SetPreferredMFARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if validationErrors := ValidateStruct(req); validationErrors != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "Validation failed",
			"details": validationErrors,
		})
		return
	}

	err = h.authService.SetPreferredMFAMethod(r.Context(), userID, req.Method)
	if err != nil {
		switch err {
		case auth.ErrMFANotSetup:
			h.writeError(w, http.StatusBadRequest, "The requested MFA method is not enabled", err)
		default:
			h.writeError(w, http.StatusInternalServerError, "Failed to set preferred MFA method", err)
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Preferred MFA method updated"})
}

// BeginWebAuthnRegistration starts WebAuthn credential registration.
func (h *Handler) BeginWebAuthnRegistration(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	var req struct {
		CredentialName string `json:"credential_name" validate:"required,min=1,max=100"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	result, err := h.authService.BeginWebAuthnRegistration(r.Context(), userID, req.CredentialName)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to start registration", err)
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// FinishWebAuthnRegistration completes WebAuthn credential registration.
func (h *Handler) FinishWebAuthnRegistration(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	var req auth.FinishWebAuthnRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	err = h.authService.FinishWebAuthnRegistration(r.Context(), userID, &req)
	if err != nil {
		switch err {
		case auth.ErrChallengeExpired:
			h.writeError(w, http.StatusBadRequest, "Challenge expired, please try again", err)
		default:
			h.writeError(w, http.StatusInternalServerError, "Failed to complete registration", err)
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "WebAuthn credential registered successfully"})
}

// BeginWebAuthnLoginRequest represents a request to begin WebAuthn login.
type BeginWebAuthnLoginRequest struct {
	UserID string `json:"user_id" validate:"required,uuid"`
}

// BeginWebAuthnLogin starts the WebAuthn login process.
func (h *Handler) BeginWebAuthnLogin(w http.ResponseWriter, r *http.Request) {
	var req BeginWebAuthnLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

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

	result, err := h.authService.BeginWebAuthnLogin(r.Context(), userID)
	if err != nil {
		switch err {
		case auth.ErrUserNotFound:
			h.writeError(w, http.StatusNotFound, "User not found", err)
		case auth.ErrMFANotSetup:
			h.writeError(w, http.StatusBadRequest, "No WebAuthn credentials registered", err)
		default:
			h.writeError(w, http.StatusInternalServerError, "Failed to start login", err)
		}
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// FinishWebAuthnLoginRequest represents a request to complete WebAuthn login.
type FinishWebAuthnLoginRequest struct {
	UserID      string                        `json:"user_id" validate:"required,uuid"`
	ChallengeID string                        `json:"challenge_id" validate:"required,uuid"`
	Credential  *auth.WebAuthnLoginCredential `json:"credential" validate:"required"`
}

// FinishWebAuthnLogin completes the WebAuthn login process.
func (h *Handler) FinishWebAuthnLogin(w http.ResponseWriter, r *http.Request) {
	var req FinishWebAuthnLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

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

	challengeID, err := parseUUID(req.ChallengeID)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid challenge ID", err)
		return
	}

	result, err := h.authService.FinishWebAuthnLogin(r.Context(), userID, &auth.FinishWebAuthnLoginRequest{
		ChallengeID: challengeID,
		Credential:  req.Credential,
		IP:          r.RemoteAddr,
		UserAgent:   r.UserAgent(),
	})

	if err != nil {
		switch err {
		case auth.ErrChallengeExpired:
			h.writeError(w, http.StatusBadRequest, "Challenge expired", err)
		case auth.ErrInvalidMFACode:
			authFailureTotal.WithLabelValues("login_webauthn", "invalid_credential").Inc()
			h.writeError(w, http.StatusUnauthorized, "Invalid credential", err)
		case auth.ErrUserNotFound:
			h.writeError(w, http.StatusNotFound, "User not found", err)
		default:
			h.writeError(w, http.StatusInternalServerError, "Login failed", err)
		}
		return
	}

	authSuccessTotal.WithLabelValues("login_webauthn").Inc()
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

// ListWebAuthnCredentials lists all WebAuthn credentials for the user.
func (h *Handler) ListWebAuthnCredentials(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	creds, err := h.authService.ListWebAuthnCredentials(r.Context(), userID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to list credentials", err)
		return
	}

	// Build response without sensitive data
	type credResponse struct {
		ID         string  `json:"id"`
		Name       string  `json:"name"`
		CreatedAt  string  `json:"created_at"`
		LastUsedAt *string `json:"last_used_at,omitempty"`
	}

	resp := make([]credResponse, len(creds))
	for i, c := range creds {
		resp[i] = credResponse{
			ID:        c.ID.String(),
			Name:      c.Name,
			CreatedAt: c.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		}
		if c.LastUsedAt != nil {
			t := c.LastUsedAt.Format("2006-01-02T15:04:05Z07:00")
			resp[i].LastUsedAt = &t
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"credentials": resp})
}

// DeleteWebAuthnCredential removes a WebAuthn credential.
func (h *Handler) DeleteWebAuthnCredential(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	var req struct {
		CredentialID string `json:"credential_id" validate:"required,uuid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	credID, err := parseUUID(req.CredentialID)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid credential ID", err)
		return
	}

	err = h.authService.DeleteWebAuthnCredential(r.Context(), userID, credID)
	if err != nil {
		switch err {
		case auth.ErrDeviceNotFound:
			h.writeError(w, http.StatusNotFound, "Credential not found", err)
		default:
			h.writeError(w, http.StatusInternalServerError, "Failed to delete credential", err)
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Credential deleted successfully"})
}

// EnableSMSMFARequest represents a request to enable SMS MFA.
type EnableSMSMFARequest struct {
	PhoneNumber string `json:"phone_number" validate:"required"`
}

// EnableSMSMFA enables SMS-based MFA for the authenticated user.
func (h *Handler) EnableSMSMFA(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	var req EnableSMSMFARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if validationErrors := ValidateStruct(req); validationErrors != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "Validation failed",
			"details": validationErrors,
		})
		return
	}

	err = h.authService.EnableSMSMFA(r.Context(), userID, req.PhoneNumber)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to enable SMS MFA", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "SMS MFA enabled successfully"})
}

// DisableSMSMFA disables SMS-based MFA for the authenticated user.
func (h *Handler) DisableSMSMFA(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	err = h.authService.DisableSMSMFA(r.Context(), userID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to disable SMS MFA", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "SMS MFA disabled successfully"})
}

// SendSMSMFARequest represents a request to send an SMS MFA code.
type SendSMSMFARequest struct {
	UserID string `json:"user_id" validate:"required,uuid"`
}

// SendSMSMFA sends an MFA code to the user's phone.
func (h *Handler) SendSMSMFA(w http.ResponseWriter, r *http.Request) {
	var req SendSMSMFARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

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

	err = h.authService.SendSMSMFACode(r.Context(), userID)
	if err != nil {
		switch err {
		case auth.ErrUserNotFound:
			h.writeError(w, http.StatusNotFound, "User not found", err)
		case auth.ErrMFANotSetup:
			h.writeError(w, http.StatusBadRequest, "SMS MFA is not enabled", err)
		case auth.ErrRateLimited:
			h.writeError(w, http.StatusTooManyRequests, "Too many requests, please wait", err)
		default:
			h.writeError(w, http.StatusInternalServerError, "Failed to send MFA code", err)
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "MFA code sent via SMS"})
}

// LoginSMSMFARequest represents a request to verify SMS MFA.
type LoginSMSMFARequest struct {
	UserID string `json:"user_id" validate:"required,uuid"`
	Code   string `json:"code" validate:"required,len=6"`
}

// LoginSMSMFA handles SMS MFA verification during login.
func (h *Handler) LoginSMSMFA(w http.ResponseWriter, r *http.Request) {
	var req LoginSMSMFARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

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
			authFailureTotal.WithLabelValues("login_sms_mfa", "mfa_locked").Inc()
			writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
				"error":               "MFA temporarily locked",
				"message":             "Too many failed MFA attempts. Please try again later.",
				"retry_after_seconds": int(remaining.Seconds()),
			})
			return
		}
	}

	result, err := h.authService.LoginWithSMSMFA(r.Context(), &auth.LoginWithSMSMFARequest{
		UserID:    userID,
		Code:      req.Code,
		IP:        r.RemoteAddr,
		UserAgent: r.UserAgent(),
	})

	if err != nil {
		if h.mfaLockout != nil && err == auth.ErrInvalidMFACode {
			locked, lockErr := h.mfaLockout.RecordFailedAttempt(r.Context(), "mfa:"+req.UserID)
			if lockErr != nil {
				h.logger.Error("Failed to record MFA attempt", "error", lockErr)
			}
			if locked {
				authFailureTotal.WithLabelValues("login_sms_mfa", "mfa_locked").Inc()
				writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
					"error":   "MFA temporarily locked",
					"message": "Too many failed MFA attempts. Please try again later.",
				})
				return
			}
		}

		switch err {
		case auth.ErrInvalidMFACode:
			authFailureTotal.WithLabelValues("login_sms_mfa", "invalid_code").Inc()
			h.writeError(w, http.StatusUnauthorized, "Invalid or expired code", err)
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

	authSuccessTotal.WithLabelValues("login_sms_mfa").Inc()
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
