// Package http provides authentication HTTP handlers.
package http

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/auth"
	"github.com/iSundram/ModernAuth/internal/device"
	"github.com/iSundram/ModernAuth/internal/storage"
	"github.com/iSundram/ModernAuth/internal/utils"
)

// getUserRole fetches the primary role for a user (admin > user)
func (h *Handler) getUserRole(ctx context.Context, userID uuid.UUID) string {
	roles, err := h.authService.GetUserRoles(ctx, userID)
	if err != nil {
		return "user"
	}
	for _, r := range roles {
		if r.Name == "admin" {
			return "admin"
		}
	}
	if len(roles) > 0 {
		return roles[0].Name
	}
	return "user"
}

// buildUserResponse creates a UserResponse with role included
func (h *Handler) buildUserResponse(ctx context.Context, user *storage.User) UserResponse {
	role := h.getUserRole(ctx, user.ID)

	resp := UserResponse{
		ID:              user.ID.String(),
		Email:           user.Email,
		Username:        user.Username,
		Phone:           user.Phone,
		FirstName:       user.FirstName,
		LastName:        user.LastName,
		IsEmailVerified: user.IsEmailVerified,
		IsActive:        user.IsActive,
		Role:            role,
		CreatedAt:       user.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	if user.Timezone != "" {
		resp.Timezone = &user.Timezone
	}
	if user.Locale != "" {
		resp.Locale = &user.Locale
	}
	if user.Metadata != nil {
		resp.Metadata = user.Metadata
	}
	if user.LastLoginAt != nil {
		t := user.LastLoginAt.Format("2006-01-02T15:04:05Z07:00")
		resp.LastLoginAt = &t
	}
	if !user.UpdatedAt.IsZero() {
		t := user.UpdatedAt.Format("2006-01-02T15:04:05Z07:00")
		resp.UpdatedAt = &t
	}

	return resp
}

// Register handles user registration.
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate request using validator
	if errors := ValidateStruct(req); errors != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "Validation failed",
			"details": errors,
		})
		return
	}

	result, err := h.authService.Register(r.Context(), &auth.RegisterRequest{
		Email:     req.Email,
		Password:  req.Password,
		Username:  req.Username,
		IP:        utils.GetClientIP(r),
		UserAgent: r.UserAgent(),
	})

	if err != nil {
		switch err {
		case auth.ErrUserExists:
			h.writeError(w, http.StatusConflict, "User with this email already exists", err)
		default:
			h.writeError(w, http.StatusInternalServerError, "Registration failed", err)
		}
		return
	}

	// Record login history and device
	h.recordLogin(r, result.User.ID, "register", result.SessionID, "")

	response := RegisterResponse{
		User: h.buildUserResponse(r.Context(), result.User),
		Tokens: TokensResponse{
			AccessToken:  result.TokenPair.AccessToken,
			RefreshToken: result.TokenPair.RefreshToken,
			TokenType:    result.TokenPair.TokenType,
			ExpiresIn:    result.TokenPair.ExpiresIn,
		},
	}

	writeJSON(w, http.StatusCreated, response)
}

// Login handles user login.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate request using validator
	if errors := ValidateStruct(req); errors != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "Validation failed",
			"details": errors,
		})
		return
	}

	// Check account lockout
	if h.accountLockout != nil {
		locked, remaining, err := h.accountLockout.IsLocked(r.Context(), req.Email)
		if err != nil {
			h.logger.Error("Failed to check account lockout", "error", err)
		} else if locked {
			authFailureTotal.WithLabelValues("login", "account_locked").Inc()
			writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
				"error":               "Account temporarily locked",
				"message":             "Too many failed login attempts. Please try again later.",
				"retry_after_seconds": int(remaining.Seconds()),
			})
			return
		}
	}

	result, err := h.authService.Login(r.Context(), &auth.LoginRequest{
		Email:       req.Email,
		Password:    req.Password,
		Fingerprint: req.Fingerprint,
		TrustDevice: req.TrustDevice,
		IP:          utils.GetClientIP(r),
		UserAgent:   r.UserAgent(),
	})

	if err != nil {
		// Record failed attempt for lockout
		if h.accountLockout != nil && (err == auth.ErrInvalidCredentials || err == auth.ErrUserNotFound) {
			locked, lockErr := h.accountLockout.RecordFailedAttempt(r.Context(), req.Email)
			if lockErr != nil {
				h.logger.Error("Failed to record failed attempt", "error", lockErr)
			}
			if locked {
				authFailureTotal.WithLabelValues("login", "account_locked").Inc()
				writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
					"error":   "Account temporarily locked",
					"message": "Too many failed login attempts. Please try again later.",
				})
				return
			}
		}

		switch err {
		case auth.ErrInvalidCredentials:
			authFailureTotal.WithLabelValues("login", "invalid_credentials").Inc()
			h.writeError(w, http.StatusUnauthorized, "Invalid email or password", err)
		case auth.ErrUserNotFound:
			authFailureTotal.WithLabelValues("login", "invalid_credentials").Inc()
			h.writeError(w, http.StatusUnauthorized, "Invalid email or password", err)
		case auth.ErrSessionLimitExceeded:
			authFailureTotal.WithLabelValues("login", "session_limit").Inc()
			h.writeError(w, http.StatusTooManyRequests, "Maximum concurrent sessions exceeded. Please log out from another device.", err)
		default:
			h.writeError(w, http.StatusInternalServerError, "Login failed", err)
		}
		return
	}

	// Clear failed attempts on successful login
	if h.accountLockout != nil {
		if err := h.accountLockout.ClearFailedAttempts(r.Context(), req.Email); err != nil {
			h.logger.Error("Failed to clear failed attempts", "error", err)
		}
	}

	if result.MFARequired {
		authSuccessTotal.WithLabelValues("login_partial").Inc()
		resp := map[string]interface{}{
			"mfa_required": true,
			"user_id":      result.User.ID.String(),
		}
		// Include the MFA challenge ID - required for MFA verification
		if result.MFAChallengeID != nil {
			resp["mfa_challenge_id"] = result.MFAChallengeID.String()
		}
		if mfaStatus, err := h.authService.GetMFAStatus(r.Context(), result.User.ID); err == nil && mfaStatus != nil {
			resp["preferred_method"] = mfaStatus.PreferredMethod
			resp["methods"] = mfaStatus.Methods
		}
		writeJSON(w, http.StatusAccepted, resp)
		return
	}

	authSuccessTotal.WithLabelValues("login").Inc()

	// Record login history and device
	h.recordLogin(r, result.User.ID, "password", result.SessionID, req.Fingerprint)

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

// LoginMFA handles MFA verification during login.
func (h *Handler) LoginMFA(w http.ResponseWriter, r *http.Request) {
	var req LoginMFARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate request using validator
	if errors := ValidateStruct(req); errors != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "Validation failed",
			"details": errors,
		})
		return
	}

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid user ID", err)
		return
	}

	mfaChallengeID, err := uuid.Parse(req.MFAChallengeID)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid MFA challenge ID", err)
		return
	}

	// Check MFA lockout
	if h.mfaLockout != nil {
		locked, remaining, err := h.mfaLockout.IsLocked(r.Context(), "mfa:"+req.UserID)
		if err != nil {
			h.logger.Error("Failed to check MFA lockout", "error", err)
		} else if locked {
			authFailureTotal.WithLabelValues("login_mfa", "mfa_locked").Inc()
			writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
				"error":               "MFA temporarily locked",
				"message":             "Too many failed MFA attempts. Please try again later.",
				"retry_after_seconds": int(remaining.Seconds()),
			})
			return
		}
	}

	result, err := h.authService.LoginWithMFA(r.Context(), &auth.LoginWithMFARequest{
		UserID:         userID,
		MFAChallengeID: &mfaChallengeID,
		Code:           req.Code,
		Fingerprint:    req.Fingerprint,
		TrustDevice:    req.TrustDevice,
		IP:             utils.GetClientIP(r),
		UserAgent:      r.UserAgent(),
	})

	if err != nil {
		// Record failed MFA attempt
		if h.mfaLockout != nil && err == auth.ErrInvalidMFACode {
			locked, lockErr := h.mfaLockout.RecordFailedAttempt(r.Context(), "mfa:"+req.UserID)
			if lockErr != nil {
				h.logger.Error("Failed to record MFA attempt", "error", lockErr)
			}
			if locked {
				authFailureTotal.WithLabelValues("login_mfa", "mfa_locked").Inc()
				writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
					"error":   "MFA temporarily locked",
					"message": "Too many failed MFA attempts. Please try again later.",
				})
				return
			}
		}

		switch err {
		case auth.ErrInvalidMFACode:
			authFailureTotal.WithLabelValues("login_mfa", "invalid_code").Inc()
			h.writeError(w, http.StatusUnauthorized, "Invalid MFA code", err)
		case auth.ErrMFAChallengeRequired:
			authFailureTotal.WithLabelValues("login_mfa", "missing_challenge").Inc()
			h.writeError(w, http.StatusBadRequest, "MFA challenge token required", err)
		case auth.ErrMFAChallengeInvalid:
			authFailureTotal.WithLabelValues("login_mfa", "invalid_challenge").Inc()
			h.writeError(w, http.StatusUnauthorized, "Invalid or expired MFA challenge", err)
		case auth.ErrChallengeExpired:
			authFailureTotal.WithLabelValues("login_mfa", "expired_challenge").Inc()
			h.writeError(w, http.StatusUnauthorized, "MFA challenge has expired, please login again", err)
		default:
			h.writeError(w, http.StatusInternalServerError, "MFA verification failed", err)
		}
		return
	}

	// Clear MFA lockout on success
	if h.mfaLockout != nil {
		if err := h.mfaLockout.ClearFailedAttempts(r.Context(), "mfa:"+req.UserID); err != nil {
			h.logger.Error("Failed to clear MFA attempts", "error", err)
		}
	}

	authSuccessTotal.WithLabelValues("login_mfa").Inc()

	// Record login history and device for MFA login
	h.recordLogin(r, userID, "mfa", result.SessionID, req.Fingerprint)

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

// Refresh handles token refresh.
func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate request using validator
	if errors := ValidateStruct(req); errors != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "Validation failed",
			"details": errors,
		})
		return
	}

	tokenPair, err := h.authService.Refresh(r.Context(), &auth.RefreshRequest{
		RefreshToken: req.RefreshToken,
		IP:           utils.GetClientIP(r),
		UserAgent:    r.UserAgent(),
	})

	if err != nil {
		switch err {
		case auth.ErrRefreshTokenNotFound:
			h.writeError(w, http.StatusUnauthorized, "Invalid refresh token", err)
		case auth.ErrRefreshTokenRevoked:
			h.writeError(w, http.StatusUnauthorized, "Refresh token has been revoked", err)
		case auth.ErrRefreshTokenExpired:
			h.writeError(w, http.StatusUnauthorized, "Refresh token has expired", err)
		case auth.ErrRefreshTokenReused:
			h.writeError(w, http.StatusUnauthorized, "Token reuse detected, session has been revoked", err)
		case auth.ErrSessionNotFound:
			h.writeError(w, http.StatusUnauthorized, "Session not found", err)
		case auth.ErrSessionRevoked:
			h.writeError(w, http.StatusUnauthorized, "Session has been revoked", err)
		case auth.ErrSessionExpired:
			h.writeError(w, http.StatusUnauthorized, "Session has expired", err)
		default:
			h.writeError(w, http.StatusInternalServerError, "Token refresh failed", err)
		}
		return
	}

	response := RefreshResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		TokenType:    tokenPair.TokenType,
		ExpiresIn:    tokenPair.ExpiresIn,
	}

	writeJSON(w, http.StatusOK, response)
}

// Logout handles user logout.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	// Get session ID from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		h.writeError(w, http.StatusUnauthorized, "Authorization header required", nil)
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		h.writeError(w, http.StatusUnauthorized, "Bearer token required", nil)
		return
	}

	// Validate the token and extract session ID
	claims, err := h.tokenService.ValidateAccessToken(tokenString)
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Invalid or expired token", err)
		return
	}

	// Parse session ID from the token claims
	sessionID, err := uuid.Parse(claims.SessionID)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid session ID in token", err)
		return
	}

	// Blacklist the current access token JTI to prevent reuse
	if h.tokenBlacklist != nil && claims.ID != "" {
		expiry := time.Now().Add(h.tokenService.GetConfig().AccessTokenTTL)
		if claims.ExpiresAt != nil {
			expiry = claims.ExpiresAt.Time
		}
		if err := h.tokenBlacklist.Blacklist(r.Context(), claims.ID, expiry); err != nil {
			h.logger.Error("Failed to blacklist token on logout", "error", err, "jti", claims.ID)
			// Continue with logout even if blacklisting fails
		}

		// Also blacklist the entire session for immediate invalidation
		if err := h.tokenBlacklist.BlacklistSession(r.Context(), claims.SessionID, h.tokenService.GetConfig().AccessTokenTTL); err != nil {
			h.logger.Error("Failed to blacklist session on logout", "error", err, "session_id", claims.SessionID)
		}
	}

	err = h.authService.Logout(r.Context(), &auth.LogoutRequest{
		SessionID: sessionID,
		TokenJTI:  claims.ID,
		IP:        utils.GetClientIP(r),
		UserAgent: r.UserAgent(),
	})

	if err != nil {
		switch err {
		case auth.ErrSessionNotFound:
			h.writeError(w, http.StatusNotFound, "Session not found", err)
		default:
			h.writeError(w, http.StatusInternalServerError, "Logout failed", err)
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Logged out successfully"})
}

// Me handles requests for the current user's profile.
func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	user, err := h.authService.GetUserByID(r.Context(), userID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to get user", err)
		return
	}

	writeJSON(w, http.StatusOK, h.buildUserResponse(r.Context(), user))
}

// SetupMFA handles the initiation of MFA setup.
func (h *Handler) SetupMFA(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	result, err := h.authService.SetupTOTP(r.Context(), userID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to setup MFA", err)
		return
	}

	writeJSON(w, http.StatusOK, SetupMFAResponse{
		Secret: result.Secret,
		URL:    result.URL,
	})
}

// EnableMFA handles enabling MFA for a user.
func (h *Handler) EnableMFA(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	var req EnableMFARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate request using validator
	if validationErrors := ValidateStruct(req); validationErrors != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "Validation failed",
			"details": validationErrors,
		})
		return
	}

	err = h.authService.EnableTOTP(r.Context(), &auth.EnableTOTPRequest{
		UserID: userID,
		Code:   req.Code,
	})

	if err != nil {
		switch err {
		case auth.ErrInvalidMFACode:
			h.writeError(w, http.StatusUnauthorized, "Invalid verification code", err)
		default:
			h.writeError(w, http.StatusInternalServerError, "Failed to enable MFA", err)
		}
		return
	}

	// Send MFA enabled notification email
	go func() {
		user, err := h.storage.GetUserByID(context.Background(), userID)
		if err != nil || user == nil {
			h.logger.Error("Failed to get user for MFA email", "error", err, "user_id", userID)
			return
		}
		if err := h.emailService.SendMFAEnabledEmail(context.Background(), user); err != nil {
			h.logger.Error("Failed to send MFA enabled email", "error", err, "user_id", userID)
		}
	}()

	writeJSON(w, http.StatusOK, map[string]string{"message": "MFA enabled successfully"})
}

// DeleteOwnAccount handles user self-deletion (GDPR compliance).
func (h *Handler) DeleteOwnAccount(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	var req DeleteOwnAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate request using validator
	if validationErrors := ValidateStruct(req); validationErrors != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "Validation failed",
			"details": validationErrors,
		})
		return
	}

	err = h.authService.DeleteOwnAccount(r.Context(), &auth.DeleteOwnAccountRequest{
		UserID:   userID,
		Password: req.Password,
	})

	if err != nil {
		switch err {
		case auth.ErrInvalidCredentials:
			h.writeError(w, http.StatusUnauthorized, "Invalid password", err)
		case auth.ErrUserNotFound:
			h.writeError(w, http.StatusNotFound, "User not found", err)
		default:
			h.writeError(w, http.StatusInternalServerError, "Failed to delete account", err)
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Account deleted successfully"})
}

// UpdateOwnProfile handles requests to update the current user's profile.
func (h *Handler) UpdateOwnProfile(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	var req UpdateProfileRequest
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

	user, err := h.authService.UpdateOwnProfile(r.Context(), &auth.UpdateOwnProfileRequest{
		UserID:    userID,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Username:  req.Username,
		Phone:     req.Phone,
		AvatarURL: req.AvatarURL,
		Timezone:  req.Timezone,
		Locale:    req.Locale,
	})

	if err != nil {
		switch err {
		case auth.ErrUserNotFound:
			h.writeError(w, http.StatusNotFound, "User not found", err)
		default:
			h.writeError(w, http.StatusInternalServerError, "Failed to update profile", err)
		}
		return
	}

	writeJSON(w, http.StatusOK, h.buildUserResponse(r.Context(), user))
}

// recordLogin records a successful login attempt, including device info and history.
func (h *Handler) recordLogin(r *http.Request, userID uuid.UUID, method string, sessionID *uuid.UUID, fingerprint string) {
	if h.deviceHandler == nil {
		return
	}

	// Extract values before goroutine since request may be closed
	userAgent := r.UserAgent()
	ipAddress := utils.GetClientIP(r)

	go func() {
		ctx := context.Background()

		// 1. Record/Update device
		var fp *string
		if fingerprint != "" {
			fp = &fingerprint
		}

		d, _, err := h.deviceHandler.RecordDevice(ctx, &device.RecordDeviceRequest{
			UserID:            userID,
			DeviceFingerprint: fp,
			UserAgent:         userAgent,
			IPAddress:         ipAddress,
		})
		
		var deviceID *uuid.UUID
		if err != nil {
			h.logger.Error("Failed to record device", "error", err, "user_id", userID)
		} else if d != nil {
			deviceID = &d.ID
			
			// 2. Link session to device if we have a session
			if sessionID != nil {
				if err := h.authService.LinkSessionToDevice(ctx, *sessionID, d.ID); err != nil {
					h.logger.Error("Failed to link session to device", "error", err, "session_id", *sessionID)
				}
			}
		}

		// 3. Record login history
		history := &storage.LoginHistory{
			UserID:      userID,
			SessionID:   sessionID,
			DeviceID:    deviceID,
			IPAddress:   &ipAddress,
			UserAgent:   &userAgent,
			LoginMethod: &method,
			Status:      "success",
		}

		if err := h.deviceHandler.RecordLogin(ctx, history); err != nil {
			h.logger.Error("Failed to record login history", "error", err, "user_id", userID)
		}
	}()
}

// recordLoginFailure records a failed login attempt.
func (h *Handler) recordLoginFailure(r *http.Request, userID uuid.UUID, method string, failureReason string) {
	if h.deviceHandler == nil {
		return
	}

	ipAddress := utils.GetClientIP(r)
	userAgent := r.UserAgent()

	go func() {
		ctx := context.Background()
		history := &storage.LoginHistory{
			UserID:        userID,
			IPAddress:     &ipAddress,
			UserAgent:     &userAgent,
			LoginMethod:   &method,
			Status:        "failed",
			FailureReason: &failureReason,
		}

		if err := h.deviceHandler.RecordLogin(ctx, history); err != nil {
			h.logger.Error("Failed to record login failure", "error", err, "user_id", userID)
		}
	}()
}
