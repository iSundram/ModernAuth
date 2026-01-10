// Package http provides HTTP handlers for ModernAuth API.
package http

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/auth"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
)

// Handler provides HTTP handlers for the authentication API.
type Handler struct {
	authService    *auth.AuthService
	tokenService   *auth.TokenService
	rdb            *redis.Client
	accountLockout *auth.AccountLockout
	tokenBlacklist *auth.TokenBlacklist
	logger         *slog.Logger
}

// NewHandler creates a new HTTP handler.
func NewHandler(authService *auth.AuthService, tokenService *auth.TokenService, rdb *redis.Client, accountLockout *auth.AccountLockout, tokenBlacklist *auth.TokenBlacklist) *Handler {
	return &Handler{
		authService:    authService,
		tokenService:   tokenService,
		rdb:            rdb,
		accountLockout: accountLockout,
		tokenBlacklist: tokenBlacklist,
		logger:         slog.Default().With("component", "http_handler"),
	}
}

// Router returns the configured chi router.
func (h *Handler) Router() *chi.Mux {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(h.Metrics)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.SetHeader("Content-Type", "application/json"))

	// Health check
	r.Get("/health", h.HealthCheck)
	
	// Metrics
	r.Handle("/metrics", promhttp.Handler())

	// API v1 routes
	r.Route("/v1", func(r chi.Router) {
		r.Route("/auth", func(r chi.Router) {
			r.With(h.RateLimit(5, time.Hour)).Post("/register", h.Register)
			r.With(h.RateLimit(10, 15*time.Minute)).Post("/login", h.Login)
			r.With(h.RateLimit(10, 15*time.Minute)).Post("/login/mfa", h.LoginMFA)
			r.With(h.RateLimit(100, 15*time.Minute)).Post("/refresh", h.Refresh)
			r.With(h.Auth).Post("/logout", h.Logout)

			// Email Verification
			r.With(h.RateLimit(5, time.Hour)).Post("/verify-email", h.VerifyEmail)
			r.With(h.Auth).Post("/send-verification", h.SendVerificationEmail)

			// Password Reset
			r.With(h.RateLimit(5, time.Hour)).Post("/forgot-password", h.ForgotPassword)
			r.With(h.RateLimit(5, time.Hour)).Post("/reset-password", h.ResetPassword)

			// Session Management (Protected)
			r.With(h.Auth).Post("/revoke-all-sessions", h.RevokeAllSessions)

			// MFA Management (Protected)
			r.Group(func(r chi.Router) {
				r.Use(h.Auth)
				r.Post("/mfa/setup", h.SetupMFA)
				r.Post("/mfa/enable", h.EnableMFA)
			})
		})
	})

	return r
}

// ErrorResponse represents an error response.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// RegisterRequest represents the register request body.
type RegisterRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8,max=128"`
	Username string `json:"username,omitempty" validate:"omitempty,min=3,max=50"`
}

// RegisterResponse represents the register response.
type RegisterResponse struct {
	User   UserResponse   `json:"user"`
	Tokens TokensResponse `json:"tokens"`
}

// UserResponse represents a user in API responses.
type UserResponse struct {
	ID              string  `json:"id"`
	Email           string  `json:"email"`
	Username        *string `json:"username,omitempty"`
	IsEmailVerified bool    `json:"is_email_verified"`
	CreatedAt       string  `json:"created_at"`
}

// TokensResponse represents tokens in API responses.
type TokensResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// HealthCheck handles health check requests.
func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	// Check Redis connectivity
	redisStatus := "healthy"
	if h.rdb != nil {
		if err := h.rdb.Ping(ctx).Err(); err != nil {
			redisStatus = "unhealthy"
			h.logger.Warn("Redis health check failed", "error", err)
		}
	} else {
		redisStatus = "not_configured"
	}

	status := "healthy"
	statusCode := http.StatusOK
	if redisStatus == "unhealthy" {
		status = "degraded"
		statusCode = http.StatusServiceUnavailable
	}

	response := map[string]interface{}{
		"status": status,
		"services": map[string]string{
			"redis": redisStatus,
		},
	}
	writeJSON(w, statusCode, response)
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
		Email:    req.Email,
		Password: req.Password,
		Username: req.Username,
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

	response := RegisterResponse{
		User: UserResponse{
			ID:              result.User.ID.String(),
			Email:           result.User.Email,
			Username:        result.User.Username,
			IsEmailVerified: result.User.IsEmailVerified,
			CreatedAt:       result.User.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		},
		Tokens: TokensResponse{
			AccessToken:  result.TokenPair.AccessToken,
			RefreshToken: result.TokenPair.RefreshToken,
			TokenType:    result.TokenPair.TokenType,
			ExpiresIn:    result.TokenPair.ExpiresIn,
		},
	}

	writeJSON(w, http.StatusCreated, response)
}

// LoginRequest represents the login request body.
type LoginRequest struct {
	Email       string `json:"email" validate:"required,email"`
	Password    string `json:"password" validate:"required"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// LoginResponse represents the login response.
type LoginResponse struct {
	User   UserResponse   `json:"user"`
	Tokens TokensResponse `json:"tokens"`
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
				"error":          "Account temporarily locked",
				"message":        "Too many failed login attempts. Please try again later.",
				"retry_after_seconds": int(remaining.Seconds()),
			})
			return
		}
	}

	result, err := h.authService.Login(r.Context(), &auth.LoginRequest{
		Email:       req.Email,
		Password:    req.Password,
		Fingerprint: req.Fingerprint,
		IP:          r.RemoteAddr,
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
		writeJSON(w, http.StatusAccepted, map[string]interface{}{
			"mfa_required": true,
			"user_id":      result.User.ID.String(),
		})
		return
	}

	authSuccessTotal.WithLabelValues("login").Inc()
	response := LoginResponse{
		User: UserResponse{
			ID:              result.User.ID.String(),
			Email:           result.User.Email,
			Username:        result.User.Username,
			IsEmailVerified: result.User.IsEmailVerified,
			CreatedAt:       result.User.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		},
		Tokens: TokensResponse{
			AccessToken:  result.TokenPair.AccessToken,
			RefreshToken: result.TokenPair.RefreshToken,
			TokenType:    result.TokenPair.TokenType,
			ExpiresIn:    result.TokenPair.ExpiresIn,
		},
	}

	writeJSON(w, http.StatusOK, response)
}

// LoginMFARequest represents the login MFA request body.
type LoginMFARequest struct {
	UserID      string `json:"user_id" validate:"required,uuid"`
	Code        string `json:"code" validate:"required,len=6"`
	Fingerprint string `json:"fingerprint,omitempty"`
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

	result, err := h.authService.LoginWithMFA(r.Context(), &auth.LoginWithMFARequest{
		UserID:      userID,
		Code:        req.Code,
		Fingerprint: req.Fingerprint,
		IP:          r.RemoteAddr,
		UserAgent:   r.UserAgent(),
	})

	if err != nil {
		switch err {
		case auth.ErrInvalidMFACode:
			authFailureTotal.WithLabelValues("login_mfa", "invalid_code").Inc()
			h.writeError(w, http.StatusUnauthorized, "Invalid MFA code", err)
		default:
			h.writeError(w, http.StatusInternalServerError, "MFA verification failed", err)
		}
		return
	}

	authSuccessTotal.WithLabelValues("login_mfa").Inc()
	response := LoginResponse{
		User: UserResponse{
			ID:              result.User.ID.String(),
			Email:           result.User.Email,
			Username:        result.User.Username,
			IsEmailVerified: result.User.IsEmailVerified,
			CreatedAt:       result.User.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		},
		Tokens: TokensResponse{
			AccessToken:  result.TokenPair.AccessToken,
			RefreshToken: result.TokenPair.RefreshToken,
			TokenType:    result.TokenPair.TokenType,
			ExpiresIn:    result.TokenPair.ExpiresIn,
		},
	}

	writeJSON(w, http.StatusOK, response)
}

// SetupMFAResponse represents the MFA setup response.
type SetupMFAResponse struct {
	Secret string `json:"secret"`
	URL    string `json:"url"`
}

// SetupMFA handles the initiation of MFA setup.
func (h *Handler) SetupMFA(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.Context().Value(userIDKey).(string)
	userID, _ := uuid.Parse(userIDStr)

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

// EnableMFARequest represents the enable MFA request body.
type EnableMFARequest struct {
	Code string `json:"code" validate:"required,len=6"`
}

// EnableMFA handles enabling MFA for a user.
func (h *Handler) EnableMFA(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.Context().Value(userIDKey).(string)
	userID, _ := uuid.Parse(userIDStr)

	var req EnableMFARequest
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

	err := h.authService.EnableTOTP(r.Context(), &auth.EnableTOTPRequest{
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

	writeJSON(w, http.StatusOK, map[string]string{"message": "MFA enabled successfully"})
}

// RefreshRequest represents the refresh request body.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// RefreshResponse represents the refresh response.
type RefreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
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
		IP:           r.RemoteAddr,
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

	err = h.authService.Logout(r.Context(), &auth.LogoutRequest{
		SessionID: sessionID,
		IP:        r.RemoteAddr,
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

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

// writeError writes an error response and logs it.
func (h *Handler) writeError(w http.ResponseWriter, status int, message string, err error) {
	attrs := []any{
		"status", status,
		"message", message,
	}
	if err != nil {
		attrs = append(attrs, "error", err)
	}
	
	if status >= 500 {
		h.logger.Error("Server error", attrs...)
	} else {
		h.logger.Warn("Client error", attrs...)
	}

	writeJSON(w, status, ErrorResponse{
		Error:   http.StatusText(status),
		Message: message,
	})
}

// VerifyEmailRequest represents the verify email request body.
type VerifyEmailHTTPRequest struct {
	Token string `json:"token" validate:"required"`
}

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
	userIDStr := r.Context().Value(userIDKey).(string)
	userID, _ := uuid.Parse(userIDStr)

	result, err := h.authService.SendEmailVerification(r.Context(), userID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to send verification email", err)
		return
	}

	// In production, you would send an email here and not return the token
	// For development/testing, we return the token
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":    "Verification email sent",
		"expires_at": result.ExpiresAt.Format(time.RFC3339),
		// Remove this in production:
		"token": result.Token,
	})
}

// ForgotPasswordRequest represents the forgot password request body.
type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

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
	
	// In production, you would send an email here and not return the token
	// For development/testing, we return the token if user exists
	if result != nil {
		response["expires_at"] = result.ExpiresAt.Format(time.RFC3339)
		// Remove this in production:
		response["token"] = result.Token
	}

	writeJSON(w, http.StatusOK, response)
}

// ResetPasswordHTTPRequest represents the reset password request body.
type ResetPasswordHTTPRequest struct {
	Token       string `json:"token" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8,max=128"`
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

// RevokeAllSessions handles revoking all user sessions.
func (h *Handler) RevokeAllSessions(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.Context().Value(userIDKey).(string)
	userID, _ := uuid.Parse(userIDStr)

	err := h.authService.RevokeAllSessions(r.Context(), &auth.RevokeAllSessionsRequest{
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
