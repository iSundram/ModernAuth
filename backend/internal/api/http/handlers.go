// Package http provides HTTP handlers for ModernAuth API.
package http

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
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
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*", "http://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))
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
			r.With(h.Auth).Get("/me", h.Me)

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

			// Password Change (Protected)
			r.With(h.Auth).Post("/change-password", h.ChangePassword)
		})

		// User Management (requires permissions)
		r.Route("/users", func(r chi.Router) {
			r.Use(h.Auth)
			r.With(h.RequirePermission("users:read")).Get("/", h.ListUsers)
			r.With(h.RequirePermission("users:write")).Post("/", h.CreateUser)
			r.With(h.RequirePermission("users:read")).Get("/{id}", h.GetUser)
			r.With(h.RequirePermission("users:write")).Put("/{id}", h.UpdateUser)
			r.With(h.RequirePermission("users:delete")).Delete("/{id}", h.DeleteUser)
		})

		// Audit Logs (requires permission)
		r.Route("/audit", func(r chi.Router) {
			r.Use(h.Auth)
			r.With(h.RequirePermission("audit:read")).Get("/logs", h.ListAuditLogs)
		})

		// Admin (requires admin role)
		r.Route("/admin", func(r chi.Router) {
			r.Use(h.Auth)
			r.Use(h.RequireRole("admin"))
			r.Get("/stats", h.GetSystemStats)
			r.Get("/services", h.GetServicesStatus)
			r.Get("/roles", h.ListRoles)
			r.Post("/users/{id}/roles", h.AssignUserRole)
			r.Delete("/users/{id}/roles/{roleId}", h.RemoveUserRole)
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

// Me handles requests for the current user's profile.
func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.Context().Value(userIDKey).(string)
	userID, _ := uuid.Parse(userIDStr)

	user, err := h.authService.GetUserByID(r.Context(), userID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to get user", err)
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

// ListUsers handles requests to list all users.
func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.authService.ListUsers(r.Context())
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to list users", err)
		return
	}

	response := make([]UserResponse, len(users))
	for i, user := range users {
		response[i] = UserResponse{
			ID:              user.ID.String(),
			Email:           user.Email,
			Username:        user.Username,
			IsEmailVerified: user.IsEmailVerified,
			CreatedAt:       user.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		}
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

// UpdateUserRequest represents the update user request body.
type UpdateUserHTTPRequest struct {
	Email    *string `json:"email,omitempty" validate:"omitempty,email"`
	Username *string `json:"username,omitempty" validate:"omitempty,min=3,max=50"`
	Phone    *string `json:"phone,omitempty"`
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
	actorIDStr := r.Context().Value(userIDKey).(string)
	actorID, _ := uuid.Parse(actorIDStr)

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

// AuditLogResponse represents an audit log in API responses.
type AuditLogResponse struct {
	ID        string                 `json:"id"`
	UserID    *string                `json:"user_id,omitempty"`
	ActorID   *string                `json:"actor_id,omitempty"`
	EventType string                 `json:"event_type"`
	IP        *string                `json:"ip,omitempty"`
	UserAgent *string                `json:"user_agent,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
	CreatedAt string                 `json:"created_at"`
}

// ListAuditLogs handles requests for audit logs.
func (h *Handler) ListAuditLogs(w http.ResponseWriter, r *http.Request) {
	// Parse pagination
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	userIDStr := r.URL.Query().Get("user_id")

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

	var userID *uuid.UUID
	if userIDStr != "" {
		if id, err := uuid.Parse(userIDStr); err == nil {
			userID = &id
		}
	}

	logs, err := h.authService.GetAuditLogs(r.Context(), userID, limit, offset)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to fetch audit logs", err)
		return
	}

	response := make([]AuditLogResponse, len(logs))
	for i, log := range logs {
		var userIDPtr, actorIDPtr *string
		if log.UserID != nil {
			s := log.UserID.String()
			userIDPtr = &s
		}
		if log.ActorID != nil {
			s := log.ActorID.String()
			actorIDPtr = &s
		}
		response[i] = AuditLogResponse{
			ID:        log.ID.String(),
			UserID:    userIDPtr,
			ActorID:   actorIDPtr,
			EventType: log.EventType,
			IP:        log.IP,
			UserAgent: log.UserAgent,
			Data:      log.Data,
			CreatedAt: log.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"logs":   response,
		"limit":  limit,
		"offset": offset,
		"count":  len(response),
	})
}

// GetSystemStats handles requests for system statistics.
func (h *Handler) GetSystemStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"users": map[string]interface{}{
			"total":     1,
			"active":    1,
			"suspended": 0,
			"byRole": map[string]int{
				"admin": 1,
				"user":  0,
			},
		},
	})
}

// GetServicesStatus handles requests for service status.
func (h *Handler) GetServicesStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	services := []map[string]interface{}{}

	// Postgres Check
	pgStatus := "healthy"
	// (In a real app, we'd ping the DB here, but let's assume it's up if the app is running
	// or we could expose the HealthCheck logic better. For now, we'll just say it's up)
	services = append(services, map[string]interface{}{
		"name": "Database",
		"status": pgStatus,
		"uptime": "99.9%", // Placeholder
		"latency": "2ms",  // Placeholder
	})

	// Redis Check
	redisStatus := "healthy"
	if h.rdb != nil {
		if err := h.rdb.Ping(ctx).Err(); err != nil {
			redisStatus = "degraded"
		}
	} else {
		redisStatus = "not_configured"
	}
	services = append(services, map[string]interface{}{
		"name": "Redis Cache",
		"status": redisStatus,
		"uptime": "99.9%",
		"latency": "1ms",
	})

	// Auth Service
	services = append(services, map[string]interface{}{
		"name": "Auth Service",
		"status": "healthy",
		"uptime": "100%",
		"version": "1.0.0",
	})

	writeJSON(w, http.StatusOK, services)
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

// ChangePasswordRequest represents the change password request body.
type ChangePasswordHTTPRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,min=8,max=128"`
}

// ChangePassword handles password change for authenticated users.
func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.Context().Value(userIDKey).(string)
	userID, _ := uuid.Parse(userIDStr)

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

	err := h.authService.ChangePassword(r.Context(), &auth.ChangePasswordRequest{
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

// RoleResponse represents a role in API responses.
type RoleResponse struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
}

// ListRoles handles requests to list all roles.
func (h *Handler) ListRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := h.authService.ListRoles(r.Context())
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to list roles", err)
		return
	}

	response := make([]RoleResponse, len(roles))
	for i, role := range roles {
		response[i] = RoleResponse{
			ID:          role.ID.String(),
			Name:        role.Name,
			Description: role.Description,
		}
	}

	writeJSON(w, http.StatusOK, response)
}

// AssignUserRoleRequest represents the assign role request body.
type AssignUserRoleRequest struct {
	RoleID string `json:"role_id" validate:"required,uuid"`
}

// AssignUserRole handles assigning a role to a user.
func (h *Handler) AssignUserRole(w http.ResponseWriter, r *http.Request) {
	userIDStr := chi.URLParam(r, "id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid user ID", err)
		return
	}

	var req AssignUserRoleRequest
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

	roleID, _ := uuid.Parse(req.RoleID)

	// Get actor ID from context
	actorIDStr := r.Context().Value(userIDKey).(string)
	actorID, _ := uuid.Parse(actorIDStr)

	err = h.authService.AssignRole(r.Context(), userID, roleID, &actorID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to assign role", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Role assigned successfully"})
}

// RemoveUserRole handles removing a role from a user.
func (h *Handler) RemoveUserRole(w http.ResponseWriter, r *http.Request) {
	userIDStr := chi.URLParam(r, "id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid user ID", err)
		return
	}

	roleIDStr := chi.URLParam(r, "roleId")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid role ID", err)
		return
	}

	// Get actor ID from context
	actorIDStr := r.Context().Value(userIDKey).(string)
	actorID, _ := uuid.Parse(actorIDStr)

	err = h.authService.RemoveRole(r.Context(), userID, roleID, &actorID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to remove role", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Role removed successfully"})
}
