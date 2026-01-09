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
	authService  *auth.AuthService
	tokenService *auth.TokenService
	rdb          *redis.Client
	logger       *slog.Logger
}

// NewHandler creates a new HTTP handler.
func NewHandler(authService *auth.AuthService, tokenService *auth.TokenService, rdb *redis.Client) *Handler {
	return &Handler{
		authService:  authService,
		tokenService: tokenService,
		rdb:          rdb,
		logger:       slog.Default().With("component", "http_handler"),
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
	Email    string `json:"email"`
	Password string `json:"password"`
	Username string `json:"username,omitempty"`
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
	response := map[string]string{
		"status": "healthy",
	}
	writeJSON(w, http.StatusOK, response)
}

// Register handles user registration.
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate request
	if req.Email == "" {
		h.writeError(w, http.StatusBadRequest, "Email is required", nil)
		return
	}
	if req.Password == "" {
		h.writeError(w, http.StatusBadRequest, "Password is required", nil)
		return
	}
	if len(req.Password) < 8 {
		h.writeError(w, http.StatusBadRequest, "Password must be at least 8 characters", nil)
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
	Email       string `json:"email"`
	Password    string `json:"password"`
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

	// Validate request
	if req.Email == "" {
		h.writeError(w, http.StatusBadRequest, "Email is required", nil)
		return
	}
	if req.Password == "" {
		h.writeError(w, http.StatusBadRequest, "Password is required", nil)
		return
	}

	result, err := h.authService.Login(r.Context(), &auth.LoginRequest{
		Email:       req.Email,
		Password:    req.Password,
		Fingerprint: req.Fingerprint,
		IP:          r.RemoteAddr,
		UserAgent:   r.UserAgent(),
	})

	if err != nil {
		switch err {
		case auth.ErrInvalidCredentials:
			h.writeError(w, http.StatusUnauthorized, "Invalid email or password", err)
		case auth.ErrUserNotFound:
			h.writeError(w, http.StatusUnauthorized, "Invalid email or password", err)
		default:
			h.writeError(w, http.StatusInternalServerError, "Login failed", err)
		}
		return
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
	UserID      string `json:"user_id"`
	Code        string `json:"code"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// LoginMFA handles MFA verification during login.
func (h *Handler) LoginMFA(w http.ResponseWriter, r *http.Request) {
	var req LoginMFARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
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
	Code string `json:"code"`
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
	RefreshToken string `json:"refresh_token"`
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

	if req.RefreshToken == "" {
		h.writeError(w, http.StatusBadRequest, "Refresh token is required", nil)
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
