// Package http provides HTTP handlers for ModernAuth API.
package http

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/iSundram/ModernAuth/internal/auth"
	"github.com/iSundram/ModernAuth/internal/email"
	"github.com/iSundram/ModernAuth/internal/storage"
	"github.com/redis/go-redis/v9"
)

// Handler provides HTTP handlers for the authentication API.
type Handler struct {
	authService    *auth.AuthService
	tokenService   *auth.TokenService
	storage        storage.Storage
	rdb            *redis.Client
	accountLockout *auth.AccountLockout
	mfaLockout     *auth.AccountLockout
	tokenBlacklist *auth.TokenBlacklist
	emailService   email.Service
	logger         *slog.Logger
	corsOrigins    []string
	dbPool         interface { // Database pool interface for health checks
		Ping(ctx context.Context) error
	}

	// Specialized handlers
	tenantHandler         *TenantHandler
	deviceHandler         *DeviceHandler
	apiKeyHandler         *APIKeyHandler
	webhookHandler        *WebhookHandler
	invitationHandler     *InvitationHandler
	oauthHandler          *OAuthHandler
	emailTemplateHandler  *EmailTemplateHandler
	analyticsHandler      *AnalyticsHandler
}

// NewHandler creates a new HTTP handler.
func NewHandler(authService *auth.AuthService, tokenService *auth.TokenService, storage storage.Storage, rdb *redis.Client, accountLockout *auth.AccountLockout, tokenBlacklist *auth.TokenBlacklist, emailService email.Service) *Handler {
	return &Handler{
		authService:    authService,
		tokenService:   tokenService,
		storage:        storage,
		rdb:            rdb,
		accountLockout: accountLockout,
		tokenBlacklist: tokenBlacklist,
		emailService:   emailService,
		logger:         slog.Default().With("component", "http_handler"),
		corsOrigins:    []string{"*"}, // Default to allow all in development
	}
}

// SetCORSOrigins sets the allowed CORS origins.
func (h *Handler) SetCORSOrigins(origins []string) {
	if len(origins) == 0 {
		h.corsOrigins = []string{"*"}
	} else {
		h.corsOrigins = origins
	}
	// Warn about wildcard CORS in production
	if len(h.corsOrigins) > 0 && h.corsOrigins[0] == "*" {
		h.logger.Warn("CORS is configured to allow all origins (*). This is insecure for production. Set CORS_ORIGINS to specific domains.")
	}
}

// SetMFALockout sets the MFA lockout manager.
func (h *Handler) SetMFALockout(lockout *auth.AccountLockout) {
	h.mfaLockout = lockout
}

// SetTenantHandler sets the tenant handler.
func (h *Handler) SetTenantHandler(handler *TenantHandler) {
	h.tenantHandler = handler
}

// SetDeviceHandler sets the device handler.
func (h *Handler) SetDeviceHandler(handler *DeviceHandler) {
	h.deviceHandler = handler
}

// SetAPIKeyHandler sets the API key handler.
func (h *Handler) SetAPIKeyHandler(handler *APIKeyHandler) {
	h.apiKeyHandler = handler
}

// SetWebhookHandler sets the webhook handler.
func (h *Handler) SetWebhookHandler(handler *WebhookHandler) {
	h.webhookHandler = handler
}

// SetInvitationHandler sets the invitation handler.
func (h *Handler) SetInvitationHandler(handler *InvitationHandler) {
	h.invitationHandler = handler
}

// SetOAuthHandler sets the OAuth handler.
func (h *Handler) SetOAuthHandler(handler *OAuthHandler) {
	h.oauthHandler = handler
}

// SetEmailTemplateHandler sets the email template handler.
func (h *Handler) SetEmailTemplateHandler(handler *EmailTemplateHandler) {
	h.emailTemplateHandler = handler
}

// SetAnalyticsHandler sets the analytics handler.
func (h *Handler) SetAnalyticsHandler(handler *AnalyticsHandler) {
	h.analyticsHandler = handler
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

	// Check database connectivity
	dbStatus := "healthy"
	if h.dbPool != nil {
		if err := h.dbPool.Ping(ctx); err != nil {
			dbStatus = "unhealthy"
			h.logger.Warn("Database health check failed", "error", err)
		}
	} else {
		dbStatus = "not_configured"
	}

	status := "healthy"
	statusCode := http.StatusOK
	if redisStatus == "unhealthy" || dbStatus == "unhealthy" {
		status = "degraded"
		statusCode = http.StatusServiceUnavailable
	}

	response := map[string]interface{}{
		"status": status,
		"services": map[string]string{
			"redis":    redisStatus,
			"database": dbStatus,
		},
	}
	writeJSON(w, statusCode, response)
}

// GetPublicSettings handles requests for non-sensitive system settings.
func (h *Handler) GetPublicSettings(w http.ResponseWriter, r *http.Request) {
	// These are the settings we want to expose publicly
	publicKeys := []string{
		"site.name",
		"site.logo_url",
		"auth.allow_registration",
		"auth.mfa_enabled",
	}

	response := make(map[string]interface{})
	for _, key := range publicKeys {
		setting, err := h.authService.GetSetting(r.Context(), key)
		if err != nil {
			h.logger.Warn("Failed to fetch public setting", "key", key, "error", err)
			continue
		}
		if setting != nil {
			response[key] = setting.Value
		}
	}

	writeJSON(w, http.StatusOK, response)
}

// SetDBPool sets the database pool for health checks.
func (h *Handler) SetDBPool(dbPool interface {
	Ping(ctx context.Context) error
}) {
	h.dbPool = dbPool
}

// getBaseURL returns the base URL for the application.
func (h *Handler) getBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		host = "localhost:8080"
	}
	return scheme + "://" + host
}
