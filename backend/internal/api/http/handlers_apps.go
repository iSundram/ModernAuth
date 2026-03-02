package http

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/apps"
	"github.com/iSundram/ModernAuth/internal/storage"
)

// AppHandler handles OAuth2 application endpoints.
type AppHandler struct {
	service *apps.Service
}

// NewAppHandler creates a new app handler.
func NewAppHandler(service *apps.Service) *AppHandler {
	return &AppHandler{service: service}
}

// AppRoutes returns the router for app endpoints.
func (h *AppHandler) AppRoutes() chi.Router {
	r := chi.NewRouter()

	// App CRUD
	r.Get("/", h.ListApps)
	r.Post("/", h.CreateApp)
	r.Get("/{id}", h.GetApp)
	r.Put("/{id}", h.UpdateApp)
	r.Delete("/{id}", h.DeleteApp)

	// App status
	r.Post("/{id}/suspend", h.SuspendApp)
	r.Post("/{id}/activate", h.ActivateApp)

	// Secrets
	r.Get("/{id}/secrets", h.ListSecrets)
	r.Post("/{id}/secrets", h.CreateSecret)
	r.Delete("/{id}/secrets/{secretId}", h.RevokeSecret)

	// Scopes
	r.Get("/{id}/scopes", h.ListScopes)
	r.Post("/{id}/scopes", h.CreateScope)
	r.Delete("/{id}/scopes/{scopeId}", h.DeleteScope)

	// Consents
	r.Get("/{id}/consents", h.ListAppConsents)
	r.Delete("/{id}/consents/{userId}", h.RevokeConsent)

	return r
}

// OAuthRoutes returns the router for OAuth2 flow endpoints.
func (h *AppHandler) OAuthRoutes() chi.Router {
	r := chi.NewRouter()

	r.Post("/token", h.Token)
	r.Post("/revoke", h.RevokeToken)
	r.Get("/userinfo", h.UserInfo)

	return r
}

// ============================================================================
// App CRUD
// ============================================================================

func (h *AppHandler) CreateApp(w http.ResponseWriter, r *http.Request) {
	var req apps.CreateAppRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	// Get user ID from context for created_by
	userID, err := getUserIDFromContext(r.Context())
	if err == nil {
		req.CreatedBy = &userID
	}

	// Get tenant ID from query param or context
	tenantIDStr := r.URL.Query().Get("tenant_id")
	if tenantIDStr != "" {
		tid, err := uuid.Parse(tenantIDStr)
		if err == nil {
			req.TenantID = &tid
		}
	}

	result, err := h.service.CreateApp(r.Context(), &req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusCreated, result)
}

func (h *AppHandler) GetApp(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid app ID"})
		return
	}

	app, err := h.service.GetApp(r.Context(), id)
	if err != nil {
		if errors.Is(err, apps.ErrAppNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "App not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, app)
}

func (h *AppHandler) ListApps(w http.ResponseWriter, r *http.Request) {
	req := &apps.ListAppsRequest{
		Limit:  50,
		Offset: 0,
	}

	// Parse query params
	if tenantIDStr := r.URL.Query().Get("tenant_id"); tenantIDStr != "" {
		tid, err := uuid.Parse(tenantIDStr)
		if err == nil {
			req.TenantID = &tid
		}
	}
	if statusStr := r.URL.Query().Get("status"); statusStr != "" {
		status := storage.AppStatus(statusStr)
		req.Status = &status
	}
	if typeStr := r.URL.Query().Get("type"); typeStr != "" {
		appType := storage.AppType(typeStr)
		req.AppType = &appType
	}
	if search := r.URL.Query().Get("search"); search != "" {
		req.Search = search
	}

	result, err := h.service.ListApps(r.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"apps":  result.Apps,
		"total": result.Total,
	})
}

func (h *AppHandler) UpdateApp(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid app ID"})
		return
	}

	var req apps.UpdateAppRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	app, err := h.service.UpdateApp(r.Context(), id, &req)
	if err != nil {
		if errors.Is(err, apps.ErrAppNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "App not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, app)
}

func (h *AppHandler) DeleteApp(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid app ID"})
		return
	}

	if err := h.service.DeleteApp(r.Context(), id); err != nil {
		if errors.Is(err, apps.ErrAppNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "App not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusNoContent, nil)
}

func (h *AppHandler) SuspendApp(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid app ID"})
		return
	}

	if err := h.service.SuspendApp(r.Context(), id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "App suspended"})
}

func (h *AppHandler) ActivateApp(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid app ID"})
		return
	}

	if err := h.service.ActivateApp(r.Context(), id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "App activated"})
}

// ============================================================================
// Secrets
// ============================================================================

func (h *AppHandler) ListSecrets(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid app ID"})
		return
	}

	secrets, err := h.service.ListSecrets(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"secrets": secrets,
	})
}

type createSecretRequest struct {
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
}

func (h *AppHandler) CreateSecret(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid app ID"})
		return
	}

	var req createSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	if req.Name == "" {
		req.Name = "Default"
	}

	userID, _ := getUserIDFromContext(r.Context())

	result, err := h.service.CreateSecret(r.Context(), id, req.Name, req.Description, &userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"secret":       result.Secret,
		"client_secret": result.RawSecret,
	})
}

func (h *AppHandler) RevokeSecret(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	_, err := uuid.Parse(idStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid app ID"})
		return
	}

	secretIDStr := chi.URLParam(r, "secretId")
	secretID, err := uuid.Parse(secretIDStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid secret ID"})
		return
	}

	userID, _ := getUserIDFromContext(r.Context())

	if err := h.service.RevokeSecret(r.Context(), secretID, &userID); err != nil {
		if errors.Is(err, apps.ErrSecretNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "Secret not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Secret revoked"})
}

// ============================================================================
// Scopes
// ============================================================================

func (h *AppHandler) ListScopes(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid app ID"})
		return
	}

	scopes, err := h.service.ListScopes(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"scopes": scopes,
	})
}

func (h *AppHandler) CreateScope(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	appID, err := uuid.Parse(idStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid app ID"})
		return
	}

	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		IsDefault   bool   `json:"is_default"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Name is required"})
		return
	}

	scope, err := h.service.CreateScope(r.Context(), appID, req.Name, req.Description, req.IsDefault)
	if err != nil {
		if errors.Is(err, apps.ErrAppNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "App not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusCreated, scope)
}

func (h *AppHandler) DeleteScope(w http.ResponseWriter, r *http.Request) {
	scopeIDStr := chi.URLParam(r, "scopeId")
	scopeID, err := uuid.Parse(scopeIDStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid scope ID"})
		return
	}

	if err := h.service.DeleteScope(r.Context(), scopeID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Scope deleted"})
}

// ============================================================================
// Consents
// ============================================================================

func (h *AppHandler) ListAppConsents(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid app ID"})
		return
	}

	consents, err := h.service.ListAppConsents(r.Context(), id, 50, 0)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"consents": consents,
	})
}

func (h *AppHandler) RevokeConsent(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	appID, err := uuid.Parse(idStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid app ID"})
		return
	}

	userIDStr := chi.URLParam(r, "userId")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid user ID"})
		return
	}

	if err := h.service.RevokeUserConsent(r.Context(), userID, appID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Consent revoked"})
}

// ============================================================================
// OAuth2 Flow
// ============================================================================

func (h *AppHandler) Token(w http.ResponseWriter, r *http.Request) {
	var req apps.TokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	// Get client IP
	req.ClientIP = getClientIP(r)

	result, err := h.service.ExchangeToken(r.Context(), &req)
	if err != nil {
		switch err {
		case apps.ErrClientCredentials:
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		case apps.ErrCodeExpired, apps.ErrCodeUsed:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		case apps.ErrTokenExpired, apps.ErrTokenRevoked:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		case apps.ErrInvalidRedirectURI:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_redirect_uri"})
		case apps.ErrInvalidScope:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_scope"})
		case apps.ErrInvalidGrantType:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
		case apps.ErrPKCERequired:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "PKCE required"})
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		}
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (h *AppHandler) RevokeToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token         string `json:"token"`
		TokenTypeHint string `json:"token_type_hint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	if req.Token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Token is required"})
		return
	}

	// Try to revoke based on type hint, or try both
	var err error
	if req.TokenTypeHint == "refresh_token" {
		err = h.service.RevokeRefreshToken(r.Context(), req.Token)
	} else if req.TokenTypeHint == "access_token" {
		err = h.service.RevokeAccessToken(r.Context(), req.Token)
	} else {
		// Try access token first, then refresh token
		err = h.service.RevokeAccessToken(r.Context(), req.Token)
		if err != nil {
			err = h.service.RevokeRefreshToken(r.Context(), req.Token)
		}
	}

	// Per RFC 7009, always return 200 OK even if token not found
	writeJSON(w, http.StatusOK, map[string]string{"message": "Token revoked"})
}

func (h *AppHandler) UserInfo(w http.ResponseWriter, r *http.Request) {
	// Get token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Missing authorization header"})
		return
	}

	token := authHeader
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		token = authHeader[7:]
	}

	accessToken, _, err := h.service.ValidateAccessToken(r.Context(), token)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid token"})
		return
	}

	// Return user info
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"user_id":    accessToken.UserID,
		"tenant_id":  accessToken.TenantID,
		"scopes":     accessToken.Scopes,
		"expires_at": accessToken.ExpiresAt,
	})
}

// Helper functions
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain
		for i, c := range xff {
			if c == ',' {
				return xff[:i]
			}
		}
		return xff
	}
	// Fall back to RemoteAddr
	return r.RemoteAddr
}
