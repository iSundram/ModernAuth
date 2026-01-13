// Package http provides API key HTTP handlers for ModernAuth API.
package http

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/apikey"
	"github.com/iSundram/ModernAuth/internal/storage"
	tenantpkg "github.com/iSundram/ModernAuth/internal/tenant"
)

// APIKeyHandler provides HTTP handlers for API key management.
type APIKeyHandler struct {
	apiKeyService *apikey.Service
}

// NewAPIKeyHandler creates a new API key handler.
func NewAPIKeyHandler(service *apikey.Service) *APIKeyHandler {
	return &APIKeyHandler{apiKeyService: service}
}

// APIKeyRoutes returns chi routes for API key management.
func (h *APIKeyHandler) APIKeyRoutes() chi.Router {
	r := chi.NewRouter()

	r.Get("/", h.ListAPIKeys)
	r.Post("/", h.CreateAPIKey)
	r.Get("/{id}", h.GetAPIKey)
	r.Delete("/{id}", h.RevokeAPIKey)
	r.Post("/{id}/rotate", h.RotateAPIKey)

	return r
}

// CreateAPIKeyRequest represents the request to create an API key.
type CreateAPIKeyRequest struct {
	Name        string   `json:"name" validate:"required,min=1,max=100"`
	Description *string  `json:"description,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
	RateLimit   *int     `json:"rate_limit,omitempty"`
	AllowedIPs  []string `json:"allowed_ips,omitempty"`
	ExpiresIn   *int     `json:"expires_in,omitempty"` // seconds
}

// APIKeyResponse represents an API key in API responses.
type APIKeyResponse struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description *string  `json:"description,omitempty"`
	KeyPrefix   string   `json:"key_prefix"`
	Scopes      []string `json:"scopes,omitempty"`
	RateLimit   *int     `json:"rate_limit,omitempty"`
	AllowedIPs  []string `json:"allowed_ips,omitempty"`
	ExpiresAt   *string  `json:"expires_at,omitempty"`
	LastUsedAt  *string  `json:"last_used_at,omitempty"`
	IsActive    bool     `json:"is_active"`
	CreatedAt   string   `json:"created_at"`
}

// CreateAPIKeyResponse includes the raw key (only shown once).
type CreateAPIKeyResponse struct {
	APIKey APIKeyResponse `json:"api_key"`
	Key    string         `json:"key"` // Raw key, only shown once
}

// CreateAPIKey handles API key creation.
func (h *APIKeyHandler) CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	var req CreateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if errors := ValidateStruct(req); errors != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "Validation failed",
			"details": errors,
		})
		return
	}

	// Get user ID from context
	userIDStr, ok := r.Context().Value(userIDKey).(string)
	if !ok || userIDStr == "" {
		writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}
	userID, _ := uuid.Parse(userIDStr)

	// Get tenant ID from context if available
	var tenantID *uuid.UUID
	if tid := tenantpkg.GetTenantIDFromContext(r.Context()); tid != nil {
		tenantID = tid
	}

	result, err := h.apiKeyService.CreateAPIKey(r.Context(), &apikey.CreateAPIKeyRequest{
		TenantID:    tenantID,
		UserID:      &userID,
		Name:        req.Name,
		Description: req.Description,
		Scopes:      req.Scopes,
		RateLimit:   req.RateLimit,
		AllowedIPs:  req.AllowedIPs,
		ExpiresIn:   req.ExpiresIn,
	})

	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create API key", err)
		return
	}

	response := CreateAPIKeyResponse{
		APIKey: h.toAPIKeyResponse(result.APIKey),
		Key:    result.Key,
	}

	writeJSON(w, http.StatusCreated, response)
}

// GetAPIKey retrieves an API key by ID.
func (h *APIKeyHandler) GetAPIKey(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid API key ID", err)
		return
	}

	key, err := h.apiKeyService.GetAPIKey(r.Context(), id)
	if err != nil {
		if err == apikey.ErrAPIKeyNotFound {
			writeError(w, http.StatusNotFound, "API key not found", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get API key", err)
		return
	}

	writeJSON(w, http.StatusOK, h.toAPIKeyResponse(key))
}

// ListAPIKeys lists API keys for the current user.
func (h *APIKeyHandler) ListAPIKeys(w http.ResponseWriter, r *http.Request) {
	userIDStr, ok := r.Context().Value(userIDKey).(string)
	if !ok || userIDStr == "" {
		writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}
	userID, _ := uuid.Parse(userIDStr)

	limit, offset := parsePagination(r)

	keys, err := h.apiKeyService.ListAPIKeys(r.Context(), &userID, nil, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list API keys", err)
		return
	}

	response := make([]APIKeyResponse, len(keys))
	for i, k := range keys {
		response[i] = h.toAPIKeyResponse(k)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data":   response,
		"limit":  limit,
		"offset": offset,
	})
}

// RevokeAPIKey revokes an API key.
func (h *APIKeyHandler) RevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid API key ID", err)
		return
	}

	userIDStr, _ := r.Context().Value(userIDKey).(string)
	var revokedBy *uuid.UUID
	if uid, err := uuid.Parse(userIDStr); err == nil {
		revokedBy = &uid
	}

	if err := h.apiKeyService.RevokeAPIKey(r.Context(), id, revokedBy); err != nil {
		if err == apikey.ErrAPIKeyNotFound {
			writeError(w, http.StatusNotFound, "API key not found", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to revoke API key", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// RotateAPIKey rotates an API key.
func (h *APIKeyHandler) RotateAPIKey(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid API key ID", err)
		return
	}

	userIDStr, _ := r.Context().Value(userIDKey).(string)
	var rotatedBy *uuid.UUID
	if uid, err := uuid.Parse(userIDStr); err == nil {
		rotatedBy = &uid
	}

	result, err := h.apiKeyService.RotateAPIKey(r.Context(), id, rotatedBy)
	if err != nil {
		if err == apikey.ErrAPIKeyNotFound {
			writeError(w, http.StatusNotFound, "API key not found", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to rotate API key", err)
		return
	}

	response := CreateAPIKeyResponse{
		APIKey: h.toAPIKeyResponse(result.APIKey),
		Key:    result.Key,
	}

	writeJSON(w, http.StatusOK, response)
}

func (h *APIKeyHandler) toAPIKeyResponse(key *storage.APIKey) APIKeyResponse {
	resp := APIKeyResponse{
		ID:          key.ID.String(),
		Name:        key.Name,
		Description: key.Description,
		KeyPrefix:   key.KeyPrefix,
		Scopes:      key.Scopes,
		RateLimit:   key.RateLimit,
		AllowedIPs:  key.AllowedIPs,
		IsActive:    key.IsActive,
		CreatedAt:   key.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
	if key.ExpiresAt != nil {
		exp := key.ExpiresAt.Format("2006-01-02T15:04:05Z07:00")
		resp.ExpiresAt = &exp
	}
	if key.LastUsedAt != nil {
		lu := key.LastUsedAt.Format("2006-01-02T15:04:05Z07:00")
		resp.LastUsedAt = &lu
	}
	return resp
}
