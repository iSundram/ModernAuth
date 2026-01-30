// Package http provides enhanced HTTP handlers for ModernAuth API.
package http

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/tenant"
)

// TenantHandler provides HTTP handlers for tenant management.
type TenantHandler struct {
	tenantService *tenant.Service
}

// NewTenantHandler creates a new tenant handler.
func NewTenantHandler(service *tenant.Service) *TenantHandler {
	return &TenantHandler{tenantService: service}
}

// TenantRoutes returns chi routes for tenant management.
func (h *TenantHandler) TenantRoutes() chi.Router {
	r := chi.NewRouter()

	r.Get("/", h.ListTenants)
	r.Post("/", h.CreateTenant)
	r.Get("/{id}", h.GetTenant)
	r.Put("/{id}", h.UpdateTenant)
	r.Delete("/{id}", h.DeleteTenant)
	r.Get("/{id}/stats", h.GetTenantStats)
	r.Get("/{id}/security-stats", h.GetTenantSecurityStats)
	r.Get("/{id}/users", h.ListTenantUsers)
	r.Post("/{id}/users/{userId}", h.AssignUserToTenant)
	r.Delete("/{id}/users/{userId}", h.RemoveUserFromTenant)

	// Suspension endpoints
	r.Post("/{id}/suspend", h.SuspendTenant)
	r.Post("/{id}/activate", h.ActivateTenant)

	// Audit export
	r.Get("/{id}/audit-logs/export", h.ExportTenantAuditLogs)

	// API Keys management
	r.Get("/{id}/api-keys", h.ListTenantAPIKeys)
	r.Post("/{id}/api-keys", h.CreateTenantAPIKey)
	r.Delete("/{id}/api-keys/{keyId}", h.RevokeTenantAPIKey)

	// Domain verification
	r.Post("/{id}/verify-domain", h.InitiateDomainVerification)
	r.Get("/{id}/verify-domain/status", h.CheckDomainVerification)

	// Bulk operations
	r.Post("/{id}/users/import", h.BulkImportUsers)

	// Feature flags
	r.Get("/{id}/features", h.GetTenantFeatures)
	r.Put("/{id}/features", h.UpdateTenantFeatures)

	return r
}

// CreateTenantRequest represents the request to create a tenant.
type CreateTenantRequest struct {
	Name     string                 `json:"name" validate:"required,min=1,max=100"`
	Slug     string                 `json:"slug" validate:"required,min=1,max=50,alphanum"`
	Domain   *string                `json:"domain,omitempty"`
	LogoURL  *string                `json:"logo_url,omitempty"`
	Settings map[string]interface{} `json:"settings,omitempty"`
	Plan     string                 `json:"plan,omitempty"`
}

// TenantResponse represents a tenant in API responses.
type TenantResponse struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Slug      string                 `json:"slug"`
	Domain    *string                `json:"domain,omitempty"`
	LogoURL   *string                `json:"logo_url,omitempty"`
	Settings  map[string]interface{} `json:"settings,omitempty"`
	Plan      string                 `json:"plan"`
	IsActive  bool                   `json:"is_active"`
	CreatedAt string                 `json:"created_at"`
	UpdatedAt string                 `json:"updated_at"`
}

// CreateTenant handles tenant creation.
func (h *TenantHandler) CreateTenant(w http.ResponseWriter, r *http.Request) {
	var req CreateTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if validationErrors := ValidateStruct(req); validationErrors != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "Validation failed",
			"details": validationErrors,
		})
		return
	}

	result, err := h.tenantService.CreateTenant(r.Context(), &tenant.CreateTenantRequest{
		Name:     req.Name,
		Slug:     req.Slug,
		Domain:   req.Domain,
		LogoURL:  req.LogoURL,
		Settings: req.Settings,
		Plan:     req.Plan,
	})

	if err != nil {
		switch err {
		case tenant.ErrTenantExists:
			writeError(w, http.StatusConflict, "Tenant with this slug or domain already exists", err)
		default:
			writeError(w, http.StatusInternalServerError, "Failed to create tenant", err)
		}
		return
	}

	response := TenantResponse{
		ID:        result.ID.String(),
		Name:      result.Name,
		Slug:      result.Slug,
		Domain:    result.Domain,
		LogoURL:   result.LogoURL,
		Settings:  result.Settings,
		Plan:      result.Plan,
		IsActive:  result.IsActive,
		CreatedAt: result.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt: result.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	writeJSON(w, http.StatusCreated, response)
}

// GetTenant retrieves a tenant by ID.
func (h *TenantHandler) GetTenant(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid tenant ID", err)
		return
	}

	result, err := h.tenantService.GetTenantByID(r.Context(), id)
	if err != nil {
		if err == tenant.ErrTenantNotFound {
			writeError(w, http.StatusNotFound, "Tenant not found", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get tenant", err)
		return
	}

	response := TenantResponse{
		ID:        result.ID.String(),
		Name:      result.Name,
		Slug:      result.Slug,
		Domain:    result.Domain,
		LogoURL:   result.LogoURL,
		Settings:  result.Settings,
		Plan:      result.Plan,
		IsActive:  result.IsActive,
		CreatedAt: result.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt: result.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	writeJSON(w, http.StatusOK, response)
}

// ListTenants lists all tenants.
func (h *TenantHandler) ListTenants(w http.ResponseWriter, r *http.Request) {
	limit, offset := parsePagination(r)

	tenants, err := h.tenantService.ListTenants(r.Context(), limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list tenants", err)
		return
	}

	response := make([]TenantResponse, len(tenants))
	for i, t := range tenants {
		response[i] = TenantResponse{
			ID:        t.ID.String(),
			Name:      t.Name,
			Slug:      t.Slug,
			Domain:    t.Domain,
			LogoURL:   t.LogoURL,
			Settings:  t.Settings,
			Plan:      t.Plan,
			IsActive:  t.IsActive,
			CreatedAt: t.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			UpdatedAt: t.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data":   response,
		"limit":  limit,
		"offset": offset,
	})
}

// UpdateTenantRequest represents the request to update a tenant.
type UpdateTenantRequest struct {
	Name     *string                `json:"name,omitempty"`
	Domain   *string                `json:"domain,omitempty"`
	LogoURL  *string                `json:"logo_url,omitempty"`
	Settings map[string]interface{} `json:"settings,omitempty"`
	Plan     *string                `json:"plan,omitempty"`
	IsActive *bool                  `json:"is_active,omitempty"`
}

// UpdateTenant updates a tenant.
func (h *TenantHandler) UpdateTenant(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid tenant ID", err)
		return
	}

	var req UpdateTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	result, err := h.tenantService.UpdateTenant(r.Context(), &tenant.UpdateTenantRequest{
		TenantID: id,
		Name:     req.Name,
		Domain:   req.Domain,
		LogoURL:  req.LogoURL,
		Settings: req.Settings,
		Plan:     req.Plan,
		IsActive: req.IsActive,
	})

	if err != nil {
		switch err {
		case tenant.ErrTenantNotFound:
			writeError(w, http.StatusNotFound, "Tenant not found", err)
		case tenant.ErrTenantExists:
			writeError(w, http.StatusConflict, "Domain already in use", err)
		default:
			writeError(w, http.StatusInternalServerError, "Failed to update tenant", err)
		}
		return
	}

	response := TenantResponse{
		ID:        result.ID.String(),
		Name:      result.Name,
		Slug:      result.Slug,
		Domain:    result.Domain,
		LogoURL:   result.LogoURL,
		Settings:  result.Settings,
		Plan:      result.Plan,
		IsActive:  result.IsActive,
		CreatedAt: result.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt: result.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	writeJSON(w, http.StatusOK, response)
}

// DeleteTenant deletes a tenant.
func (h *TenantHandler) DeleteTenant(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid tenant ID", err)
		return
	}

	if err := h.tenantService.DeleteTenant(r.Context(), id); err != nil {
		if err == tenant.ErrTenantNotFound {
			writeError(w, http.StatusNotFound, "Tenant not found", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to delete tenant", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetTenantStats retrieves tenant statistics.
func (h *TenantHandler) GetTenantStats(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid tenant ID", err)
		return
	}

	stats, err := h.tenantService.GetTenantStats(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get tenant stats", err)
		return
	}

	writeJSON(w, http.StatusOK, stats)
}

// GetTenantSecurityStats retrieves security-related statistics for a tenant.
func (h *TenantHandler) GetTenantSecurityStats(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid tenant ID", err)
		return
	}

	stats, err := h.tenantService.GetTenantSecurityStats(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get tenant security stats", err)
		return
	}

	writeJSON(w, http.StatusOK, stats)
}

// ListTenantUsers handles listing users in a tenant.
func (h *TenantHandler) ListTenantUsers(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid tenant ID", err)
		return
	}

	limit, offset := parsePagination(r)

	users, err := h.tenantService.ListTenantUsers(r.Context(), id, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list tenant users", err)
		return
	}

	response := make([]TenantUserResponse, len(users))
	for i, user := range users {
		response[i] = TenantUserResponse{
			ID:              user.ID.String(),
			Email:           user.Email,
			Username:        user.Username,
			FirstName:       user.FirstName,
			LastName:        user.LastName,
			IsEmailVerified: user.IsEmailVerified,
			IsActive:        user.IsActive,
			CreatedAt:       user.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data":   response,
		"limit":  limit,
		"offset": offset,
		"count":  len(response),
	})
}

// AssignUserToTenant handles assigning a user to a tenant.
func (h *TenantHandler) AssignUserToTenant(w http.ResponseWriter, r *http.Request) {
	tenantIDStr := chi.URLParam(r, "id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid tenant ID", err)
		return
	}

	userIDStr := chi.URLParam(r, "userId")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid user ID", err)
		return
	}

	err = h.tenantService.AssignUserToTenant(r.Context(), tenantID, userID)
	if err != nil {
		switch err {
		case tenant.ErrTenantNotFound:
			writeError(w, http.StatusNotFound, "Tenant not found", err)
		case tenant.ErrUserNotFound:
			writeError(w, http.StatusNotFound, "User not found", err)
		default:
			writeError(w, http.StatusInternalServerError, "Failed to assign user to tenant", err)
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "User assigned to tenant successfully"})
}

// RemoveUserFromTenant handles removing a user from a tenant.
func (h *TenantHandler) RemoveUserFromTenant(w http.ResponseWriter, r *http.Request) {
	tenantIDStr := chi.URLParam(r, "id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid tenant ID", err)
		return
	}

	userIDStr := chi.URLParam(r, "userId")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid user ID", err)
		return
	}

	err = h.tenantService.RemoveUserFromTenant(r.Context(), tenantID, userID)
	if err != nil {
		switch err {
		case tenant.ErrTenantNotFound:
			writeError(w, http.StatusNotFound, "Tenant not found", err)
		case tenant.ErrUserNotFound:
			writeError(w, http.StatusNotFound, "User not found", err)
		default:
			writeError(w, http.StatusInternalServerError, "Failed to remove user from tenant", err)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// TenantUserResponse represents a user in tenant API responses.
type TenantUserResponse struct {
	ID              string  `json:"id"`
	Email           string  `json:"email"`
	Username        *string `json:"username,omitempty"`
	FirstName       *string `json:"first_name,omitempty"`
	LastName        *string `json:"last_name,omitempty"`
	IsEmailVerified bool    `json:"is_email_verified"`
	IsActive        bool    `json:"is_active"`
	CreatedAt       string  `json:"created_at"`
}

// SuspendTenant handles suspending a tenant.
func (h *TenantHandler) SuspendTenant(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid tenant ID", err)
		return
	}

	if err := h.tenantService.SuspendTenant(r.Context(), id); err != nil {
		if err == tenant.ErrTenantNotFound {
			writeError(w, http.StatusNotFound, "Tenant not found", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to suspend tenant", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Tenant suspended successfully"})
}

// ActivateTenant handles activating a suspended tenant.
func (h *TenantHandler) ActivateTenant(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid tenant ID", err)
		return
	}

	if err := h.tenantService.ActivateTenant(r.Context(), id); err != nil {
		if err == tenant.ErrTenantNotFound {
			writeError(w, http.StatusNotFound, "Tenant not found", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to activate tenant", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Tenant activated successfully"})
}

// ExportTenantAuditLogs exports audit logs for a tenant in CSV or JSON format.
func (h *TenantHandler) ExportTenantAuditLogs(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid tenant ID", err)
		return
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	logs, err := h.tenantService.ExportAuditLogs(r.Context(), id, format)
	if err != nil {
		if err == tenant.ErrTenantNotFound {
			writeError(w, http.StatusNotFound, "Tenant not found", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to export audit logs", err)
		return
	}

	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=audit_logs.csv")
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=audit_logs.json")
	}

	w.Write(logs)
}

// TenantAPIKeyResponse represents an API key in responses.
type TenantAPIKeyResponse struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	KeyPrefix   string  `json:"key_prefix"`
	Scopes      []string `json:"scopes,omitempty"`
	ExpiresAt   *string `json:"expires_at,omitempty"`
	LastUsedAt  *string `json:"last_used_at,omitempty"`
	CreatedAt   string  `json:"created_at"`
}

// TenantCreateAPIKeyRequest represents a request to create a tenant API key.
type TenantCreateAPIKeyRequest struct {
	Name      string   `json:"name" validate:"required,min=1,max=100"`
	Scopes    []string `json:"scopes,omitempty"`
	ExpiresIn *int     `json:"expires_in,omitempty"` // seconds
}

// TenantCreateAPIKeyResponse includes the full key (only shown once).
type TenantCreateAPIKeyResponse struct {
	TenantAPIKeyResponse
	Key string `json:"key"` // Full key, only returned on creation
}

// ListTenantAPIKeys lists API keys for a tenant.
func (h *TenantHandler) ListTenantAPIKeys(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid tenant ID", err)
		return
	}

	keys, err := h.tenantService.ListAPIKeys(r.Context(), id)
	if err != nil {
		if err == tenant.ErrTenantNotFound {
			writeError(w, http.StatusNotFound, "Tenant not found", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to list API keys", err)
		return
	}

	response := make([]TenantAPIKeyResponse, len(keys))
	for i, key := range keys {
		response[i] = TenantAPIKeyResponse{
			ID:        key.ID.String(),
			Name:      key.Name,
			KeyPrefix: key.KeyPrefix,
			Scopes:    key.Scopes,
			CreatedAt: key.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		}
		if key.ExpiresAt != nil {
			expiresAt := key.ExpiresAt.Format("2006-01-02T15:04:05Z07:00")
			response[i].ExpiresAt = &expiresAt
		}
		if key.LastUsedAt != nil {
			lastUsedAt := key.LastUsedAt.Format("2006-01-02T15:04:05Z07:00")
			response[i].LastUsedAt = &lastUsedAt
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data":  response,
		"count": len(response),
	})
}

// CreateTenantAPIKey creates a new API key for a tenant.
func (h *TenantHandler) CreateTenantAPIKey(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid tenant ID", err)
		return
	}

	var req TenantCreateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if validationErrors := ValidateStruct(req); validationErrors != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "Validation failed",
			"details": validationErrors,
		})
		return
	}

	result, err := h.tenantService.CreateAPIKey(r.Context(), id, &tenant.CreateAPIKeyRequest{
		Name:      req.Name,
		Scopes:    req.Scopes,
		ExpiresIn: req.ExpiresIn,
	})
	if err != nil {
		if err == tenant.ErrTenantNotFound {
			writeError(w, http.StatusNotFound, "Tenant not found", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to create API key", err)
		return
	}

	response := TenantCreateAPIKeyResponse{
		TenantAPIKeyResponse: TenantAPIKeyResponse{
			ID:        result.APIKey.ID.String(),
			Name:      result.APIKey.Name,
			KeyPrefix: result.APIKey.KeyPrefix,
			Scopes:    result.APIKey.Scopes,
			CreatedAt: result.APIKey.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		},
		Key: result.RawKey,
	}
	if result.APIKey.ExpiresAt != nil {
		expiresAt := result.APIKey.ExpiresAt.Format("2006-01-02T15:04:05Z07:00")
		response.TenantAPIKeyResponse.ExpiresAt = &expiresAt
	}

	writeJSON(w, http.StatusCreated, response)
}

// RevokeTenantAPIKey revokes an API key.
func (h *TenantHandler) RevokeTenantAPIKey(w http.ResponseWriter, r *http.Request) {
	tenantIDStr := chi.URLParam(r, "id")
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid tenant ID", err)
		return
	}

	keyIDStr := chi.URLParam(r, "keyId")
	keyID, err := uuid.Parse(keyIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid API key ID", err)
		return
	}

	if err := h.tenantService.RevokeAPIKey(r.Context(), tenantID, keyID); err != nil {
		if err == tenant.ErrTenantNotFound {
			writeError(w, http.StatusNotFound, "Tenant not found", err)
			return
		}
		if err == tenant.ErrAPIKeyNotFound {
			writeError(w, http.StatusNotFound, "API key not found", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to revoke API key", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// DomainVerificationResponse represents domain verification status.
type DomainVerificationResponse struct {
	Domain         string `json:"domain"`
	TXTRecord      string `json:"txt_record"`
	VerifiedAt     *string `json:"verified_at,omitempty"`
	Status         string `json:"status"` // pending, verified, failed
}

// InitiateDomainVerification starts domain verification for a tenant.
func (h *TenantHandler) InitiateDomainVerification(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid tenant ID", err)
		return
	}

	result, err := h.tenantService.InitiateDomainVerification(r.Context(), id)
	if err != nil {
		if err == tenant.ErrTenantNotFound {
			writeError(w, http.StatusNotFound, "Tenant not found", err)
			return
		}
		if err == tenant.ErrNoDomainConfigured {
			writeError(w, http.StatusBadRequest, "No domain configured for tenant", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to initiate domain verification", err)
		return
	}

	writeJSON(w, http.StatusOK, DomainVerificationResponse{
		Domain:    result.Domain,
		TXTRecord: result.TXTRecord,
		Status:    result.Status,
	})
}

// CheckDomainVerification checks domain verification status.
func (h *TenantHandler) CheckDomainVerification(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid tenant ID", err)
		return
	}

	result, err := h.tenantService.CheckDomainVerification(r.Context(), id)
	if err != nil {
		if err == tenant.ErrTenantNotFound {
			writeError(w, http.StatusNotFound, "Tenant not found", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to check domain verification", err)
		return
	}

	response := DomainVerificationResponse{
		Domain:    result.Domain,
		TXTRecord: result.TXTRecord,
		Status:    result.Status,
	}
	if result.VerifiedAt != nil {
		verifiedAt := result.VerifiedAt.Format("2006-01-02T15:04:05Z07:00")
		response.VerifiedAt = &verifiedAt
	}

	writeJSON(w, http.StatusOK, response)
}

// BulkImportUsersRequest represents a bulk user import request.
type BulkImportUsersRequest struct {
	Users []BulkUserEntry `json:"users" validate:"required,min=1,max=500"`
}

// BulkUserEntry represents a single user in bulk import.
type BulkUserEntry struct {
	Email     string   `json:"email" validate:"required,email"`
	FirstName *string  `json:"first_name,omitempty"`
	LastName  *string  `json:"last_name,omitempty"`
	RoleIDs   []string `json:"role_ids,omitempty"`
}

// BulkImportUsersResponse represents the result of bulk import.
type BulkImportUsersResponse struct {
	Total     int              `json:"total"`
	Succeeded int              `json:"succeeded"`
	Failed    int              `json:"failed"`
	Errors    []BulkImportError `json:"errors,omitempty"`
}

// BulkImportError represents an error for a specific user.
type BulkImportError struct {
	Email  string `json:"email"`
	Reason string `json:"reason"`
}

// BulkImportUsers handles bulk user import for a tenant.
func (h *TenantHandler) BulkImportUsers(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid tenant ID", err)
		return
	}

	var req BulkImportUsersRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if validationErrors := ValidateStruct(req); validationErrors != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "Validation failed",
			"details": validationErrors,
		})
		return
	}

	// Convert to service request
	users := make([]tenant.BulkUserEntry, len(req.Users))
	for i, u := range req.Users {
		roleIDs := make([]uuid.UUID, 0, len(u.RoleIDs))
		for _, rid := range u.RoleIDs {
			if roleID, err := uuid.Parse(rid); err == nil {
				roleIDs = append(roleIDs, roleID)
			}
		}
		users[i] = tenant.BulkUserEntry{
			Email:     u.Email,
			FirstName: u.FirstName,
			LastName:  u.LastName,
			RoleIDs:   roleIDs,
		}
	}

	result, err := h.tenantService.BulkImportUsers(r.Context(), id, users)
	if err != nil {
		if err == tenant.ErrTenantNotFound {
			writeError(w, http.StatusNotFound, "Tenant not found", err)
			return
		}
		if err == tenant.ErrPlanLimitExceeded {
			writeError(w, http.StatusForbidden, "Tenant user limit exceeded", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to import users", err)
		return
	}

	response := BulkImportUsersResponse{
		Total:     result.Total,
		Succeeded: result.Succeeded,
		Failed:    result.Failed,
	}
	for _, e := range result.Errors {
		response.Errors = append(response.Errors, BulkImportError{
			Email:  e.Email,
			Reason: e.Reason,
		})
	}

	writeJSON(w, http.StatusOK, response)
}

// TenantFeaturesResponse represents tenant feature flags.
type TenantFeaturesResponse struct {
	SSOEnabled       bool `json:"sso_enabled"`
	APIAccessEnabled bool `json:"api_access_enabled"`
	WebhooksEnabled  bool `json:"webhooks_enabled"`
	MFARequired      bool `json:"mfa_required"`
	CustomBranding   bool `json:"custom_branding"`
}

// UpdateTenantFeaturesRequest represents a request to update feature flags.
type UpdateTenantFeaturesRequest struct {
	SSOEnabled       *bool `json:"sso_enabled,omitempty"`
	APIAccessEnabled *bool `json:"api_access_enabled,omitempty"`
	WebhooksEnabled  *bool `json:"webhooks_enabled,omitempty"`
	MFARequired      *bool `json:"mfa_required,omitempty"`
	CustomBranding   *bool `json:"custom_branding,omitempty"`
}

// GetTenantFeatures retrieves feature flags for a tenant.
func (h *TenantHandler) GetTenantFeatures(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid tenant ID", err)
		return
	}

	features, err := h.tenantService.GetFeatures(r.Context(), id)
	if err != nil {
		if err == tenant.ErrTenantNotFound {
			writeError(w, http.StatusNotFound, "Tenant not found", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get tenant features", err)
		return
	}

	writeJSON(w, http.StatusOK, TenantFeaturesResponse{
		SSOEnabled:       features.SSOEnabled,
		APIAccessEnabled: features.APIAccessEnabled,
		WebhooksEnabled:  features.WebhooksEnabled,
		MFARequired:      features.MFARequired,
		CustomBranding:   features.CustomBranding,
	})
}

// UpdateTenantFeatures updates feature flags for a tenant.
func (h *TenantHandler) UpdateTenantFeatures(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid tenant ID", err)
		return
	}

	var req UpdateTenantFeaturesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	features, err := h.tenantService.UpdateFeatures(r.Context(), id, &tenant.UpdateFeaturesRequest{
		SSOEnabled:       req.SSOEnabled,
		APIAccessEnabled: req.APIAccessEnabled,
		WebhooksEnabled:  req.WebhooksEnabled,
		MFARequired:      req.MFARequired,
		CustomBranding:   req.CustomBranding,
	})
	if err != nil {
		if err == tenant.ErrTenantNotFound {
			writeError(w, http.StatusNotFound, "Tenant not found", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to update tenant features", err)
		return
	}

	writeJSON(w, http.StatusOK, TenantFeaturesResponse{
		SSOEnabled:       features.SSOEnabled,
		APIAccessEnabled: features.APIAccessEnabled,
		WebhooksEnabled:  features.WebhooksEnabled,
		MFARequired:      features.MFARequired,
		CustomBranding:   features.CustomBranding,
	})
}
