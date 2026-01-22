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
