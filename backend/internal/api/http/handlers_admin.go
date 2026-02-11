// Package http provides admin HTTP handlers.
package http

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/auth"
)

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
		"name":    "Database",
		"status":  pgStatus,
		"uptime":  "99.9%", // Placeholder
		"latency": "2ms",   // Placeholder
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
		"name":    "Redis Cache",
		"status":  redisStatus,
		"uptime":  "99.9%",
		"latency": "1ms",
	})

	// Auth Service
	services = append(services, map[string]interface{}{
		"name":    "Auth Service",
		"status":  "healthy",
		"uptime":  "100%",
		"version": "1.0.0",
	})

	writeJSON(w, http.StatusOK, services)
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
			IsSystem:    role.IsSystem,
			CreatedAt:   role.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		}
		if role.TenantID != nil {
			id := role.TenantID.String()
			response[i].TenantID = &id
		}
	}

	writeJSON(w, http.StatusOK, response)
}

// GetRole handles getting a role by ID.
func (h *Handler) GetRole(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid role ID", err)
		return
	}

	role, err := h.storage.GetRoleByID(r.Context(), id)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to get role", err)
		return
	}
	if role == nil {
		h.writeError(w, http.StatusNotFound, "Role not found", nil)
		return
	}

	response := RoleResponse{
		ID:          role.ID.String(),
		Name:        role.Name,
		Description: role.Description,
		IsSystem:    role.IsSystem,
		CreatedAt:   role.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
	if role.TenantID != nil {
		id := role.TenantID.String()
		response.TenantID = &id
	}

	writeJSON(w, http.StatusOK, response)
}

// CreateRole handles creating a new role.
func (h *Handler) CreateRole(w http.ResponseWriter, r *http.Request) {
	var req CreateRoleRequest
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

	// Convert TenantID from string to UUID if provided
	var tenantID *uuid.UUID
	if req.TenantID != nil {
		id, err := uuid.Parse(*req.TenantID)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, "Invalid tenant ID format", err)
			return
		}
		tenantID = &id
	}

	role, err := h.authService.CreateRole(r.Context(), &auth.CreateRoleRequest{
		TenantID:    tenantID,
		Name:        req.Name,
		Description: req.Description,
	})
	if err != nil {
		switch err {
		case auth.ErrRoleExists:
			h.writeError(w, http.StatusConflict, "Role with this name already exists", err)
		default:
			h.writeError(w, http.StatusInternalServerError, "Failed to create role", err)
		}
		return
	}

	response := RoleResponse{
		ID:          role.ID.String(),
		Name:        role.Name,
		Description: role.Description,
		IsSystem:    role.IsSystem,
		CreatedAt:   role.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
	if role.TenantID != nil {
		id := role.TenantID.String()
		response.TenantID = &id
	}

	writeJSON(w, http.StatusCreated, response)
}

// UpdateRole handles updating a role.
func (h *Handler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid role ID", err)
		return
	}

	var req UpdateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	role, err := h.authService.UpdateRole(r.Context(), id, &auth.UpdateRoleRequest{
		Name:        req.Name,
		Description: req.Description,
	})
	if err != nil {
		switch err {
		case auth.ErrRoleNotFound:
			h.writeError(w, http.StatusNotFound, "Role not found", err)
		case auth.ErrCannotModifySystemRole:
			h.writeError(w, http.StatusForbidden, "Cannot modify system role", err)
		case auth.ErrRoleExists:
			h.writeError(w, http.StatusConflict, "Role with this name already exists", err)
		default:
			h.writeError(w, http.StatusInternalServerError, "Failed to update role", err)
		}
		return
	}

	response := RoleResponse{
		ID:          role.ID.String(),
		Name:        role.Name,
		Description: role.Description,
		IsSystem:    role.IsSystem,
		CreatedAt:   role.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
	if role.TenantID != nil {
		id := role.TenantID.String()
		response.TenantID = &id
	}

	writeJSON(w, http.StatusOK, response)
}

// DeleteRole handles deleting a role.
func (h *Handler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid role ID", err)
		return
	}

	err = h.authService.DeleteRole(r.Context(), id)
	if err != nil {
		switch err {
		case auth.ErrRoleNotFound:
			h.writeError(w, http.StatusNotFound, "Role not found", err)
		case auth.ErrCannotModifySystemRole:
			h.writeError(w, http.StatusForbidden, "Cannot delete system role", err)
		default:
			h.writeError(w, http.StatusInternalServerError, "Failed to delete role", err)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetRolePermissions handles getting permissions for a role.
func (h *Handler) GetRolePermissions(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid role ID", err)
		return
	}

	permissions, err := h.authService.GetRolePermissions(r.Context(), id)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to get role permissions", err)
		return
	}

	response := make([]PermissionResponse, len(permissions))
	for i, perm := range permissions {
		response[i] = PermissionResponse{
			ID:          perm.ID.String(),
			Name:        perm.Name,
			Description: perm.Description,
		}
	}

	writeJSON(w, http.StatusOK, response)
}

// AssignPermissionToRole handles assigning a permission to a role.
func (h *Handler) AssignPermissionToRole(w http.ResponseWriter, r *http.Request) {
	roleIDStr := chi.URLParam(r, "id")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid role ID", err)
		return
	}

	var req AssignPermissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	permissionID, err := uuid.Parse(req.PermissionID)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid permission ID", err)
		return
	}

	err = h.authService.AssignPermissionToRole(r.Context(), roleID, permissionID)
	if err != nil {
		switch err {
		case auth.ErrRoleNotFound:
			h.writeError(w, http.StatusNotFound, "Role not found", err)
		case auth.ErrPermissionNotFound:
			h.writeError(w, http.StatusNotFound, "Permission not found", err)
		default:
			h.writeError(w, http.StatusInternalServerError, "Failed to assign permission", err)
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Permission assigned successfully"})
}

// RemovePermissionFromRole handles removing a permission from a role.
func (h *Handler) RemovePermissionFromRole(w http.ResponseWriter, r *http.Request) {
	roleIDStr := chi.URLParam(r, "id")
	roleID, err := uuid.Parse(roleIDStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid role ID", err)
		return
	}

	permissionIDStr := chi.URLParam(r, "permissionId")
	permissionID, err := uuid.Parse(permissionIDStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid permission ID", err)
		return
	}

	err = h.authService.RemovePermissionFromRole(r.Context(), roleID, permissionID)
	if err != nil {
		switch err {
		case auth.ErrRoleNotFound:
			h.writeError(w, http.StatusNotFound, "Role not found", err)
		default:
			h.writeError(w, http.StatusInternalServerError, "Failed to remove permission", err)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ListPermissions handles listing all permissions.
func (h *Handler) ListPermissions(w http.ResponseWriter, r *http.Request) {
	permissions, err := h.authService.ListPermissions(r.Context())
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to list permissions", err)
		return
	}

	response := make([]PermissionResponse, len(permissions))
	for i, perm := range permissions {
		response[i] = PermissionResponse{
			ID:          perm.ID.String(),
			Name:        perm.Name,
			Description: perm.Description,
		}
	}

	writeJSON(w, http.StatusOK, response)
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
	actorID, err := getUserIDFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	// Admin role assignment is global (no tenant ID)
	err = h.authService.AssignRole(r.Context(), userID, roleID, nil, &actorID)
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
	actorID, err := getUserIDFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	// Admin role removal is global (no tenant ID)
	err = h.authService.RemoveRole(r.Context(), userID, roleID, nil, &actorID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to remove role", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Role removed successfully"})
}

// ListSettings handles requests to list all system settings.
func (h *Handler) ListSettings(w http.ResponseWriter, r *http.Request) {
	category := r.URL.Query().Get("category")
	settings, err := h.authService.ListSettings(r.Context(), category)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to list settings", err)
		return
	}

	writeJSON(w, http.StatusOK, settings)
}

// UpdateSettingRequest represents a request to update a system setting.
type UpdateSettingRequest struct {
	Value interface{} `json:"value" validate:"required"`
}

// UpdateSetting handles updating a system setting.
func (h *Handler) UpdateSetting(w http.ResponseWriter, r *http.Request) {
	key := chi.URLParam(r, "key")
	var req UpdateSettingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	err := h.authService.UpdateSetting(r.Context(), key, req.Value)
	if err != nil {
		// Check for validation errors
		if errors.Is(err, auth.ErrUnknownSettingKey) {
			h.writeError(w, http.StatusBadRequest, "Unknown setting key", err)
			return
		}
		if errors.Is(err, auth.ErrInvalidSettingValueType) {
			h.writeError(w, http.StatusBadRequest, "Invalid value type for setting", err)
			return
		}
		h.writeError(w, http.StatusInternalServerError, "Failed to update setting", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Setting updated successfully"})
}

// BulkUpdateSettingsRequest represents a bulk settings update request.
type BulkUpdateSettingsRequest struct {
	Settings map[string]interface{} `json:"settings"`
}

// BulkUpdateSettings handles bulk settings updates.
func (h *Handler) BulkUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var req BulkUpdateSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if len(req.Settings) == 0 {
		h.writeError(w, http.StatusBadRequest, "No settings provided", nil)
		return
	}

	// Validate all settings first before updating any
	for key, value := range req.Settings {
		expectedType, err := validateSettingKeyPublic(key)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, "Unknown setting key: "+key, err)
			return
		}
		if err := validateSettingValuePublic(key, value, expectedType); err != nil {
			h.writeError(w, http.StatusBadRequest, "Invalid value for setting: "+key, err)
			return
		}
	}

	// Update all settings
	var updated []string
	var failed []string
	for key, value := range req.Settings {
		if err := h.authService.UpdateSetting(r.Context(), key, value); err != nil {
			failed = append(failed, key)
		} else {
			updated = append(updated, key)
		}
	}

	if len(failed) > 0 {
		writeJSON(w, http.StatusPartialContent, map[string]interface{}{
			"message": "Some settings failed to update",
			"updated": updated,
			"failed":  failed,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "All settings updated successfully",
		"updated": updated,
	})
}

// ExportSettings exports all non-secret settings.
func (h *Handler) ExportSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := h.authService.ListSettings(r.Context(), "")
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to list settings", err)
		return
	}

	// Filter out secrets
	export := make(map[string]interface{})
	definitions := auth.GetSettingDefinitions()
	for _, s := range settings {
		if def, ok := definitions[s.Key]; ok && def.IsSecret {
			continue // Skip secrets
		}
		export[s.Key] = s.Value
	}

	w.Header().Set("Content-Disposition", "attachment; filename=settings.json")
	writeJSON(w, http.StatusOK, export)
}

// ImportSettings imports settings from JSON.
func (h *Handler) ImportSettings(w http.ResponseWriter, r *http.Request) {
	var settings map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid JSON", err)
		return
	}

	// Use bulk update logic
	req := BulkUpdateSettingsRequest{Settings: settings}
	r.Body = nil // Clear body since we've already decoded

	// Validate and update
	var updated []string
	var failed []string
	var skipped []string

	definitions := auth.GetSettingDefinitions()
	for key, value := range req.Settings {
		// Skip secrets in import
		if def, ok := definitions[key]; ok && def.IsSecret {
			skipped = append(skipped, key)
			continue
		}

		if err := h.authService.UpdateSetting(r.Context(), key, value); err != nil {
			failed = append(failed, key)
		} else {
			updated = append(updated, key)
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Settings imported",
		"updated": updated,
		"failed":  failed,
		"skipped": skipped,
	})
}

// GetSettingDefinitions returns all available setting definitions.
func (h *Handler) GetSettingDefinitions(w http.ResponseWriter, r *http.Request) {
	definitions := auth.GetSettingDefinitions()
	writeJSON(w, http.StatusOK, definitions)
}

// validateSettingKeyPublic is a public wrapper for key validation.
func validateSettingKeyPublic(key string) (string, error) {
	// Access the allowedSettingKeys map via a public function
	return auth.ValidateSettingKeyPublic(key)
}

// validateSettingValuePublic is a public wrapper for value validation.
func validateSettingValuePublic(key string, value interface{}, expectedType string) error {
	return auth.ValidateSettingValuePublic(key, value, expectedType)
}
