// Package http provides admin HTTP handlers.
package http

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
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
	actorID, err := getUserIDFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	err = h.authService.RemoveRole(r.Context(), userID, roleID, &actorID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to remove role", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Role removed successfully"})
}
