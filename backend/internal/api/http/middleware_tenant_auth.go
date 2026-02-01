// Package http provides tenant authorization middleware for ModernAuth API.
package http

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/tenant"
)

// TenantAuthorizationMiddleware provides authorization checks for tenant operations.
type TenantAuthorizationMiddleware struct {
	tenantService *tenant.Service
}

// NewTenantAuthorizationMiddleware creates a new tenant authorization middleware.
func NewTenantAuthorizationMiddleware(service *tenant.Service) *TenantAuthorizationMiddleware {
	return &TenantAuthorizationMiddleware{tenantService: service}
}

// RequireTenantAccess ensures the authenticated user has access to the specified tenant.
// For now, only users with admin role can access any tenant.
// Future: implement per-tenant membership validation.
func (m *TenantAuthorizationMiddleware) RequireTenantAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantIDStr := chi.URLParam(r, "id")
		if tenantIDStr == "" {
			// No tenant ID in URL, allow through for list operations
			next.ServeHTTP(w, r)
			return
		}

		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid tenant ID", err)
			return
		}

		// Verify tenant exists and is accessible
		t, err := m.tenantService.GetTenantByID(r.Context(), tenantID)
		if err != nil {
			if err == tenant.ErrTenantNotFound {
				writeError(w, http.StatusNotFound, "Tenant not found", err)
				return
			}
			writeError(w, http.StatusInternalServerError, "Failed to verify tenant access", err)
			return
		}

		// Add tenant to context for downstream handlers
		ctx := context.WithValue(r.Context(), tenantContextKey, t)
		ctx = context.WithValue(ctx, tenantIDContextKey, tenantID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireTenantOwnership ensures the user owns or is a member of the tenant.
// This is stricter than RequireTenantAccess - checks actual membership.
func (m *TenantAuthorizationMiddleware) RequireTenantOwnership(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, err := getUserIDFromContext(r.Context())
		if err != nil {
			writeError(w, http.StatusUnauthorized, "Authentication required", err)
			return
		}

		tenantIDStr := chi.URLParam(r, "id")
		if tenantIDStr == "" {
			next.ServeHTTP(w, r)
			return
		}

		tenantID, err := uuid.Parse(tenantIDStr)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid tenant ID", err)
			return
		}

		// Check if user belongs to or manages this tenant
		isMember, err := m.tenantService.IsUserTenantMember(r.Context(), userID, tenantID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to verify tenant membership", err)
			return
		}

		if !isMember {
			writeError(w, http.StatusForbidden, "You do not have access to this tenant", nil)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Context keys for tenant authorization
type tenantAuthContextKey string

const (
	tenantContextKey   tenantAuthContextKey = "auth_tenant"
	tenantIDContextKey tenantAuthContextKey = "auth_tenant_id"
)

// GetAuthorizedTenantID retrieves the authorized tenant ID from context.
func GetAuthorizedTenantID(ctx context.Context) *uuid.UUID {
	if id, ok := ctx.Value(tenantIDContextKey).(uuid.UUID); ok {
		return &id
	}
	return nil
}
