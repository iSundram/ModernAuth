// Package tenant provides multi-tenancy middleware.
package tenant

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
)

type contextKey string

const (
	// TenantContextKey is the context key for the current tenant.
	TenantContextKey contextKey = "tenant"
	// TenantIDContextKey is the context key for the current tenant ID.
	TenantIDContextKey contextKey = "tenant_id"
)

// Middleware extracts tenant information from the request and adds it to the context.
type Middleware struct {
	service       *Service
	headerName    string
	defaultTenant *uuid.UUID
}

// MiddlewareConfig configures the tenant middleware.
type MiddlewareConfig struct {
	// HeaderName is the header to look for tenant identifier (default: X-Tenant-ID)
	HeaderName string
	// DefaultTenantID is the fallback tenant if none is specified
	DefaultTenantID *uuid.UUID
}

// NewMiddleware creates a new tenant middleware.
func NewMiddleware(service *Service, config *MiddlewareConfig) *Middleware {
	headerName := "X-Tenant-ID"
	if config != nil && config.HeaderName != "" {
		headerName = config.HeaderName
	}

	var defaultTenant *uuid.UUID
	if config != nil {
		defaultTenant = config.DefaultTenantID
	}

	return &Middleware{
		service:       service,
		headerName:    headerName,
		defaultTenant: defaultTenant,
	}
}

// Handler is the middleware handler that extracts tenant from request.
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		var tenant *storage.Tenant
		var err error

		// Try to get tenant from header
		tenantIdentifier := r.Header.Get(m.headerName)

		// If not in header, try subdomain
		if tenantIdentifier == "" {
			tenantIdentifier = m.extractSubdomain(r.Host)
		}

		// If we have an identifier, resolve the tenant
		if tenantIdentifier != "" {
			tenant, err = m.service.ResolveTenant(ctx, tenantIdentifier)
			if err != nil && err != ErrTenantNotFound {
				http.Error(w, "Failed to resolve tenant", http.StatusInternalServerError)
				return
			}
		}

		// Fall back to default tenant if configured
		if tenant == nil && m.defaultTenant != nil {
			tenant, err = m.service.GetTenantByID(ctx, *m.defaultTenant)
			if err != nil {
				http.Error(w, "Failed to load default tenant", http.StatusInternalServerError)
				return
			}
		}

		// Add tenant to context if found
		if tenant != nil {
			if !tenant.IsActive {
				http.Error(w, "Tenant is inactive", http.StatusForbidden)
				return
			}
			ctx = context.WithValue(ctx, TenantContextKey, tenant)
			ctx = context.WithValue(ctx, TenantIDContextKey, tenant.ID)
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireTenant is middleware that requires a tenant to be present.
func (m *Middleware) RequireTenant(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant := GetTenantFromContext(r.Context())
		if tenant == nil {
			http.Error(w, "Tenant required", http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// extractSubdomain extracts the subdomain from the host.
func (m *Middleware) extractSubdomain(host string) string {
	// Remove port if present
	if colonIdx := strings.LastIndex(host, ":"); colonIdx != -1 {
		host = host[:colonIdx]
	}

	parts := strings.Split(host, ".")
	// Need at least 3 parts for subdomain (subdomain.domain.tld)
	if len(parts) >= 3 {
		subdomain := parts[0]
		// Skip common non-tenant subdomains
		if subdomain != "www" && subdomain != "api" && subdomain != "app" {
			return subdomain
		}
	}
	return ""
}

// GetTenantFromContext retrieves the tenant from the context.
func GetTenantFromContext(ctx context.Context) *storage.Tenant {
	if tenant, ok := ctx.Value(TenantContextKey).(*storage.Tenant); ok {
		return tenant
	}
	return nil
}

// GetTenantIDFromContext retrieves the tenant ID from the context.
func GetTenantIDFromContext(ctx context.Context) *uuid.UUID {
	if id, ok := ctx.Value(TenantIDContextKey).(uuid.UUID); ok {
		return &id
	}
	return nil
}
