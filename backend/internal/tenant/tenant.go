// Package tenant provides multi-tenancy support for ModernAuth.
package tenant

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
)

var (
	// ErrTenantNotFound indicates the tenant was not found.
	ErrTenantNotFound = errors.New("tenant not found")
	// ErrTenantExists indicates a tenant with the given slug already exists.
	ErrTenantExists = errors.New("tenant already exists")
	// ErrTenantInactive indicates the tenant is not active.
	ErrTenantInactive = errors.New("tenant is inactive")
	// ErrInvalidTenant indicates an invalid tenant configuration.
	ErrInvalidTenant = errors.New("invalid tenant configuration")
)

// Service provides tenant management operations.
type Service struct {
	storage storage.TenantStorage
	logger  *slog.Logger
}

// NewService creates a new tenant service.
func NewService(store storage.TenantStorage) *Service {
	return &Service{
		storage: store,
		logger:  slog.Default().With("component", "tenant_service"),
	}
}

// CreateTenantRequest represents a request to create a tenant.
type CreateTenantRequest struct {
	Name     string                 `json:"name"`
	Slug     string                 `json:"slug"`
	Domain   *string                `json:"domain,omitempty"`
	LogoURL  *string                `json:"logo_url,omitempty"`
	Settings map[string]interface{} `json:"settings,omitempty"`
	Plan     string                 `json:"plan,omitempty"`
}

// CreateTenant creates a new tenant.
func (s *Service) CreateTenant(ctx context.Context, req *CreateTenantRequest) (*storage.Tenant, error) {
	// Check if slug is already taken
	existing, err := s.storage.GetTenantBySlug(ctx, req.Slug)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, ErrTenantExists
	}

	// Check if domain is already taken
	if req.Domain != nil && *req.Domain != "" {
		existing, err = s.storage.GetTenantByDomain(ctx, *req.Domain)
		if err != nil {
			return nil, err
		}
		if existing != nil {
			return nil, ErrTenantExists
		}
	}

	now := time.Now()
	plan := req.Plan
	if plan == "" {
		plan = "free"
	}

	tenant := &storage.Tenant{
		ID:        uuid.New(),
		Name:      req.Name,
		Slug:      req.Slug,
		Domain:    req.Domain,
		LogoURL:   req.LogoURL,
		Settings:  req.Settings,
		Plan:      plan,
		IsActive:  true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.storage.CreateTenant(ctx, tenant); err != nil {
		return nil, err
	}

	s.logger.Info("Tenant created", "tenant_id", tenant.ID, "slug", tenant.Slug)
	return tenant, nil
}

// GetTenantByID retrieves a tenant by ID.
func (s *Service) GetTenantByID(ctx context.Context, id uuid.UUID) (*storage.Tenant, error) {
	tenant, err := s.storage.GetTenantByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if tenant == nil {
		return nil, ErrTenantNotFound
	}
	return tenant, nil
}

// GetTenantBySlug retrieves a tenant by slug.
func (s *Service) GetTenantBySlug(ctx context.Context, slug string) (*storage.Tenant, error) {
	tenant, err := s.storage.GetTenantBySlug(ctx, slug)
	if err != nil {
		return nil, err
	}
	if tenant == nil {
		return nil, ErrTenantNotFound
	}
	return tenant, nil
}

// GetTenantByDomain retrieves a tenant by domain.
func (s *Service) GetTenantByDomain(ctx context.Context, domain string) (*storage.Tenant, error) {
	tenant, err := s.storage.GetTenantByDomain(ctx, domain)
	if err != nil {
		return nil, err
	}
	if tenant == nil {
		return nil, ErrTenantNotFound
	}
	return tenant, nil
}

// ListTenants retrieves all tenants with pagination.
func (s *Service) ListTenants(ctx context.Context, limit, offset int) ([]*storage.Tenant, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	return s.storage.ListTenants(ctx, limit, offset)
}

// UpdateTenantRequest represents a request to update a tenant.
type UpdateTenantRequest struct {
	TenantID uuid.UUID              `json:"-"`
	Name     *string                `json:"name,omitempty"`
	Domain   *string                `json:"domain,omitempty"`
	LogoURL  *string                `json:"logo_url,omitempty"`
	Settings map[string]interface{} `json:"settings,omitempty"`
	Plan     *string                `json:"plan,omitempty"`
	IsActive *bool                  `json:"is_active,omitempty"`
}

// UpdateTenant updates a tenant.
func (s *Service) UpdateTenant(ctx context.Context, req *UpdateTenantRequest) (*storage.Tenant, error) {
	tenant, err := s.storage.GetTenantByID(ctx, req.TenantID)
	if err != nil {
		return nil, err
	}
	if tenant == nil {
		return nil, ErrTenantNotFound
	}

	if req.Name != nil {
		tenant.Name = *req.Name
	}
	if req.Domain != nil {
		// Check if domain is already taken by another tenant
		existing, err := s.storage.GetTenantByDomain(ctx, *req.Domain)
		if err != nil {
			return nil, err
		}
		if existing != nil && existing.ID != tenant.ID {
			return nil, ErrTenantExists
		}
		tenant.Domain = req.Domain
	}
	if req.LogoURL != nil {
		tenant.LogoURL = req.LogoURL
	}
	if req.Settings != nil {
		tenant.Settings = req.Settings
	}
	if req.Plan != nil {
		tenant.Plan = *req.Plan
	}
	if req.IsActive != nil {
		tenant.IsActive = *req.IsActive
	}

	tenant.UpdatedAt = time.Now()

	if err := s.storage.UpdateTenant(ctx, tenant); err != nil {
		return nil, err
	}

	return tenant, nil
}

// DeleteTenant deletes a tenant.
func (s *Service) DeleteTenant(ctx context.Context, id uuid.UUID) error {
	tenant, err := s.storage.GetTenantByID(ctx, id)
	if err != nil {
		return err
	}
	if tenant == nil {
		return ErrTenantNotFound
	}

	if err := s.storage.DeleteTenant(ctx, id); err != nil {
		return err
	}

	s.logger.Info("Tenant deleted", "tenant_id", id, "slug", tenant.Slug)
	return nil
}

// GetTenantStats retrieves statistics for a tenant.
func (s *Service) GetTenantStats(ctx context.Context, tenantID uuid.UUID) (*TenantStats, error) {
	userCount, err := s.storage.CountTenantUsers(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	return &TenantStats{
		TenantID:  tenantID,
		UserCount: userCount,
	}, nil
}

// TenantStats represents statistics for a tenant.
type TenantStats struct {
	TenantID  uuid.UUID `json:"tenant_id"`
	UserCount int       `json:"user_count"`
}

// ResolveTenant resolves a tenant from various identifiers.
func (s *Service) ResolveTenant(ctx context.Context, identifier string) (*storage.Tenant, error) {
	// Try as UUID first
	if id, err := uuid.Parse(identifier); err == nil {
		return s.GetTenantByID(ctx, id)
	}

	// Try as slug
	tenant, err := s.storage.GetTenantBySlug(ctx, identifier)
	if err != nil {
		return nil, err
	}
	if tenant != nil {
		return tenant, nil
	}

	// Try as domain
	tenant, err = s.storage.GetTenantByDomain(ctx, identifier)
	if err != nil {
		return nil, err
	}
	if tenant != nil {
		return tenant, nil
	}

	return nil, ErrTenantNotFound
}
