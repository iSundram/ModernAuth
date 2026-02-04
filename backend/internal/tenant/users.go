package tenant

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
)

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

// ListTenantUsers lists users in a tenant.
func (s *Service) ListTenantUsers(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*storage.User, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	return s.storage.ListTenantUsers(ctx, tenantID, limit, offset)
}

// AssignUserToTenant assigns a user to a tenant.
func (s *Service) AssignUserToTenant(ctx context.Context, tenantID, userID uuid.UUID) error {
	// Verify tenant exists
	tenant, err := s.storage.GetTenantByID(ctx, tenantID)
	if err != nil {
		return err
	}
	if tenant == nil {
		return ErrTenantNotFound
	}

	// Verify user exists
	user, err := s.storage.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	// Update user's tenant_id
	user.TenantID = &tenantID
	user.UpdatedAt = time.Now()
	if err := s.storage.UpdateUser(ctx, user); err != nil {
		return err
	}

	s.logger.Info("User assigned to tenant", "user_id", userID, "tenant_id", tenantID)
	return nil
}

// RemoveUserFromTenant removes a user from a tenant.
func (s *Service) RemoveUserFromTenant(ctx context.Context, tenantID, userID uuid.UUID) error {
	// Verify tenant exists
	tenant, err := s.storage.GetTenantByID(ctx, tenantID)
	if err != nil {
		return err
	}
	if tenant == nil {
		return ErrTenantNotFound
	}

	// Verify user exists and belongs to this tenant
	user, err := s.storage.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	// Check if user belongs to this tenant
	if user.TenantID == nil || *user.TenantID != tenantID {
		return ErrUserNotFound // User doesn't belong to this tenant
	}

	// Remove user from tenant by setting tenant_id to nil
	user.TenantID = nil
	user.UpdatedAt = time.Now()
	if err := s.storage.UpdateUser(ctx, user); err != nil {
		return err
	}

	s.logger.Info("User removed from tenant", "user_id", userID, "tenant_id", tenantID)
	return nil
}

// IsUserTenantMember checks if a user belongs to or can manage a tenant.
// Returns true if the user is a member of the tenant or has admin privileges.
func (s *Service) IsUserTenantMember(ctx context.Context, userID, tenantID uuid.UUID) (bool, error) {
	// Get user to check their tenant membership
	user, err := s.storage.GetUserByID(ctx, userID)
	if err != nil {
		return false, err
	}
	if user == nil {
		return false, ErrUserNotFound
	}

	// Check if user belongs to this tenant
	if user.TenantID != nil && *user.TenantID == tenantID {
		return true, nil
	}

	// Check if user has admin role (admins can manage all tenants)
	roles, err := s.storage.GetUserRoles(ctx, userID)
	if err != nil {
		return false, err
	}
	for _, role := range roles {
		if role.Name == "admin" || role.Name == "super_admin" {
			return true, nil
		}
	}

	return false, nil
}

// IsUserTenantAdmin checks if a user has admin privileges for a specific tenant.
func (s *Service) IsUserTenantAdmin(ctx context.Context, userID, tenantID uuid.UUID) (bool, error) {
	// First check if user is a member
	isMember, err := s.IsUserTenantMember(ctx, userID, tenantID)
	if err != nil {
		return false, err
	}
	if !isMember {
		return false, nil
	}

	// Check if user has admin role
	roles, err := s.storage.GetUserRoles(ctx, userID)
	if err != nil {
		return false, err
	}
	for _, role := range roles {
		if role.Name == "admin" || role.Name == "super_admin" || role.Name == "tenant_admin" {
			return true, nil
		}
	}

	return false, nil
}
