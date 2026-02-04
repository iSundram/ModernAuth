package tenant

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// SuspendTenant suspends a tenant, preventing access.
func (s *Service) SuspendTenant(ctx context.Context, tenantID uuid.UUID) error {
	tenant, err := s.storage.GetTenantByID(ctx, tenantID)
	if err != nil {
		return err
	}
	if tenant == nil {
		return ErrTenantNotFound
	}

	tenant.IsActive = false
	tenant.UpdatedAt = time.Now()

	if err := s.storage.UpdateTenant(ctx, tenant); err != nil {
		return err
	}

	s.logger.Info("Tenant suspended", "tenant_id", tenantID)
	return nil
}

// ActivateTenant activates a suspended tenant.
func (s *Service) ActivateTenant(ctx context.Context, tenantID uuid.UUID) error {
	tenant, err := s.storage.GetTenantByID(ctx, tenantID)
	if err != nil {
		return err
	}
	if tenant == nil {
		return ErrTenantNotFound
	}

	tenant.IsActive = true
	tenant.UpdatedAt = time.Now()

	if err := s.storage.UpdateTenant(ctx, tenant); err != nil {
		return err
	}

	s.logger.Info("Tenant activated", "tenant_id", tenantID)
	return nil
}

// CheckPlanLimit checks if adding users would exceed the plan limit.
func (s *Service) CheckPlanLimit(ctx context.Context, tenantID uuid.UUID, additionalUsers int) error {
	stats, err := s.GetTenantStats(ctx, tenantID)
	if err != nil {
		return err
	}

	// 0 means unlimited
	if stats.MaxUsers == 0 {
		return nil
	}

	if stats.UserCount+additionalUsers > stats.MaxUsers {
		return ErrPlanLimitExceeded
	}

	return nil
}
