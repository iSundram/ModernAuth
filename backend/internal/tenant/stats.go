package tenant

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
)

// TenantStats represents statistics for a tenant.
type TenantStats struct {
	TenantID  uuid.UUID `json:"tenant_id"`
	UserCount int       `json:"user_count"`
	Plan      string    `json:"plan"`
	MaxUsers  int       `json:"max_users"`
}

// GetTenantStats retrieves statistics for a tenant.
func (s *Service) GetTenantStats(ctx context.Context, tenantID uuid.UUID) (*TenantStats, error) {
	tenant, err := s.storage.GetTenantByID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if tenant == nil {
		return nil, ErrTenantNotFound
	}

	userCount, err := s.storage.CountTenantUsers(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	return &TenantStats{
		TenantID:  tenantID,
		UserCount: userCount,
		Plan:      tenant.Plan,
		MaxUsers:  getPlanMaxUsers(tenant.Plan),
	}, nil
}

// getPlanMaxUsers returns the soft user limit for a given plan.
// A value of 0 means "unlimited" (no enforced limit).
func getPlanMaxUsers(plan string) int {
	switch plan {
	case "free":
		return 5
	case "starter":
		return 20
	case "professional":
		return 100
	case "enterprise":
		return 0
	default:
		return 0
	}
}

// TenantSecurityStats represents security posture for a tenant.
type TenantSecurityStats struct {
	TenantID               uuid.UUID `json:"tenant_id"`
	TotalUsers             int       `json:"total_users"`
	ActiveUsers            int       `json:"active_users"`
	VerifiedUsers          int       `json:"verified_users"`
	MFAEnabledUsers        int       `json:"mfa_enabled_users"`
	TOTPEnabledUsers       int       `json:"totp_enabled_users"`
	EmailMFAEnabledUsers   int       `json:"email_mfa_enabled_users"`
	WebAuthnUsers          int       `json:"webauthn_users"`
	UsersWithTrustedDevice int       `json:"users_with_trusted_device"`
	RecentFailedLogins     int       `json:"recent_failed_logins"`
	RecentLockouts         int       `json:"recent_lockouts"`
}

// GetTenantSecurityStats computes security-related statistics for a tenant.
func (s *Service) GetTenantSecurityStats(ctx context.Context, tenantID uuid.UUID) (*TenantSecurityStats, error) {
	// Reuse ListTenantUsers; for now we fetch up to 1000 users per tenant.
	const maxUsersPerTenant = 1000

	users, err := s.storage.ListTenantUsers(ctx, tenantID, maxUsersPerTenant, 0)
	if err != nil {
		return nil, err
	}

	stats := &TenantSecurityStats{
		TenantID:   tenantID,
		TotalUsers: len(users),
	}

	// Track which users have at least one trusted device.
	usersWithTrusted := make(map[uuid.UUID]struct{})

	for _, u := range users {
		if u.IsActive {
			stats.ActiveUsers++
		}
		if u.IsEmailVerified {
			stats.VerifiedUsers++
		}

		// MFA settings per user
		mfaSettings, err := s.storage.GetMFASettings(ctx, u.ID)
		if err != nil {
			// Log and continue; a single failure shouldn't break the whole stats call.
			s.logger.Warn("Failed to load MFA settings for tenant security stats",
				"user_id", u.ID, "tenant_id", tenantID, "error", err)
		} else if mfaSettings != nil {
			if mfaSettings.IsTOTPEnabled {
				stats.TOTPEnabledUsers++
				stats.MFAEnabledUsers++
			}
			if mfaSettings.IsEmailMFAEnabled {
				stats.EmailMFAEnabledUsers++
				stats.MFAEnabledUsers++
			}
			// WebAuthn presence is approximated via credentials count below.
		}

		// Trusted devices per user (best-effort; ignore errors)
		if devices, err := s.storage.ListUserDevices(ctx, u.ID); err == nil {
			for _, d := range devices {
				if d.IsTrusted {
					usersWithTrusted[u.ID] = struct{}{}
					break
				}
			}
		}

		// WebAuthn credentials per user (best-effort)
		if creds, err := s.storage.GetWebAuthnCredentials(ctx, u.ID); err == nil && len(creds) > 0 {
			stats.WebAuthnUsers++
		}
	}

	stats.UsersWithTrustedDevice = len(usersWithTrusted)

	// Recent failed logins / lockouts can be derived from login_history and audit_logs.
	// For now, we count failed login_history entries in the last 7 days for this tenant.
	// This keeps the implementation data-source-agnostic: storage can provide a helper
	// without changing the HTTP surface.
	sevenDaysAgo := time.Now().Add(-7 * 24 * time.Hour)
	if logs, err := s.storage.ListAuditLogsByTenant(ctx, tenantID, 1000, 0); err == nil {
		for _, log := range logs {
			if log.CreatedAt.Before(sevenDaysAgo) {
				continue
			}
			switch {
			case strings.Contains(log.EventType, "login.failed"):
				stats.RecentFailedLogins++
			case strings.Contains(log.EventType, "account_locked") || strings.Contains(log.EventType, "mfa_locked"):
				stats.RecentLockouts++
			}
		}
	}

	return stats, nil
}
