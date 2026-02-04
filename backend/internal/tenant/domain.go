package tenant

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
)

// DomainVerificationResult represents domain verification status.
type DomainVerificationResult struct {
	Domain     string     `json:"domain"`
	TXTRecord  string     `json:"txt_record"`
	Status     string     `json:"status"` // pending, verified, failed
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
}

// InitiateDomainVerification starts domain verification for a tenant.
func (s *Service) InitiateDomainVerification(ctx context.Context, tenantID uuid.UUID) (*DomainVerificationResult, error) {
	tenant, err := s.storage.GetTenantByID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if tenant == nil {
		return nil, ErrTenantNotFound
	}

	if tenant.Domain == nil || *tenant.Domain == "" {
		return nil, ErrNoDomainConfigured
	}

	// Generate verification token if not exists
	verificationToken := s.getOrCreateVerificationToken(tenant)

	// Update tenant settings with verification token
	if tenant.Settings == nil {
		tenant.Settings = make(map[string]interface{})
	}
	tenant.Settings["domain_verification_token"] = verificationToken
	tenant.Settings["domain_verification_status"] = "pending"
	tenant.UpdatedAt = time.Now()

	if err := s.storage.UpdateTenant(ctx, tenant); err != nil {
		return nil, err
	}

	return &DomainVerificationResult{
		Domain:    *tenant.Domain,
		TXTRecord: fmt.Sprintf("modernauth-verify=%s", verificationToken),
		Status:    "pending",
	}, nil
}

// CheckDomainVerification checks domain verification status.
func (s *Service) CheckDomainVerification(ctx context.Context, tenantID uuid.UUID) (*DomainVerificationResult, error) {
	tenant, err := s.storage.GetTenantByID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if tenant == nil {
		return nil, ErrTenantNotFound
	}

	if tenant.Domain == nil || *tenant.Domain == "" {
		return nil, ErrNoDomainConfigured
	}

	token, _ := tenant.Settings["domain_verification_token"].(string)
	status, _ := tenant.Settings["domain_verification_status"].(string)

	result := &DomainVerificationResult{
		Domain:    *tenant.Domain,
		TXTRecord: fmt.Sprintf("modernauth-verify=%s", token),
		Status:    status,
	}

	// If already verified, return
	if status == "verified" {
		if verifiedAtStr, ok := tenant.Settings["domain_verified_at"].(string); ok {
			if t, err := time.Parse(time.RFC3339, verifiedAtStr); err == nil {
				result.VerifiedAt = &t
			}
		}
		return result, nil
	}

	// Perform DNS TXT lookup
	expectedRecord := fmt.Sprintf("modernauth-verify=%s", token)
	txtRecords, err := net.LookupTXT("_modernauth." + *tenant.Domain)
	if err != nil {
		result.Status = "pending"
		return result, nil
	}

	for _, txt := range txtRecords {
		if txt == expectedRecord {
			// Verified!
			now := time.Now()
			tenant.Settings["domain_verification_status"] = "verified"
			tenant.Settings["domain_verified_at"] = now.Format(time.RFC3339)
			tenant.UpdatedAt = now

			if err := s.storage.UpdateTenant(ctx, tenant); err != nil {
				s.logger.Error("Failed to update domain verification status", "error", err)
			}

			result.Status = "verified"
			result.VerifiedAt = &now
			s.logger.Info("Domain verified", "tenant_id", tenantID, "domain", *tenant.Domain)
			return result, nil
		}
	}

	result.Status = "pending"
	return result, nil
}

func (s *Service) getOrCreateVerificationToken(tenant *storage.Tenant) string {
	if token, ok := tenant.Settings["domain_verification_token"].(string); ok && token != "" {
		return token
	}

	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
