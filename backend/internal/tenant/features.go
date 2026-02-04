package tenant

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// TenantFeatures represents feature flags for a tenant.
type TenantFeatures struct {
	SSOEnabled       bool `json:"sso_enabled"`
	APIAccessEnabled bool `json:"api_access_enabled"`
	WebhooksEnabled  bool `json:"webhooks_enabled"`
	MFARequired      bool `json:"mfa_required"`
	CustomBranding   bool `json:"custom_branding"`
}

// UpdateFeaturesRequest represents a request to update feature flags.
type UpdateFeaturesRequest struct {
	SSOEnabled       *bool `json:"sso_enabled,omitempty"`
	APIAccessEnabled *bool `json:"api_access_enabled,omitempty"`
	WebhooksEnabled  *bool `json:"webhooks_enabled,omitempty"`
	MFARequired      *bool `json:"mfa_required,omitempty"`
	CustomBranding   *bool `json:"custom_branding,omitempty"`
}

// GetFeatures retrieves feature flags for a tenant.
func (s *Service) GetFeatures(ctx context.Context, tenantID uuid.UUID) (*TenantFeatures, error) {
	tenant, err := s.storage.GetTenantByID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if tenant == nil {
		return nil, ErrTenantNotFound
	}

	return s.extractFeaturesFromSettings(tenant.Settings), nil
}

// UpdateFeatures updates feature flags for a tenant.
func (s *Service) UpdateFeatures(ctx context.Context, tenantID uuid.UUID, req *UpdateFeaturesRequest) (*TenantFeatures, error) {
	tenant, err := s.storage.GetTenantByID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if tenant == nil {
		return nil, ErrTenantNotFound
	}

	if tenant.Settings == nil {
		tenant.Settings = make(map[string]interface{})
	}

	features := s.extractFeaturesFromSettings(tenant.Settings)

	if req.SSOEnabled != nil {
		features.SSOEnabled = *req.SSOEnabled
	}
	if req.APIAccessEnabled != nil {
		features.APIAccessEnabled = *req.APIAccessEnabled
	}
	if req.WebhooksEnabled != nil {
		features.WebhooksEnabled = *req.WebhooksEnabled
	}
	if req.MFARequired != nil {
		features.MFARequired = *req.MFARequired
	}
	if req.CustomBranding != nil {
		features.CustomBranding = *req.CustomBranding
	}

	// Store features in settings
	tenant.Settings["features"] = map[string]interface{}{
		"sso_enabled":        features.SSOEnabled,
		"api_access_enabled": features.APIAccessEnabled,
		"webhooks_enabled":   features.WebhooksEnabled,
		"mfa_required":       features.MFARequired,
		"custom_branding":    features.CustomBranding,
	}
	tenant.UpdatedAt = time.Now()

	if err := s.storage.UpdateTenant(ctx, tenant); err != nil {
		return nil, err
	}

	s.logger.Info("Tenant features updated", "tenant_id", tenantID)
	return features, nil
}

func (s *Service) extractFeaturesFromSettings(settings map[string]interface{}) *TenantFeatures {
	features := &TenantFeatures{
		SSOEnabled:       false,
		APIAccessEnabled: true,  // Default enabled
		WebhooksEnabled:  true,  // Default enabled
		MFARequired:      false,
		CustomBranding:   false,
	}

	if settings == nil {
		return features
	}

	featuresData, ok := settings["features"].(map[string]interface{})
	if !ok {
		return features
	}

	if v, ok := featuresData["sso_enabled"].(bool); ok {
		features.SSOEnabled = v
	}
	if v, ok := featuresData["api_access_enabled"].(bool); ok {
		features.APIAccessEnabled = v
	}
	if v, ok := featuresData["webhooks_enabled"].(bool); ok {
		features.WebhooksEnabled = v
	}
	if v, ok := featuresData["mfa_required"].(bool); ok {
		features.MFARequired = v
	}
	if v, ok := featuresData["custom_branding"].(bool); ok {
		features.CustomBranding = v
	}

	return features
}
