// Package auth provides authentication services for ModernAuth.
package auth

import (
	"context"

	"github.com/iSundram/ModernAuth/internal/storage"
)

// ListSettings retrieves all system settings.
func (s *AuthService) ListSettings(ctx context.Context, category string) ([]*storage.SystemSetting, error) {
	return s.storage.ListSettings(ctx, category)
}

// GetSetting retrieves a specific system setting.
func (s *AuthService) GetSetting(ctx context.Context, key string) (*storage.SystemSetting, error) {
	return s.storage.GetSetting(ctx, key)
}

// UpdateSetting updates a system setting.
func (s *AuthService) UpdateSetting(ctx context.Context, key string, value interface{}) error {
	// Add validation logic here if needed
	if err := s.storage.UpdateSetting(ctx, key, value); err != nil {
		return err
	}

	s.logAuditEvent(ctx, nil, nil, "system.setting_updated", nil, nil, map[string]interface{}{
		"key": key,
	})
	return nil
}
