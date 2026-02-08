// Package auth provides authentication services for ModernAuth.
package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/iSundram/ModernAuth/internal/storage"
)

// ErrUnknownSettingKey indicates that the setting key is not in the allowed whitelist.
var ErrUnknownSettingKey = errors.New("unknown setting key")

// ErrInvalidSettingValueType indicates that the value type is incorrect for the setting key.
var ErrInvalidSettingValueType = errors.New("invalid setting value type")

// allowedSettingKeys defines the whitelist of allowed setting keys and their expected value types.
var allowedSettingKeys = map[string]string{
	"site.name":                       "string",
	"site.logo_url":                   "string",
	"auth.allow_registration":         "bool",
	"auth.require_email_verification": "bool",
	"auth.mfa_enabled":                "bool",
	"email.provider":                  "string",
	"email.from_name":                 "string",
	"email.from_email":                "string",
	"email.smtp_host":                 "string",
	"email.smtp_port":                 "number",
	"email.smtp_user":                 "string",
	"email.smtp_password":             "string",
}

// ListSettings retrieves all system settings.
func (s *AuthService) ListSettings(ctx context.Context, category string) ([]*storage.SystemSetting, error) {
	settings, err := s.storage.ListSettings(ctx, category)
	if err != nil {
		return nil, err
	}

	s.logAuditEvent(ctx, nil, nil, "system.settings_listed", nil, nil, map[string]interface{}{
		"category": category,
	})

	return settings, nil
}

// GetSetting retrieves a specific system setting.
func (s *AuthService) GetSetting(ctx context.Context, key string) (*storage.SystemSetting, error) {
	setting, err := s.storage.GetSetting(ctx, key)
	if err != nil {
		return nil, err
	}

	s.logAuditEvent(ctx, nil, nil, "system.setting_retrieved", nil, nil, map[string]interface{}{
		"key": key,
	})

	return setting, nil
}

// validateSettingKey checks if the key is in the allowed whitelist.
func validateSettingKey(key string) (string, error) {
	expectedType, ok := allowedSettingKeys[key]
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrUnknownSettingKey, key)
	}
	return expectedType, nil
}

// validateSettingValue checks if the value type matches the expected type for the key.
func validateSettingValue(key string, value interface{}, expectedType string) error {
	switch expectedType {
	case "string":
		if _, ok := value.(string); !ok {
			return fmt.Errorf("%w: expected string for key %s", ErrInvalidSettingValueType, key)
		}
	case "bool":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("%w: expected bool for key %s", ErrInvalidSettingValueType, key)
		}
	case "number":
		switch value.(type) {
		case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
			// Valid number type
		default:
			return fmt.Errorf("%w: expected number for key %s", ErrInvalidSettingValueType, key)
		}
	default:
		return fmt.Errorf("%w: unknown type %s for key %s", ErrInvalidSettingValueType, expectedType, key)
	}
	return nil
}

// UpdateSetting updates a system setting.
func (s *AuthService) UpdateSetting(ctx context.Context, key string, value interface{}) error {
	// Validate the key is in the whitelist
	expectedType, err := validateSettingKey(key)
	if err != nil {
		return err
	}

	// Validate the value type matches the expected type
	if err := validateSettingValue(key, value, expectedType); err != nil {
		return err
	}

	if err := s.storage.UpdateSetting(ctx, key, value); err != nil {
		return err
	}

	s.logAuditEvent(ctx, nil, nil, "system.setting_updated", nil, nil, map[string]interface{}{
		"key": key,
	})
	return nil
}
