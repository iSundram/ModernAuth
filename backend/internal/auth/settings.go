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

// SettingCategory defines categories for settings.
type SettingCategory string

const (
	CategoryBranding SettingCategory = "branding"
	CategoryAuth     SettingCategory = "auth"
	CategorySecurity SettingCategory = "security"
	CategoryEmail    SettingCategory = "email"
	CategoryFeature  SettingCategory = "feature"
)

// SettingDefinition defines a setting with its type, category, and validation.
type SettingDefinition struct {
	Type        string          // "string", "bool", "number"
	Category    SettingCategory // Category for grouping
	IsSecret    bool            // Whether value should be masked
	Description string          // Human-readable description
	MinValue    *float64        // Minimum value for numbers
	MaxValue    *float64        // Maximum value for numbers
}

// Helper to create float64 pointers for min/max values
func floatPtr(v float64) *float64 { return &v }

// allowedSettingKeys defines the whitelist of allowed setting keys and their definitions.
var allowedSettingKeys = map[string]string{
	// Branding
	"site.name":     "string",
	"site.logo_url": "string",

	// Authentication
	"auth.allow_registration":         "bool",
	"auth.require_email_verification": "bool",
	"auth.mfa_enabled":                "bool",

	// Email
	"email.provider":      "string",
	"email.from_name":     "string",
	"email.from_email":    "string",
	"email.smtp_host":     "string",
	"email.smtp_port":     "number",
	"email.smtp_user":     "string",
	"email.smtp_password": "string",

	// Rate Limits
	"rate_limit.login":          "number",
	"rate_limit.register":       "number",
	"rate_limit.password_reset": "number",
	"rate_limit.mfa":            "number",
	"rate_limit.magic_link":     "number",
	"rate_limit.export_data":    "number",
	"rate_limit.refresh":        "number",
	"rate_limit.verify_email":   "number",

	// Lockout Settings
	"lockout.max_attempts":      "number",
	"lockout.window_minutes":    "number",
	"lockout.duration_minutes":  "number",
	"session.max_concurrent":    "number",

	// Token TTLs
	"token.access_ttl_minutes":  "number",
	"token.refresh_ttl_hours":   "number",
	"session.ttl_hours":         "number",

	// Password Policy
	"password.min_length":       "number",
	"password.max_length":       "number",
	"password.require_uppercase": "bool",
	"password.require_lowercase": "bool",
	"password.require_digit":     "bool",
	"password.require_special":   "bool",

	// Feature Toggles
	"feature.hibp_enabled":              "bool",
	"feature.captcha_enabled":           "bool",
	"feature.captcha_provider":          "string",
	"feature.captcha_min_score":         "number",
	"feature.magic_link_enabled":        "bool",
	"feature.oauth_enabled":             "bool",
	"feature.email_queue_enabled":       "bool",
	"feature.email_rate_limit_enabled":  "bool",

	// Email Rate Limits
	"email.verification_rate_limit":    "number",
	"email.password_reset_rate_limit":  "number",
	"email.mfa_code_rate_limit":        "number",
	"email.login_alert_rate_limit":     "number",
}

// settingDefinitions provides detailed metadata for settings validation and documentation.
var settingDefinitions = map[string]SettingDefinition{
	// Rate limits (1-1000 range)
	"rate_limit.login":          {Type: "number", Category: CategorySecurity, MinValue: floatPtr(1), MaxValue: floatPtr(1000), Description: "Login attempts per 15 minutes"},
	"rate_limit.register":       {Type: "number", Category: CategorySecurity, MinValue: floatPtr(1), MaxValue: floatPtr(100), Description: "Registrations per hour"},
	"rate_limit.password_reset": {Type: "number", Category: CategorySecurity, MinValue: floatPtr(1), MaxValue: floatPtr(100), Description: "Password resets per hour"},
	"rate_limit.mfa":            {Type: "number", Category: CategorySecurity, MinValue: floatPtr(1), MaxValue: floatPtr(100), Description: "MFA attempts per 15 minutes"},
	"rate_limit.magic_link":     {Type: "number", Category: CategorySecurity, MinValue: floatPtr(1), MaxValue: floatPtr(100), Description: "Magic links per hour"},
	"rate_limit.export_data":    {Type: "number", Category: CategorySecurity, MinValue: floatPtr(1), MaxValue: floatPtr(10), Description: "Data exports per 24 hours"},
	"rate_limit.refresh":        {Type: "number", Category: CategorySecurity, MinValue: floatPtr(1), MaxValue: floatPtr(1000), Description: "Token refreshes per 15 minutes"},
	"rate_limit.verify_email":   {Type: "number", Category: CategorySecurity, MinValue: floatPtr(1), MaxValue: floatPtr(100), Description: "Email verifications per hour"},

	// Lockout settings
	"lockout.max_attempts":     {Type: "number", Category: CategorySecurity, MinValue: floatPtr(1), MaxValue: floatPtr(100), Description: "Failed attempts before lockout"},
	"lockout.window_minutes":   {Type: "number", Category: CategorySecurity, MinValue: floatPtr(1), MaxValue: floatPtr(1440), Description: "Window for counting failed attempts (minutes)"},
	"lockout.duration_minutes": {Type: "number", Category: CategorySecurity, MinValue: floatPtr(1), MaxValue: floatPtr(1440), Description: "Lockout duration (minutes)"},
	"session.max_concurrent":   {Type: "number", Category: CategorySecurity, MinValue: floatPtr(1), MaxValue: floatPtr(100), Description: "Max concurrent sessions per user"},

	// Token TTLs
	"token.access_ttl_minutes": {Type: "number", Category: CategoryAuth, MinValue: floatPtr(1), MaxValue: floatPtr(1440), Description: "Access token TTL (minutes)"},
	"token.refresh_ttl_hours":  {Type: "number", Category: CategoryAuth, MinValue: floatPtr(1), MaxValue: floatPtr(8760), Description: "Refresh token TTL (hours)"},
	"session.ttl_hours":        {Type: "number", Category: CategoryAuth, MinValue: floatPtr(1), MaxValue: floatPtr(8760), Description: "Session TTL (hours)"},

	// Password policy
	"password.min_length":        {Type: "number", Category: CategorySecurity, MinValue: floatPtr(6), MaxValue: floatPtr(128), Description: "Minimum password length"},
	"password.max_length":        {Type: "number", Category: CategorySecurity, MinValue: floatPtr(16), MaxValue: floatPtr(256), Description: "Maximum password length"},
	"password.require_uppercase": {Type: "bool", Category: CategorySecurity, Description: "Require uppercase letter"},
	"password.require_lowercase": {Type: "bool", Category: CategorySecurity, Description: "Require lowercase letter"},
	"password.require_digit":     {Type: "bool", Category: CategorySecurity, Description: "Require digit"},
	"password.require_special":   {Type: "bool", Category: CategorySecurity, Description: "Require special character"},

	// Feature toggles
	"feature.hibp_enabled":             {Type: "bool", Category: CategoryFeature, Description: "Enable breached password checking"},
	"feature.captcha_enabled":          {Type: "bool", Category: CategoryFeature, Description: "Enable CAPTCHA on auth endpoints"},
	"feature.captcha_provider":         {Type: "string", Category: CategoryFeature, Description: "CAPTCHA provider (none, recaptcha_v2, recaptcha_v3, turnstile)"},
	"feature.captcha_min_score":        {Type: "number", Category: CategoryFeature, MinValue: floatPtr(0), MaxValue: floatPtr(1), Description: "reCAPTCHA v3 minimum score"},
	"feature.magic_link_enabled":       {Type: "bool", Category: CategoryFeature, Description: "Enable passwordless magic link login"},
	"feature.oauth_enabled":            {Type: "bool", Category: CategoryFeature, Description: "Enable OAuth social login"},
	"feature.email_queue_enabled":      {Type: "bool", Category: CategoryFeature, Description: "Enable async email queue"},
	"feature.email_rate_limit_enabled": {Type: "bool", Category: CategoryFeature, Description: "Enable email rate limiting"},

	// Email rate limits
	"email.verification_rate_limit":   {Type: "number", Category: CategoryEmail, MinValue: floatPtr(1), MaxValue: floatPtr(100), Description: "Verification emails per hour"},
	"email.password_reset_rate_limit": {Type: "number", Category: CategoryEmail, MinValue: floatPtr(1), MaxValue: floatPtr(100), Description: "Password reset emails per hour"},
	"email.mfa_code_rate_limit":       {Type: "number", Category: CategoryEmail, MinValue: floatPtr(1), MaxValue: floatPtr(100), Description: "MFA code emails per hour"},
	"email.login_alert_rate_limit":    {Type: "number", Category: CategoryEmail, MinValue: floatPtr(1), MaxValue: floatPtr(100), Description: "Login alert emails per hour"},

	// Secrets (masked in API responses)
	"email.smtp_password": {Type: "string", Category: CategoryEmail, IsSecret: true, Description: "SMTP password"},
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

// ErrSettingValueOutOfRange indicates that the value is outside the allowed range.
var ErrSettingValueOutOfRange = errors.New("setting value out of range")

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
		var numValue float64
		switch v := value.(type) {
		case int:
			numValue = float64(v)
		case int8:
			numValue = float64(v)
		case int16:
			numValue = float64(v)
		case int32:
			numValue = float64(v)
		case int64:
			numValue = float64(v)
		case uint:
			numValue = float64(v)
		case uint8:
			numValue = float64(v)
		case uint16:
			numValue = float64(v)
		case uint32:
			numValue = float64(v)
		case uint64:
			numValue = float64(v)
		case float32:
			numValue = float64(v)
		case float64:
			numValue = v
		default:
			return fmt.Errorf("%w: expected number for key %s", ErrInvalidSettingValueType, key)
		}

		// Validate range if defined
		if def, ok := settingDefinitions[key]; ok {
			if def.MinValue != nil && numValue < *def.MinValue {
				return fmt.Errorf("%w: %s must be >= %.0f", ErrSettingValueOutOfRange, key, *def.MinValue)
			}
			if def.MaxValue != nil && numValue > *def.MaxValue {
				return fmt.Errorf("%w: %s must be <= %.0f", ErrSettingValueOutOfRange, key, *def.MaxValue)
			}
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

	// Invalidate cache if cache is available
	if s.settingsCache != nil {
		s.settingsCache.Invalidate(ctx, key)
	}

	s.logAuditEvent(ctx, nil, nil, "system.setting_updated", nil, nil, map[string]interface{}{
		"key": key,
	})
	return nil
}

// GetSettingDefinitions returns all setting definitions for documentation.
func GetSettingDefinitions() map[string]SettingDefinition {
	return settingDefinitions
}

// ValidateSettingKeyPublic is a public wrapper for key validation.
func ValidateSettingKeyPublic(key string) (string, error) {
	return validateSettingKey(key)
}

// ValidateSettingValuePublic is a public wrapper for value validation.
func ValidateSettingValuePublic(key string, value interface{}, expectedType string) error {
	return validateSettingValue(key, value, expectedType)
}
