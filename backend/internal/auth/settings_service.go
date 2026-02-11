// Package auth provides authentication services for ModernAuth.
package auth

import (
	"context"
	"time"

	"github.com/iSundram/ModernAuth/internal/storage"
	"github.com/iSundram/ModernAuth/internal/utils"
)

// SettingsService provides access to dynamic system settings with caching.
type SettingsService struct {
	storage storage.Storage
	cache   *SettingsCache
	// Default values from environment/config
	defaults map[string]interface{}
}

// NewSettingsService creates a new settings service.
func NewSettingsService(store storage.Storage, cache *SettingsCache, defaults map[string]interface{}) *SettingsService {
	if defaults == nil {
		defaults = make(map[string]interface{})
	}
	return &SettingsService{
		storage:  store,
		cache:    cache,
		defaults: defaults,
	}
}

// getValue retrieves a setting value with caching and fallback to defaults.
func (s *SettingsService) getValue(ctx context.Context, key string) interface{} {
	// Check cache first
	if s.cache != nil {
		if val, ok := s.cache.Get(ctx, key); ok {
			return val
		}
	}

	// Check database
	setting, err := s.storage.GetSetting(ctx, key)
	if err == nil && setting != nil {
		// Cache the value
		if s.cache != nil {
			s.cache.Set(ctx, key, setting.Value)
		}
		return setting.Value
	}

	// Fall back to defaults
	if val, ok := s.defaults[key]; ok {
		return val
	}

	return nil
}

// GetInt retrieves an integer setting.
func (s *SettingsService) GetInt(ctx context.Context, key string, defaultVal int) int {
	val := s.getValue(ctx, key)
	if val == nil {
		return defaultVal
	}

	switch v := val.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case float32:
		return int(v)
	}
	return defaultVal
}

// GetBool retrieves a boolean setting.
func (s *SettingsService) GetBool(ctx context.Context, key string, defaultVal bool) bool {
	val := s.getValue(ctx, key)
	if val == nil {
		return defaultVal
	}

	if b, ok := val.(bool); ok {
		return b
	}
	return defaultVal
}

// GetString retrieves a string setting.
func (s *SettingsService) GetString(ctx context.Context, key string, defaultVal string) string {
	val := s.getValue(ctx, key)
	if val == nil {
		return defaultVal
	}

	if str, ok := val.(string); ok {
		return str
	}
	return defaultVal
}

// GetFloat retrieves a float setting.
func (s *SettingsService) GetFloat(ctx context.Context, key string, defaultVal float64) float64 {
	val := s.getValue(ctx, key)
	if val == nil {
		return defaultVal
	}

	switch v := val.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int64:
		return float64(v)
	}
	return defaultVal
}

// GetDuration retrieves a duration setting from minutes.
func (s *SettingsService) GetDurationMinutes(ctx context.Context, key string, defaultMinutes int) time.Duration {
	minutes := s.GetInt(ctx, key, defaultMinutes)
	return time.Duration(minutes) * time.Minute
}

// GetDurationHours retrieves a duration setting from hours.
func (s *SettingsService) GetDurationHours(ctx context.Context, key string, defaultHours int) time.Duration {
	hours := s.GetInt(ctx, key, defaultHours)
	return time.Duration(hours) * time.Hour
}

// RateLimitConfig holds rate limit configuration.
type RateLimitConfig struct {
	Login         int
	Register      int
	PasswordReset int
	MFA           int
	MagicLink     int
	ExportData    int
	Refresh       int
	VerifyEmail   int
}

// GetRateLimits retrieves all rate limit settings.
func (s *SettingsService) GetRateLimits(ctx context.Context) *RateLimitConfig {
	return &RateLimitConfig{
		Login:         s.GetInt(ctx, "rate_limit.login", 10),
		Register:      s.GetInt(ctx, "rate_limit.register", 5),
		PasswordReset: s.GetInt(ctx, "rate_limit.password_reset", 5),
		MFA:           s.GetInt(ctx, "rate_limit.mfa", 10),
		MagicLink:     s.GetInt(ctx, "rate_limit.magic_link", 3),
		ExportData:    s.GetInt(ctx, "rate_limit.export_data", 1),
		Refresh:       s.GetInt(ctx, "rate_limit.refresh", 100),
		VerifyEmail:   s.GetInt(ctx, "rate_limit.verify_email", 5),
	}
}

// DynamicLockoutConfig holds lockout configuration.
type DynamicLockoutConfig struct {
	MaxAttempts     int
	WindowMinutes   int
	DurationMinutes int
}

// GetLockoutConfig retrieves lockout settings.
func (s *SettingsService) GetLockoutConfig(ctx context.Context) *DynamicLockoutConfig {
	return &DynamicLockoutConfig{
		MaxAttempts:     s.GetInt(ctx, "lockout.max_attempts", 5),
		WindowMinutes:   s.GetInt(ctx, "lockout.window_minutes", 15),
		DurationMinutes: s.GetInt(ctx, "lockout.duration_minutes", 30),
	}
}

// GetMaxConcurrentSessions retrieves the max concurrent sessions setting.
func (s *SettingsService) GetMaxConcurrentSessions(ctx context.Context) int {
	return s.GetInt(ctx, "session.max_concurrent", 5)
}

// DynamicPasswordPolicy holds password policy from settings.
type DynamicPasswordPolicy struct {
	MinLength        int
	MaxLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireDigit     bool
	RequireSpecial   bool
}

// GetPasswordPolicy retrieves password policy settings.
func (s *SettingsService) GetPasswordPolicy(ctx context.Context) *DynamicPasswordPolicy {
	return &DynamicPasswordPolicy{
		MinLength:        s.GetInt(ctx, "password.min_length", 8),
		MaxLength:        s.GetInt(ctx, "password.max_length", 128),
		RequireUppercase: s.GetBool(ctx, "password.require_uppercase", true),
		RequireLowercase: s.GetBool(ctx, "password.require_lowercase", true),
		RequireDigit:     s.GetBool(ctx, "password.require_digit", true),
		RequireSpecial:   s.GetBool(ctx, "password.require_special", false),
	}
}

// ToPasswordPolicy converts DynamicPasswordPolicy to utils.PasswordPolicy.
func (p *DynamicPasswordPolicy) ToPasswordPolicy() *utils.PasswordPolicy {
	return &utils.PasswordPolicy{
		MinLength:        p.MinLength,
		MaxLength:        p.MaxLength,
		RequireUppercase: p.RequireUppercase,
		RequireLowercase: p.RequireLowercase,
		RequireDigit:     p.RequireDigit,
		RequireSpecial:   p.RequireSpecial,
	}
}

// TokenTTLConfig holds token TTL configuration.
type TokenTTLConfig struct {
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	SessionTTL      time.Duration
}

// GetTokenTTLs retrieves token TTL settings.
func (s *SettingsService) GetTokenTTLs(ctx context.Context) *TokenTTLConfig {
	return &TokenTTLConfig{
		AccessTokenTTL:  s.GetDurationMinutes(ctx, "token.access_ttl_minutes", 15),
		RefreshTokenTTL: s.GetDurationHours(ctx, "token.refresh_ttl_hours", 168),
		SessionTTL:      s.GetDurationHours(ctx, "session.ttl_hours", 168),
	}
}

// FeatureFlags holds feature toggle states.
type FeatureFlags struct {
	HIBPEnabled            bool
	CaptchaEnabled         bool
	CaptchaProvider        string
	CaptchaMinScore        float64
	MagicLinkEnabled       bool
	OAuthEnabled           bool
	EmailQueueEnabled      bool
	EmailRateLimitEnabled  bool
}

// GetFeatureFlags retrieves feature flag settings.
func (s *SettingsService) GetFeatureFlags(ctx context.Context) *FeatureFlags {
	return &FeatureFlags{
		HIBPEnabled:           s.GetBool(ctx, "feature.hibp_enabled", false),
		CaptchaEnabled:        s.GetBool(ctx, "feature.captcha_enabled", false),
		CaptchaProvider:       s.GetString(ctx, "feature.captcha_provider", "none"),
		CaptchaMinScore:       s.GetFloat(ctx, "feature.captcha_min_score", 0.5),
		MagicLinkEnabled:      s.GetBool(ctx, "feature.magic_link_enabled", true),
		OAuthEnabled:          s.GetBool(ctx, "feature.oauth_enabled", true),
		EmailQueueEnabled:     s.GetBool(ctx, "feature.email_queue_enabled", true),
		EmailRateLimitEnabled: s.GetBool(ctx, "feature.email_rate_limit_enabled", true),
	}
}

// EmailRateLimitConfig holds email rate limit configuration.
type EmailRateLimitConfig struct {
	VerificationLimit  int
	PasswordResetLimit int
	MFACodeLimit       int
	LoginAlertLimit    int
}

// GetEmailRateLimits retrieves email rate limit settings.
func (s *SettingsService) GetEmailRateLimits(ctx context.Context) *EmailRateLimitConfig {
	return &EmailRateLimitConfig{
		VerificationLimit:  s.GetInt(ctx, "email.verification_rate_limit", 3),
		PasswordResetLimit: s.GetInt(ctx, "email.password_reset_rate_limit", 5),
		MFACodeLimit:       s.GetInt(ctx, "email.mfa_code_rate_limit", 10),
		LoginAlertLimit:    s.GetInt(ctx, "email.login_alert_rate_limit", 10),
	}
}
