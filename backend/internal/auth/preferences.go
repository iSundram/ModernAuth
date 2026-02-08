// Package auth provides authentication services for ModernAuth.
package auth

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
)

// Validation errors for preferences
var (
	ErrInvalidDigestFrequency    = errors.New("email_digest_frequency must be one of: none, daily, weekly, monthly")
	ErrInvalidFontSize           = errors.New("font_size must be one of: small, medium, large")
	ErrInvalidProfileVisibility  = errors.New("profile_visibility must be one of: public, private, contacts")
	ErrInvalidAccentColor        = errors.New("accent_color must be a valid hex color (#xxxxxx)")
)

// Valid values for preference fields
var (
	validDigestFrequencies   = map[string]bool{"none": true, "daily": true, "weekly": true, "monthly": true}
	validFontSizes           = map[string]bool{"small": true, "medium": true, "large": true}
	validProfileVisibilities = map[string]bool{"public": true, "private": true, "contacts": true}
	hexColorRegex            = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)
)

// UpdatePreferencesRequest represents a request to update user preferences.
type UpdatePreferencesRequest struct {
	EmailSecurityAlerts      *bool   `json:"email_security_alerts"`
	EmailMarketing           *bool   `json:"email_marketing"`
	EmailProductUpdates      *bool   `json:"email_product_updates"`
	EmailDigestFrequency     *string `json:"email_digest_frequency"`
	PushEnabled              *bool   `json:"push_enabled"`
	AccentColor              *string `json:"accent_color"`
	FontSize                 *string `json:"font_size"`
	HighContrast             *bool   `json:"high_contrast"`
	ReducedMotion            *bool   `json:"reduced_motion"`
	ProfileVisibility        *string `json:"profile_visibility"`
	ShowActivityStatus       *bool   `json:"show_activity_status"`
	ShowEmailPublicly        *bool   `json:"show_email_publicly"`
	KeyboardShortcutsEnabled *bool   `json:"keyboard_shortcuts_enabled"`
}

// ValidatePreferencesRequest validates the UpdatePreferencesRequest fields.
func ValidatePreferencesRequest(req *UpdatePreferencesRequest) error {
	if req.EmailDigestFrequency != nil && !validDigestFrequencies[*req.EmailDigestFrequency] {
		return ErrInvalidDigestFrequency
	}
	if req.FontSize != nil && !validFontSizes[*req.FontSize] {
		return ErrInvalidFontSize
	}
	if req.ProfileVisibility != nil && !validProfileVisibilities[*req.ProfileVisibility] {
		return ErrInvalidProfileVisibility
	}
	if req.AccentColor != nil && !hexColorRegex.MatchString(*req.AccentColor) {
		return ErrInvalidAccentColor
	}
	return nil
}

// GetPreferences retrieves user preferences by user ID.
func (s *AuthService) GetPreferences(ctx context.Context, userID uuid.UUID) (*storage.UserPreferences, error) {
	return s.storage.GetOrCreatePreferences(ctx, userID)
}

// UpdatePreferences updates user preferences.
func (s *AuthService) UpdatePreferences(ctx context.Context, userID uuid.UUID, req *UpdatePreferencesRequest) (*storage.UserPreferences, error) {
	// Validate the request
	if err := ValidatePreferencesRequest(req); err != nil {
		return nil, err
	}

	// Get existing preferences or create defaults
	prefs, err := s.storage.GetOrCreatePreferences(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Apply updates
	if req.EmailSecurityAlerts != nil {
		prefs.EmailSecurityAlerts = *req.EmailSecurityAlerts
	}
	if req.EmailMarketing != nil {
		prefs.EmailMarketing = *req.EmailMarketing
	}
	if req.EmailProductUpdates != nil {
		prefs.EmailProductUpdates = *req.EmailProductUpdates
	}
	if req.EmailDigestFrequency != nil {
		prefs.EmailDigestFrequency = *req.EmailDigestFrequency
	}
	if req.PushEnabled != nil {
		prefs.PushEnabled = *req.PushEnabled
	}
	if req.AccentColor != nil {
		prefs.AccentColor = *req.AccentColor
	}
	if req.FontSize != nil {
		prefs.FontSize = *req.FontSize
	}
	if req.HighContrast != nil {
		prefs.HighContrast = *req.HighContrast
	}
	if req.ReducedMotion != nil {
		prefs.ReducedMotion = *req.ReducedMotion
	}
	if req.ProfileVisibility != nil {
		prefs.ProfileVisibility = *req.ProfileVisibility
	}
	if req.ShowActivityStatus != nil {
		prefs.ShowActivityStatus = *req.ShowActivityStatus
	}
	if req.ShowEmailPublicly != nil {
		prefs.ShowEmailPublicly = *req.ShowEmailPublicly
	}
	if req.KeyboardShortcutsEnabled != nil {
		prefs.KeyboardShortcutsEnabled = *req.KeyboardShortcutsEnabled
	}

	prefs.UpdatedAt = time.Now()

	if err := s.storage.UpdatePreferences(ctx, prefs); err != nil {
		return nil, err
	}

	// Log audit event
	s.logAuditEvent(ctx, &userID, nil, "user.preferences_updated", nil, nil, nil)

	return prefs, nil
}
