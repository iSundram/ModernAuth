package storage

import (
	"time"

	"github.com/google/uuid"
)

// UserPreferences represents user-specific preferences and settings.
type UserPreferences struct {
	ID                       uuid.UUID `json:"id"`
	UserID                   uuid.UUID `json:"user_id"`
	// Notifications
	EmailSecurityAlerts      bool   `json:"email_security_alerts"`
	EmailMarketing           bool   `json:"email_marketing"`
	EmailProductUpdates      bool   `json:"email_product_updates"`
	EmailDigestFrequency     string `json:"email_digest_frequency"` // none, daily, weekly, monthly
	PushEnabled              bool   `json:"push_enabled"`
	// Appearance
	AccentColor              string `json:"accent_color"`
	FontSize                 string `json:"font_size"` // small, medium, large
	HighContrast             bool   `json:"high_contrast"`
	ReducedMotion            bool   `json:"reduced_motion"`
	// Privacy
	ProfileVisibility        string `json:"profile_visibility"` // public, private, contacts
	ShowActivityStatus       bool   `json:"show_activity_status"`
	ShowEmailPublicly        bool   `json:"show_email_publicly"`
	// Accessibility
	KeyboardShortcutsEnabled bool      `json:"keyboard_shortcuts_enabled"`
	CreatedAt                time.Time `json:"created_at"`
	UpdatedAt                time.Time `json:"updated_at"`
}
