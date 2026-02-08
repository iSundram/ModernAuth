package pg

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/iSundram/ModernAuth/internal/storage"
)

// ============================================================================
// PreferencesStorage methods
// ============================================================================

func (s *PostgresStorage) GetPreferences(ctx context.Context, userID uuid.UUID) (*storage.UserPreferences, error) {
	query := `
		SELECT id, user_id, email_security_alerts, email_marketing, email_product_updates,
		       email_digest_frequency, push_enabled, accent_color, font_size, high_contrast,
		       reduced_motion, profile_visibility, show_activity_status, show_email_publicly,
		       keyboard_shortcuts_enabled, created_at, updated_at
		FROM user_preferences WHERE user_id = $1
	`
	prefs := &storage.UserPreferences{}
	err := s.pool.QueryRow(ctx, query, userID).Scan(
		&prefs.ID, &prefs.UserID, &prefs.EmailSecurityAlerts, &prefs.EmailMarketing,
		&prefs.EmailProductUpdates, &prefs.EmailDigestFrequency, &prefs.PushEnabled,
		&prefs.AccentColor, &prefs.FontSize, &prefs.HighContrast, &prefs.ReducedMotion,
		&prefs.ProfileVisibility, &prefs.ShowActivityStatus, &prefs.ShowEmailPublicly,
		&prefs.KeyboardShortcutsEnabled, &prefs.CreatedAt, &prefs.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return prefs, nil
}

func (s *PostgresStorage) CreatePreferences(ctx context.Context, prefs *storage.UserPreferences) error {
	query := `
		INSERT INTO user_preferences (
			id, user_id, email_security_alerts, email_marketing, email_product_updates,
			email_digest_frequency, push_enabled, accent_color, font_size, high_contrast,
			reduced_motion, profile_visibility, show_activity_status, show_email_publicly,
			keyboard_shortcuts_enabled, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
	`
	_, err := s.pool.Exec(ctx, query,
		prefs.ID, prefs.UserID, prefs.EmailSecurityAlerts, prefs.EmailMarketing,
		prefs.EmailProductUpdates, prefs.EmailDigestFrequency, prefs.PushEnabled,
		prefs.AccentColor, prefs.FontSize, prefs.HighContrast, prefs.ReducedMotion,
		prefs.ProfileVisibility, prefs.ShowActivityStatus, prefs.ShowEmailPublicly,
		prefs.KeyboardShortcutsEnabled, prefs.CreatedAt, prefs.UpdatedAt,
	)
	return err
}

func (s *PostgresStorage) UpdatePreferences(ctx context.Context, prefs *storage.UserPreferences) error {
	query := `
		UPDATE user_preferences SET
			email_security_alerts = $2, email_marketing = $3, email_product_updates = $4,
			email_digest_frequency = $5, push_enabled = $6, accent_color = $7, font_size = $8,
			high_contrast = $9, reduced_motion = $10, profile_visibility = $11,
			show_activity_status = $12, show_email_publicly = $13, keyboard_shortcuts_enabled = $14,
			updated_at = $15
		WHERE user_id = $1
	`
	_, err := s.pool.Exec(ctx, query,
		prefs.UserID, prefs.EmailSecurityAlerts, prefs.EmailMarketing, prefs.EmailProductUpdates,
		prefs.EmailDigestFrequency, prefs.PushEnabled, prefs.AccentColor, prefs.FontSize,
		prefs.HighContrast, prefs.ReducedMotion, prefs.ProfileVisibility, prefs.ShowActivityStatus,
		prefs.ShowEmailPublicly, prefs.KeyboardShortcutsEnabled, prefs.UpdatedAt,
	)
	return err
}

func (s *PostgresStorage) GetOrCreatePreferences(ctx context.Context, userID uuid.UUID) (*storage.UserPreferences, error) {
	prefs, err := s.GetPreferences(ctx, userID)
	if err != nil {
		return nil, err
	}
	if prefs != nil {
		return prefs, nil
	}

	// Create default preferences
	now := time.Now()
	prefs = &storage.UserPreferences{
		ID:                       uuid.New(),
		UserID:                   userID,
		EmailSecurityAlerts:      true,
		EmailMarketing:           false,
		EmailProductUpdates:      true,
		EmailDigestFrequency:     "weekly",
		PushEnabled:              true,
		AccentColor:              "#3b82f6",
		FontSize:                 "medium",
		HighContrast:             false,
		ReducedMotion:            false,
		ProfileVisibility:        "private",
		ShowActivityStatus:       true,
		ShowEmailPublicly:        false,
		KeyboardShortcutsEnabled: true,
		CreatedAt:                now,
		UpdatedAt:                now,
	}

	if err := s.CreatePreferences(ctx, prefs); err != nil {
		return nil, err
	}
	return prefs, nil
}
