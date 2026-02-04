package pg

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/iSundram/ModernAuth/internal/storage"
)

// ============================================================================
// SystemSettingsStorage methods
// ============================================================================

func (s *PostgresStorage) GetSetting(ctx context.Context, key string) (*storage.SystemSetting, error) {
	query := `
		SELECT key, value, category, is_secret, description, updated_at
		FROM system_settings WHERE key = $1
	`
	setting := &storage.SystemSetting{}
	err := s.pool.QueryRow(ctx, query, key).Scan(
		&setting.Key, &setting.Value, &setting.Category, &setting.IsSecret,
		&setting.Description, &setting.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return setting, nil
}

func (s *PostgresStorage) ListSettings(ctx context.Context, category string) ([]*storage.SystemSetting, error) {
	var query string
	var args []interface{}

	if category != "" {
		query = `
			SELECT key, value, category, is_secret, description, updated_at
			FROM system_settings WHERE category = $1 ORDER BY key
		`
		args = []interface{}{category}
	} else {
		query = `
			SELECT key, value, category, is_secret, description, updated_at
			FROM system_settings ORDER BY category, key
		`
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var settings []*storage.SystemSetting
	for rows.Next() {
		setting := &storage.SystemSetting{}
		err := rows.Scan(
			&setting.Key, &setting.Value, &setting.Category, &setting.IsSecret,
			&setting.Description, &setting.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		settings = append(settings, setting)
	}
	return settings, rows.Err()
}

func (s *PostgresStorage) UpdateSetting(ctx context.Context, key string, value interface{}) error {
	query := `
		UPDATE system_settings
		SET value = $2, updated_at = now()
		WHERE key = $1
	`
	_, err := s.pool.Exec(ctx, query, key, value)
	return err
}
