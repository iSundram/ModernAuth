package pg

import (
	"context"

	"github.com/google/uuid"

	"github.com/iSundram/ModernAuth/internal/storage"
)

// ========== Password History Storage ==========

// AddPasswordHistory adds a password hash to user's password history.
func (s *PostgresStorage) AddPasswordHistory(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	query := `INSERT INTO password_history (user_id, password_hash) VALUES ($1, $2)`
	_, err := s.pool.Exec(ctx, query, userID, passwordHash)
	return err
}

// GetPasswordHistory retrieves the user's password history.
func (s *PostgresStorage) GetPasswordHistory(ctx context.Context, userID uuid.UUID, limit int) ([]*storage.PasswordHistory, error) {
	query := `
		SELECT id, user_id, password_hash, created_at
		FROM password_history
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2`

	rows, err := s.pool.Query(ctx, query, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []*storage.PasswordHistory
	for rows.Next() {
		h := &storage.PasswordHistory{}
		if err := rows.Scan(&h.ID, &h.UserID, &h.PasswordHash, &h.CreatedAt); err != nil {
			return nil, err
		}
		history = append(history, h)
	}
	return history, rows.Err()
}

// CleanupOldPasswordHistory removes old password history entries beyond the keep count.
func (s *PostgresStorage) CleanupOldPasswordHistory(ctx context.Context, userID uuid.UUID, keepCount int) error {
	query := `
		DELETE FROM password_history
		WHERE user_id = $1 AND id NOT IN (
			SELECT id FROM password_history
			WHERE user_id = $1
			ORDER BY created_at DESC
			LIMIT $2
		)`
	_, err := s.pool.Exec(ctx, query, userID, keepCount)
	return err
}
