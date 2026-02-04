package pg

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/iSundram/ModernAuth/internal/storage"
)

// CreateVerificationToken creates a new verification token.
func (s *PostgresStorage) CreateVerificationToken(ctx context.Context, token *storage.VerificationToken) error {
	query := `
		INSERT INTO verification_tokens (id, user_id, token_hash, token_type, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := s.pool.Exec(ctx, query,
		token.ID,
		token.UserID,
		token.TokenHash,
		token.TokenType,
		token.ExpiresAt,
		token.CreatedAt,
	)
	return err
}

// GetVerificationTokenByHash retrieves a verification token by its hash and type.
func (s *PostgresStorage) GetVerificationTokenByHash(ctx context.Context, tokenHash string, tokenType string) (*storage.VerificationToken, error) {
	query := `
		SELECT id, user_id, token_hash, token_type, expires_at, used_at, created_at
		FROM verification_tokens
		WHERE token_hash = $1 AND token_type = $2
	`
	token := &storage.VerificationToken{}
	err := s.pool.QueryRow(ctx, query, tokenHash, tokenType).Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&token.TokenType,
		&token.ExpiresAt,
		&token.UsedAt,
		&token.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return token, nil
}

// MarkVerificationTokenUsed marks a verification token as used.
func (s *PostgresStorage) MarkVerificationTokenUsed(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE verification_tokens SET used_at = $2 WHERE id = $1`
	_, err := s.pool.Exec(ctx, query, id, time.Now())
	return err
}

// DeleteExpiredVerificationTokens deletes all expired verification tokens.
func (s *PostgresStorage) DeleteExpiredVerificationTokens(ctx context.Context) error {
	query := `DELETE FROM verification_tokens WHERE expires_at < $1`
	_, err := s.pool.Exec(ctx, query, time.Now())
	return err
}
