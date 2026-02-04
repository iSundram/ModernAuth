package pg

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/iSundram/ModernAuth/internal/storage"
)

// CreateSession creates a new session.
func (s *PostgresStorage) CreateSession(ctx context.Context, session *storage.Session) error {
	query := `
		INSERT INTO sessions (id, user_id, tenant_id, device_id, fingerprint, created_at, expires_at, revoked, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err := s.pool.Exec(ctx, query,
		session.ID,
		session.UserID,
		session.TenantID,
		session.DeviceID,
		session.Fingerprint,
		session.CreatedAt,
		session.ExpiresAt,
		session.Revoked,
		session.Metadata,
	)
	return err
}

// GetSessionByID retrieves a session by its ID.
func (s *PostgresStorage) GetSessionByID(ctx context.Context, id uuid.UUID) (*storage.Session, error) {
	query := `
		SELECT id, user_id, tenant_id, device_id, fingerprint, created_at, expires_at, revoked, metadata
		FROM sessions
		WHERE id = $1
	`
	session := &storage.Session{}
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&session.ID,
		&session.UserID,
		&session.TenantID,
		&session.DeviceID,
		&session.Fingerprint,
		&session.CreatedAt,
		&session.ExpiresAt,
		&session.Revoked,
		&session.Metadata,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return session, nil
}

// GetUserSessions retrieves active sessions for a user.
func (s *PostgresStorage) GetUserSessions(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*storage.Session, error) {
	query := `
		SELECT id, user_id, tenant_id, device_id, fingerprint, created_at, expires_at, revoked, metadata
		FROM sessions
		WHERE user_id = $1 AND revoked = false AND expires_at > now()
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`
	rows, err := s.pool.Query(ctx, query, userID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*storage.Session
	for rows.Next() {
		session := &storage.Session{}
		err := rows.Scan(
			&session.ID,
			&session.UserID,
			&session.TenantID,
			&session.DeviceID,
			&session.Fingerprint,
			&session.CreatedAt,
			&session.ExpiresAt,
			&session.Revoked,
			&session.Metadata,
		)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}

	return sessions, rows.Err()
}

// RevokeSession revokes a session by its ID.
func (s *PostgresStorage) RevokeSession(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE sessions SET revoked = true WHERE id = $1`
	_, err := s.pool.Exec(ctx, query, id)
	return err
}

// RevokeUserSessions revokes all sessions for a user.
func (s *PostgresStorage) RevokeUserSessions(ctx context.Context, userID uuid.UUID) error {
	query := `UPDATE sessions SET revoked = true WHERE user_id = $1`
	_, err := s.pool.Exec(ctx, query, userID)
	return err
}

// CreateRefreshToken creates a new refresh token.
func (s *PostgresStorage) CreateRefreshToken(ctx context.Context, token *storage.RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (id, session_id, token_hash, issued_at, expires_at, revoked, replaced_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := s.pool.Exec(ctx, query,
		token.ID,
		token.SessionID,
		token.TokenHash,
		token.IssuedAt,
		token.ExpiresAt,
		token.Revoked,
		token.ReplacedBy,
	)
	return err
}

// GetRefreshTokenByHash retrieves a refresh token by its hash.
func (s *PostgresStorage) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*storage.RefreshToken, error) {
	query := `
		SELECT id, session_id, token_hash, issued_at, expires_at, revoked, replaced_by
		FROM refresh_tokens
		WHERE token_hash = $1
	`
	token := &storage.RefreshToken{}
	err := s.pool.QueryRow(ctx, query, tokenHash).Scan(
		&token.ID,
		&token.SessionID,
		&token.TokenHash,
		&token.IssuedAt,
		&token.ExpiresAt,
		&token.Revoked,
		&token.ReplacedBy,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return token, nil
}

// RevokeRefreshToken revokes a refresh token and optionally sets its replacement.
func (s *PostgresStorage) RevokeRefreshToken(ctx context.Context, id uuid.UUID, replacedBy *uuid.UUID) error {
	query := `UPDATE refresh_tokens SET revoked = true, replaced_by = $2 WHERE id = $1`
	_, err := s.pool.Exec(ctx, query, id, replacedBy)
	return err
}

// RevokeSessionRefreshTokens revokes all refresh tokens for a session.
func (s *PostgresStorage) RevokeSessionRefreshTokens(ctx context.Context, sessionID uuid.UUID) error {
	query := `UPDATE refresh_tokens SET revoked = true WHERE session_id = $1`
	_, err := s.pool.Exec(ctx, query, sessionID)
	return err
}
