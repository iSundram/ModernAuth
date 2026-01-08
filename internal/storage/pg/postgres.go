// Package pg provides PostgreSQL implementation of the storage interfaces.
package pg

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/iSundram/ModernAuth/internal/storage"
)

// PostgresStorage implements the Storage interface using PostgreSQL.
type PostgresStorage struct {
	pool *pgxpool.Pool
}

// NewPostgresStorage creates a new PostgreSQL storage instance.
func NewPostgresStorage(pool *pgxpool.Pool) *PostgresStorage {
	return &PostgresStorage{pool: pool}
}

// CreateUser creates a new user in the database.
func (s *PostgresStorage) CreateUser(ctx context.Context, user *storage.User) error {
	query := `
		INSERT INTO users (id, email, phone, username, hashed_password, is_email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := s.pool.Exec(ctx, query,
		user.ID,
		user.Email,
		user.Phone,
		user.Username,
		user.HashedPassword,
		user.IsEmailVerified,
		user.CreatedAt,
		user.UpdatedAt,
	)
	return err
}

// GetUserByID retrieves a user by their ID.
func (s *PostgresStorage) GetUserByID(ctx context.Context, id uuid.UUID) (*storage.User, error) {
	query := `
		SELECT id, email, phone, username, hashed_password, is_email_verified, created_at, updated_at
		FROM users
		WHERE id = $1
	`
	user := &storage.User{}
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.Email,
		&user.Phone,
		&user.Username,
		&user.HashedPassword,
		&user.IsEmailVerified,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return user, nil
}

// GetUserByEmail retrieves a user by their email.
func (s *PostgresStorage) GetUserByEmail(ctx context.Context, email string) (*storage.User, error) {
	query := `
		SELECT id, email, phone, username, hashed_password, is_email_verified, created_at, updated_at
		FROM users
		WHERE email = $1
	`
	user := &storage.User{}
	err := s.pool.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.Phone,
		&user.Username,
		&user.HashedPassword,
		&user.IsEmailVerified,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return user, nil
}

// UpdateUser updates an existing user.
func (s *PostgresStorage) UpdateUser(ctx context.Context, user *storage.User) error {
	query := `
		UPDATE users
		SET email = $2, phone = $3, username = $4, hashed_password = $5, is_email_verified = $6, updated_at = $7
		WHERE id = $1
	`
	user.UpdatedAt = time.Now()
	_, err := s.pool.Exec(ctx, query,
		user.ID,
		user.Email,
		user.Phone,
		user.Username,
		user.HashedPassword,
		user.IsEmailVerified,
		user.UpdatedAt,
	)
	return err
}

// DeleteUser deletes a user by their ID.
func (s *PostgresStorage) DeleteUser(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM users WHERE id = $1`
	_, err := s.pool.Exec(ctx, query, id)
	return err
}

// CreateSession creates a new session.
func (s *PostgresStorage) CreateSession(ctx context.Context, session *storage.Session) error {
	query := `
		INSERT INTO sessions (id, user_id, fingerprint, created_at, expires_at, revoked, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := s.pool.Exec(ctx, query,
		session.ID,
		session.UserID,
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
		SELECT id, user_id, fingerprint, created_at, expires_at, revoked, metadata
		FROM sessions
		WHERE id = $1
	`
	session := &storage.Session{}
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&session.ID,
		&session.UserID,
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

// CreateAuditLog creates a new audit log entry.
func (s *PostgresStorage) CreateAuditLog(ctx context.Context, log *storage.AuditLog) error {
	query := `
		INSERT INTO audit_logs (id, user_id, actor_id, event_type, ip, user_agent, data, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := s.pool.Exec(ctx, query,
		log.ID,
		log.UserID,
		log.ActorID,
		log.EventType,
		log.IP,
		log.UserAgent,
		log.Data,
		log.CreatedAt,
	)
	return err
}

// GetAuditLogs retrieves audit logs with optional user filtering.
func (s *PostgresStorage) GetAuditLogs(ctx context.Context, userID *uuid.UUID, limit, offset int) ([]*storage.AuditLog, error) {
	var query string
	var rows pgx.Rows
	var err error

	if userID != nil {
		query = `
			SELECT id, user_id, actor_id, event_type, ip, user_agent, data, created_at
			FROM audit_logs
			WHERE user_id = $1
			ORDER BY created_at DESC
			LIMIT $2 OFFSET $3
		`
		rows, err = s.pool.Query(ctx, query, userID, limit, offset)
	} else {
		query = `
			SELECT id, user_id, actor_id, event_type, ip, user_agent, data, created_at
			FROM audit_logs
			ORDER BY created_at DESC
			LIMIT $1 OFFSET $2
		`
		rows, err = s.pool.Query(ctx, query, limit, offset)
	}

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []*storage.AuditLog
	for rows.Next() {
		log := &storage.AuditLog{}
		err := rows.Scan(
			&log.ID,
			&log.UserID,
			&log.ActorID,
			&log.EventType,
			&log.IP,
			&log.UserAgent,
			&log.Data,
			&log.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}

	return logs, rows.Err()
}
