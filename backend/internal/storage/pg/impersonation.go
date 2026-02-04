package pg

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/iSundram/ModernAuth/internal/storage"
)

// ========== Impersonation Storage ==========

// CreateImpersonationSession creates a new impersonation session.
func (s *PostgresStorage) CreateImpersonationSession(ctx context.Context, session *storage.ImpersonationSession) error {
	query := `
		INSERT INTO impersonation_sessions (id, session_id, admin_user_id, target_user_id, reason, started_at, ip_address, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := s.pool.Exec(ctx, query, session.ID, session.SessionID, session.AdminUserID,
		session.TargetUserID, session.Reason, session.StartedAt, session.IPAddress, session.UserAgent)
	return err
}

// GetImpersonationSession retrieves an impersonation session by session ID.
func (s *PostgresStorage) GetImpersonationSession(ctx context.Context, sessionID uuid.UUID) (*storage.ImpersonationSession, error) {
	query := `
		SELECT id, session_id, admin_user_id, target_user_id, reason, started_at, ended_at, ip_address, user_agent
		FROM impersonation_sessions
		WHERE session_id = $1`

	session := &storage.ImpersonationSession{}
	err := s.pool.QueryRow(ctx, query, sessionID).Scan(
		&session.ID, &session.SessionID, &session.AdminUserID, &session.TargetUserID,
		&session.Reason, &session.StartedAt, &session.EndedAt, &session.IPAddress, &session.UserAgent)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, nil
		}
		return nil, err
	}
	return session, nil
}

// EndImpersonationSession ends an impersonation session.
func (s *PostgresStorage) EndImpersonationSession(ctx context.Context, sessionID uuid.UUID) error {
	query := `UPDATE impersonation_sessions SET ended_at = $1 WHERE session_id = $2 AND ended_at IS NULL`
	_, err := s.pool.Exec(ctx, query, time.Now(), sessionID)
	return err
}

// ListImpersonationSessions lists impersonation sessions with optional filters.
func (s *PostgresStorage) ListImpersonationSessions(ctx context.Context, adminUserID *uuid.UUID, targetUserID *uuid.UUID, limit, offset int) ([]*storage.ImpersonationSession, error) {
	query := `
		SELECT id, session_id, admin_user_id, target_user_id, reason, started_at, ended_at, ip_address, user_agent
		FROM impersonation_sessions
		WHERE ($1::uuid IS NULL OR admin_user_id = $1)
		AND ($2::uuid IS NULL OR target_user_id = $2)
		ORDER BY started_at DESC
		LIMIT $3 OFFSET $4`

	rows, err := s.pool.Query(ctx, query, adminUserID, targetUserID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*storage.ImpersonationSession
	for rows.Next() {
		session := &storage.ImpersonationSession{}
		if err := rows.Scan(&session.ID, &session.SessionID, &session.AdminUserID, &session.TargetUserID,
			&session.Reason, &session.StartedAt, &session.EndedAt, &session.IPAddress, &session.UserAgent); err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}
