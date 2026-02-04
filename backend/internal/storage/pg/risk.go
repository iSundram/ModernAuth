package pg

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/iSundram/ModernAuth/internal/storage"
)

// ========== Risk Assessment Storage ==========

// CreateRiskAssessment creates a new risk assessment record.
func (s *PostgresStorage) CreateRiskAssessment(ctx context.Context, assessment *storage.RiskAssessment) error {
	query := `
		INSERT INTO risk_assessments (id, user_id, session_id, risk_score, risk_level, factors, action_taken, ip_address, user_agent, location_country, location_city, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`
	_, err := s.pool.Exec(ctx, query, assessment.ID, assessment.UserID, assessment.SessionID,
		assessment.RiskScore, assessment.RiskLevel, assessment.Factors, assessment.ActionTaken,
		assessment.IPAddress, assessment.UserAgent, assessment.LocationCountry, assessment.LocationCity, assessment.CreatedAt)
	return err
}

// GetRecentRiskAssessments retrieves recent risk assessments for a user.
func (s *PostgresStorage) GetRecentRiskAssessments(ctx context.Context, userID uuid.UUID, limit int) ([]*storage.RiskAssessment, error) {
	query := `
		SELECT id, user_id, session_id, risk_score, risk_level, factors, action_taken, ip_address, user_agent, location_country, location_city, created_at
		FROM risk_assessments
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2`

	rows, err := s.pool.Query(ctx, query, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var assessments []*storage.RiskAssessment
	for rows.Next() {
		a := &storage.RiskAssessment{}
		if err := rows.Scan(&a.ID, &a.UserID, &a.SessionID, &a.RiskScore, &a.RiskLevel, &a.Factors,
			&a.ActionTaken, &a.IPAddress, &a.UserAgent, &a.LocationCountry, &a.LocationCity, &a.CreatedAt); err != nil {
			return nil, err
		}
		assessments = append(assessments, a)
	}
	return assessments, rows.Err()
}

// GetRiskAssessmentStats retrieves risk assessment statistics for a user.
func (s *PostgresStorage) GetRiskAssessmentStats(ctx context.Context, userID uuid.UUID, since time.Time) (map[string]int, error) {
	query := `
		SELECT risk_level, COUNT(*) as count
		FROM risk_assessments
		WHERE user_id = $1 AND created_at > $2
		GROUP BY risk_level`

	rows, err := s.pool.Query(ctx, query, userID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := make(map[string]int)
	for rows.Next() {
		var level string
		var count int
		if err := rows.Scan(&level, &count); err != nil {
			return nil, err
		}
		stats[level] = count
	}
	return stats, rows.Err()
}

// ========== Session Count ==========

// CountActiveUserSessions counts active (non-revoked, non-expired) sessions for a user.
func (s *PostgresStorage) CountActiveUserSessions(ctx context.Context, userID uuid.UUID) (int, error) {
	query := `
		SELECT COUNT(*) FROM sessions
		WHERE user_id = $1 AND revoked = false AND expires_at > $2`
	var count int
	err := s.pool.QueryRow(ctx, query, userID, time.Now()).Scan(&count)
	return count, err
}

// GetOldestActiveSession retrieves the oldest active session for a user.
func (s *PostgresStorage) GetOldestActiveSession(ctx context.Context, userID uuid.UUID) (*storage.Session, error) {
	query := `
		SELECT id, user_id, tenant_id, device_id, fingerprint, created_at, expires_at, revoked, metadata
		FROM sessions
		WHERE user_id = $1 AND revoked = false AND expires_at > $2
		ORDER BY created_at ASC
		LIMIT 1`

	session := &storage.Session{}
	err := s.pool.QueryRow(ctx, query, userID, time.Now()).Scan(
		&session.ID, &session.UserID, &session.TenantID, &session.DeviceID,
		&session.Fingerprint, &session.CreatedAt, &session.ExpiresAt, &session.Revoked, &session.Metadata)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, nil
		}
		return nil, err
	}
	return session, nil
}
