package pg

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/iSundram/ModernAuth/internal/storage"
)

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

// GetAuditLogs retrieves audit logs with optional user and event type filtering.
func (s *PostgresStorage) GetAuditLogs(ctx context.Context, userID *uuid.UUID, eventType *string, limit, offset int) ([]*storage.AuditLog, error) {
	var query string
	var rows pgx.Rows
	var err error
	var args []interface{}
	argIndex := 1

	// Build WHERE clause dynamically
	var conditions []string
	if userID != nil {
		conditions = append(conditions, fmt.Sprintf("user_id = $%d", argIndex))
		args = append(args, *userID)
		argIndex++
	}
	if eventType != nil {
		conditions = append(conditions, fmt.Sprintf("event_type = $%d", argIndex))
		args = append(args, *eventType)
		argIndex++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Add limit and offset
	args = append(args, limit, offset)
	query = fmt.Sprintf(`
		SELECT id, tenant_id, user_id, actor_id, event_type, ip, user_agent, data, created_at
		FROM audit_logs
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIndex, argIndex+1)

	rows, err = s.pool.Query(ctx, query, args...)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []*storage.AuditLog
	for rows.Next() {
		log := &storage.AuditLog{}
		err := rows.Scan(
			&log.ID,
			&log.TenantID,
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

// DeleteOldAuditLogs deletes audit logs older than the specified time.
func (s *PostgresStorage) DeleteOldAuditLogs(ctx context.Context, olderThan time.Time) (int64, error) {
	query := `DELETE FROM audit_logs WHERE created_at < $1`
	result, err := s.pool.Exec(ctx, query, olderThan)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

// ListAuditLogsByTenant retrieves audit logs for a specific tenant.
func (s *PostgresStorage) ListAuditLogsByTenant(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*storage.AuditLog, error) {
	query := `
		SELECT id, tenant_id, user_id, actor_id, event_type, ip, user_agent, data, created_at
		FROM audit_logs
		WHERE tenant_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`
	rows, err := s.pool.Query(ctx, query, tenantID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []*storage.AuditLog
	for rows.Next() {
		log := &storage.AuditLog{}
		if err := rows.Scan(
			&log.ID, &log.TenantID, &log.UserID, &log.ActorID, &log.EventType,
			&log.IP, &log.UserAgent, &log.Data, &log.CreatedAt,
		); err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}
	return logs, nil
}

// ListAuditLogsByEventTypes retrieves audit logs filtered by event types.
func (s *PostgresStorage) ListAuditLogsByEventTypes(ctx context.Context, eventTypes []string, limit, offset int) ([]*storage.AuditLog, error) {
	query := `
		SELECT id, tenant_id, user_id, actor_id, event_type, ip, user_agent, data, created_at
		FROM audit_logs
		WHERE event_type = ANY($1)
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`
	rows, err := s.pool.Query(ctx, query, eventTypes, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []*storage.AuditLog
	for rows.Next() {
		log := &storage.AuditLog{}
		if err := rows.Scan(
			&log.ID, &log.TenantID, &log.UserID, &log.ActorID, &log.EventType,
			&log.IP, &log.UserAgent, &log.Data, &log.CreatedAt,
		); err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}
	return logs, nil
}

// CountAuditLogsByEventTypes counts audit logs filtered by event types.
func (s *PostgresStorage) CountAuditLogsByEventTypes(ctx context.Context, eventTypes []string) (int, error) {
	query := `SELECT COUNT(*) FROM audit_logs WHERE event_type = ANY($1)`
	var count int
	err := s.pool.QueryRow(ctx, query, eventTypes).Scan(&count)
	return count, err
}
