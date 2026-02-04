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
// WebhookStorage methods
// ============================================================================

func (s *PostgresStorage) CreateWebhook(ctx context.Context, webhook *storage.Webhook) error {
	query := `
		INSERT INTO webhooks (id, tenant_id, name, description, url, secret, events, headers, is_active,
		                      retry_count, timeout_seconds, created_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`
	_, err := s.pool.Exec(ctx, query,
		webhook.ID, webhook.TenantID, webhook.Name, webhook.Description, webhook.URL, webhook.Secret,
		webhook.Events, webhook.Headers, webhook.IsActive, webhook.RetryCount, webhook.TimeoutSeconds,
		webhook.CreatedBy, webhook.CreatedAt, webhook.UpdatedAt,
	)
	return err
}

func (s *PostgresStorage) GetWebhookByID(ctx context.Context, id uuid.UUID) (*storage.Webhook, error) {
	query := `
		SELECT id, tenant_id, name, description, url, secret, events, headers, is_active, retry_count,
		       timeout_seconds, created_by, created_at, updated_at
		FROM webhooks WHERE id = $1
	`
	webhook := &storage.Webhook{}
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&webhook.ID, &webhook.TenantID, &webhook.Name, &webhook.Description, &webhook.URL, &webhook.Secret,
		&webhook.Events, &webhook.Headers, &webhook.IsActive, &webhook.RetryCount, &webhook.TimeoutSeconds,
		&webhook.CreatedBy, &webhook.CreatedAt, &webhook.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return webhook, nil
}

func (s *PostgresStorage) ListWebhooks(ctx context.Context, tenantID *uuid.UUID, limit, offset int) ([]*storage.Webhook, error) {
	var query string
	var args []interface{}

	if tenantID != nil {
		query = `
			SELECT id, tenant_id, name, description, url, secret, events, headers, is_active, retry_count,
			       timeout_seconds, created_by, created_at, updated_at
			FROM webhooks WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3
		`
		args = []interface{}{*tenantID, limit, offset}
	} else {
		query = `
			SELECT id, tenant_id, name, description, url, secret, events, headers, is_active, retry_count,
			       timeout_seconds, created_by, created_at, updated_at
			FROM webhooks ORDER BY created_at DESC LIMIT $1 OFFSET $2
		`
		args = []interface{}{limit, offset}
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var webhooks []*storage.Webhook
	for rows.Next() {
		webhook := &storage.Webhook{}
		err := rows.Scan(
			&webhook.ID, &webhook.TenantID, &webhook.Name, &webhook.Description, &webhook.URL, &webhook.Secret,
			&webhook.Events, &webhook.Headers, &webhook.IsActive, &webhook.RetryCount, &webhook.TimeoutSeconds,
			&webhook.CreatedBy, &webhook.CreatedAt, &webhook.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		webhooks = append(webhooks, webhook)
	}
	return webhooks, rows.Err()
}

func (s *PostgresStorage) ListWebhooksByEvent(ctx context.Context, tenantID *uuid.UUID, eventType string) ([]*storage.Webhook, error) {
	var query string
	var args []interface{}

	if tenantID != nil {
		query = `
			SELECT id, tenant_id, name, description, url, secret, events, headers, is_active, retry_count,
			       timeout_seconds, created_by, created_at, updated_at
			FROM webhooks WHERE tenant_id = $1 AND is_active = true AND $2 = ANY(events)
		`
		args = []interface{}{*tenantID, eventType}
	} else {
		query = `
			SELECT id, tenant_id, name, description, url, secret, events, headers, is_active, retry_count,
			       timeout_seconds, created_by, created_at, updated_at
			FROM webhooks WHERE is_active = true AND $1 = ANY(events)
		`
		args = []interface{}{eventType}
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var webhooks []*storage.Webhook
	for rows.Next() {
		webhook := &storage.Webhook{}
		err := rows.Scan(
			&webhook.ID, &webhook.TenantID, &webhook.Name, &webhook.Description, &webhook.URL, &webhook.Secret,
			&webhook.Events, &webhook.Headers, &webhook.IsActive, &webhook.RetryCount, &webhook.TimeoutSeconds,
			&webhook.CreatedBy, &webhook.CreatedAt, &webhook.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		webhooks = append(webhooks, webhook)
	}
	return webhooks, rows.Err()
}

func (s *PostgresStorage) UpdateWebhook(ctx context.Context, webhook *storage.Webhook) error {
	query := `
		UPDATE webhooks
		SET name = $2, description = $3, url = $4, events = $5, headers = $6, is_active = $7,
		    retry_count = $8, timeout_seconds = $9, updated_at = $10
		WHERE id = $1
	`
	webhook.UpdatedAt = time.Now()
	_, err := s.pool.Exec(ctx, query,
		webhook.ID, webhook.Name, webhook.Description, webhook.URL, webhook.Events, webhook.Headers,
		webhook.IsActive, webhook.RetryCount, webhook.TimeoutSeconds, webhook.UpdatedAt,
	)
	return err
}

func (s *PostgresStorage) DeleteWebhook(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM webhooks WHERE id = $1`
	_, err := s.pool.Exec(ctx, query, id)
	return err
}

func (s *PostgresStorage) CreateWebhookDelivery(ctx context.Context, delivery *storage.WebhookDelivery) error {
	query := `
		INSERT INTO webhook_deliveries (id, webhook_id, event_id, event_type, payload, response_status_code,
		                               response_time_ms, attempt_number, status, error_message, next_retry_at,
		                               created_at, completed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`
	_, err := s.pool.Exec(ctx, query,
		delivery.ID, delivery.WebhookID, delivery.EventID, delivery.EventType, delivery.Payload,
		delivery.ResponseStatusCode, delivery.ResponseTimeMs, delivery.AttemptNumber, delivery.Status,
		delivery.ErrorMessage, delivery.NextRetryAt, delivery.CreatedAt, delivery.CompletedAt,
	)
	return err
}

func (s *PostgresStorage) UpdateWebhookDelivery(ctx context.Context, delivery *storage.WebhookDelivery) error {
	query := `
		UPDATE webhook_deliveries
		SET response_status_code = $2, response_time_ms = $3, attempt_number = $4, status = $5,
		    error_message = $6, next_retry_at = $7, completed_at = $8
		WHERE id = $1
	`
	_, err := s.pool.Exec(ctx, query,
		delivery.ID, delivery.ResponseStatusCode, delivery.ResponseTimeMs, delivery.AttemptNumber,
		delivery.Status, delivery.ErrorMessage, delivery.NextRetryAt, delivery.CompletedAt,
	)
	return err
}

func (s *PostgresStorage) GetPendingDeliveries(ctx context.Context, limit int) ([]*storage.WebhookDelivery, error) {
	query := `
		SELECT id, webhook_id, event_id, event_type, payload, response_status_code, response_time_ms,
		       attempt_number, status, error_message, next_retry_at, created_at, completed_at
		FROM webhook_deliveries
		WHERE status IN ('pending', 'retrying') AND (next_retry_at IS NULL OR next_retry_at <= now())
		ORDER BY created_at ASC LIMIT $1
	`
	rows, err := s.pool.Query(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var deliveries []*storage.WebhookDelivery
	for rows.Next() {
		delivery := &storage.WebhookDelivery{}
		err := rows.Scan(
			&delivery.ID, &delivery.WebhookID, &delivery.EventID, &delivery.EventType, &delivery.Payload,
			&delivery.ResponseStatusCode, &delivery.ResponseTimeMs, &delivery.AttemptNumber, &delivery.Status,
			&delivery.ErrorMessage, &delivery.NextRetryAt, &delivery.CreatedAt, &delivery.CompletedAt,
		)
		if err != nil {
			return nil, err
		}
		deliveries = append(deliveries, delivery)
	}
	return deliveries, rows.Err()
}

func (s *PostgresStorage) GetWebhookDeliveries(ctx context.Context, webhookID uuid.UUID, limit, offset int) ([]*storage.WebhookDelivery, error) {
	query := `
		SELECT id, webhook_id, event_id, event_type, payload, response_status_code, response_time_ms,
		       attempt_number, status, error_message, next_retry_at, created_at, completed_at
		FROM webhook_deliveries WHERE webhook_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3
	`
	rows, err := s.pool.Query(ctx, query, webhookID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var deliveries []*storage.WebhookDelivery
	for rows.Next() {
		delivery := &storage.WebhookDelivery{}
		err := rows.Scan(
			&delivery.ID, &delivery.WebhookID, &delivery.EventID, &delivery.EventType, &delivery.Payload,
			&delivery.ResponseStatusCode, &delivery.ResponseTimeMs, &delivery.AttemptNumber, &delivery.Status,
			&delivery.ErrorMessage, &delivery.NextRetryAt, &delivery.CreatedAt, &delivery.CompletedAt,
		)
		if err != nil {
			return nil, err
		}
		deliveries = append(deliveries, delivery)
	}
	return deliveries, rows.Err()
}
