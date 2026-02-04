package storage

import (
	"time"

	"github.com/google/uuid"
)

// Webhook represents a webhook subscription.
type Webhook struct {
	ID             uuid.UUID              `json:"id"`
	TenantID       *uuid.UUID             `json:"tenant_id,omitempty"`
	Name           string                 `json:"name"`
	Description    *string                `json:"description,omitempty"`
	URL            string                 `json:"url"`
	Secret         string                 `json:"-"`
	Events         []string               `json:"events"`
	Headers        map[string]interface{} `json:"headers,omitempty"`
	IsActive       bool                   `json:"is_active"`
	RetryCount     int                    `json:"retry_count"`
	TimeoutSeconds int                    `json:"timeout_seconds"`
	CreatedBy      *uuid.UUID             `json:"created_by,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
}

// WebhookDelivery represents a webhook delivery attempt.
type WebhookDelivery struct {
	ID                 uuid.UUID              `json:"id"`
	WebhookID          uuid.UUID              `json:"webhook_id"`
	EventID            uuid.UUID              `json:"event_id"`
	EventType          string                 `json:"event_type"`
	Payload            map[string]interface{} `json:"payload"`
	ResponseStatusCode *int                   `json:"response_status_code,omitempty"`
	ResponseTimeMs     *int                   `json:"response_time_ms,omitempty"`
	AttemptNumber      int                    `json:"attempt_number"`
	Status             string                 `json:"status"` // pending, success, failed, retrying
	ErrorMessage       *string                `json:"error_message,omitempty"`
	NextRetryAt        *time.Time             `json:"next_retry_at,omitempty"`
	CreatedAt          time.Time              `json:"created_at"`
	CompletedAt        *time.Time             `json:"completed_at,omitempty"`
}
