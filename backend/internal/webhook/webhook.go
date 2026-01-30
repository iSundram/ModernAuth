// Package webhook provides webhook management for ModernAuth.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
)

var (
	// ErrWebhookNotFound indicates the webhook was not found.
	ErrWebhookNotFound = errors.New("webhook not found")
	// ErrDeliveryFailed indicates the webhook delivery failed.
	ErrDeliveryFailed = errors.New("webhook delivery failed")
)

// Event types for webhooks.
const (
	EventUserCreated         = "user.created"
	EventUserUpdated         = "user.updated"
	EventUserDeleted         = "user.deleted"
	EventUserLogin           = "user.login"
	EventUserLoginFailed     = "user.login.failed"
	EventUserLogout          = "user.logout"
	EventUserPasswordChanged = "user.password.changed"
	EventUserPasswordReset   = "user.password.reset"
	EventUserEmailVerified   = "user.email.verified"
	EventUserMFAEnabled      = "user.mfa.enabled"
	EventUserMFADisabled     = "user.mfa.disabled"
	EventSessionCreated      = "session.created"
	EventSessionRevoked      = "session.revoked"
	EventTenantCreated       = "tenant.created"
	EventTenantUpdated       = "tenant.updated"
	EventRoleAssigned        = "role.assigned"
	EventRoleRemoved         = "role.removed"
	EventAPIKeyCreated       = "api_key.created"
	EventAPIKeyRevoked       = "api_key.revoked"
)

// Service provides webhook management operations.
type Service struct {
	storage    storage.WebhookStorage
	httpClient *http.Client
	logger     *slog.Logger
}

// NewService creates a new webhook service.
func NewService(store storage.WebhookStorage) *Service {
	return &Service{
		storage: store,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: slog.Default().With("component", "webhook_service"),
	}
}

// CreateWebhookRequest represents a request to create a webhook.
type CreateWebhookRequest struct {
	TenantID       *uuid.UUID             `json:"tenant_id,omitempty"`
	Name           string                 `json:"name"`
	Description    *string                `json:"description,omitempty"`
	URL            string                 `json:"url"`
	Events         []string               `json:"events"`
	Headers        map[string]interface{} `json:"headers,omitempty"`
	RetryCount     int                    `json:"retry_count,omitempty"`
	TimeoutSeconds int                    `json:"timeout_seconds,omitempty"`
	CreatedBy      *uuid.UUID             `json:"created_by,omitempty"`
}

// CreateWebhook creates a new webhook.
func (s *Service) CreateWebhook(ctx context.Context, req *CreateWebhookRequest) (*storage.Webhook, error) {
	// Generate webhook secret
	secret, err := generateSecret()
	if err != nil {
		return nil, err
	}

	retryCount := req.RetryCount
	if retryCount <= 0 {
		retryCount = 3
	}

	timeoutSeconds := req.TimeoutSeconds
	if timeoutSeconds <= 0 {
		timeoutSeconds = 30
	}

	now := time.Now()
	webhook := &storage.Webhook{
		ID:             uuid.New(),
		TenantID:       req.TenantID,
		Name:           req.Name,
		Description:    req.Description,
		URL:            req.URL,
		Secret:         secret,
		Events:         req.Events,
		Headers:        req.Headers,
		IsActive:       true,
		RetryCount:     retryCount,
		TimeoutSeconds: timeoutSeconds,
		CreatedBy:      req.CreatedBy,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := s.storage.CreateWebhook(ctx, webhook); err != nil {
		return nil, err
	}

	s.logger.Info("Webhook created", "webhook_id", webhook.ID, "name", webhook.Name)
	return webhook, nil
}

// GetWebhook retrieves a webhook by ID.
func (s *Service) GetWebhook(ctx context.Context, id uuid.UUID) (*storage.Webhook, error) {
	webhook, err := s.storage.GetWebhookByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if webhook == nil {
		return nil, ErrWebhookNotFound
	}
	return webhook, nil
}

// ListWebhooks lists webhooks for a tenant.
func (s *Service) ListWebhooks(ctx context.Context, tenantID *uuid.UUID, limit, offset int) ([]*storage.Webhook, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	return s.storage.ListWebhooks(ctx, tenantID, limit, offset)
}

// UpdateWebhookRequest represents a request to update a webhook.
type UpdateWebhookRequest struct {
	WebhookID      uuid.UUID              `json:"-"`
	Name           *string                `json:"name,omitempty"`
	Description    *string                `json:"description,omitempty"`
	URL            *string                `json:"url,omitempty"`
	Events         []string               `json:"events,omitempty"`
	Headers        map[string]interface{} `json:"headers,omitempty"`
	IsActive       *bool                  `json:"is_active,omitempty"`
	RetryCount     *int                   `json:"retry_count,omitempty"`
	TimeoutSeconds *int                   `json:"timeout_seconds,omitempty"`
}

// UpdateWebhook updates a webhook.
func (s *Service) UpdateWebhook(ctx context.Context, req *UpdateWebhookRequest) (*storage.Webhook, error) {
	webhook, err := s.storage.GetWebhookByID(ctx, req.WebhookID)
	if err != nil {
		return nil, err
	}
	if webhook == nil {
		return nil, ErrWebhookNotFound
	}

	if req.Name != nil {
		webhook.Name = *req.Name
	}
	if req.Description != nil {
		webhook.Description = req.Description
	}
	if req.URL != nil {
		webhook.URL = *req.URL
	}
	if req.Events != nil {
		webhook.Events = req.Events
	}
	if req.Headers != nil {
		webhook.Headers = req.Headers
	}
	if req.IsActive != nil {
		webhook.IsActive = *req.IsActive
	}
	if req.RetryCount != nil {
		webhook.RetryCount = *req.RetryCount
	}
	if req.TimeoutSeconds != nil {
		webhook.TimeoutSeconds = *req.TimeoutSeconds
	}

	webhook.UpdatedAt = time.Now()

	if err := s.storage.UpdateWebhook(ctx, webhook); err != nil {
		return nil, err
	}

	return webhook, nil
}

// DeleteWebhook deletes a webhook.
func (s *Service) DeleteWebhook(ctx context.Context, id uuid.UUID) error {
	webhook, err := s.storage.GetWebhookByID(ctx, id)
	if err != nil {
		return err
	}
	if webhook == nil {
		return ErrWebhookNotFound
	}

	if err := s.storage.DeleteWebhook(ctx, id); err != nil {
		return err
	}

	s.logger.Info("Webhook deleted", "webhook_id", id)
	return nil
}

// Event represents a webhook event to be delivered.
type Event struct {
	ID        uuid.UUID              `json:"id"`
	Type      string                 `json:"type"`
	TenantID  *uuid.UUID             `json:"tenant_id,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
}

// TriggerEvent triggers webhooks for an event.
func (s *Service) TriggerEvent(ctx context.Context, eventType string, tenantID *uuid.UUID, data map[string]interface{}) error {
	// Find all webhooks subscribed to this event
	webhooks, err := s.storage.ListWebhooksByEvent(ctx, tenantID, eventType)
	if err != nil {
		return err
	}

	if len(webhooks) == 0 {
		return nil
	}

	event := &Event{
		ID:        uuid.New(),
		Type:      eventType,
		TenantID:  tenantID,
		Timestamp: time.Now(),
		Data:      data,
	}

	// Dispatch to all matching webhooks
	for _, webhook := range webhooks {
		if !webhook.IsActive {
			continue
		}

		delivery := &storage.WebhookDelivery{
			ID:            uuid.New(),
			WebhookID:     webhook.ID,
			EventID:       event.ID,
			EventType:     event.Type,
			Payload:       s.buildPayload(event),
			AttemptNumber: 1,
			Status:        "pending",
			CreatedAt:     time.Now(),
		}

		if err := s.storage.CreateWebhookDelivery(ctx, delivery); err != nil {
			s.logger.Error("Failed to create webhook delivery", "error", err, "webhook_id", webhook.ID)
			continue
		}

		// Deliver asynchronously
		go s.deliverWebhook(context.Background(), webhook, delivery)
	}

	return nil
}

// deliverWebhook delivers a webhook event.
func (s *Service) deliverWebhook(ctx context.Context, webhook *storage.Webhook, delivery *storage.WebhookDelivery) {
	payload, err := json.Marshal(delivery.Payload)
	if err != nil {
		s.updateDeliveryFailed(ctx, delivery, "failed to marshal payload", nil)
		return
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook.URL, bytes.NewReader(payload))
	if err != nil {
		s.updateDeliveryFailed(ctx, delivery, "failed to create request", nil)
		return
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Webhook-ID", webhook.ID.String())
	req.Header.Set("X-Event-ID", delivery.EventID.String())
	req.Header.Set("X-Event-Type", delivery.EventType)
	req.Header.Set("X-Signature", s.signPayload(payload, webhook.Secret))

	// Add custom headers
	for key, value := range webhook.Headers {
		if strValue, ok := value.(string); ok {
			req.Header.Set(key, strValue)
		}
	}

	// Send request
	start := time.Now()
	client := &http.Client{
		Timeout: time.Duration(webhook.TimeoutSeconds) * time.Second,
	}
	resp, err := client.Do(req)
	duration := int(time.Since(start).Milliseconds())

	if err != nil {
		s.handleDeliveryError(ctx, webhook, delivery, err.Error(), duration)
		return
	}
	defer resp.Body.Close()

	// Check response status
	statusCode := resp.StatusCode
	delivery.ResponseStatusCode = &statusCode
	delivery.ResponseTimeMs = &duration

	if statusCode >= 200 && statusCode < 300 {
		// Success
		delivery.Status = "success"
		now := time.Now()
		delivery.CompletedAt = &now
		if err := s.storage.UpdateWebhookDelivery(ctx, delivery); err != nil {
			s.logger.Error("Failed to update delivery status", "error", err, "delivery_id", delivery.ID)
		}
		s.logger.Info("Webhook delivered", "webhook_id", webhook.ID, "event_id", delivery.EventID, "status", statusCode)
	} else {
		// Failed, maybe retry
		errorMsg := fmt.Sprintf("HTTP %d", statusCode)
		s.handleDeliveryError(ctx, webhook, delivery, errorMsg, duration)
	}
}

// handleDeliveryError handles a failed delivery and schedules retry if needed.
func (s *Service) handleDeliveryError(ctx context.Context, webhook *storage.Webhook, delivery *storage.WebhookDelivery, errorMsg string, durationMs int) {
	delivery.ResponseTimeMs = &durationMs
	delivery.ErrorMessage = &errorMsg

	if delivery.AttemptNumber < webhook.RetryCount {
		// Schedule retry with exponential backoff
		backoff := time.Duration(1<<uint(delivery.AttemptNumber)) * time.Minute
		nextRetry := time.Now().Add(backoff)
		delivery.NextRetryAt = &nextRetry
		delivery.Status = "retrying"
		delivery.AttemptNumber++
	} else {
		delivery.Status = "failed"
		now := time.Now()
		delivery.CompletedAt = &now
	}

	if err := s.storage.UpdateWebhookDelivery(ctx, delivery); err != nil {
		s.logger.Error("Failed to update delivery status", "error", err, "delivery_id", delivery.ID)
	}

	s.logger.Warn("Webhook delivery failed", "webhook_id", webhook.ID, "event_id", delivery.EventID, "error", errorMsg, "status", delivery.Status)
}

// updateDeliveryFailed marks a delivery as failed.
func (s *Service) updateDeliveryFailed(ctx context.Context, delivery *storage.WebhookDelivery, errorMsg string, statusCode *int) {
	delivery.Status = "failed"
	delivery.ErrorMessage = &errorMsg
	delivery.ResponseStatusCode = statusCode
	now := time.Now()
	delivery.CompletedAt = &now

	if err := s.storage.UpdateWebhookDelivery(ctx, delivery); err != nil {
		s.logger.Error("Failed to update delivery status", "error", err, "delivery_id", delivery.ID)
	}
}

// buildPayload builds the webhook payload.
func (s *Service) buildPayload(event *Event) map[string]interface{} {
	return map[string]interface{}{
		"id":        event.ID.String(),
		"type":      event.Type,
		"timestamp": event.Timestamp.Format(time.RFC3339),
		"data":      event.Data,
	}
}

// signPayload signs the payload with HMAC-SHA256.
func (s *Service) signPayload(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// generateSecret generates a random webhook secret.
func generateSecret() (string, error) {
	bytes := make([]byte, 32)
	if _, err := uuid.New().MarshalBinary(); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes[:16]) + uuid.New().String(), nil
}

// ProcessRetries processes pending webhook retries.
func (s *Service) ProcessRetries(ctx context.Context) error {
	deliveries, err := s.storage.GetPendingDeliveries(ctx, 100)
	if err != nil {
		return err
	}

	for _, delivery := range deliveries {
		if delivery.NextRetryAt != nil && time.Now().Before(*delivery.NextRetryAt) {
			continue
		}

		webhook, err := s.storage.GetWebhookByID(ctx, delivery.WebhookID)
		if err != nil || webhook == nil {
			s.updateDeliveryFailed(ctx, delivery, "webhook not found", nil)
			continue
		}

		go s.deliverWebhook(ctx, webhook, delivery)
	}

	return nil
}

// GetDeliveries retrieves delivery history for a webhook.
func (s *Service) GetDeliveries(ctx context.Context, webhookID uuid.UUID, limit, offset int) ([]*storage.WebhookDelivery, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	return s.storage.GetWebhookDeliveries(ctx, webhookID, limit, offset)
}

// TestWebhookResult represents the result of a webhook test.
type TestWebhookResult struct {
	Success        bool
	StatusCode     int
	ResponseTimeMs int
	Error          string
}

// TestWebhook sends a test event to a webhook and returns the result.
func (s *Service) TestWebhook(ctx context.Context, webhook *storage.Webhook) (*TestWebhookResult, error) {
	// Build test payload
	testEvent := &Event{
		ID:        uuid.New(),
		Type:      "webhook.test",
		TenantID:  webhook.TenantID,
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"message":    "This is a test event from ModernAuth",
			"webhook_id": webhook.ID.String(),
			"test":       true,
		},
	}

	payload, err := json.Marshal(s.buildPayload(testEvent))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook.URL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Webhook-ID", webhook.ID.String())
	req.Header.Set("X-Event-ID", testEvent.ID.String())
	req.Header.Set("X-Event-Type", "webhook.test")
	req.Header.Set("X-Signature", s.signPayload(payload, webhook.Secret))

	// Add custom headers
	for key, value := range webhook.Headers {
		if strValue, ok := value.(string); ok {
			req.Header.Set(key, strValue)
		}
	}

	// Send request with timeout
	client := &http.Client{
		Timeout: time.Duration(webhook.TimeoutSeconds) * time.Second,
	}
	start := time.Now()
	resp, err := client.Do(req)
	duration := int(time.Since(start).Milliseconds())

	if err != nil {
		return &TestWebhookResult{
			Success:        false,
			ResponseTimeMs: duration,
			Error:          err.Error(),
		}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	s.logger.Info("Webhook test completed", "webhook_id", webhook.ID, "status", resp.StatusCode, "duration_ms", duration)

	return &TestWebhookResult{
		Success:        resp.StatusCode >= 200 && resp.StatusCode < 300,
		StatusCode:     resp.StatusCode,
		ResponseTimeMs: duration,
	}, nil
}
