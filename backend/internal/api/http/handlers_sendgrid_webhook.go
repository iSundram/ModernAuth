// Package http provides SendGrid webhook handlers.
package http

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/iSundram/ModernAuth/internal/storage"
)

// SendGridWebhookHandler handles SendGrid webhook events.
type SendGridWebhookHandler struct {
	storage          storage.EmailTemplateStorage
	webhookSecretKey string
	logger           *slog.Logger
}

// NewSendGridWebhookHandler creates a new SendGrid webhook handler.
func NewSendGridWebhookHandler(store storage.EmailTemplateStorage, webhookSecretKey string) *SendGridWebhookHandler {
	return &SendGridWebhookHandler{
		storage:          store,
		webhookSecretKey: webhookSecretKey,
		logger:           slog.Default().With("component", "sendgrid_webhook"),
	}
}

// SendGridEvent represents a SendGrid webhook event.
type SendGridEvent struct {
	Email       string `json:"email"`
	Timestamp   int64  `json:"timestamp"`
	Event       string `json:"event"` // processed, dropped, delivered, deferred, bounce, open, click, spamreport, unsubscribe
	SGMessageID string `json:"sg_message_id"`
	SGEventID   string `json:"sg_event_id"`
	Reason      string `json:"reason,omitempty"`
	Status      string `json:"status,omitempty"`
	Type        string `json:"type,omitempty"`   // For bounce: bounce, blocked
	BounceClass string `json:"bounce_classification,omitempty"`
	URL         string `json:"url,omitempty"`    // For click events
	Category    []string `json:"category,omitempty"`
	ASMGroupID  int    `json:"asm_group_id,omitempty"`
}

// WebhookRoutes returns the webhook routes.
func (h *SendGridWebhookHandler) WebhookRoutes() chi.Router {
	r := chi.NewRouter()
	r.Post("/sendgrid", h.HandleSendGridWebhook)
	return r
}

// HandleSendGridWebhook processes SendGrid webhook events.
func (h *SendGridWebhookHandler) HandleSendGridWebhook(w http.ResponseWriter, r *http.Request) {
	// Read body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.logger.Error("Failed to read webhook body", "error", err)
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	// Verify signature if secret is configured
	if h.webhookSecretKey != "" {
		signature := r.Header.Get("X-Twilio-Email-Event-Webhook-Signature")
		timestamp := r.Header.Get("X-Twilio-Email-Event-Webhook-Timestamp")
		
		if !h.verifySignature(timestamp, string(body), signature) {
			h.logger.Warn("Invalid webhook signature")
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			return
		}
	}

	// Parse events
	var events []SendGridEvent
	if err := json.Unmarshal(body, &events); err != nil {
		h.logger.Error("Failed to parse webhook events", "error", err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Process each event
	for _, event := range events {
		h.processEvent(r.Context(), event)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// processEvent handles a single SendGrid event.
func (h *SendGridWebhookHandler) processEvent(ctx context.Context, event SendGridEvent) {
	h.logger.Info("Processing SendGrid event",
		"event", event.Event,
		"email", event.Email,
		"sg_event_id", event.SGEventID,
	)

	switch event.Event {
	case "bounce", "blocked":
		h.handleBounce(ctx, event)
	case "dropped":
		h.handleDropped(ctx, event)
	case "spamreport":
		h.handleSpamReport(ctx, event)
	case "unsubscribe":
		h.handleUnsubscribe(ctx, event)
	case "delivered":
		h.recordEvent(ctx, event, "delivered")
	case "open":
		h.recordEvent(ctx, event, "opened")
	case "click":
		h.recordEvent(ctx, event, "clicked")
	case "processed":
		h.recordEvent(ctx, event, "sent")
	}
}

// handleBounce processes bounce events.
func (h *SendGridWebhookHandler) handleBounce(ctx context.Context, event SendGridEvent) {
	bounceType := "soft"
	if event.Type == "bounce" || strings.Contains(strings.ToLower(event.Reason), "does not exist") {
		bounceType = "hard"
	}

	// Create bounce record
	eventID := event.SGEventID
	errorMsg := event.Reason
	bounce := &storage.EmailBounce{
		Email:        event.Email,
		BounceType:   bounceType,
		EventID:      &eventID,
		ErrorMessage: &errorMsg,
	}

	if err := h.storage.CreateEmailBounce(ctx, bounce); err != nil {
		h.logger.Error("Failed to create bounce record", "error", err, "email", event.Email)
	}

	// Add to suppression list for hard bounces
	if bounceType == "hard" {
		source := "sendgrid_webhook"
		suppression := &storage.EmailSuppression{
			Email:  event.Email,
			Reason: "hard_bounce",
			Source: &source,
		}
		if err := h.storage.CreateEmailSuppression(ctx, suppression); err != nil {
			h.logger.Error("Failed to create suppression", "error", err, "email", event.Email)
		}
	}
}

// handleDropped processes dropped events.
func (h *SendGridWebhookHandler) handleDropped(ctx context.Context, event SendGridEvent) {
	eventID := event.SGEventID
	errorMsg := event.Reason
	bounce := &storage.EmailBounce{
		Email:        event.Email,
		BounceType:   "dropped",
		EventID:      &eventID,
		ErrorMessage: &errorMsg,
	}

	if err := h.storage.CreateEmailBounce(ctx, bounce); err != nil {
		h.logger.Error("Failed to create dropped record", "error", err, "email", event.Email)
	}

	h.recordEvent(ctx, event, "dropped")
}

// handleSpamReport processes spam report events.
func (h *SendGridWebhookHandler) handleSpamReport(ctx context.Context, event SendGridEvent) {
	eventID := event.SGEventID
	bounce := &storage.EmailBounce{
		Email:      event.Email,
		BounceType: "complaint",
		EventID:    &eventID,
	}

	if err := h.storage.CreateEmailBounce(ctx, bounce); err != nil {
		h.logger.Error("Failed to create complaint record", "error", err, "email", event.Email)
	}

	// Add to suppression list
	source := "sendgrid_webhook"
	suppression := &storage.EmailSuppression{
		Email:  event.Email,
		Reason: "complaint",
		Source: &source,
	}
	if err := h.storage.CreateEmailSuppression(ctx, suppression); err != nil {
		h.logger.Error("Failed to create suppression", "error", err, "email", event.Email)
	}
}

// handleUnsubscribe processes unsubscribe events.
func (h *SendGridWebhookHandler) handleUnsubscribe(ctx context.Context, event SendGridEvent) {
	source := "sendgrid_webhook"
	suppression := &storage.EmailSuppression{
		Email:  event.Email,
		Reason: "unsubscribe",
		Source: &source,
	}
	if err := h.storage.CreateEmailSuppression(ctx, suppression); err != nil {
		h.logger.Error("Failed to create unsubscribe suppression", "error", err, "email", event.Email)
	}
}

// recordEvent records an email event for analytics.
func (h *SendGridWebhookHandler) recordEvent(ctx context.Context, sgEvent SendGridEvent, eventType string) {
	eventID := sgEvent.SGEventID
	event := &storage.EmailEvent{
		EventType: eventType,
		Recipient: sgEvent.Email,
		EventID:   &eventID,
	}

	if err := h.storage.CreateEmailEvent(ctx, event); err != nil {
		h.logger.Error("Failed to record email event", "error", err, "type", eventType, "email", sgEvent.Email)
	}
}

// verifySignature verifies the SendGrid webhook signature.
func (h *SendGridWebhookHandler) verifySignature(timestamp, payload, signature string) bool {
	if h.webhookSecretKey == "" {
		return true // No verification if no secret configured
	}

	// SendGrid uses ECDSA signature, simplified HMAC verification here
	// For production, use proper ECDSA verification
	mac := hmac.New(sha256.New, []byte(h.webhookSecretKey))
	mac.Write([]byte(timestamp + payload))
	expectedSig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(signature), []byte(expectedSig))
}
