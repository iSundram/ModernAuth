// Package http provides webhook HTTP handlers for ModernAuth API.
package http

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
	tenantpkg "github.com/iSundram/ModernAuth/internal/tenant"
	"github.com/iSundram/ModernAuth/internal/webhook"
)

// WebhookHandler provides HTTP handlers for webhook management.
type WebhookHandler struct {
	webhookService *webhook.Service
}

// NewWebhookHandler creates a new webhook handler.
func NewWebhookHandler(service *webhook.Service) *WebhookHandler {
	return &WebhookHandler{webhookService: service}
}

// WebhookRoutes returns chi routes for webhook management.
func (h *WebhookHandler) WebhookRoutes() chi.Router {
	r := chi.NewRouter()

	r.Get("/", h.ListWebhooks)
	r.Post("/", h.CreateWebhook)
	r.Get("/{id}", h.GetWebhook)
	r.Put("/{id}", h.UpdateWebhook)
	r.Delete("/{id}", h.DeleteWebhook)
	r.Get("/{id}/deliveries", h.GetDeliveries)
	r.Post("/{id}/test", h.TestWebhook)

	return r
}

// CreateWebhookRequest represents the request to create a webhook.
type CreateWebhookRequest struct {
	Name           string                 `json:"name" validate:"required,min=1,max=100"`
	Description    *string                `json:"description,omitempty"`
	URL            string                 `json:"url" validate:"required,url"`
	Events         []string               `json:"events" validate:"required,min=1"`
	Headers        map[string]interface{} `json:"headers,omitempty"`
	RetryCount     int                    `json:"retry_count,omitempty"`
	TimeoutSeconds int                    `json:"timeout_seconds,omitempty"`
}

// WebhookResponse represents a webhook in API responses.
type WebhookResponse struct {
	ID             string                 `json:"id"`
	Name           string                 `json:"name"`
	Description    *string                `json:"description,omitempty"`
	URL            string                 `json:"url"`
	Events         []string               `json:"events"`
	Headers        map[string]interface{} `json:"headers,omitempty"`
	IsActive       bool                   `json:"is_active"`
	RetryCount     int                    `json:"retry_count"`
	TimeoutSeconds int                    `json:"timeout_seconds"`
	CreatedAt      string                 `json:"created_at"`
	UpdatedAt      string                 `json:"updated_at"`
}

// WebhookDeliveryResponse represents a webhook delivery in API responses.
type WebhookDeliveryResponse struct {
	ID                 string  `json:"id"`
	EventType          string  `json:"event_type"`
	Status             string  `json:"status"`
	ResponseStatusCode *int    `json:"response_status_code,omitempty"`
	ResponseTimeMs     *int    `json:"response_time_ms,omitempty"`
	AttemptNumber      int     `json:"attempt_number"`
	ErrorMessage       *string `json:"error_message,omitempty"`
	CreatedAt          string  `json:"created_at"`
	CompletedAt        *string `json:"completed_at,omitempty"`
}

// CreateWebhook handles webhook creation.
func (h *WebhookHandler) CreateWebhook(w http.ResponseWriter, r *http.Request) {
	var req CreateWebhookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if errors := ValidateStruct(req); errors != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "Validation failed",
			"details": errors,
		})
		return
	}

	// Get user ID from context
	userIDStr, ok := r.Context().Value(userIDKey).(string)
	var createdBy *uuid.UUID
	if ok && userIDStr != "" {
		if uid, err := uuid.Parse(userIDStr); err == nil {
			createdBy = &uid
		}
	}

	// Get tenant ID from context
	tenantID := tenantpkg.GetTenantIDFromContext(r.Context())

	result, err := h.webhookService.CreateWebhook(r.Context(), &webhook.CreateWebhookRequest{
		TenantID:       tenantID,
		Name:           req.Name,
		Description:    req.Description,
		URL:            req.URL,
		Events:         req.Events,
		Headers:        req.Headers,
		RetryCount:     req.RetryCount,
		TimeoutSeconds: req.TimeoutSeconds,
		CreatedBy:      createdBy,
	})

	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create webhook", err)
		return
	}

	writeJSON(w, http.StatusCreated, h.toWebhookResponse(result))
}

// GetWebhook retrieves a webhook by ID.
func (h *WebhookHandler) GetWebhook(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid webhook ID", err)
		return
	}

	wh, err := h.webhookService.GetWebhook(r.Context(), id)
	if err != nil {
		if err == webhook.ErrWebhookNotFound {
			writeError(w, http.StatusNotFound, "Webhook not found", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get webhook", err)
		return
	}

	writeJSON(w, http.StatusOK, h.toWebhookResponse(wh))
}

// ListWebhooks lists webhooks.
func (h *WebhookHandler) ListWebhooks(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantpkg.GetTenantIDFromContext(r.Context())
	limit, offset := parsePagination(r)

	webhooks, err := h.webhookService.ListWebhooks(r.Context(), tenantID, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list webhooks", err)
		return
	}

	response := make([]WebhookResponse, len(webhooks))
	for i, wh := range webhooks {
		response[i] = h.toWebhookResponse(wh)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data":   response,
		"limit":  limit,
		"offset": offset,
	})
}

// UpdateWebhookRequest represents the request to update a webhook.
type UpdateWebhookRequest struct {
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
func (h *WebhookHandler) UpdateWebhook(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid webhook ID", err)
		return
	}

	var req UpdateWebhookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	result, err := h.webhookService.UpdateWebhook(r.Context(), &webhook.UpdateWebhookRequest{
		WebhookID:      id,
		Name:           req.Name,
		Description:    req.Description,
		URL:            req.URL,
		Events:         req.Events,
		Headers:        req.Headers,
		IsActive:       req.IsActive,
		RetryCount:     req.RetryCount,
		TimeoutSeconds: req.TimeoutSeconds,
	})

	if err != nil {
		if err == webhook.ErrWebhookNotFound {
			writeError(w, http.StatusNotFound, "Webhook not found", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to update webhook", err)
		return
	}

	writeJSON(w, http.StatusOK, h.toWebhookResponse(result))
}

// DeleteWebhook deletes a webhook.
func (h *WebhookHandler) DeleteWebhook(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid webhook ID", err)
		return
	}

	if err := h.webhookService.DeleteWebhook(r.Context(), id); err != nil {
		if err == webhook.ErrWebhookNotFound {
			writeError(w, http.StatusNotFound, "Webhook not found", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to delete webhook", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetDeliveries retrieves webhook delivery history.
func (h *WebhookHandler) GetDeliveries(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid webhook ID", err)
		return
	}

	limit, offset := parsePagination(r)

	deliveries, err := h.webhookService.GetDeliveries(r.Context(), id, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get deliveries", err)
		return
	}

	response := make([]WebhookDeliveryResponse, len(deliveries))
	for i, d := range deliveries {
		response[i] = h.toDeliveryResponse(d)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data":   response,
		"limit":  limit,
		"offset": offset,
	})
}

func (h *WebhookHandler) toWebhookResponse(wh *storage.Webhook) WebhookResponse {
	return WebhookResponse{
		ID:             wh.ID.String(),
		Name:           wh.Name,
		Description:    wh.Description,
		URL:            wh.URL,
		Events:         wh.Events,
		Headers:        wh.Headers,
		IsActive:       wh.IsActive,
		RetryCount:     wh.RetryCount,
		TimeoutSeconds: wh.TimeoutSeconds,
		CreatedAt:      wh.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:      wh.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
}

func (h *WebhookHandler) toDeliveryResponse(d *storage.WebhookDelivery) WebhookDeliveryResponse {
	resp := WebhookDeliveryResponse{
		ID:                 d.ID.String(),
		EventType:          d.EventType,
		Status:             d.Status,
		ResponseStatusCode: d.ResponseStatusCode,
		ResponseTimeMs:     d.ResponseTimeMs,
		AttemptNumber:      d.AttemptNumber,
		ErrorMessage:       d.ErrorMessage,
		CreatedAt:          d.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
	if d.CompletedAt != nil {
		ca := d.CompletedAt.Format("2006-01-02T15:04:05Z07:00")
		resp.CompletedAt = &ca
	}
	return resp
}

// TestWebhook sends a test event to a webhook endpoint.
func (h *WebhookHandler) TestWebhook(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid webhook ID", err)
		return
	}

	// Get the webhook
	wh, err := h.webhookService.GetWebhook(r.Context(), id)
	if err != nil {
		if err == webhook.ErrWebhookNotFound {
			writeError(w, http.StatusNotFound, "Webhook not found", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get webhook", err)
		return
	}

	// Send a test event
	result, err := h.webhookService.TestWebhook(r.Context(), wh)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success":      false,
			"error":        err.Error(),
			"webhook_id":   wh.ID.String(),
			"webhook_name": wh.Name,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":       true,
		"status_code":   result.StatusCode,
		"response_time": result.ResponseTimeMs,
		"webhook_id":    wh.ID.String(),
		"webhook_name":  wh.Name,
	})
}
