// Package http provides audit log HTTP handlers.
package http

import (
	"net/http"
	"strconv"

	"github.com/google/uuid"
)

// ListAuditLogs handles requests for audit logs.
func (h *Handler) ListAuditLogs(w http.ResponseWriter, r *http.Request) {
	// Parse pagination
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	userIDStr := r.URL.Query().Get("user_id")
	eventTypeStr := r.URL.Query().Get("event_type")

	limit := 50
	offset := 0

	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	if offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	var userID *uuid.UUID
	if userIDStr != "" {
		if id, err := uuid.Parse(userIDStr); err == nil {
			userID = &id
		}
	}

	var eventType *string
	if eventTypeStr != "" {
		eventType = &eventTypeStr
	}

	logs, err := h.authService.GetAuditLogs(r.Context(), userID, eventType, limit, offset)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to fetch audit logs", err)
		return
	}

	response := make([]AuditLogResponse, len(logs))
	for i, log := range logs {
		var userIDPtr, actorIDPtr *string
		if log.UserID != nil {
			s := log.UserID.String()
			userIDPtr = &s
		}
		if log.ActorID != nil {
			s := log.ActorID.String()
			actorIDPtr = &s
		}
		response[i] = AuditLogResponse{
			ID:        log.ID.String(),
			UserID:    userIDPtr,
			ActorID:   actorIDPtr,
			EventType: log.EventType,
			IP:        log.IP,
			UserAgent: log.UserAgent,
			Data:      log.Data,
			CreatedAt: log.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"logs":   response,
		"limit":  limit,
		"offset": offset,
		"count":  len(response),
	})
}
