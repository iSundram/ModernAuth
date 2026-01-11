// Package http provides error handling utilities for ModernAuth API.
package http

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// ErrorResponse represents an error response.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

// writeError writes an error response (standalone version for use outside Handler).
func writeError(w http.ResponseWriter, status int, message string, err error) {
	writeJSON(w, status, ErrorResponse{
		Error:   http.StatusText(status),
		Message: message,
	})
}

// writeError writes an error response and logs it.
func (h *Handler) writeError(w http.ResponseWriter, status int, message string, err error) {
	attrs := []any{
		"status", status,
		"message", message,
	}
	if err != nil {
		attrs = append(attrs, "error", err)
	}
	
	if status >= 500 {
		h.logger.Error("Server error", attrs...)
	} else {
		h.logger.Warn("Client error", attrs...)
	}

	writeJSON(w, status, ErrorResponse{
		Error:   http.StatusText(status),
		Message: message,
	})
}

// parsePagination extracts limit and offset from query parameters.
func parsePagination(r *http.Request) (limit, offset int) {
	limit = 50  // default
	offset = 0

	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
			if limit > 100 {
				limit = 100
			}
		}
	}

	if o := r.URL.Query().Get("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	return limit, offset
}
