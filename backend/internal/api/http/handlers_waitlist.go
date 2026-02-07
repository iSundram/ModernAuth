// Package http provides waitlist management handlers.
package http

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	waitlistEntriesKey = "waitlist:entries"
	waitlistEmailKey   = "waitlist:email:%s"
)

// JoinWaitlist handles requests to join the waitlist.
func (h *Handler) JoinWaitlist(w http.ResponseWriter, r *http.Request) {
	var req JoinWaitlistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate request
	if validationErrors := ValidateStruct(req); validationErrors != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "Validation failed",
			"details": validationErrors,
		})
		return
	}

	// Check if waitlist is enabled
	setting, err := h.authService.GetSetting(r.Context(), "auth.waitlist_enabled")
	if err != nil || setting == nil || setting.Value != "true" {
		h.writeError(w, http.StatusBadRequest, "Waitlist is not enabled", nil)
		return
	}

	// Check if the email is already on the waitlist
	existingKey := fmt.Sprintf(waitlistEmailKey, req.Email)
	exists, err := h.rdb.Exists(r.Context(), existingKey).Result()
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to check waitlist status", err)
		return
	}
	if exists > 0 {
		// Already on the waitlist, return current position
		rank, err := h.rdb.ZRank(r.Context(), waitlistEntriesKey, req.Email).Result()
		if err != nil {
			h.writeError(w, http.StatusInternalServerError, "Failed to get waitlist position", err)
			return
		}
		total, _ := h.rdb.ZCard(r.Context(), waitlistEntriesKey).Result()

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"message":  "You are already on the waitlist",
			"position": rank + 1,
			"total":    total,
		})
		return
	}

	// Add to the waitlist sorted set (score = timestamp for FIFO ordering)
	now := time.Now()
	score := float64(now.UnixNano())

	if err := h.rdb.ZAdd(r.Context(), waitlistEntriesKey, redis.Z{
		Score:  score,
		Member: req.Email,
	}).Err(); err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to join waitlist", err)
		return
	}

	// Store email metadata (name, joined_at)
	metadata := map[string]interface{}{
		"email":     req.Email,
		"name":      req.Name,
		"joined_at": now.Format(time.RFC3339),
	}
	metadataJSON, _ := json.Marshal(metadata)
	h.rdb.Set(r.Context(), existingKey, metadataJSON, 0)

	// Get position
	rank, err := h.rdb.ZRank(r.Context(), waitlistEntriesKey, req.Email).Result()
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to get waitlist position", err)
		return
	}
	total, _ := h.rdb.ZCard(r.Context(), waitlistEntriesKey).Result()

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"message":  "Successfully joined the waitlist",
		"position": rank + 1,
		"total":    total,
	})
}

// GetWaitlistStatus handles requests to check waitlist position.
func (h *Handler) GetWaitlistStatus(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" {
		h.writeError(w, http.StatusBadRequest, "Email query parameter is required", nil)
		return
	}

	// Check if the email is on the waitlist
	rank, err := h.rdb.ZRank(r.Context(), waitlistEntriesKey, email).Result()
	if err == redis.Nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"on_waitlist": false,
			"message":     "Email is not on the waitlist",
		})
		return
	}
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to check waitlist status", err)
		return
	}

	total, _ := h.rdb.ZCard(r.Context(), waitlistEntriesKey).Result()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"on_waitlist": true,
		"position":    rank + 1,
		"total":       total,
		"status":      "waiting",
	})
}
