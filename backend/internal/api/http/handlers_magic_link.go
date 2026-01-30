// Package http provides HTTP handlers for ModernAuth API.
// This file contains magic link (passwordless) authentication handlers.
package http

import (
	"encoding/json"
	"net/http"

	"github.com/iSundram/ModernAuth/internal/auth"
)

// SendMagicLinkRequest represents a request to send a magic link.
type SendMagicLinkRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// SendMagicLinkResponse represents the response for magic link request.
type SendMagicLinkResponse struct {
	Message string `json:"message"`
}

// VerifyMagicLinkRequest represents a request to verify a magic link.
type VerifyMagicLinkRequest struct {
	Token             string `json:"token" validate:"required"`
	AllowRegistration bool   `json:"allow_registration"`
}

// SendMagicLink handles POST /v1/auth/magic-link/send
func (h *Handler) SendMagicLink(w http.ResponseWriter, r *http.Request) {
	var req SendMagicLinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if errs := ValidateStruct(req); len(errs) > 0 {
		h.writeError(w, http.StatusBadRequest, errs[0].Message, nil)
		return
	}

	// Get settings
	expiryMinutes := 15
	rateLimit := 3

	if setting, err := h.storage.GetSetting(r.Context(), "magic_link_expiry_minutes"); err == nil && setting != nil {
		if v, ok := setting.Value.(string); ok {
			if parsed, err := parseInt(v); err == nil {
				expiryMinutes = parsed
			}
		}
	}

	if setting, err := h.storage.GetSetting(r.Context(), "magic_link_rate_limit"); err == nil && setting != nil {
		if v, ok := setting.Value.(string); ok {
			if parsed, err := parseInt(v); err == nil {
				rateLimit = parsed
			}
		}
	}

	// Create magic link request
	magicLinkReq := &auth.MagicLinkRequest{
		Email:     req.Email,
		IPAddress: r.RemoteAddr,
		UserAgent: r.Header.Get("User-Agent"),
	}

	token, err := h.authService.SendMagicLink(r.Context(), magicLinkReq, expiryMinutes, rateLimit)
	if err != nil {
		if err == auth.ErrMagicLinkRateLimited {
			h.writeError(w, http.StatusTooManyRequests, "Too many magic link requests. Please try again later.", err)
			return
		}
		// Don't reveal if user exists or not
		h.logger.Info("Magic link request", "email", req.Email, "error", err)
	}

	// Send email if we got a token and email service is available
	if token != "" && h.emailService != nil {
		// Get base URL for the magic link
		baseURL := "http://localhost:3000" // Default
		if setting, err := h.storage.GetSetting(r.Context(), "app_base_url"); err == nil && setting != nil {
			if v, ok := setting.Value.(string); ok && v != "" {
				baseURL = v
			}
		}

		magicLinkURL := baseURL + "/auth/magic-link?token=" + token

		// Send magic link email
		go func() {
			if err := h.emailService.SendMagicLink(req.Email, magicLinkURL); err != nil {
				h.logger.Error("Failed to send magic link email", "error", err, "email", req.Email)
			}
		}()
	}

	// Always return success to prevent email enumeration
	writeJSON(w, http.StatusOK, SendMagicLinkResponse{
		Message: "If an account exists with this email, a magic link has been sent.",
	})
}

// VerifyMagicLink handles POST /v1/auth/magic-link/verify
func (h *Handler) VerifyMagicLink(w http.ResponseWriter, r *http.Request) {
	var req VerifyMagicLinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if errs := ValidateStruct(req); len(errs) > 0 {
		h.writeError(w, http.StatusBadRequest, errs[0].Message, nil)
		return
	}

	result, err := h.authService.VerifyMagicLink(r.Context(), req.Token, req.AllowRegistration)
	if err != nil {
		switch err {
		case auth.ErrMagicLinkNotFound:
			h.writeError(w, http.StatusNotFound, "Invalid or expired magic link", err)
		case auth.ErrMagicLinkExpired:
			h.writeError(w, http.StatusGone, "Magic link has expired", err)
		case auth.ErrMagicLinkUsed:
			h.writeError(w, http.StatusConflict, "Magic link has already been used", err)
		case auth.ErrUserNotFound:
			h.writeError(w, http.StatusNotFound, "User not found and registration not allowed", err)
		case auth.ErrUserInactive:
			h.writeError(w, http.StatusForbidden, "User account is deactivated", err)
		default:
			h.writeError(w, http.StatusInternalServerError, "Failed to verify magic link", err)
		}
		return
	}

	// Prepare response
	response := map[string]interface{}{
		"user":        sanitizeUser(result.User),
		"tokens":      result.TokenPair,
		"is_new_user": result.IsNewUser,
	}

	writeJSON(w, http.StatusOK, response)
}

// parseInt is a helper to parse string to int.
func parseInt(s string) (int, error) {
	var i int
	err := json.Unmarshal([]byte(s), &i)
	if err != nil {
		// Try parsing directly
		i = 0
		for _, c := range s {
			if c < '0' || c > '9' {
				return 0, err
			}
			i = i*10 + int(c-'0')
		}
	}
	return i, nil
}

// sanitizeUser removes sensitive fields from user for response.
func sanitizeUser(user interface{}) interface{} {
	// The storage.User struct already has json:"-" on HashedPassword
	return user
}
