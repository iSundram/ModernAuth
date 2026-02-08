// Package http provides HTTP handlers for ModernAuth API.
package http

import (
	"encoding/json"
	"net/http"

	"github.com/iSundram/ModernAuth/internal/auth"
	"github.com/iSundram/ModernAuth/internal/storage"
)

// UpdatePreferencesHTTPRequest represents the request body for updating user preferences.
type UpdatePreferencesHTTPRequest struct {
	EmailSecurityAlerts      *bool   `json:"email_security_alerts"`
	EmailMarketing           *bool   `json:"email_marketing"`
	EmailProductUpdates      *bool   `json:"email_product_updates"`
	EmailDigestFrequency     *string `json:"email_digest_frequency"`
	PushEnabled              *bool   `json:"push_enabled"`
	AccentColor              *string `json:"accent_color"`
	FontSize                 *string `json:"font_size"`
	HighContrast             *bool   `json:"high_contrast"`
	ReducedMotion            *bool   `json:"reduced_motion"`
	ProfileVisibility        *string `json:"profile_visibility"`
	ShowActivityStatus       *bool   `json:"show_activity_status"`
	ShowEmailPublicly        *bool   `json:"show_email_publicly"`
	KeyboardShortcutsEnabled *bool   `json:"keyboard_shortcuts_enabled"`
}

// PreferencesResponse represents the user preferences API response.
type PreferencesResponse struct {
	ID                       string `json:"id"`
	UserID                   string `json:"user_id"`
	EmailSecurityAlerts      bool   `json:"email_security_alerts"`
	EmailMarketing           bool   `json:"email_marketing"`
	EmailProductUpdates      bool   `json:"email_product_updates"`
	EmailDigestFrequency     string `json:"email_digest_frequency"`
	PushEnabled              bool   `json:"push_enabled"`
	AccentColor              string `json:"accent_color"`
	FontSize                 string `json:"font_size"`
	HighContrast             bool   `json:"high_contrast"`
	ReducedMotion            bool   `json:"reduced_motion"`
	ProfileVisibility        string `json:"profile_visibility"`
	ShowActivityStatus       bool   `json:"show_activity_status"`
	ShowEmailPublicly        bool   `json:"show_email_publicly"`
	KeyboardShortcutsEnabled bool   `json:"keyboard_shortcuts_enabled"`
	CreatedAt                string `json:"created_at"`
	UpdatedAt                string `json:"updated_at"`
}

// buildPreferencesResponse builds a PreferencesResponse from storage.UserPreferences.
func buildPreferencesResponse(prefs *storage.UserPreferences) PreferencesResponse {
	return PreferencesResponse{
		ID:                       prefs.ID.String(),
		UserID:                   prefs.UserID.String(),
		EmailSecurityAlerts:      prefs.EmailSecurityAlerts,
		EmailMarketing:           prefs.EmailMarketing,
		EmailProductUpdates:      prefs.EmailProductUpdates,
		EmailDigestFrequency:     prefs.EmailDigestFrequency,
		PushEnabled:              prefs.PushEnabled,
		AccentColor:              prefs.AccentColor,
		FontSize:                 prefs.FontSize,
		HighContrast:             prefs.HighContrast,
		ReducedMotion:            prefs.ReducedMotion,
		ProfileVisibility:        prefs.ProfileVisibility,
		ShowActivityStatus:       prefs.ShowActivityStatus,
		ShowEmailPublicly:        prefs.ShowEmailPublicly,
		KeyboardShortcutsEnabled: prefs.KeyboardShortcutsEnabled,
		CreatedAt:                prefs.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:                prefs.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
}

// GetPreferencesHandler handles GET /v1/auth/preferences requests.
func (h *Handler) GetPreferencesHandler(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	prefs, err := h.authService.GetPreferences(r.Context(), userID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to get preferences", err)
		return
	}

	writeJSON(w, http.StatusOK, buildPreferencesResponse(prefs))
}

// UpdatePreferencesHandler handles PUT /v1/auth/preferences requests.
func (h *Handler) UpdatePreferencesHandler(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	var req UpdatePreferencesHTTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Log audit event with IP and User-Agent
	ip := r.RemoteAddr
	userAgent := r.UserAgent()

	prefs, err := h.authService.UpdatePreferences(r.Context(), userID, &auth.UpdatePreferencesRequest{
		EmailSecurityAlerts:      req.EmailSecurityAlerts,
		EmailMarketing:           req.EmailMarketing,
		EmailProductUpdates:      req.EmailProductUpdates,
		EmailDigestFrequency:     req.EmailDigestFrequency,
		PushEnabled:              req.PushEnabled,
		AccentColor:              req.AccentColor,
		FontSize:                 req.FontSize,
		HighContrast:             req.HighContrast,
		ReducedMotion:            req.ReducedMotion,
		ProfileVisibility:        req.ProfileVisibility,
		ShowActivityStatus:       req.ShowActivityStatus,
		ShowEmailPublicly:        req.ShowEmailPublicly,
		KeyboardShortcutsEnabled: req.KeyboardShortcutsEnabled,
	})

	if err != nil {
		switch err {
		case auth.ErrInvalidDigestFrequency:
			h.writeError(w, http.StatusBadRequest, "Invalid email_digest_frequency. Must be one of: none, daily, weekly, monthly", err)
		case auth.ErrInvalidFontSize:
			h.writeError(w, http.StatusBadRequest, "Invalid font_size. Must be one of: small, medium, large", err)
		case auth.ErrInvalidProfileVisibility:
			h.writeError(w, http.StatusBadRequest, "Invalid profile_visibility. Must be one of: public, private, contacts", err)
		case auth.ErrInvalidAccentColor:
			h.writeError(w, http.StatusBadRequest, "Invalid accent_color. Must be a valid hex color (#xxxxxx)", err)
		default:
			h.writeError(w, http.StatusInternalServerError, "Failed to update preferences", err)
		}
		return
	}

	// Log additional audit with IP/UserAgent
	_ = h.authService.LogAuditEventPublic(r.Context(), &userID, nil, "user.preferences_updated", &ip, &userAgent, nil)

	writeJSON(w, http.StatusOK, buildPreferencesResponse(prefs))
}
