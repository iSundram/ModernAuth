// Package http provides data export HTTP handlers for GDPR compliance.
package http

import (
	"net/http"

	"github.com/iSundram/ModernAuth/internal/storage"
)

// ExportUserData handles GDPR data export requests.
// Rate limiting recommended: 1 request per 24 hours per user.
func (h *Handler) ExportUserData(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserIDFromContext(r.Context())
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}

	result, err := h.authService.ExportUserData(r.Context(), userID, r.RemoteAddr, r.UserAgent())
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to export user data", err)
		return
	}

	// Build the response
	response := DataExportResponse{
		ExportedAt: result.ExportedAt.Format("2006-01-02T15:04:05Z07:00"),
		User:       h.buildUserResponse(r.Context(), result.User),
	}

	// Add preferences if available
	if result.Preferences != nil {
		response.Preferences = toUserPreferencesResponse(result.Preferences)
	}

	// Add login history
	if len(result.LoginHistory) > 0 {
		response.LoginHistory = make([]LoginHistoryResponse, len(result.LoginHistory))
		for i, h := range result.LoginHistory {
			response.LoginHistory[i] = toLoginHistoryResponse(h)
		}
	}

	// Add devices
	if len(result.Devices) > 0 {
		response.Devices = make([]DeviceExportResponse, len(result.Devices))
		for i, d := range result.Devices {
			response.Devices[i] = toDeviceExportResponse(d)
		}
	}

	// Add audit logs
	if len(result.AuditLogs) > 0 {
		response.AuditLogs = make([]AuditLogResponse, len(result.AuditLogs))
		for i, log := range result.AuditLogs {
			response.AuditLogs[i] = toAuditLogExportResponse(log)
		}
	}

	writeJSON(w, http.StatusOK, response)
}

// toUserPreferencesResponse converts storage preferences to API response.
func toUserPreferencesResponse(prefs *storage.UserPreferences) *UserPreferencesResponse {
	return &UserPreferencesResponse{
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

// toDeviceExportResponse converts storage device to API export response.
func toDeviceExportResponse(d *storage.UserDevice) DeviceExportResponse {
	resp := DeviceExportResponse{
		ID:              d.ID.String(),
		DeviceName:      d.DeviceName,
		DeviceType:      d.DeviceType,
		Browser:         d.Browser,
		OS:              d.OS,
		IPAddress:       d.IPAddress,
		LocationCountry: d.LocationCountry,
		LocationCity:    d.LocationCity,
		IsTrusted:       d.IsTrusted,
		CreatedAt:       d.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
	if d.LastSeenAt != nil {
		ls := d.LastSeenAt.Format("2006-01-02T15:04:05Z07:00")
		resp.LastSeenAt = &ls
	}
	return resp
}

// toAuditLogExportResponse converts storage audit log to API response.
func toAuditLogExportResponse(log *storage.AuditLog) AuditLogResponse {
	resp := AuditLogResponse{
		ID:        log.ID.String(),
		EventType: log.EventType,
		Data:      log.Data,
		CreatedAt: log.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
	if log.UserID != nil {
		uid := log.UserID.String()
		resp.UserID = &uid
	}
	if log.ActorID != nil {
		aid := log.ActorID.String()
		resp.ActorID = &aid
	}
	if log.IP != nil {
		resp.IP = log.IP
	}
	if log.UserAgent != nil {
		resp.UserAgent = log.UserAgent
	}
	return resp
}
