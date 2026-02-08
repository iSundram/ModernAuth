// Package auth provides authentication services for ModernAuth.
package auth

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
)

// DataExportResult contains all user data for GDPR export.
// Rate limiting recommended: 1 request per 24 hours per user.
type DataExportResult struct {
	ExportedAt   time.Time                `json:"exported_at"`
	User         *storage.User            `json:"user"`
	Preferences  *storage.UserPreferences `json:"preferences,omitempty"`
	LoginHistory []*storage.LoginHistory  `json:"login_history,omitempty"`
	Devices      []*storage.UserDevice    `json:"devices,omitempty"`
	AuditLogs    []*storage.AuditLog      `json:"audit_logs,omitempty"`
}

// ExportUserData collects all user data for GDPR compliance data export.
// This includes user profile, preferences, login history, devices, and audit logs.
// Sensitive data like password hashes are excluded from the export.
func (s *AuthService) ExportUserData(ctx context.Context, userID uuid.UUID, ip, userAgent string) (*DataExportResult, error) {
	// Get user profile
	user, err := s.storage.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}

	result := &DataExportResult{
		ExportedAt: time.Now(),
		User:       user,
	}

	// Get user preferences (optional - may not exist)
	prefs, err := s.storage.GetPreferences(ctx, userID)
	if err != nil {
		s.logger.Warn("Failed to get preferences for export", "error", err, "user_id", userID)
	} else {
		result.Preferences = prefs
	}

	// Get login history (limit to last 100 entries)
	loginHistory, err := s.storage.GetLoginHistory(ctx, userID, 100, 0)
	if err != nil {
		s.logger.Warn("Failed to get login history for export", "error", err, "user_id", userID)
	} else {
		result.LoginHistory = loginHistory
	}

	// Get user devices
	devices, err := s.storage.ListUserDevices(ctx, userID)
	if err != nil {
		s.logger.Warn("Failed to get devices for export", "error", err, "user_id", userID)
	} else {
		result.Devices = devices
	}

	// Get audit logs for the user (limit to last 100 entries)
	auditLogs, err := s.storage.GetAuditLogs(ctx, &userID, nil, 100, 0)
	if err != nil {
		s.logger.Warn("Failed to get audit logs for export", "error", err, "user_id", userID)
	} else {
		result.AuditLogs = auditLogs
	}

	// Log the data export audit event
	s.logAuditEvent(ctx, &userID, nil, "user.data_exported", &ip, &userAgent, nil)

	return result, nil
}
