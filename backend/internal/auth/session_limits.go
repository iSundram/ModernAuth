// Package auth provides authentication services for ModernAuth.
// This file contains session concurrent limits functionality.
package auth

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
)

var (
	// ErrSessionLimitExceeded indicates the user has too many active sessions.
	ErrSessionLimitExceeded = errors.New("maximum concurrent sessions exceeded")
)

// SessionLimitAction defines what action to take when session limit is exceeded.
type SessionLimitAction string

const (
	// SessionLimitActionRejectNew rejects new session creation.
	SessionLimitActionRejectNew SessionLimitAction = "reject_new"
	// SessionLimitActionRevokeOldest revokes the oldest session to make room.
	SessionLimitActionRevokeOldest SessionLimitAction = "revoke_oldest"
)

// SessionLimitStorage interface for session limit operations.
type SessionLimitStorage interface {
	CountActiveUserSessions(ctx context.Context, userID uuid.UUID) (int, error)
	GetOldestActiveSession(ctx context.Context, userID uuid.UUID) (*storage.Session, error)
}

// CheckSessionLimit checks if the user can create a new session based on limits.
// Returns the session to revoke if action is revoke_oldest, or error if action is reject_new.
func (s *AuthService) CheckSessionLimit(ctx context.Context, userID uuid.UUID, maxSessions int, action SessionLimitAction) (*uuid.UUID, error) {
	if maxSessions <= 0 {
		return nil, nil // Session limits disabled
	}

	limitStorage, ok := s.storage.(SessionLimitStorage)
	if !ok {
		s.logger.Warn("Storage does not support session limits")
		return nil, nil
	}

	// Count active sessions
	count, err := limitStorage.CountActiveUserSessions(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to count active sessions", "error", err)
		return nil, nil // Fail open - don't block login on count failure
	}

	// Check if under limit
	if count < maxSessions {
		return nil, nil
	}

	// Limit exceeded
	switch action {
	case SessionLimitActionRejectNew:
		s.logger.Warn("Session limit exceeded, rejecting new session", "user_id", userID, "count", count, "max", maxSessions)
		return nil, ErrSessionLimitExceeded

	case SessionLimitActionRevokeOldest:
		// Get oldest session to revoke
		oldestSession, err := limitStorage.GetOldestActiveSession(ctx, userID)
		if err != nil {
			s.logger.Error("Failed to get oldest session", "error", err)
			return nil, nil // Fail open
		}
		if oldestSession == nil {
			return nil, nil
		}

		s.logger.Info("Session limit exceeded, will revoke oldest session", 
			"user_id", userID, "session_to_revoke", oldestSession.ID, "count", count, "max", maxSessions)
		return &oldestSession.ID, nil

	default:
		return nil, nil
	}
}

// EnforceSessionLimit enforces session limits by revoking the oldest session if needed.
func (s *AuthService) EnforceSessionLimit(ctx context.Context, userID uuid.UUID, maxSessions int, action SessionLimitAction) error {
	sessionToRevoke, err := s.CheckSessionLimit(ctx, userID, maxSessions, action)
	if err != nil {
		return err
	}

	if sessionToRevoke != nil {
		if err := s.storage.RevokeSession(ctx, *sessionToRevoke); err != nil {
			s.logger.Error("Failed to revoke oldest session", "error", err, "session_id", sessionToRevoke)
			// Continue anyway - don't block new login
		} else {
			s.logger.Info("Revoked oldest session to enforce limit", "session_id", sessionToRevoke)
		}
	}

	return nil
}
