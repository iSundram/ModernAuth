// Package auth provides authentication services for ModernAuth.
package auth

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
)

// RevokeAllSessionsRequest represents a request to revoke all user sessions.
type RevokeAllSessionsRequest struct {
	UserID    uuid.UUID `json:"user_id"`
	IP        string    `json:"-"`
	UserAgent string    `json:"-"`
}

// RevokeAllSessions revokes all sessions for a user.
func (s *AuthService) RevokeAllSessions(ctx context.Context, req *RevokeAllSessionsRequest) error {
	// Get all active sessions before revoking them so we can blacklist them
	sessions, err := s.storage.GetUserSessions(ctx, req.UserID, 1000, 0)
	if err != nil {
		s.logger.Error("Failed to get sessions for blacklisting", "error", err)
		// Continue with revocation even if we can't get sessions
	}

	if err := s.storage.RevokeUserSessions(ctx, req.UserID); err != nil {
		return err
	}

	// Blacklist all sessions in Redis to ensure immediate invalidation
	if s.tokenBlacklist != nil && sessions != nil {
		for _, session := range sessions {
			ttl := time.Until(session.ExpiresAt)
			if ttl > 0 {
				if err := s.tokenBlacklist.BlacklistSession(ctx, session.ID.String(), ttl); err != nil {
					s.logger.Error("Failed to blacklist session", "error", err, "session_id", session.ID)
				}
			}
		}
	}

	s.logAuditEvent(ctx, &req.UserID, nil, "sessions.revoke_all", &req.IP, &req.UserAgent, nil)

	return nil
}

// GetUserSessions retrieves active sessions for a user.
func (s *AuthService) GetUserSessions(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*storage.Session, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	return s.storage.GetUserSessions(ctx, userID, limit, offset)
}

// RevokeSession revokes a single session if it belongs to the user.
func (s *AuthService) RevokeSession(ctx context.Context, userID, sessionID uuid.UUID) error {
	session, err := s.storage.GetSessionByID(ctx, sessionID)
	if err != nil {
		return err
	}
	if session == nil || session.UserID != userID {
		return ErrSessionRevoked
	}

	// Revoke refresh tokens and session in database
	if err := s.storage.RevokeSessionRefreshTokens(ctx, sessionID); err != nil {
		return err
	}
	if err := s.storage.RevokeSession(ctx, sessionID); err != nil {
		return err
	}

	// Blacklist session in Redis for immediate invalidation
	if s.tokenBlacklist != nil {
		ttl := time.Until(session.ExpiresAt)
		if ttl > 0 {
			if err := s.tokenBlacklist.BlacklistSession(ctx, sessionID.String(), ttl); err != nil {
				s.logger.Error("Failed to blacklist session", "error", err, "session_id", sessionID)
			}
		}
	}

	return nil
}
