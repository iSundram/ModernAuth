// Package auth provides authentication services for ModernAuth.
package auth

import (
	"context"

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
	if err := s.storage.RevokeUserSessions(ctx, req.UserID); err != nil {
		return err
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
	if err := s.storage.RevokeSessionRefreshTokens(ctx, sessionID); err != nil {
		return err
	}
	return s.storage.RevokeSession(ctx, sessionID)
}
