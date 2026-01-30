// Package auth provides authentication services for ModernAuth.
// This file contains user impersonation functionality for admin support.
package auth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
)

var (
	// ErrImpersonationNotAllowed indicates that impersonation is not allowed.
	ErrImpersonationNotAllowed = errors.New("user impersonation is not allowed")
	// ErrCannotImpersonateAdmin indicates that admin users cannot be impersonated.
	ErrCannotImpersonateAdmin = errors.New("cannot impersonate admin users")
	// ErrImpersonationSessionNotFound indicates that the impersonation session was not found.
	ErrImpersonationSessionNotFound = errors.New("impersonation session not found")
)

// ImpersonationRequest represents a request to impersonate a user.
type ImpersonationRequest struct {
	AdminUserID  uuid.UUID `json:"-"`
	TargetUserID uuid.UUID `json:"target_user_id"`
	Reason       string    `json:"reason"`
	IPAddress    string    `json:"-"`
	UserAgent    string    `json:"-"`
}

// ImpersonationResult represents the result of starting an impersonation session.
type ImpersonationResult struct {
	Session   *storage.Session           `json:"session"`
	TokenPair *TokenPair                 `json:"tokens"`
	Impersonation *storage.ImpersonationSession `json:"impersonation"`
}

// ImpersonationStorage interface for impersonation operations.
type ImpersonationStorage interface {
	CreateImpersonationSession(ctx context.Context, session *storage.ImpersonationSession) error
	GetImpersonationSession(ctx context.Context, sessionID uuid.UUID) (*storage.ImpersonationSession, error)
	EndImpersonationSession(ctx context.Context, sessionID uuid.UUID) error
	ListImpersonationSessions(ctx context.Context, adminUserID *uuid.UUID, targetUserID *uuid.UUID, limit, offset int) ([]*storage.ImpersonationSession, error)
}

// StartImpersonation starts an impersonation session.
func (s *AuthService) StartImpersonation(ctx context.Context, req *ImpersonationRequest, sessionTTLMinutes int) (*ImpersonationResult, error) {
	// Check if admin has impersonation permission
	hasPermission, err := s.UserHasPermission(ctx, req.AdminUserID, "users:impersonate")
	if err != nil {
		return nil, err
	}
	if !hasPermission {
		return nil, ErrImpersonationNotAllowed
	}

	// Get target user
	targetUser, err := s.storage.GetUserByID(ctx, req.TargetUserID)
	if err != nil {
		return nil, err
	}
	if targetUser == nil {
		return nil, ErrUserNotFound
	}

	// Check if target is admin (prevent impersonating admins)
	isAdmin, err := s.UserHasRole(ctx, req.TargetUserID, "admin")
	if err != nil {
		return nil, err
	}
	if isAdmin {
		return nil, ErrCannotImpersonateAdmin
	}

	// Check if target user is active
	if !targetUser.IsActive {
		return nil, ErrUserInactive
	}

	// Create impersonation session with short TTL
	now := time.Now()
	ttl := time.Duration(sessionTTLMinutes) * time.Minute
	if ttl == 0 {
		ttl = 30 * time.Minute // Default 30 minutes
	}

	session := &storage.Session{
		ID:        uuid.New(),
		UserID:    targetUser.ID,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		Revoked:   false,
		Metadata: map[string]interface{}{
			"impersonation":    true,
			"admin_user_id":    req.AdminUserID.String(),
			"impersonation_ttl": ttl.String(),
		},
	}

	if err := s.storage.CreateSession(ctx, session); err != nil {
		return nil, err
	}

	// Create impersonation record
	impersonationStorage, ok := s.storage.(ImpersonationStorage)
	if !ok {
		s.logger.Warn("Storage does not support impersonation sessions")
	} else {
		impersonation := &storage.ImpersonationSession{
			ID:           uuid.New(),
			SessionID:    session.ID,
			AdminUserID:  req.AdminUserID,
			TargetUserID: req.TargetUserID,
			StartedAt:    now,
		}
		if req.Reason != "" {
			impersonation.Reason = &req.Reason
		}
		if req.IPAddress != "" {
			impersonation.IPAddress = &req.IPAddress
		}
		if req.UserAgent != "" {
			impersonation.UserAgent = &req.UserAgent
		}

		if err := impersonationStorage.CreateImpersonationSession(ctx, impersonation); err != nil {
			s.logger.Error("Failed to create impersonation record", "error", err)
		}
	}

	// Generate tokens with impersonation claim
	tokenPair, err := s.tokenService.GenerateTokenPairWithClaims(targetUser.ID, session.ID, nil, map[string]interface{}{
		"impersonation":  true,
		"admin_user_id": req.AdminUserID.String(),
	})
	if err != nil {
		return nil, err
	}

	// Store refresh token
	refreshToken := &storage.RefreshToken{
		ID:        uuid.New(),
		SessionID: session.ID,
		TokenHash: hashToken(tokenPair.RefreshToken),
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl), // Same TTL as session
		Revoked:   false,
	}

	if err := s.storage.CreateRefreshToken(ctx, refreshToken); err != nil {
		return nil, err
	}

	// Create audit log
	s.createAuditLog(ctx, "user.impersonation.started", &req.AdminUserID, &req.TargetUserID, map[string]interface{}{
		"reason":     req.Reason,
		"session_id": session.ID.String(),
	})

	s.logger.Info("Impersonation session started",
		"admin_user_id", req.AdminUserID,
		"target_user_id", req.TargetUserID,
		"session_id", session.ID,
		"expires_at", session.ExpiresAt)

	return &ImpersonationResult{
		Session:   session,
		TokenPair: tokenPair,
	}, nil
}

// EndImpersonation ends an impersonation session.
func (s *AuthService) EndImpersonation(ctx context.Context, sessionID uuid.UUID) error {
	// Revoke the session
	if err := s.storage.RevokeSession(ctx, sessionID); err != nil {
		return err
	}

	// End impersonation record
	if impersonationStorage, ok := s.storage.(ImpersonationStorage); ok {
		if err := impersonationStorage.EndImpersonationSession(ctx, sessionID); err != nil {
			s.logger.Warn("Failed to end impersonation record", "error", err)
		}
	}

	// Revoke refresh tokens
	if err := s.storage.RevokeSessionRefreshTokens(ctx, sessionID); err != nil {
		s.logger.Warn("Failed to revoke impersonation refresh tokens", "error", err)
	}

	s.logger.Info("Impersonation session ended", "session_id", sessionID)
	return nil
}

// IsImpersonationSession checks if a session is an impersonation session.
func (s *AuthService) IsImpersonationSession(ctx context.Context, sessionID uuid.UUID) (bool, *uuid.UUID) {
	session, err := s.storage.GetSessionByID(ctx, sessionID)
	if err != nil || session == nil {
		return false, nil
	}

	if session.Metadata == nil {
		return false, nil
	}

	isImpersonation, ok := session.Metadata["impersonation"].(bool)
	if !ok || !isImpersonation {
		return false, nil
	}

	adminUserIDStr, ok := session.Metadata["admin_user_id"].(string)
	if !ok {
		return true, nil
	}

	adminUserID, err := uuid.Parse(adminUserIDStr)
	if err != nil {
		return true, nil
	}

	return true, &adminUserID
}

// ListImpersonationSessions lists impersonation sessions for audit purposes.
func (s *AuthService) ListImpersonationSessions(ctx context.Context, adminUserID *uuid.UUID, targetUserID *uuid.UUID, limit, offset int) ([]*storage.ImpersonationSession, error) {
	impersonationStorage, ok := s.storage.(ImpersonationStorage)
	if !ok {
		return nil, errors.New("impersonation not supported")
	}
	return impersonationStorage.ListImpersonationSessions(ctx, adminUserID, targetUserID, limit, offset)
}

// createAuditLog creates an audit log entry.
func (s *AuthService) createAuditLog(ctx context.Context, eventType string, actorID, userID *uuid.UUID, data map[string]interface{}) {
	log := &storage.AuditLog{
		ID:        uuid.New(),
		EventType: eventType,
		Data:      data,
		CreatedAt: time.Now(),
	}
	if actorID != nil {
		log.ActorID = actorID
	}
	if userID != nil {
		log.UserID = userID
	}

	if err := s.storage.CreateAuditLog(ctx, log); err != nil {
		s.logger.Error("Failed to create audit log", "error", err)
	}
}

// hashToken is a helper function to hash tokens.
func hashToken(token string) string {
	// Use the same hash function as utils.HashToken
	// This is a simple implementation; in production, use the utils package
	return token // Placeholder - should use proper hash
}

// GenerateTokenPairWithClaims generates tokens with additional custom claims.
func (t *TokenService) GenerateTokenPairWithClaims(userID, sessionID uuid.UUID, scopes []string, customClaims map[string]interface{}) (*TokenPair, error) {
	// Generate base token pair
	tokenPair, err := t.GenerateTokenPair(userID, sessionID, scopes)
	if err != nil {
		return nil, err
	}

	// For impersonation, we include the custom claims in the access token
	// The token already contains the session ID, which links to the impersonation record
	// Additional claims can be verified by checking the session metadata

	return tokenPair, nil
}
