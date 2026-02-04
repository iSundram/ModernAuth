// Package auth provides authentication services for ModernAuth.
package auth

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
)

var (
	// ErrUserNotFound indicates that the user was not found.
	ErrUserNotFound = errors.New("user not found")
	// ErrUserExists indicates that a user with the given email already exists.
	ErrUserExists = errors.New("user already exists")
	// ErrUserInactive indicates that the user account is deactivated.
	ErrUserInactive = errors.New("user account is deactivated")
	// ErrInvalidCredentials indicates that the provided credentials are invalid.
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrSessionNotFound indicates that the session was not found.
	ErrSessionNotFound = errors.New("session not found")
	// ErrSessionRevoked indicates that the session has been revoked.
	ErrSessionRevoked = errors.New("session has been revoked")
	// ErrSessionExpired indicates that the session has expired.
	ErrSessionExpired = errors.New("session has expired")
	// ErrRefreshTokenNotFound indicates that the refresh token was not found.
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
	// ErrRefreshTokenRevoked indicates that the refresh token has been revoked.
	ErrRefreshTokenRevoked = errors.New("refresh token has been revoked")
	// ErrRefreshTokenExpired indicates that the refresh token has expired.
	ErrRefreshTokenExpired = errors.New("refresh token has expired")
	// ErrRefreshTokenReused indicates potential token theft (token reuse detected).
	ErrRefreshTokenReused = errors.New("refresh token reuse detected")
	// ErrMFARequired indicates that MFA is required to complete the action.
	ErrMFARequired = errors.New("mfa required")
	// ErrInvalidMFACode indicates that the provided MFA code is invalid.
	ErrInvalidMFACode = errors.New("invalid mfa code")
	// ErrMFANotSetup indicates that MFA has not been set up for the user.
	ErrMFANotSetup = errors.New("mfa not setup")
	// ErrDeviceNotFound indicates that the device was not found.
	ErrDeviceNotFound = errors.New("device not found")
	// ErrRateLimited indicates that the rate limit has been exceeded.
	ErrRateLimited = errors.New("rate limit exceeded")
	// ErrChallengeExpired indicates that the MFA challenge has expired.
	ErrChallengeExpired = errors.New("challenge expired")
)

// AuthService provides authentication operations.
type AuthService struct {
	storage      storage.Storage
	tokenService *TokenService
	emailService interface{}
	sessionTTL   time.Duration
	logger       *slog.Logger
}

// NewAuthService creates a new authentication service.
func NewAuthService(store storage.Storage, tokenService *TokenService, emailService interface{}, sessionTTL time.Duration) *AuthService {
	if sessionTTL == 0 {
		sessionTTL = 7 * 24 * time.Hour // Default 7 days
	}
	return &AuthService{
		storage:      store,
		tokenService: tokenService,
		emailService: emailService,
		sessionTTL:   sessionTTL,
		logger:       slog.Default().With("component", "auth_service"),
	}
}

// logAuditEvent creates an audit log entry.
func (s *AuthService) logAuditEvent(ctx context.Context, userID, actorID *uuid.UUID, eventType string, ip, userAgent *string, data map[string]interface{}) error {
	log := &storage.AuditLog{
		ID:        uuid.New(),
		UserID:    userID,
		ActorID:   actorID,
		EventType: eventType,
		IP:        ip,
		UserAgent: userAgent,
		Data:      data,
		CreatedAt: time.Now(),
	}
	return s.storage.CreateAuditLog(ctx, log)
}

// GetUserByID retrieves a user by their ID.
func (s *AuthService) GetUserByID(ctx context.Context, id uuid.UUID) (*storage.User, error) {
	return s.storage.GetUserByID(ctx, id)
}

// ListUsersRequest represents a request to list users with pagination.
type ListUsersRequest struct {
	Limit  int
	Offset int
}

// ListUsersResult represents the result of listing users.
type ListUsersResult struct {
	Users   []*storage.User `json:"users"`
	Total   int             `json:"total"`
	Limit   int             `json:"limit"`
	Offset  int             `json:"offset"`
	HasMore bool            `json:"has_more"`
}

// ListUsers retrieves users with pagination.
func (s *AuthService) ListUsers(ctx context.Context, limit, offset int) (*ListUsersResult, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	users, err := s.storage.ListUsers(ctx, limit, offset)
	if err != nil {
		return nil, err
	}

	total, err := s.storage.CountUsers(ctx)
	if err != nil {
		// Don't fail if count fails, just set to 0
		s.logger.Error("Failed to count users", "error", err)
		total = 0
	}

	return &ListUsersResult{
		Users:   users,
		Total:   total,
		Limit:   limit,
		Offset:  offset,
		HasMore: offset+len(users) < total,
	}, nil
}
