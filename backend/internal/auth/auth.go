// Package auth provides authentication services for ModernAuth.
package auth

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/email"
	"github.com/iSundram/ModernAuth/internal/hibp"
	"github.com/iSundram/ModernAuth/internal/storage"
	"github.com/iSundram/ModernAuth/internal/utils"
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
	// ErrInvalidWebAuthnData indicates that the WebAuthn data is invalid.
	ErrInvalidWebAuthnData = errors.New("invalid webauthn data")
	// ErrChallengeMismatch indicates that the challenge does not match.
	ErrChallengeMismatch = errors.New("challenge mismatch")
	// ErrSignatureInvalid indicates that the cryptographic signature is invalid.
	ErrSignatureInvalid = errors.New("signature verification failed")
	// ErrMFAChallengeRequired indicates that an MFA challenge token is required.
	ErrMFAChallengeRequired = errors.New("mfa challenge token required")
	// ErrMFAChallengeInvalid indicates that the MFA challenge token is invalid.
	ErrMFAChallengeInvalid = errors.New("invalid mfa challenge token")
)

// AuthService provides authentication operations.
type AuthService struct {
	storage        storage.Storage
	tokenService   *TokenService
	emailService   email.Service
	accountLockout *AccountLockout
	hibpService    *hibp.Service
	smsService     interface {
		SendSMS(ctx context.Context, to string, message string) error
	}
	tokenBlacklist *TokenBlacklist
	sessionTTL     time.Duration
	settingsCache  *SettingsCache
	logger         *slog.Logger
}

// SetHIBPService sets the HIBP breached password detection service.
func (s *AuthService) SetHIBPService(svc *hibp.Service) {
	s.hibpService = svc
}

// SetSMSService sets the SMS service for SMS MFA.
func (s *AuthService) SetSMSService(svc interface {
	SendSMS(ctx context.Context, to string, message string) error
}) {
	s.smsService = svc
}

// SetSettingsCache sets the settings cache for cache invalidation on updates.
func (s *AuthService) SetSettingsCache(cache *SettingsCache) {
	s.settingsCache = cache
}

// SetTokenBlacklist sets the token blacklist for session revocation.
func (s *AuthService) SetTokenBlacklist(blacklist *TokenBlacklist) {
	s.tokenBlacklist = blacklist
}

// NewAuthService creates a new authentication service.
func NewAuthService(store storage.Storage, tokenService *TokenService, emailService email.Service, sessionTTL time.Duration) *AuthService {
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

// SetAccountLockout sets the account lockout manager.
func (s *AuthService) SetAccountLockout(lockout *AccountLockout) {
	s.accountLockout = lockout
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

// LogAuditEventPublic creates an audit log entry (public API for use by handlers).
func (s *AuthService) LogAuditEventPublic(ctx context.Context, userID, actorID *uuid.UUID, eventType string, ip, userAgent *string, data map[string]interface{}) error {
	return s.logAuditEvent(ctx, userID, actorID, eventType, ip, userAgent, data)
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

// DeleteOwnAccountRequest represents a request to self-delete a user account.
type DeleteOwnAccountRequest struct {
	UserID   uuid.UUID `json:"user_id"`
	Password string    `json:"password"`
}

// DeleteOwnAccount allows a user to delete their own account after password confirmation.
func (s *AuthService) DeleteOwnAccount(ctx context.Context, req *DeleteOwnAccountRequest) error {
	user, err := s.storage.GetUserByID(ctx, req.UserID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	// Verify the user's password before allowing deletion
	match, err := utils.VerifyPassword(req.Password, user.HashedPassword)
	if err != nil {
		return err
	}
	if !match {
		return ErrInvalidCredentials
	}

	// Try to use transactional deletion if the storage supports it
	if txStorage, ok := s.storage.(storage.TransactionalStorage); ok {
		if err := txStorage.DeleteUserWithSessions(ctx, req.UserID); err != nil {
			return err
		}
	} else {
		// Fallback to non-transactional deletion for storage implementations
		// that don't support transactions (e.g., in-memory storage for testing)
		if err := s.storage.RevokeUserSessions(ctx, req.UserID); err != nil {
			s.logger.Error("Failed to revoke sessions during self-deletion", "error", err, "user_id", req.UserID)
		}

		if err := s.storage.DeleteUser(ctx, req.UserID); err != nil {
			return err
		}
	}

	// Log the audit event
	s.logAuditEvent(ctx, &req.UserID, &req.UserID, "user.self_deleted", nil, nil, nil)

	return nil
}
