// Package auth provides authentication services for ModernAuth.
package auth

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
	"github.com/iSundram/ModernAuth/internal/utils"
)

var (
	// ErrUserNotFound indicates that the user was not found.
	ErrUserNotFound = errors.New("user not found")
	// ErrUserExists indicates that a user with the given email already exists.
	ErrUserExists = errors.New("user already exists")
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
)

// AuthService provides authentication operations.
type AuthService struct {
	storage      storage.Storage
	tokenService *TokenService
	sessionTTL   time.Duration
	logger       *slog.Logger
}

// NewAuthService creates a new authentication service.
func NewAuthService(store storage.Storage, tokenService *TokenService, sessionTTL time.Duration) *AuthService {
	if sessionTTL == 0 {
		sessionTTL = 7 * 24 * time.Hour // Default 7 days
	}
	return &AuthService{
		storage:      store,
		tokenService: tokenService,
		sessionTTL:   sessionTTL,
		logger:       slog.Default().With("component", "auth_service"),
	}
}

// RegisterRequest represents a user registration request.
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Username string `json:"username,omitempty"`
}

// RegisterResult represents the result of user registration.
type RegisterResult struct {
	User      *storage.User `json:"user"`
	TokenPair *TokenPair    `json:"tokens"`
}

// Register creates a new user account.
func (s *AuthService) Register(ctx context.Context, req *RegisterRequest) (*RegisterResult, error) {
	// Check if user already exists
	existingUser, err := s.storage.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, err
	}
	if existingUser != nil {
		return nil, ErrUserExists
	}

	// Hash the password
	hashedPassword, err := utils.HashPassword(req.Password, nil)
	if err != nil {
		return nil, err
	}

	// Create the user
	now := time.Now()
	user := &storage.User{
		ID:              uuid.New(),
		Email:           req.Email,
		HashedPassword:  hashedPassword,
		IsEmailVerified: false,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	if req.Username != "" {
		user.Username = &req.Username
	}

	if err := s.storage.CreateUser(ctx, user); err != nil {
		return nil, err
	}

	// Create a session
	session := &storage.Session{
		ID:        uuid.New(),
		UserID:    user.ID,
		CreatedAt: now,
		ExpiresAt: now.Add(s.sessionTTL),
		Revoked:   false,
	}

	if err := s.storage.CreateSession(ctx, session); err != nil {
		return nil, err
	}

	// Generate tokens
	tokenPair, err := s.tokenService.GenerateTokenPair(user.ID, session.ID, nil)
	if err != nil {
		return nil, err
	}

	// Store the refresh token hash
	refreshToken := &storage.RefreshToken{
		ID:        uuid.New(),
		SessionID: session.ID,
		TokenHash: utils.HashToken(tokenPair.RefreshToken),
		IssuedAt:  now,
		ExpiresAt: now.Add(s.tokenService.config.RefreshTokenTTL),
		Revoked:   false,
	}

	if err := s.storage.CreateRefreshToken(ctx, refreshToken); err != nil {
		return nil, err
	}

	// Log the registration event
	if err := s.logAuditEvent(ctx, &user.ID, nil, "user.registered", nil, nil, nil); err != nil {
		s.logger.Error("Failed to log registration event", "error", err, "user_id", user.ID)
	}

	return &RegisterResult{
		User:      user,
		TokenPair: tokenPair,
	}, nil
}

// LoginRequest represents a login request.
type LoginRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	Fingerprint string `json:"fingerprint,omitempty"`
	IP          string `json:"-"`
	UserAgent   string `json:"-"`
}

// LoginResult represents the result of a successful login.
type LoginResult struct {
	User      *storage.User `json:"user"`
	TokenPair *TokenPair    `json:"tokens"`
}

// Login authenticates a user with email and password.
func (s *AuthService) Login(ctx context.Context, req *LoginRequest) (*LoginResult, error) {
	// Find the user
	user, err := s.storage.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrInvalidCredentials
	}

	// Verify the password
	match, err := utils.VerifyPassword(req.Password, user.HashedPassword)
	if err != nil {
		return nil, err
	}
	if !match {
		// Log failed login attempt
		s.logger.Warn("Failed login attempt", "email", req.Email, "ip", req.IP)
		s.logAuditEvent(ctx, &user.ID, nil, "login.failed", &req.IP, &req.UserAgent, map[string]interface{}{
			"reason": "invalid_password",
		})
		return nil, ErrInvalidCredentials
	}

	// Create a new session
	now := time.Now()
	session := &storage.Session{
		ID:        uuid.New(),
		UserID:    user.ID,
		CreatedAt: now,
		ExpiresAt: now.Add(s.sessionTTL),
		Revoked:   false,
	}

	if req.Fingerprint != "" {
		session.Fingerprint = &req.Fingerprint
	}

	if err := s.storage.CreateSession(ctx, session); err != nil {
		return nil, err
	}

	// Generate tokens
	tokenPair, err := s.tokenService.GenerateTokenPair(user.ID, session.ID, nil)
	if err != nil {
		return nil, err
	}

	// Store the refresh token hash
	refreshToken := &storage.RefreshToken{
		ID:        uuid.New(),
		SessionID: session.ID,
		TokenHash: utils.HashToken(tokenPair.RefreshToken),
		IssuedAt:  now,
		ExpiresAt: now.Add(s.tokenService.config.RefreshTokenTTL),
		Revoked:   false,
	}

	if err := s.storage.CreateRefreshToken(ctx, refreshToken); err != nil {
		return nil, err
	}

	// Log successful login
	s.logAuditEvent(ctx, &user.ID, nil, "login.success", &req.IP, &req.UserAgent, nil)

	return &LoginResult{
		User:      user,
		TokenPair: tokenPair,
	}, nil
}

// RefreshRequest represents a token refresh request.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
	IP           string `json:"-"`
	UserAgent    string `json:"-"`
}

// Refresh exchanges a refresh token for new tokens.
func (s *AuthService) Refresh(ctx context.Context, req *RefreshRequest) (*TokenPair, error) {
	// Hash the incoming token to look it up
	tokenHash := utils.HashToken(req.RefreshToken)

	// Find the refresh token
	refreshToken, err := s.storage.GetRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		return nil, err
	}
	if refreshToken == nil {
		return nil, ErrRefreshTokenNotFound
	}

	// Check if token was already replaced (reuse detection)
	if refreshToken.ReplacedBy != nil {
		// Potential token theft - revoke the entire session
		s.logger.Warn("Refresh token reuse detected!", 
			"session_id", refreshToken.SessionID, 
			"token_id", refreshToken.ID,
			"ip", req.IP)
		s.storage.RevokeSession(ctx, refreshToken.SessionID)
		s.storage.RevokeSessionRefreshTokens(ctx, refreshToken.SessionID)
		return nil, ErrRefreshTokenReused
	}

	// Check if token is revoked
	if refreshToken.Revoked {
		return nil, ErrRefreshTokenRevoked
	}

	// Check if token is expired
	if time.Now().After(refreshToken.ExpiresAt) {
		return nil, ErrRefreshTokenExpired
	}

	// Get the session
	session, err := s.storage.GetSessionByID(ctx, refreshToken.SessionID)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, ErrSessionNotFound
	}

	// Check if session is revoked
	if session.Revoked {
		return nil, ErrSessionRevoked
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		return nil, ErrSessionExpired
	}

	// Generate new token pair
	newTokenPair, err := s.tokenService.GenerateTokenPair(session.UserID, session.ID, nil)
	if err != nil {
		return nil, err
	}

	// Create new refresh token
	now := time.Now()
	newRefreshToken := &storage.RefreshToken{
		ID:        uuid.New(),
		SessionID: session.ID,
		TokenHash: utils.HashToken(newTokenPair.RefreshToken),
		IssuedAt:  now,
		ExpiresAt: now.Add(s.tokenService.config.RefreshTokenTTL),
		Revoked:   false,
	}

	if err := s.storage.CreateRefreshToken(ctx, newRefreshToken); err != nil {
		return nil, err
	}

	// Mark the old token as replaced
	if err := s.storage.RevokeRefreshToken(ctx, refreshToken.ID, &newRefreshToken.ID); err != nil {
		return nil, err
	}

	// Log token refresh
	s.logAuditEvent(ctx, &session.UserID, nil, "token.refresh", &req.IP, &req.UserAgent, nil)

	return newTokenPair, nil
}

// LogoutRequest represents a logout request.
type LogoutRequest struct {
	SessionID uuid.UUID `json:"session_id"`
	IP        string    `json:"-"`
	UserAgent string    `json:"-"`
}

// Logout revokes a session and its tokens.
func (s *AuthService) Logout(ctx context.Context, req *LogoutRequest) error {
	// Get the session to find the user ID for audit log
	session, err := s.storage.GetSessionByID(ctx, req.SessionID)
	if err != nil {
		return err
	}
	if session == nil {
		return ErrSessionNotFound
	}

	// Revoke all refresh tokens for this session
	if err := s.storage.RevokeSessionRefreshTokens(ctx, req.SessionID); err != nil {
		return err
	}

	// Revoke the session
	if err := s.storage.RevokeSession(ctx, req.SessionID); err != nil {
		return err
	}

	// Log logout
	s.logAuditEvent(ctx, &session.UserID, nil, "logout", &req.IP, &req.UserAgent, nil)

	return nil
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
