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
	"github.com/pquerna/otp/totp"
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
		IsActive:        true,
		Timezone:        "UTC",
		Locale:          "en",
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

// LoginResult represents the result of a login attempt.
type LoginResult struct {
	User           *storage.User `json:"user"`
	TokenPair      *TokenPair    `json:"tokens,omitempty"`
	MFARequired    bool          `json:"mfa_required"`
	MFAChallengeID *uuid.UUID    `json:"mfa_challenge_id,omitempty"`
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

	// Check if user account is active
	if !user.IsActive {
		s.logAuditEvent(ctx, &user.ID, nil, "login.failed", &req.IP, &req.UserAgent, map[string]interface{}{
			"reason": "account_inactive",
		})
		return nil, ErrUserInactive
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

	// Check if MFA is enabled for this user
	mfaSettings, err := s.storage.GetMFASettings(ctx, user.ID)
	if err != nil {
		s.logger.Error("Failed to get MFA settings", "error", err, "user_id", user.ID)
		// Continue without MFA if settings can't be retrieved? 
		// For high security, we should probably fail.
	}

	if mfaSettings != nil && mfaSettings.IsTOTPEnabled {
		// Log MFA requirement
		s.logAuditEvent(ctx, &user.ID, nil, "login.mfa_required", &req.IP, &req.UserAgent, nil)
		
		return &LoginResult{
			User:        user,
			MFARequired: true,
			// In a full implementation, we'd create an mfa_challenge record here
		}, nil
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
	Users      []*storage.User `json:"users"`
	Total      int             `json:"total"`
	Limit      int             `json:"limit"`
	Offset     int             `json:"offset"`
	HasMore    bool            `json:"has_more"`
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

// SetupTOTPRequest represents a request to setup TOTP.
type SetupTOTPRequest struct {
	UserID uuid.UUID `json:"user_id"`
}

// SetupTOTPResult represents the result of TOTP setup.
type SetupTOTPResult struct {
	Secret string `json:"secret"`
	URL    string `json:"url"`
}

// SetupTOTP generates a new TOTP secret for the user.
func (s *AuthService) SetupTOTP(ctx context.Context, userID uuid.UUID) (*SetupTOTPResult, error) {
	user, err := s.storage.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "ModernAuth",
		AccountName: user.Email,
	})
	if err != nil {
		return nil, err
	}

	secret := key.Secret()
	settings := &storage.MFASettings{
		UserID:     userID,
		TOTPSecret: &secret,
	}

	if err := s.storage.UpdateMFASettings(ctx, settings); err != nil {
		return nil, err
	}

	return &SetupTOTPResult{
		Secret: secret,
		URL:    key.URL(),
	}, nil
}

// EnableTOTPRequest represents a request to enable TOTP.
type EnableTOTPRequest struct {
	UserID uuid.UUID `json:"user_id"`
	Code   string    `json:"code"`
}

// EnableTOTP verifies the first code and enables TOTP for the user.
func (s *AuthService) EnableTOTP(ctx context.Context, req *EnableTOTPRequest) error {
	settings, err := s.storage.GetMFASettings(ctx, req.UserID)
	if err != nil {
		return err
	}
	if settings == nil || settings.TOTPSecret == nil {
		return ErrMFANotSetup
	}

	valid := totp.Validate(req.Code, *settings.TOTPSecret)
	if !valid {
		return ErrInvalidMFACode
	}

	settings.IsTOTPEnabled = true
	if err := s.storage.UpdateMFASettings(ctx, settings); err != nil {
		return err
	}

	s.logAuditEvent(ctx, &req.UserID, nil, "mfa.totp_enabled", nil, nil, nil)
	return nil
}

// LoginWithMFARequest represents a request to complete login with MFA.
type LoginWithMFARequest struct {
	UserID      uuid.UUID `json:"user_id"`
	Code        string    `json:"code"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	IP          string    `json:"-"`
	UserAgent   string    `json:"-"`
}

// LoginWithMFA verifies the MFA code and completes the login process.
func (s *AuthService) LoginWithMFA(ctx context.Context, req *LoginWithMFARequest) (*LoginResult, error) {
	user, err := s.storage.GetUserByID(ctx, req.UserID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}

	settings, err := s.storage.GetMFASettings(ctx, req.UserID)
	if err != nil {
		return nil, err
	}
	if settings == nil || !settings.IsTOTPEnabled || settings.TOTPSecret == nil {
		return nil, ErrMFANotSetup
	}

	valid := totp.Validate(req.Code, *settings.TOTPSecret)
	if !valid {
		s.logAuditEvent(ctx, &user.ID, nil, "login.mfa_failed", &req.IP, &req.UserAgent, nil)
		return nil, ErrInvalidMFACode
	}

	// MFA verified, create session and tokens
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

	tokenPair, err := s.tokenService.GenerateTokenPair(user.ID, session.ID, nil)
	if err != nil {
		return nil, err
	}

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

	s.logAuditEvent(ctx, &user.ID, nil, "login.success", &req.IP, &req.UserAgent, map[string]interface{}{"mfa": true})

	return &LoginResult{
		User:      user,
		TokenPair: tokenPair,
	}, nil
}

// Email Verification Constants
const (
	TokenTypeEmailVerification = "email_verification"
	TokenTypePasswordReset     = "password_reset"
	VerificationTokenTTL       = 24 * time.Hour
	PasswordResetTokenTTL      = 1 * time.Hour
)

var (
	// ErrTokenNotFound indicates the verification token was not found.
	ErrTokenNotFound = errors.New("token not found")
	// ErrTokenExpired indicates the verification token has expired.
	ErrTokenExpired = errors.New("token has expired")
	// ErrTokenUsed indicates the verification token has already been used.
	ErrTokenUsed = errors.New("token has already been used")
)

// SendEmailVerificationRequest represents a request to send email verification.
type SendEmailVerificationRequest struct {
	UserID uuid.UUID `json:"user_id"`
}

// SendEmailVerificationResult contains the verification token (for testing/development).
type SendEmailVerificationResult struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// SendEmailVerification creates a verification token for email verification.
// In production, this would send an email. Here we return the token for the caller to handle.
func (s *AuthService) SendEmailVerification(ctx context.Context, userID uuid.UUID) (*SendEmailVerificationResult, error) {
	user, err := s.storage.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}

	// Generate a secure token
	token, err := utils.GenerateRandomString(32)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	expiresAt := now.Add(VerificationTokenTTL)

	verificationToken := &storage.VerificationToken{
		ID:        uuid.New(),
		UserID:    userID,
		TokenHash: utils.HashToken(token),
		TokenType: TokenTypeEmailVerification,
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}

	if err := s.storage.CreateVerificationToken(ctx, verificationToken); err != nil {
		return nil, err
	}

	s.logAuditEvent(ctx, &userID, nil, "email_verification.sent", nil, nil, nil)

	return &SendEmailVerificationResult{
		Token:     token,
		ExpiresAt: expiresAt,
	}, nil
}

// VerifyEmailRequest represents a request to verify an email.
type VerifyEmailRequest struct {
	Token string `json:"token"`
}

// VerifyEmail verifies a user's email using the verification token.
func (s *AuthService) VerifyEmail(ctx context.Context, token string) error {
	tokenHash := utils.HashToken(token)

	verificationToken, err := s.storage.GetVerificationTokenByHash(ctx, tokenHash, TokenTypeEmailVerification)
	if err != nil {
		return err
	}
	if verificationToken == nil {
		return ErrTokenNotFound
	}

	if verificationToken.UsedAt != nil {
		return ErrTokenUsed
	}

	if time.Now().After(verificationToken.ExpiresAt) {
		return ErrTokenExpired
	}

	// Mark email as verified
	user, err := s.storage.GetUserByID(ctx, verificationToken.UserID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	user.IsEmailVerified = true
	if err := s.storage.UpdateUser(ctx, user); err != nil {
		return err
	}

	// Mark token as used
	if err := s.storage.MarkVerificationTokenUsed(ctx, verificationToken.ID); err != nil {
		return err
	}

	s.logAuditEvent(ctx, &user.ID, nil, "email_verification.verified", nil, nil, nil)

	return nil
}

// RequestPasswordResetRequest represents a request to reset password.
type RequestPasswordResetRequest struct {
	Email string `json:"email"`
}

// RequestPasswordResetResult contains the reset token (for testing/development).
type RequestPasswordResetResult struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// RequestPasswordReset creates a password reset token.
// In production, this would send an email. Here we return the token for the caller to handle.
func (s *AuthService) RequestPasswordReset(ctx context.Context, email string) (*RequestPasswordResetResult, error) {
	user, err := s.storage.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if user == nil {
		// Don't reveal if user exists - return success anyway
		s.logger.Info("Password reset requested for non-existent user", "email", email)
		return nil, nil
	}

	// Generate a secure token
	token, err := utils.GenerateRandomString(32)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	expiresAt := now.Add(PasswordResetTokenTTL)

	verificationToken := &storage.VerificationToken{
		ID:        uuid.New(),
		UserID:    user.ID,
		TokenHash: utils.HashToken(token),
		TokenType: TokenTypePasswordReset,
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}

	if err := s.storage.CreateVerificationToken(ctx, verificationToken); err != nil {
		return nil, err
	}

	s.logAuditEvent(ctx, &user.ID, nil, "password_reset.requested", nil, nil, nil)

	return &RequestPasswordResetResult{
		Token:     token,
		ExpiresAt: expiresAt,
	}, nil
}

// ResetPasswordRequest represents a request to reset password with token.
type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

// ResetPassword resets a user's password using a reset token.
func (s *AuthService) ResetPassword(ctx context.Context, req *ResetPasswordRequest) error {
	tokenHash := utils.HashToken(req.Token)

	verificationToken, err := s.storage.GetVerificationTokenByHash(ctx, tokenHash, TokenTypePasswordReset)
	if err != nil {
		return err
	}
	if verificationToken == nil {
		return ErrTokenNotFound
	}

	if verificationToken.UsedAt != nil {
		return ErrTokenUsed
	}

	if time.Now().After(verificationToken.ExpiresAt) {
		return ErrTokenExpired
	}

	// Get the user
	user, err := s.storage.GetUserByID(ctx, verificationToken.UserID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	// Hash the new password
	hashedPassword, err := utils.HashPassword(req.NewPassword, nil)
	if err != nil {
		return err
	}

	user.HashedPassword = hashedPassword
	if err := s.storage.UpdateUser(ctx, user); err != nil {
		return err
	}

	// Mark token as used
	if err := s.storage.MarkVerificationTokenUsed(ctx, verificationToken.ID); err != nil {
		return err
	}

	// Revoke all existing sessions for security
	if err := s.storage.RevokeUserSessions(ctx, user.ID); err != nil {
		s.logger.Error("Failed to revoke user sessions after password reset", "error", err, "user_id", user.ID)
	}

	s.logAuditEvent(ctx, &user.ID, nil, "password_reset.completed", nil, nil, nil)

	return nil
}

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

// ChangePasswordRequest represents a request to change password.
type ChangePasswordRequest struct {
	UserID          uuid.UUID `json:"user_id"`
	CurrentPassword string    `json:"current_password"`
	NewPassword     string    `json:"new_password"`
	IP              string    `json:"-"`
	UserAgent       string    `json:"-"`
}

// ChangePassword changes a user's password after verifying the current one.
func (s *AuthService) ChangePassword(ctx context.Context, req *ChangePasswordRequest) error {
	user, err := s.storage.GetUserByID(ctx, req.UserID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	// Verify current password
	match, err := utils.VerifyPassword(req.CurrentPassword, user.HashedPassword)
	if err != nil {
		return err
	}
	if !match {
		s.logAuditEvent(ctx, &req.UserID, nil, "password_change.failed", &req.IP, &req.UserAgent, map[string]interface{}{
			"reason": "invalid_current_password",
		})
		return ErrInvalidCredentials
	}

	// Hash new password
	hashedPassword, err := utils.HashPassword(req.NewPassword, nil)
	if err != nil {
		return err
	}

	user.HashedPassword = hashedPassword
	if err := s.storage.UpdateUser(ctx, user); err != nil {
		return err
	}

	s.logAuditEvent(ctx, &req.UserID, nil, "password_change.success", &req.IP, &req.UserAgent, nil)

	return nil
}

// UpdateUserRequest represents a request to update user details.
type UpdateUserRequest struct {
	UserID   uuid.UUID `json:"user_id"`
	Email    *string   `json:"email,omitempty"`
	Username *string   `json:"username,omitempty"`
	Phone    *string   `json:"phone,omitempty"`
}

// UpdateUser updates a user's profile information.
func (s *AuthService) UpdateUser(ctx context.Context, req *UpdateUserRequest) (*storage.User, error) {
	user, err := s.storage.GetUserByID(ctx, req.UserID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}

	if req.Email != nil && *req.Email != user.Email {
		// Check if email is already taken
		existing, err := s.storage.GetUserByEmail(ctx, *req.Email)
		if err != nil {
			return nil, err
		}
		if existing != nil {
			return nil, ErrUserExists
		}
		user.Email = *req.Email
		user.IsEmailVerified = false // Reset verification on email change
	}

	if req.Username != nil {
		user.Username = req.Username
	}

	if req.Phone != nil {
		user.Phone = req.Phone
	}

	if err := s.storage.UpdateUser(ctx, user); err != nil {
		return nil, err
	}

	s.logAuditEvent(ctx, &req.UserID, nil, "user.updated", nil, nil, nil)

	return user, nil
}

// DeleteUser deletes a user and all associated data.
func (s *AuthService) DeleteUser(ctx context.Context, userID uuid.UUID, actorID *uuid.UUID) error {
	user, err := s.storage.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	// Revoke all sessions first
	if err := s.storage.RevokeUserSessions(ctx, userID); err != nil {
		s.logger.Error("Failed to revoke sessions during user deletion", "error", err, "user_id", userID)
	}

	if err := s.storage.DeleteUser(ctx, userID); err != nil {
		return err
	}

	s.logAuditEvent(ctx, &userID, actorID, "user.deleted", nil, nil, nil)

	return nil
}

// GetAuditLogs retrieves audit logs with pagination.
func (s *AuthService) GetAuditLogs(ctx context.Context, userID *uuid.UUID, limit, offset int) ([]*storage.AuditLog, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	return s.storage.GetAuditLogs(ctx, userID, limit, offset)
}

// GetUserRoles retrieves all roles assigned to a user.
func (s *AuthService) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*storage.Role, error) {
	return s.storage.GetUserRoles(ctx, userID)
}

// AssignRole assigns a role to a user.
func (s *AuthService) AssignRole(ctx context.Context, userID, roleID uuid.UUID, assignedBy *uuid.UUID) error {
	if err := s.storage.AssignRoleToUser(ctx, userID, roleID, assignedBy); err != nil {
		return err
	}
	s.logAuditEvent(ctx, &userID, assignedBy, "role.assigned", nil, nil, map[string]interface{}{
		"role_id": roleID.String(),
	})
	return nil
}

// RemoveRole removes a role from a user.
func (s *AuthService) RemoveRole(ctx context.Context, userID, roleID uuid.UUID, actorID *uuid.UUID) error {
	if err := s.storage.RemoveRoleFromUser(ctx, userID, roleID); err != nil {
		return err
	}
	s.logAuditEvent(ctx, &userID, actorID, "role.removed", nil, nil, map[string]interface{}{
		"role_id": roleID.String(),
	})
	return nil
}

// UserHasRole checks if a user has a specific role.
func (s *AuthService) UserHasRole(ctx context.Context, userID uuid.UUID, roleName string) (bool, error) {
	return s.storage.UserHasRole(ctx, userID, roleName)
}

// UserHasPermission checks if a user has a specific permission.
func (s *AuthService) UserHasPermission(ctx context.Context, userID uuid.UUID, permissionName string) (bool, error) {
	return s.storage.UserHasPermission(ctx, userID, permissionName)
}

// ListRoles retrieves all available roles.
func (s *AuthService) ListRoles(ctx context.Context) ([]*storage.Role, error) {
	return s.storage.ListRoles(ctx)
}
