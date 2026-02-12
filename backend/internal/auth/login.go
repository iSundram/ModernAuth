// Package auth provides authentication services for ModernAuth.
package auth

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
	"github.com/iSundram/ModernAuth/internal/utils"
)

// LoginRequest represents a login request.
type LoginRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	Fingerprint string `json:"fingerprint,omitempty"`
	TrustDevice bool   `json:"trust_device,omitempty"`
	IP          string `json:"-"`
	UserAgent   string `json:"-"`
}

// LoginResult represents the result of a login attempt.
type LoginResult struct {
	User           *storage.User `json:"user"`
	TokenPair      *TokenPair    `json:"tokens,omitempty"`
	SessionID      *uuid.UUID    `json:"session_id,omitempty"`
	MFARequired    bool          `json:"mfa_required"`
	MFAChallengeID *uuid.UUID    `json:"mfa_challenge_id,omitempty"`
}

// CheckEmailResult contains information about an email address for login.
type CheckEmailResult struct {
	Exists          bool     `json:"exists"`
	MFARequired     bool     `json:"mfa_required"`
	PreferredMethod string   `json:"preferred_method,omitempty"`
	Methods         []string `json:"methods,omitempty"`
}

// CheckEmail checks if an email address exists and returns login-related info.
func (s *AuthService) CheckEmail(ctx context.Context, email string) (*CheckEmailResult, error) {
	user, err := s.storage.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	if user == nil {
		return &CheckEmailResult{Exists: false}, nil
	}

	res := &CheckEmailResult{
		Exists: true,
	}

	// Check MFA settings
	mfa, err := s.storage.GetMFASettings(ctx, user.ID)
	if err == nil && mfa != nil {
		// MFA is enabled if any method is enabled
		isEnabled := mfa.IsTOTPEnabled || mfa.IsEmailMFAEnabled || mfa.IsSMSMFAEnabled
		if isEnabled {
			res.MFARequired = true
			res.PreferredMethod = mfa.PreferredMethod

			// Add available methods
			if mfa.IsTOTPEnabled {
				res.Methods = append(res.Methods, "totp")
			}
			if mfa.IsSMSMFAEnabled && user.Phone != nil && *user.Phone != "" {
				res.Methods = append(res.Methods, "sms")
			}
			if mfa.IsEmailMFAEnabled {
				res.Methods = append(res.Methods, "email")
			}
		}
	}

	return res, nil
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
		// Log failed login attempt without exposing email (use user ID instead)
		s.logger.Warn("Failed login attempt", "user_id", user.ID, "ip", req.IP)
		s.logAuditEvent(ctx, &user.ID, nil, "login.failed", &req.IP, &req.UserAgent, map[string]interface{}{
			"reason": "invalid_password",
		})
		return nil, ErrInvalidCredentials
	}

	// Check MFA policy (system-wide and tenant-specific) including trusted device logic.
	needMFA, err := s.CheckMFAPolicy(ctx, user.ID, req.Fingerprint)
	if err != nil {
		s.logger.Error("Failed to evaluate MFA policy", "error", err, "user_id", user.ID)
	}
	if needMFA {
		// Create an MFA challenge token to prove password was verified
		// This prevents attackers from skipping password verification
		mfaChallengeID := uuid.New()
		mfaChallenge := &storage.MFAChallenge{
			ID:        mfaChallengeID,
			UserID:    user.ID,
			Type:      "password_verified",
			ExpiresAt: time.Now().Add(5 * time.Minute), // MFA must be completed within 5 minutes
			Verified:  false,
			CreatedAt: time.Now(),
		}

		if err := s.storage.CreateMFAChallenge(ctx, mfaChallenge); err != nil {
			s.logger.Error("Failed to create MFA challenge", "error", err)
			return nil, err
		}

		// Log MFA requirement
		_ = s.logAuditEvent(ctx, &user.ID, nil, "login.mfa_required", &req.IP, &req.UserAgent, nil)

		return &LoginResult{
			User:           user,
			MFARequired:    true,
			MFAChallengeID: &mfaChallengeID,
		}, nil
	}

	// Enforce session limits (max 5 concurrent sessions, revoke oldest if exceeded)
	const maxConcurrentSessions = 5
	if err := s.EnforceSessionLimit(ctx, user.ID, maxConcurrentSessions, SessionLimitActionRevokeOldest); err != nil {
		// With SessionLimitActionRevokeOldest, this will only happen on storage errors
		// For stricter enforcement (reject new logins), use SessionLimitActionRejectNew
		s.logger.Warn("Session limit enforcement failed", "error", err)
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

	// Trust device if requested
	if req.TrustDevice && req.Fingerprint != "" {
		if err := s.TrustDeviceForMFA(ctx, user.ID, req.Fingerprint, 30); err != nil {
			s.logger.Error("Failed to trust device during login", "error", err, "user_id", user.ID)
		}
	}

	return &LoginResult{
		User:      user,
		TokenPair: tokenPair,
		SessionID: &session.ID,
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
	TokenJTI  string    `json:"-"` // JTI of the current access token for blacklisting
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
