// Package auth provides authentication services for ModernAuth.
package auth

import (
	"context"
	"encoding/base32"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
	"github.com/iSundram/ModernAuth/internal/utils"
	"github.com/pquerna/otp/totp"
)

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

	// Get existing MFA settings to check for unverified TOTP secret
	existingSettings, err := s.storage.GetMFASettings(ctx, userID)
	if err != nil {
		return nil, err
	}

	var secret string
	if existingSettings != nil && existingSettings.TOTPSecret != nil && !existingSettings.IsTOTPEnabled {
		// TOTP secret exists but hasn't been verified yet
		// Return existing secret to prevent regeneration without verification
		secret = *existingSettings.TOTPSecret
		secretBytes, _ := base32.StdEncoding.DecodeString(secret)
		key, _ := totp.Generate(totp.GenerateOpts{
			Issuer:      "ModernAuth",
			AccountName: user.Email,
			Secret:      secretBytes,
		})
		return &SetupTOTPResult{
			Secret: secret,
			URL:    key.URL(),
		}, nil
	}

	// Generate new TOTP secret
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "ModernAuth",
		AccountName: user.Email,
	})
	if err != nil {
		return nil, err
	}

	secret = key.Secret()
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

	// Check TOTP code replay protection
	if s.isTOTPCodeUsed(ctx, req.UserID, req.Code) {
		s.logger.Warn("TOTP code already used", "user_id", req.UserID, "code", "***")
		return ErrInvalidMFACode
	}

	settings.IsTOTPEnabled = true
	if err := s.storage.UpdateMFASettings(ctx, settings); err != nil {
		return err
	}

	s.logAuditEvent(ctx, &req.UserID, nil, "mfa.totp_enabled", nil, nil, nil)
	return nil
}

// isTOTPCodeUsed checks if a TOTP code was recently used (replay protection).
func (s *AuthService) isTOTPCodeUsed(ctx context.Context, userID uuid.UUID, code string) bool {
	settings, err := s.storage.GetMFASettings(ctx, userID)
	if err != nil {
		return false
	}

	if settings.UsedTOTPCodes == nil {
		return false
	}

	// Check if code was used
	if used, ok := settings.UsedTOTPCodes[code]; ok && used {
		return true
	}

	return false
}

// recordTOTPCodeUsed records that a TOTP code was used.
func (s *AuthService) recordTOTPCodeUsed(ctx context.Context, userID uuid.UUID, code string) error {
	settings, err := s.storage.GetMFASettings(ctx, userID)
	if err != nil {
		return err
	}

	if settings.UsedTOTPCodes == nil {
		settings.UsedTOTPCodes = make(map[string]bool)
	}

	settings.UsedTOTPCodes[code] = true
	if err := s.storage.UpdateMFASettings(ctx, settings); err != nil {
		return err
	}

	s.logger.Debug("TOTP code recorded as used", "user_id", userID, "code", "***")
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

	// Check TOTP code replay protection
	if s.isTOTPCodeUsed(ctx, req.UserID, req.Code) {
		s.logger.Warn("TOTP code already used", "user_id", req.UserID)
		return nil, ErrInvalidMFACode
	}

	valid := totp.Validate(req.Code, *settings.TOTPSecret)
	if !valid {
		s.logAuditEvent(ctx, &user.ID, nil, "login.mfa_failed", &req.IP, &req.UserAgent, nil)
		return nil, ErrInvalidMFACode
	}

	// Record code as used before proceeding
	if err := s.recordTOTPCodeUsed(ctx, req.UserID, req.Code); err != nil {
		s.logger.Error("Failed to record TOTP code usage", "error", err)
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
