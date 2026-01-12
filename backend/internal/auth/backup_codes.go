// Package auth provides MFA backup codes support for ModernAuth.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/iSundram/ModernAuth/internal/storage"
	"github.com/iSundram/ModernAuth/internal/utils"
)

const (
	// BackupCodeCount is the number of backup codes to generate.
	BackupCodeCount = 10
	// BackupCodeLength is the length of each backup code.
	BackupCodeLength = 8
)

// GenerateBackupCodesRequest represents a request to generate backup codes.
type GenerateBackupCodesRequest struct {
	UserID uuid.UUID `json:"user_id"`
}

// GenerateBackupCodesResult contains the generated backup codes.
type GenerateBackupCodesResult struct {
	BackupCodes []string `json:"backup_codes"`
}

// GenerateBackupCodes generates new backup codes for MFA recovery.
// This replaces any existing backup codes.
func (s *AuthService) GenerateBackupCodes(ctx context.Context, userID uuid.UUID) (*GenerateBackupCodesResult, error) {
	settings, err := s.storage.GetMFASettings(ctx, userID)
	if err != nil {
		return nil, err
	}
	if settings == nil {
		// Create new MFA settings if they don't exist
		settings = &storage.MFASettings{
			UserID: userID,
		}
	}

	// Generate new backup codes
	codes := make([]string, BackupCodeCount)
	hashedCodes := make([]string, BackupCodeCount)

	for i := 0; i < BackupCodeCount; i++ {
		code, err := generateBackupCode()
		if err != nil {
			return nil, err
		}
		codes[i] = code
		hashedCodes[i] = utils.HashToken(code)
	}

	// Store hashed codes
	settings.BackupCodes = hashedCodes
	if err := s.storage.UpdateMFASettings(ctx, settings); err != nil {
		return nil, err
	}

	s.logAuditEvent(ctx, &userID, nil, "mfa.backup_codes_generated", nil, nil, nil)

	return &GenerateBackupCodesResult{
		BackupCodes: codes,
	}, nil
}

// VerifyBackupCode verifies a backup code and invalidates it if valid.
func (s *AuthService) VerifyBackupCode(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
	settings, err := s.storage.GetMFASettings(ctx, userID)
	if err != nil {
		return false, err
	}
	if settings == nil || len(settings.BackupCodes) == 0 {
		return false, nil
	}

	// Normalize the code (remove dashes, lowercase)
	code = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(code)), "-", "")
	codeHash := utils.HashToken(code)

	// Find and remove the matching code
	for i, hashedCode := range settings.BackupCodes {
		if hashedCode == codeHash {
			// Remove the used code
			settings.BackupCodes = append(settings.BackupCodes[:i], settings.BackupCodes[i+1:]...)
			if err := s.storage.UpdateMFASettings(ctx, settings); err != nil {
				s.logger.Error("Failed to update backup codes after use", "error", err, "user_id", userID)
				// Still return true since the code was valid
			}

			s.logAuditEvent(ctx, &userID, nil, "mfa.backup_code_used", nil, nil, map[string]interface{}{
				"remaining_codes": len(settings.BackupCodes),
			})

			return true, nil
		}
	}

	return false, nil
}

// GetBackupCodeCount returns the number of remaining backup codes for a user.
func (s *AuthService) GetBackupCodeCount(ctx context.Context, userID uuid.UUID) (int, error) {
	settings, err := s.storage.GetMFASettings(ctx, userID)
	if err != nil {
		return 0, err
	}
	if settings == nil {
		return 0, nil
	}
	return len(settings.BackupCodes), nil
}

// LoginWithBackupCodeRequest represents a request to login with a backup code.
type LoginWithBackupCodeRequest struct {
	UserID      uuid.UUID `json:"user_id"`
	BackupCode  string    `json:"backup_code"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	IP          string    `json:"-"`
	UserAgent   string    `json:"-"`
}

// LoginWithBackupCode verifies a backup code and completes the login process.
func (s *AuthService) LoginWithBackupCode(ctx context.Context, req *LoginWithBackupCodeRequest) (*LoginResult, error) {
	user, err := s.storage.GetUserByID(ctx, req.UserID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}

	// Verify the backup code
	valid, err := s.VerifyBackupCode(ctx, req.UserID, req.BackupCode)
	if err != nil {
		return nil, err
	}
	if !valid {
		s.logAuditEvent(ctx, &user.ID, nil, "login.backup_code_failed", &req.IP, &req.UserAgent, nil)
		return nil, ErrInvalidMFACode
	}

	// Backup code verified, create session and tokens
	session, tokenPair, err := s.createSessionAndTokens(ctx, user, req.Fingerprint)
	if err != nil {
		return nil, err
	}

	s.logAuditEvent(ctx, &user.ID, nil, "login.success", &req.IP, &req.UserAgent, map[string]interface{}{
		"method": "backup_code",
	})

	// Check remaining backup codes and warn if low
	remaining, _ := s.GetBackupCodeCount(ctx, user.ID)
	if remaining <= 2 {
		s.logger.Warn("User has low backup codes remaining", "user_id", user.ID, "remaining", remaining)
	}

	_ = session // session is used internally
	return &LoginResult{
		User:      user,
		TokenPair: tokenPair,
	}, nil
}

// DisableMFA disables TOTP MFA for a user after verifying their password or TOTP code.
func (s *AuthService) DisableMFA(ctx context.Context, userID uuid.UUID, verificationCode string) error {
	settings, err := s.storage.GetMFASettings(ctx, userID)
	if err != nil {
		return err
	}
	if settings == nil || !settings.IsTOTPEnabled {
		return ErrMFANotSetup
	}

	// Verify the TOTP code before disabling
	if settings.TOTPSecret != nil {
		valid := validateTOTPCode(verificationCode, *settings.TOTPSecret)
		if !valid {
			return ErrInvalidMFACode
		}
	}

	// Disable MFA
	settings.IsTOTPEnabled = false
	settings.TOTPSecret = nil
	settings.BackupCodes = nil

	if err := s.storage.UpdateMFASettings(ctx, settings); err != nil {
		return err
	}

	s.logAuditEvent(ctx, &userID, nil, "mfa.disabled", nil, nil, nil)
	return nil
}

// createSessionAndTokens creates a new session and generates tokens for a user.
func (s *AuthService) createSessionAndTokens(ctx context.Context, user *storage.User, fingerprint string) (*storage.Session, *TokenPair, error) {
	now := currentTime()
	session := &storage.Session{
		ID:        uuid.New(),
		UserID:    user.ID,
		CreatedAt: now,
		ExpiresAt: now.Add(s.sessionTTL),
		Revoked:   false,
	}

	if fingerprint != "" {
		session.Fingerprint = &fingerprint
	}

	if err := s.storage.CreateSession(ctx, session); err != nil {
		return nil, nil, err
	}

	tokenPair, err := s.tokenService.GenerateTokenPair(user.ID, session.ID, nil)
	if err != nil {
		return nil, nil, err
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
		return nil, nil, err
	}

	return session, tokenPair, nil
}

// generateBackupCode generates a single backup code.
func generateBackupCode() (string, error) {
	bytes := make([]byte, BackupCodeLength/2)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	code := hex.EncodeToString(bytes)
	// Format as xxxx-xxxx for readability
	if len(code) == 8 {
		return code[:4] + "-" + code[4:], nil
	}
	return code, nil
}

// validateTOTPCode validates a TOTP code against a secret.
func validateTOTPCode(code, secret string) bool {
	return totp.Validate(code, secret)
}

// currentTime returns the current time (can be overridden in tests).
var currentTime = func() time.Time {
	return time.Now()
}
