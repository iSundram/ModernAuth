// Package auth provides authentication services for ModernAuth.
package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
	"github.com/iSundram/ModernAuth/internal/utils"
)

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
// Includes password history check to prevent reuse of recent passwords.
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

	// Check if new password is the same as current password
	sameAsCurrent, err := utils.VerifyPassword(req.NewPassword, user.HashedPassword)
	if err != nil {
		return err
	}
	if sameAsCurrent {
		s.logAuditEvent(ctx, &user.ID, nil, "password_reset.failed", nil, nil, map[string]interface{}{
			"reason": "password_reused",
		})
		return ErrPasswordReused
	}

	// Check password against known data breaches (HIBP)
	if s.hibpService != nil {
		result, err := s.hibpService.CheckPassword(ctx, req.NewPassword)
		if err != nil {
			s.logger.Warn("HIBP check failed during password reset", "error", err)
			// Don't block password reset on HIBP API errors
		} else if result.IsBreached {
			s.logAuditEvent(ctx, &user.ID, nil, "password_reset.failed", nil, nil, map[string]interface{}{
				"reason": "password_breached",
				"count":  result.Count,
			})
			return fmt.Errorf("this password has appeared in %d data breaches and cannot be used", result.Count)
		}
	}

	// Check password history (prevent reuse of last 5 passwords)
	const passwordHistoryDepth = 5
	if err := s.CheckPasswordHistory(ctx, user.ID, req.NewPassword, passwordHistoryDepth); err != nil {
		s.logAuditEvent(ctx, &user.ID, nil, "password_reset.failed", nil, nil, map[string]interface{}{
			"reason": "password_reused",
		})
		return err
	}

	// Add current password to history before changing
	if err := s.AddToPasswordHistory(ctx, user.ID, user.HashedPassword, passwordHistoryDepth); err != nil {
		s.logger.Warn("Failed to add password to history", "error", err)
		// Continue anyway - don't block password reset
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

// ChangePasswordRequest represents a request to change password.
type ChangePasswordRequest struct {
	UserID          uuid.UUID `json:"user_id"`
	CurrentPassword string    `json:"current_password"`
	NewPassword     string    `json:"new_password"`
	IP              string    `json:"-"`
	UserAgent       string    `json:"-"`
}

// ChangePassword changes a user's password after verifying the current one.
// Includes password history check to prevent reuse of recent passwords.
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

	// Check if new password is the same as current password
	sameAsCurrent, err := utils.VerifyPassword(req.NewPassword, user.HashedPassword)
	if err != nil {
		return err
	}
	if sameAsCurrent {
		s.logAuditEvent(ctx, &req.UserID, nil, "password_change.failed", &req.IP, &req.UserAgent, map[string]interface{}{
			"reason": "password_reused",
		})
		return ErrPasswordReused
	}

	// Check password against known data breaches (HIBP)
	if s.hibpService != nil {
		result, err := s.hibpService.CheckPassword(ctx, req.NewPassword)
		if err != nil {
			s.logger.Warn("HIBP check failed during password change", "error", err)
			// Don't block password change on HIBP API errors
		} else if result.IsBreached {
			s.logAuditEvent(ctx, &req.UserID, nil, "password_change.failed", &req.IP, &req.UserAgent, map[string]interface{}{
				"reason": "password_breached",
				"count":  result.Count,
			})
			return fmt.Errorf("this password has appeared in %d data breaches and cannot be used", result.Count)
		}
	}

	// Check password history (prevent reuse of last 5 passwords)
	const passwordHistoryDepth = 5
	if err := s.CheckPasswordHistory(ctx, req.UserID, req.NewPassword, passwordHistoryDepth); err != nil {
		s.logAuditEvent(ctx, &req.UserID, nil, "password_change.failed", &req.IP, &req.UserAgent, map[string]interface{}{
			"reason": "password_reused",
		})
		return err
	}

	// Add current password to history before changing
	if err := s.AddToPasswordHistory(ctx, req.UserID, user.HashedPassword, passwordHistoryDepth); err != nil {
		s.logger.Warn("Failed to add password to history", "error", err)
		// Continue anyway - don't block password change
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
