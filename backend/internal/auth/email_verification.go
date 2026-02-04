// Package auth provides authentication services for ModernAuth.
package auth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
	"github.com/iSundram/ModernAuth/internal/utils"
)

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
// Returns the verified user on success.
func (s *AuthService) VerifyEmail(ctx context.Context, token string) (*storage.User, error) {
	tokenHash := utils.HashToken(token)

	verificationToken, err := s.storage.GetVerificationTokenByHash(ctx, tokenHash, TokenTypeEmailVerification)
	if err != nil {
		return nil, err
	}
	if verificationToken == nil {
		return nil, ErrTokenNotFound
	}

	if verificationToken.UsedAt != nil {
		return nil, ErrTokenUsed
	}

	if time.Now().After(verificationToken.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	// Mark email as verified
	user, err := s.storage.GetUserByID(ctx, verificationToken.UserID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}

	user.IsEmailVerified = true
	if err := s.storage.UpdateUser(ctx, user); err != nil {
		return nil, err
	}

	// Mark token as used
	if err := s.storage.MarkVerificationTokenUsed(ctx, verificationToken.ID); err != nil {
		return nil, err
	}

	s.logAuditEvent(ctx, &user.ID, nil, "email_verification.verified", nil, nil, nil)

	return user, nil
}
