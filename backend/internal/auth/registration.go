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

	// Check password against known data breaches (HIBP)
	if s.hibpService != nil {
		result, err := s.hibpService.CheckPassword(ctx, req.Password)
		if err != nil {
			s.logger.Warn("HIBP check failed during registration", "error", err)
			// Don't block registration on HIBP API errors
		} else if result.IsBreached {
			return nil, fmt.Errorf("this password has appeared in %d data breaches and cannot be used", result.Count)
		}
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
