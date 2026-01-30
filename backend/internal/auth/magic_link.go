// Package auth provides authentication services for ModernAuth.
// This file contains magic link (passwordless) authentication functionality.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
	"github.com/iSundram/ModernAuth/internal/utils"
)

var (
	// ErrMagicLinkNotFound indicates that the magic link was not found.
	ErrMagicLinkNotFound = errors.New("magic link not found")
	// ErrMagicLinkExpired indicates that the magic link has expired.
	ErrMagicLinkExpired = errors.New("magic link has expired")
	// ErrMagicLinkUsed indicates that the magic link has already been used.
	ErrMagicLinkUsed = errors.New("magic link has already been used")
	// ErrMagicLinkRateLimited indicates too many magic link requests.
	ErrMagicLinkRateLimited = errors.New("too many magic link requests, please try again later")
)

// MagicLinkRequest represents a request to send a magic link.
type MagicLinkRequest struct {
	Email     string `json:"email"`
	IPAddress string `json:"-"`
	UserAgent string `json:"-"`
}

// MagicLinkResult represents the result of magic link verification.
type MagicLinkResult struct {
	User      *storage.User `json:"user"`
	TokenPair *TokenPair    `json:"tokens"`
	IsNewUser bool          `json:"is_new_user"`
}

// MagicLinkStorage interface for magic link operations.
type MagicLinkStorage interface {
	CreateMagicLink(ctx context.Context, link *storage.MagicLink) error
	GetMagicLinkByHash(ctx context.Context, tokenHash string) (*storage.MagicLink, error)
	MarkMagicLinkUsed(ctx context.Context, id uuid.UUID) error
	DeleteExpiredMagicLinks(ctx context.Context) error
	CountRecentMagicLinks(ctx context.Context, email string, since time.Time) (int, error)
}

// generateMagicLinkToken generates a secure random token for magic links.
func generateMagicLinkToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// SendMagicLink creates and returns a magic link token for the given email.
// The caller is responsible for sending the actual email.
func (s *AuthService) SendMagicLink(ctx context.Context, req *MagicLinkRequest, expiryMinutes int, rateLimit int) (string, error) {
	// Check rate limit
	recentCount, err := s.storage.(MagicLinkStorage).CountRecentMagicLinks(ctx, req.Email, time.Now().Add(-time.Hour))
	if err != nil {
		s.logger.Error("Failed to count recent magic links", "error", err)
		// Continue on error, fail open for availability
	} else if recentCount >= rateLimit {
		return "", ErrMagicLinkRateLimited
	}

	// Check if user exists
	user, err := s.storage.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return "", err
	}

	// Generate token
	token, err := generateMagicLinkToken()
	if err != nil {
		return "", err
	}

	// Create magic link record
	now := time.Now()
	link := &storage.MagicLink{
		ID:        uuid.New(),
		Email:     req.Email,
		TokenHash: utils.HashToken(token),
		ExpiresAt: now.Add(time.Duration(expiryMinutes) * time.Minute),
		CreatedAt: now,
	}

	if user != nil {
		link.UserID = &user.ID
	}

	if req.IPAddress != "" {
		link.IPAddress = &req.IPAddress
	}
	if req.UserAgent != "" {
		link.UserAgent = &req.UserAgent
	}

	if err := s.storage.(MagicLinkStorage).CreateMagicLink(ctx, link); err != nil {
		return "", err
	}

	s.logger.Info("Magic link created", "email", req.Email, "expires_at", link.ExpiresAt)
	return token, nil
}

// VerifyMagicLink verifies a magic link token and creates a session.
// If the user doesn't exist and allowRegistration is true, creates a new user.
func (s *AuthService) VerifyMagicLink(ctx context.Context, token string, allowRegistration bool) (*MagicLinkResult, error) {
	tokenHash := utils.HashToken(token)

	// Get magic link
	link, err := s.storage.(MagicLinkStorage).GetMagicLinkByHash(ctx, tokenHash)
	if err != nil {
		return nil, err
	}
	if link == nil {
		return nil, ErrMagicLinkNotFound
	}

	// Check if already used
	if link.UsedAt != nil {
		return nil, ErrMagicLinkUsed
	}

	// Check if expired
	if time.Now().After(link.ExpiresAt) {
		return nil, ErrMagicLinkExpired
	}

	// Mark as used
	if err := s.storage.(MagicLinkStorage).MarkMagicLinkUsed(ctx, link.ID); err != nil {
		return nil, err
	}

	// Get or create user
	var user *storage.User
	var isNewUser bool

	if link.UserID != nil {
		user, err = s.storage.GetUserByID(ctx, *link.UserID)
		if err != nil {
			return nil, err
		}
	} else {
		user, err = s.storage.GetUserByEmail(ctx, link.Email)
		if err != nil {
			return nil, err
		}
	}

	if user == nil {
		if !allowRegistration {
			return nil, ErrUserNotFound
		}

		// Create new user
		now := time.Now()
		user = &storage.User{
			ID:              uuid.New(),
			Email:           link.Email,
			HashedPassword:  "", // No password for magic link users
			IsEmailVerified: true, // Email is verified by magic link
			IsActive:        true,
			Timezone:        "UTC",
			Locale:          "en",
			CreatedAt:       now,
			UpdatedAt:       now,
		}

		if err := s.storage.CreateUser(ctx, user); err != nil {
			return nil, err
		}
		isNewUser = true
	}

	// Check if user is active
	if !user.IsActive {
		return nil, ErrUserInactive
	}

	// Create session
	now := time.Now()
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

	// Store refresh token
	refreshToken := &storage.RefreshToken{
		ID:        uuid.New(),
		SessionID: session.ID,
		TokenHash: utils.HashToken(tokenPair.RefreshToken),
		IssuedAt:  now,
		ExpiresAt: now.Add(7 * 24 * time.Hour),
		Revoked:   false,
	}

	if err := s.storage.CreateRefreshToken(ctx, refreshToken); err != nil {
		return nil, err
	}

	// Update last login
	user.LastLoginAt = &now
	if !user.IsEmailVerified {
		user.IsEmailVerified = true
	}
	if err := s.storage.UpdateUser(ctx, user); err != nil {
		s.logger.Warn("Failed to update user last login", "error", err)
	}

	s.logger.Info("Magic link verified", "user_id", user.ID, "is_new_user", isNewUser)

	return &MagicLinkResult{
		User:      user,
		TokenPair: tokenPair,
		IsNewUser: isNewUser,
	}, nil
}
