// Package auth provides authentication services for ModernAuth.
// This file contains password history functionality for preventing password reuse.
package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
	"github.com/iSundram/ModernAuth/internal/utils"
)

var (
	// ErrPasswordReused indicates that the password was recently used.
	ErrPasswordReused = errors.New("password was recently used, please choose a different password")
)

// PasswordHistoryStorage interface for password history operations.
type PasswordHistoryStorage interface {
	AddPasswordHistory(ctx context.Context, userID uuid.UUID, passwordHash string) error
	GetPasswordHistory(ctx context.Context, userID uuid.UUID, limit int) ([]*storage.PasswordHistory, error)
	CleanupOldPasswordHistory(ctx context.Context, userID uuid.UUID, keepCount int) error
}

// CheckPasswordHistory checks if a password was recently used.
func (s *AuthService) CheckPasswordHistory(ctx context.Context, userID uuid.UUID, newPassword string, historyDepth int) error {
	if historyDepth <= 0 {
		return nil // Password history check disabled
	}

	historyStorage, ok := s.storage.(PasswordHistoryStorage)
	if !ok {
		s.logger.Warn("Storage does not support password history")
		return nil
	}

	// Get password history
	history, err := historyStorage.GetPasswordHistory(ctx, userID, historyDepth)
	if err != nil {
		s.logger.Error("Failed to get password history", "error", err)
		return nil // Fail open - don't block password change on history check failure
	}

	// Check against each historical password
	for _, h := range history {
		match, err := utils.VerifyPassword(newPassword, h.PasswordHash)
		if err != nil {
			s.logger.Error("Failed to verify password against history", "error", err)
			continue
		}
		if match {
			return ErrPasswordReused
		}
	}

	return nil
}

// AddToPasswordHistory adds the current password to history before changing it.
func (s *AuthService) AddToPasswordHistory(ctx context.Context, userID uuid.UUID, passwordHash string, keepCount int) error {
	historyStorage, ok := s.storage.(PasswordHistoryStorage)
	if !ok {
		s.logger.Warn("Storage does not support password history")
		return nil
	}

	// Add to history
	if err := historyStorage.AddPasswordHistory(ctx, userID, passwordHash); err != nil {
		s.logger.Error("Failed to add password to history", "error", err)
		return err
	}

	// Cleanup old entries
	if err := historyStorage.CleanupOldPasswordHistory(ctx, userID, keepCount); err != nil {
		s.logger.Warn("Failed to cleanup old password history", "error", err)
		// Don't fail on cleanup error
	}

	return nil
}

// ChangePasswordWithHistory changes the user's password with history check.
func (s *AuthService) ChangePasswordWithHistory(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string, historyDepth int) error {
	// Get user
	user, err := s.storage.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	// Verify current password
	match, err := utils.VerifyPassword(currentPassword, user.HashedPassword)
	if err != nil {
		return err
	}
	if !match {
		return ErrInvalidCredentials
	}

	// Check password against known data breaches (HIBP)
	if s.hibpService != nil {
		result, err := s.hibpService.CheckPassword(ctx, newPassword)
		if err != nil {
			s.logger.Warn("HIBP check failed during password change with history", "error", err)
			// Don't block password change on HIBP API errors
		} else if result.IsBreached {
			return fmt.Errorf("this password has appeared in %d data breaches and cannot be used", result.Count)
		}
	}

	// Check password history
	if err := s.CheckPasswordHistory(ctx, userID, newPassword, historyDepth); err != nil {
		return err
	}

	// Add current password to history before changing
	if err := s.AddToPasswordHistory(ctx, userID, user.HashedPassword, historyDepth); err != nil {
		return err
	}

	// Hash new password
	hashedPassword, err := utils.HashPassword(newPassword, nil)
	if err != nil {
		return err
	}

	// Update password
	user.HashedPassword = hashedPassword
	if err := s.storage.UpdateUser(ctx, user); err != nil {
		return err
	}

	s.logger.Info("Password changed with history check", "user_id", userID)
	return nil
}
