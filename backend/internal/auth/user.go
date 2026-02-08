// Package auth provides authentication services for ModernAuth.
package auth

import (
	"context"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
)

// UpdateUserRequest represents a request to update user details.
type UpdateUserRequest struct {
	UserID   uuid.UUID `json:"user_id"`
	Email    *string   `json:"email,omitempty"`
	Username *string   `json:"username,omitempty"`
	Phone    *string   `json:"phone,omitempty"`
}

// UpdateOwnProfileRequest represents a request to update the current user's profile.
type UpdateOwnProfileRequest struct {
	UserID    uuid.UUID `json:"user_id"`
	FirstName *string   `json:"first_name,omitempty"`
	LastName  *string   `json:"last_name,omitempty"`
	Username  *string   `json:"username,omitempty"`
	Phone     *string   `json:"phone,omitempty"`
	AvatarURL *string   `json:"avatar_url,omitempty"`
	Timezone  *string   `json:"timezone,omitempty"`
	Locale    *string   `json:"locale,omitempty"`
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

// UpdateOwnProfile updates the current user's profile information.
func (s *AuthService) UpdateOwnProfile(ctx context.Context, req *UpdateOwnProfileRequest) (*storage.User, error) {
	user, err := s.storage.GetUserByID(ctx, req.UserID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}

	if req.FirstName != nil {
		user.FirstName = req.FirstName
	}
	if req.LastName != nil {
		user.LastName = req.LastName
	}
	if req.Username != nil {
		user.Username = req.Username
	}
	if req.Phone != nil {
		user.Phone = req.Phone
	}
	if req.AvatarURL != nil {
		user.AvatarURL = req.AvatarURL
	}
	if req.Timezone != nil {
		user.Timezone = *req.Timezone
	}
	if req.Locale != nil {
		user.Locale = *req.Locale
	}

	if err := s.storage.UpdateUser(ctx, user); err != nil {
		return nil, err
	}

	s.logAuditEvent(ctx, &req.UserID, nil, "user.profile_updated", nil, nil, nil)

	return user, nil
}
