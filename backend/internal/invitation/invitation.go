// Package invitation provides user invitation management for ModernAuth.
package invitation

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/email"
	"github.com/iSundram/ModernAuth/internal/storage"
	"github.com/iSundram/ModernAuth/internal/utils"
)

var (
	// ErrInvitationNotFound indicates the invitation was not found.
	ErrInvitationNotFound = errors.New("invitation not found")
	// ErrInvitationExpired indicates the invitation has expired.
	ErrInvitationExpired = errors.New("invitation has expired")
	// ErrInvitationAlreadyAccepted indicates the invitation was already accepted.
	ErrInvitationAlreadyAccepted = errors.New("invitation already accepted")
	// ErrInvitationExists indicates an invitation already exists for this email.
	ErrInvitationExists = errors.New("invitation already exists for this email")
	// ErrUserAlreadyExists indicates the user already exists in the system.
	ErrUserAlreadyExists = errors.New("user already exists")
)

const (
	// DefaultInvitationTTL is the default invitation expiration time.
	DefaultInvitationTTL = 7 * 24 * time.Hour // 7 days
)

// Service provides invitation management operations.
type Service struct {
	invitationStorage storage.InvitationStorage
	userStorage       storage.UserStorage
	rbacStorage       storage.RBACStorage
	emailService      email.Service
	baseURL           string
	logger            *slog.Logger
}

// Config holds invitation service configuration.
type Config struct {
	BaseURL string
}

// NewService creates a new invitation service.
func NewService(
	invitationStore storage.InvitationStorage,
	userStore storage.UserStorage,
	emailSvc email.Service,
	cfg *Config,
) *Service {
	baseURL := "http://localhost:3000"
	if cfg != nil && cfg.BaseURL != "" {
		baseURL = cfg.BaseURL
	}

	return &Service{
		invitationStorage: invitationStore,
		userStorage:       userStore,
		emailService:      emailSvc,
		baseURL:           baseURL,
		logger:            slog.Default().With("component", "invitation_service"),
	}
}

// NewServiceWithRBAC creates a new invitation service with RBAC support for role assignment.
func NewServiceWithRBAC(
	invitationStore storage.InvitationStorage,
	userStore storage.UserStorage,
	rbacStore storage.RBACStorage,
	emailSvc email.Service,
	cfg *Config,
) *Service {
	svc := NewService(invitationStore, userStore, emailSvc, cfg)
	svc.rbacStorage = rbacStore
	return svc
}

// CreateInvitationRequest represents a request to create an invitation.
type CreateInvitationRequest struct {
	TenantID  *uuid.UUID  `json:"tenant_id,omitempty"`
	Email     string      `json:"email"`
	FirstName *string     `json:"first_name,omitempty"`
	LastName  *string     `json:"last_name,omitempty"`
	RoleIDs   []uuid.UUID `json:"role_ids,omitempty"`
	GroupIDs  []uuid.UUID `json:"group_ids,omitempty"`
	Message   *string     `json:"message,omitempty"`
	InvitedBy *uuid.UUID  `json:"invited_by,omitempty"`
	ExpiresIn *int        `json:"expires_in,omitempty"` // seconds, default 7 days
}

// CreateInvitationResult contains the created invitation and token.
type CreateInvitationResult struct {
	Invitation *storage.UserInvitation `json:"invitation"`
	Token      string                  `json:"token"` // Raw token for sending email
}

// CreateInvitation creates a new user invitation.
func (s *Service) CreateInvitation(ctx context.Context, req *CreateInvitationRequest) (*CreateInvitationResult, error) {
	// Check if user already exists
	existingUser, err := s.userStorage.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, err
	}
	if existingUser != nil {
		return nil, ErrUserAlreadyExists
	}

	// Check if there's already a pending invitation
	existing, err := s.invitationStorage.GetInvitationByEmail(ctx, req.TenantID, req.Email)
	if err != nil {
		return nil, err
	}
	if existing != nil && existing.AcceptedAt == nil && time.Now().Before(existing.ExpiresAt) {
		return nil, ErrInvitationExists
	}

	// Generate invitation token
	token, err := utils.GenerateRandomString(32)
	if err != nil {
		return nil, err
	}

	expiresIn := DefaultInvitationTTL
	if req.ExpiresIn != nil && *req.ExpiresIn > 0 {
		expiresIn = time.Duration(*req.ExpiresIn) * time.Second
	}

	now := time.Now()
	invitation := &storage.UserInvitation{
		ID:        uuid.New(),
		TenantID:  req.TenantID,
		Email:     req.Email,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		RoleIDs:   req.RoleIDs,
		GroupIDs:  req.GroupIDs,
		TokenHash: utils.HashToken(token),
		InvitedBy: req.InvitedBy,
		Message:   req.Message,
		ExpiresAt: now.Add(expiresIn),
		CreatedAt: now,
	}

	if err := s.invitationStorage.CreateInvitation(ctx, invitation); err != nil {
		return nil, err
	}

	// Send invitation email
	inviteURL := s.baseURL + "/accept-invitation?token=" + token
	if s.emailService != nil {
		inviterName := "Someone"
		tenantName := "ModernAuth"
		message := ""
		if req.Message != nil {
			message = *req.Message
		}

		if err := s.emailService.SendInvitationEmail(ctx, &email.InvitationEmail{
			Email:       req.Email,
			InviterName: inviterName,
			TenantName:  tenantName,
			InviteURL:   inviteURL,
			Message:     message,
			ExpiresAt:   invitation.ExpiresAt.Format(time.RFC3339),
		}); err != nil {
			s.logger.Error("Failed to send invitation email", "error", err, "email", req.Email)
			// Don't fail the invitation creation if email fails
		}
	}

	s.logger.Info("Invitation created", "invitation_id", invitation.ID, "email", req.Email)

	return &CreateInvitationResult{
		Invitation: invitation,
		Token:      token,
	}, nil
}

// GetInvitation retrieves an invitation by ID.
func (s *Service) GetInvitation(ctx context.Context, id uuid.UUID) (*storage.UserInvitation, error) {
	invitation, err := s.invitationStorage.GetInvitationByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if invitation == nil {
		return nil, ErrInvitationNotFound
	}
	return invitation, nil
}

// GetInvitationByToken retrieves an invitation by token.
func (s *Service) GetInvitationByToken(ctx context.Context, token string) (*storage.UserInvitation, error) {
	tokenHash := utils.HashToken(token)
	invitation, err := s.invitationStorage.GetInvitationByToken(ctx, tokenHash)
	if err != nil {
		return nil, err
	}
	if invitation == nil {
		return nil, ErrInvitationNotFound
	}
	return invitation, nil
}

// ValidateInvitation validates an invitation token.
func (s *Service) ValidateInvitation(ctx context.Context, token string) (*storage.UserInvitation, error) {
	invitation, err := s.GetInvitationByToken(ctx, token)
	if err != nil {
		return nil, err
	}

	if invitation.AcceptedAt != nil {
		return nil, ErrInvitationAlreadyAccepted
	}

	if time.Now().After(invitation.ExpiresAt) {
		return nil, ErrInvitationExpired
	}

	return invitation, nil
}

// AcceptInvitationRequest represents a request to accept an invitation.
type AcceptInvitationRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
	Username *string `json:"username,omitempty"`
}

// AcceptInvitation accepts an invitation and creates a user account.
func (s *Service) AcceptInvitation(ctx context.Context, req *AcceptInvitationRequest) (*storage.User, error) {
	// Validate the invitation
	invitation, err := s.ValidateInvitation(ctx, req.Token)
	if err != nil {
		return nil, err
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
		TenantID:        invitation.TenantID,
		Email:           invitation.Email,
		FirstName:       invitation.FirstName,
		LastName:        invitation.LastName,
		Username:        req.Username,
		HashedPassword:  hashedPassword,
		IsEmailVerified: true, // Email is verified since they received the invitation
		IsActive:        true,
		Timezone:        "UTC",
		Locale:          "en",
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	if err := s.userStorage.CreateUser(ctx, user); err != nil {
		return nil, err
	}

	// Mark invitation as accepted
	if err := s.invitationStorage.AcceptInvitation(ctx, invitation.ID); err != nil {
		s.logger.Error("Failed to mark invitation as accepted", "error", err, "invitation_id", invitation.ID)
	}

	// Assign roles from invitation if RBAC storage is configured
	if s.rbacStorage != nil && len(invitation.RoleIDs) > 0 {
		for _, roleID := range invitation.RoleIDs {
			if err := s.rbacStorage.AssignRoleToUser(ctx, user.ID, roleID, invitation.InvitedBy); err != nil {
				s.logger.Error("Failed to assign role to user from invitation",
					"error", err,
					"user_id", user.ID,
					"role_id", roleID,
				)
				// Continue with other roles - don't fail the whole invitation
			}
		}
		s.logger.Info("Assigned roles to invited user",
			"user_id", user.ID,
			"role_count", len(invitation.RoleIDs),
		)
	}

	s.logger.Info("Invitation accepted", "invitation_id", invitation.ID, "user_id", user.ID)

	return user, nil
}

// ListInvitations lists invitations for a tenant.
func (s *Service) ListInvitations(ctx context.Context, tenantID *uuid.UUID, limit, offset int) ([]*storage.UserInvitation, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	return s.invitationStorage.ListInvitations(ctx, tenantID, limit, offset)
}

// DeleteInvitation deletes an invitation.
func (s *Service) DeleteInvitation(ctx context.Context, id uuid.UUID) error {
	invitation, err := s.invitationStorage.GetInvitationByID(ctx, id)
	if err != nil {
		return err
	}
	if invitation == nil {
		return ErrInvitationNotFound
	}

	if err := s.invitationStorage.DeleteInvitation(ctx, id); err != nil {
		return err
	}

	s.logger.Info("Invitation deleted", "invitation_id", id)
	return nil
}

// ResendInvitation resends an invitation email.
func (s *Service) ResendInvitation(ctx context.Context, id uuid.UUID) error {
	invitation, err := s.invitationStorage.GetInvitationByID(ctx, id)
	if err != nil {
		return err
	}
	if invitation == nil {
		return ErrInvitationNotFound
	}

	if invitation.AcceptedAt != nil {
		return ErrInvitationAlreadyAccepted
	}

	// Generate new token
	token, err := utils.GenerateRandomString(32)
	if err != nil {
		return err
	}

	// Update invitation with new token and extended expiry
	invitation.TokenHash = utils.HashToken(token)
	invitation.ExpiresAt = time.Now().Add(DefaultInvitationTTL)

	// Update invitation in storage
	if err := s.invitationStorage.UpdateInvitation(ctx, invitation); err != nil {
		return err
	}

	// Send invitation email
	inviteURL := s.baseURL + "/accept-invitation?token=" + token
	if s.emailService != nil {
		if err := s.emailService.SendInvitationEmail(ctx, &email.InvitationEmail{
			Email:       invitation.Email,
			InviterName: "Someone",
			TenantName:  "ModernAuth",
			InviteURL:   inviteURL,
			Message:     "",
			ExpiresAt:   invitation.ExpiresAt.Format(time.RFC3339),
		}); err != nil {
			return err
		}
	}

	s.logger.Info("Invitation resent", "invitation_id", id, "email", invitation.Email)
	return nil
}

// CleanupExpired removes expired invitations.
func (s *Service) CleanupExpired(ctx context.Context) error {
	return s.invitationStorage.DeleteExpiredInvitations(ctx)
}
