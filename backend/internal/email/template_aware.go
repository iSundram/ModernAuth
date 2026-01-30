// Package email provides a template-aware email service wrapper.
package email

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
)

// TemplateAwareService wraps an email sender with template service support.
// It renders templates using the TemplateService and sends via the underlying sender.
type TemplateAwareService struct {
	sender          EmailSender
	templateService *TemplateService
	storage         storage.EmailTemplateStorage
	logger          *slog.Logger
}

// EmailSender defines the low-level email sending interface.
type EmailSender interface {
	SendEmail(to, subject, htmlBody, textBody string) error
}

// TemplateAwareConfig holds configuration for the template-aware service.
type TemplateAwareConfig struct {
	Sender          EmailSender
	TemplateService *TemplateService
	Storage         storage.EmailTemplateStorage
}

// NewTemplateAwareService creates a new template-aware email service.
func NewTemplateAwareService(cfg *TemplateAwareConfig) *TemplateAwareService {
	return &TemplateAwareService{
		sender:          cfg.Sender,
		templateService: cfg.TemplateService,
		storage:         cfg.Storage,
		logger:          slog.Default().With("component", "template_aware_email"),
	}
}

// getTenantID extracts tenant ID from user if available.
func getTenantID(user *storage.User) *uuid.UUID {
	if user != nil {
		return user.TenantID
	}
	return nil
}

// SendVerificationEmail sends an email verification email using templates.
func (s *TemplateAwareService) SendVerificationEmail(ctx context.Context, user *storage.User, token string, verifyURL string) error {
	tenantID := getTenantID(user)

	// Get branding
	branding, err := s.storage.GetEmailBranding(ctx, tenantID)
	if err != nil {
		s.logger.Warn("Failed to get branding, using defaults", "error", err)
	}

	// Create template variables
	vars := NewTemplateVars(user, branding).WithVerification(token, verifyURL)

	// Render template
	subject, htmlBody, textBody, err := s.templateService.RenderTemplate(ctx, tenantID, TemplateVerification, vars)
	if err != nil {
		return err
	}

	s.logger.Info("Sending verification email", "to", user.Email)
	return s.sender.SendEmail(user.Email, subject, htmlBody, textBody)
}

// SendPasswordResetEmail sends a password reset email using templates.
func (s *TemplateAwareService) SendPasswordResetEmail(ctx context.Context, user *storage.User, token string, resetURL string) error {
	tenantID := getTenantID(user)

	branding, _ := s.storage.GetEmailBranding(ctx, tenantID)
	vars := NewTemplateVars(user, branding).WithPasswordReset(token, resetURL)

	subject, htmlBody, textBody, err := s.templateService.RenderTemplate(ctx, tenantID, TemplatePasswordReset, vars)
	if err != nil {
		return err
	}

	s.logger.Info("Sending password reset email", "to", user.Email)
	return s.sender.SendEmail(user.Email, subject, htmlBody, textBody)
}

// SendWelcomeEmail sends a welcome email using templates.
func (s *TemplateAwareService) SendWelcomeEmail(ctx context.Context, user *storage.User) error {
	tenantID := getTenantID(user)

	branding, _ := s.storage.GetEmailBranding(ctx, tenantID)
	vars := NewTemplateVars(user, branding)
	if branding != nil {
		vars.BaseURL = branding.AppName // Use app name as base context
	}

	subject, htmlBody, textBody, err := s.templateService.RenderTemplate(ctx, tenantID, TemplateWelcome, vars)
	if err != nil {
		return err
	}

	s.logger.Info("Sending welcome email", "to", user.Email)
	return s.sender.SendEmail(user.Email, subject, htmlBody, textBody)
}

// SendLoginAlertEmail sends a login alert email using templates.
func (s *TemplateAwareService) SendLoginAlertEmail(ctx context.Context, user *storage.User, device *DeviceInfo) error {
	tenantID := getTenantID(user)

	branding, _ := s.storage.GetEmailBranding(ctx, tenantID)
	vars := NewTemplateVars(user, branding).WithDevice(device)

	subject, htmlBody, textBody, err := s.templateService.RenderTemplate(ctx, tenantID, TemplateLoginAlert, vars)
	if err != nil {
		return err
	}

	s.logger.Info("Sending login alert email", "to", user.Email)
	return s.sender.SendEmail(user.Email, subject, htmlBody, textBody)
}

// SendInvitationEmail sends an invitation email using templates.
func (s *TemplateAwareService) SendInvitationEmail(ctx context.Context, invitation *InvitationEmail) error {
	// For invitations, we don't have a user yet, so use nil tenant
	branding, _ := s.storage.GetEmailBranding(ctx, nil)
	vars := NewTemplateVars(nil, branding).WithInvitation(invitation)

	subject, htmlBody, textBody, err := s.templateService.RenderTemplate(ctx, nil, TemplateInvitation, vars)
	if err != nil {
		return err
	}

	s.logger.Info("Sending invitation email", "to", invitation.Email)
	return s.sender.SendEmail(invitation.Email, subject, htmlBody, textBody)
}

// SendMFAEnabledEmail sends MFA enabled notification using templates.
func (s *TemplateAwareService) SendMFAEnabledEmail(ctx context.Context, user *storage.User) error {
	tenantID := getTenantID(user)

	branding, _ := s.storage.GetEmailBranding(ctx, tenantID)
	vars := NewTemplateVars(user, branding)

	subject, htmlBody, textBody, err := s.templateService.RenderTemplate(ctx, tenantID, TemplateMFAEnabled, vars)
	if err != nil {
		return err
	}

	s.logger.Info("Sending MFA enabled email", "to", user.Email)
	return s.sender.SendEmail(user.Email, subject, htmlBody, textBody)
}

// SendPasswordChangedEmail sends password changed notification using templates.
func (s *TemplateAwareService) SendPasswordChangedEmail(ctx context.Context, user *storage.User) error {
	tenantID := getTenantID(user)

	branding, _ := s.storage.GetEmailBranding(ctx, tenantID)
	vars := NewTemplateVars(user, branding)

	subject, htmlBody, textBody, err := s.templateService.RenderTemplate(ctx, tenantID, TemplatePasswordChanged, vars)
	if err != nil {
		return err
	}

	s.logger.Info("Sending password changed email", "to", user.Email)
	return s.sender.SendEmail(user.Email, subject, htmlBody, textBody)
}

// SendSessionRevokedEmail sends session revoked notification using templates.
func (s *TemplateAwareService) SendSessionRevokedEmail(ctx context.Context, user *storage.User, reason string) error {
	tenantID := getTenantID(user)

	branding, _ := s.storage.GetEmailBranding(ctx, tenantID)
	vars := NewTemplateVars(user, branding).WithReason(reason)

	subject, htmlBody, textBody, err := s.templateService.RenderTemplate(ctx, tenantID, TemplateSessionRevoked, vars)
	if err != nil {
		return err
	}

	s.logger.Info("Sending session revoked email", "to", user.Email)
	return s.sender.SendEmail(user.Email, subject, htmlBody, textBody)
}

// SendMagicLink sends a magic link email for passwordless authentication.
func (s *TemplateAwareService) SendMagicLink(email string, magicLinkURL string) error {
	// Magic links don't need tenant-specific templates for now
	// Delegate to underlying sender which has basic implementation
	s.logger.Info("Sending magic link email", "to", email)
	
	subject := "Sign in to your account"
	
	// Extract name from email
	emailName := email
	if idx := len(email) - 1; idx >= 0 {
		for i := 0; i < len(email); i++ {
			if email[i] == '@' {
				emailName = email[:i]
				break
			}
		}
	}
	
	htmlBody := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Sign in</title></head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0;">Sign In</h1>
    </div>
    <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px;">
        <p>Hi %s,</p>
        <p>Click the button below to sign in to your account:</p>
        <div style="text-align: center; margin: 30px 0;">
            <a href="%s" style="background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-weight: bold;">Sign In</a>
        </div>
        <p style="color: #666; font-size: 14px;">This link will expire in 15 minutes.</p>
    </div>
</body>
</html>`, emailName, magicLinkURL)

	textBody := fmt.Sprintf("Hi %s,\n\nClick the link below to sign in:\n\n%s\n\nThis link will expire in 15 minutes.\n\nThanks,\nThe ModernAuth Team", emailName, magicLinkURL)

	return s.sender.SendEmail(email, subject, htmlBody, textBody)
}

// Verify TemplateAwareService implements Service interface
var _ Service = (*TemplateAwareService)(nil)
