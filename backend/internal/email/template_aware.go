// Package email provides a template-aware email service wrapper.
package email

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
)

// injectTrackingPixel injects a tracking pixel into the HTML body.
func (s *TemplateAwareService) injectTrackingPixel(htmlBody string, vars *TemplateVars, templateType TemplateType) (string, string) {
	eventID := uuid.New().String()
	vars.EventID = eventID
	vars.TemplateType = string(templateType)

	pixel, err := s.renderString(TrackingPixel, map[string]string{
		"BaseURL":      vars.BaseURL,
		"Email":        vars.Email,
		"TemplateType": vars.TemplateType,
		"EventID":      vars.EventID,
	})
	if err != nil {
		return htmlBody, eventID
	}

	if idx := strings.LastIndex(strings.ToLower(htmlBody), "</body>"); idx != -1 {
		return htmlBody[:idx] + pixel + htmlBody[idx:], eventID
	}
	return htmlBody + pixel, eventID
}

// recordSentEvent records a sent email event in the database.
func (s *TemplateAwareService) recordSentEvent(ctx context.Context, user *storage.User, recipient string, templateType string, eventID string) {
	event := &storage.EmailEvent{
		ID:           uuid.New(),
		TenantID:     getTenantID(user),
		TemplateType: templateType,
		EventType:    "sent",
		Recipient:    recipient,
		EventID:      &eventID,
		CreatedAt:    time.Now(),
	}
	if user != nil {
		event.UserID = &user.ID
	}

	if err := s.storage.CreateEmailEvent(ctx, event); err != nil {
		s.logger.Error("Failed to record email sent event", "error", err, "event_id", eventID)
	}
}

// TemplateAwareService wraps an email sender with template service support.
// It renders templates using the TemplateService and sends via the underlying sender.
type TemplateAwareService struct {
	sender          EmailSender
	templateService *TemplateService
	storage         storage.EmailTemplateStorage
	baseURL         string
	logger          *slog.Logger
}

// TemplateAwareConfig holds configuration for the template-aware service.
type TemplateAwareConfig struct {
	Sender          EmailSender
	TemplateService *TemplateService
	Storage         storage.EmailTemplateStorage
	BaseURL         string
}

// NewTemplateAwareService creates a new template-aware email service.
func NewTemplateAwareService(cfg *TemplateAwareConfig) *TemplateAwareService {
	return &TemplateAwareService{
		sender:          cfg.Sender,
		templateService: cfg.TemplateService,
		storage:         cfg.Storage,
		baseURL:         cfg.BaseURL,
		logger:          slog.Default().With("component", "template_aware_email"),
	}
}

// renderString renders a template string with the given data.
func (s *TemplateAwareService) renderString(templateStr string, data map[string]string) (string, error) {
	tmpl, err := template.New("email").Parse(templateStr)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
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
	vars := NewTemplateVars(user, branding).WithBaseURL(s.baseURL).WithVerification(token, verifyURL)

	// Render template
	subject, htmlBody, textBody, err := s.templateService.RenderTemplate(ctx, tenantID, TemplateVerification, vars)
	if err != nil {
		return err
	}

	// Inject tracking pixel
	htmlWithTracking, eventID := s.injectTrackingPixel(htmlBody, vars, TemplateVerification)

	s.logger.Info("Sending verification email", "to", user.Email)
	err = s.sender.SendEmail(user.Email, subject, htmlWithTracking, textBody)
	if err == nil {
		s.recordSentEvent(ctx, user, user.Email, string(TemplateVerification), eventID)
	}
	return err
}

// SendPasswordResetEmail sends a password reset email using templates.
func (s *TemplateAwareService) SendPasswordResetEmail(ctx context.Context, user *storage.User, token string, resetURL string) error {
	tenantID := getTenantID(user)

	branding, err := s.storage.GetEmailBranding(ctx, tenantID)
	if err != nil {
		s.logger.Warn("Failed to get branding, using defaults", "error", err)
	}
	vars := NewTemplateVars(user, branding).WithBaseURL(s.baseURL).WithPasswordReset(token, resetURL)

	subject, htmlBody, textBody, err := s.templateService.RenderTemplate(ctx, tenantID, TemplatePasswordReset, vars)
	if err != nil {
		return err
	}

	// Inject tracking pixel
	htmlWithTracking, eventID := s.injectTrackingPixel(htmlBody, vars, TemplatePasswordReset)

	s.logger.Info("Sending password reset email", "to", user.Email)
	err = s.sender.SendEmail(user.Email, subject, htmlWithTracking, textBody)
	if err == nil {
		s.recordSentEvent(ctx, user, user.Email, string(TemplatePasswordReset), eventID)
	}
	return err
}

// SendWelcomeEmail sends a welcome email using templates.
func (s *TemplateAwareService) SendWelcomeEmail(ctx context.Context, user *storage.User) error {
	tenantID := getTenantID(user)

	branding, err := s.storage.GetEmailBranding(ctx, tenantID)
	if err != nil {
		s.logger.Warn("Failed to get branding, using defaults", "error", err)
	}
	vars := NewTemplateVars(user, branding).WithBaseURL(s.baseURL)

	subject, htmlBody, textBody, err := s.templateService.RenderTemplate(ctx, tenantID, TemplateWelcome, vars)
	if err != nil {
		return err
	}

	// Inject tracking pixel
	htmlWithTracking, eventID := s.injectTrackingPixel(htmlBody, vars, TemplateWelcome)

	s.logger.Info("Sending welcome email", "to", user.Email)
	err = s.sender.SendEmail(user.Email, subject, htmlWithTracking, textBody)
	if err == nil {
		s.recordSentEvent(ctx, user, user.Email, string(TemplateWelcome), eventID)
	}
	return err
}

// SendLoginAlertEmail sends a login alert email using templates.
func (s *TemplateAwareService) SendLoginAlertEmail(ctx context.Context, user *storage.User, device *DeviceInfo) error {
	tenantID := getTenantID(user)

	branding, err := s.storage.GetEmailBranding(ctx, tenantID)
	if err != nil {
		s.logger.Warn("Failed to get branding, using defaults", "error", err)
	}
	vars := NewTemplateVars(user, branding).WithBaseURL(s.baseURL).WithDevice(device)

	subject, htmlBody, textBody, err := s.templateService.RenderTemplate(ctx, tenantID, TemplateLoginAlert, vars)
	if err != nil {
		return err
	}

	// Inject tracking pixel
	htmlWithTracking, eventID := s.injectTrackingPixel(htmlBody, vars, TemplateLoginAlert)

	s.logger.Info("Sending login alert email", "to", user.Email)
	err = s.sender.SendEmail(user.Email, subject, htmlWithTracking, textBody)
	if err == nil {
		s.recordSentEvent(ctx, user, user.Email, string(TemplateLoginAlert), eventID)
	}
	return err
}

// SendInvitationEmail sends an invitation email using templates.
func (s *TemplateAwareService) SendInvitationEmail(ctx context.Context, invitation *InvitationEmail) error {
	// For invitations, we don't have a user yet, so use nil tenant
	branding, err := s.storage.GetEmailBranding(ctx, nil)
	if err != nil {
		s.logger.Warn("Failed to get branding, using defaults", "error", err)
	}
	vars := NewTemplateVars(nil, branding).WithBaseURL(s.baseURL).WithInvitation(invitation)

	subject, htmlBody, textBody, err := s.templateService.RenderTemplate(ctx, nil, TemplateInvitation, vars)
	if err != nil {
		return err
	}

	// Inject tracking pixel
	htmlWithTracking, eventID := s.injectTrackingPixel(htmlBody, vars, TemplateInvitation)

	s.logger.Info("Sending invitation email", "to", invitation.Email)
	err = s.sender.SendEmail(invitation.Email, subject, htmlWithTracking, textBody)
	if err == nil {
		s.recordSentEvent(ctx, nil, invitation.Email, string(TemplateInvitation), eventID)
	}
	return err
}

// SendMFAEnabledEmail sends MFA enabled notification using templates.
func (s *TemplateAwareService) SendMFAEnabledEmail(ctx context.Context, user *storage.User) error {
	tenantID := getTenantID(user)

	branding, err := s.storage.GetEmailBranding(ctx, tenantID)
	if err != nil {
		s.logger.Warn("Failed to get branding, using defaults", "error", err)
	}
	vars := NewTemplateVars(user, branding).WithBaseURL(s.baseURL)

	subject, htmlBody, textBody, err := s.templateService.RenderTemplate(ctx, tenantID, TemplateMFAEnabled, vars)
	if err != nil {
		return err
	}

	// Inject tracking pixel
	htmlWithTracking, eventID := s.injectTrackingPixel(htmlBody, vars, TemplateMFAEnabled)

	s.logger.Info("Sending MFA enabled email", "to", user.Email)
	err = s.sender.SendEmail(user.Email, subject, htmlWithTracking, textBody)
	if err == nil {
		s.recordSentEvent(ctx, user, user.Email, string(TemplateMFAEnabled), eventID)
	}
	return err
}

// SendMFACodeEmail sends MFA verification code.
func (s *TemplateAwareService) SendMFACodeEmail(ctx context.Context, email string, code string) error {
	branding, err := s.storage.GetEmailBranding(ctx, nil)
	if err != nil {
		s.logger.Warn("Failed to get branding, using defaults", "error", err)
	}

	vars := NewTemplateVars(nil, branding).WithBaseURL(s.baseURL).WithMFACode(code)

	subject, htmlBody, textBody, err := s.templateService.RenderTemplate(ctx, nil, TemplateMFACode, vars)
	if err != nil {
		return err
	}

	// Inject tracking pixel
	htmlWithTracking, eventID := s.injectTrackingPixel(htmlBody, vars, TemplateMFACode)

	s.logger.Info("Sending MFA code email", "to", email)
	err = s.sender.SendEmail(email, subject, htmlWithTracking, textBody)
	if err == nil {
		s.recordSentEvent(ctx, nil, email, string(TemplateMFACode), eventID)
	}
	return err
}

// SendLowBackupCodesEmail sends notification when backup codes are running low.
func (s *TemplateAwareService) SendLowBackupCodesEmail(ctx context.Context, user *storage.User, remaining int) error {
	tenantID := getTenantID(user)

	branding, err := s.storage.GetEmailBranding(ctx, tenantID)
	if err != nil {
		s.logger.Warn("Failed to get branding, using defaults", "error", err)
	}
	vars := NewTemplateVars(user, branding).WithBaseURL(s.baseURL).WithRemainingCodes(remaining)

	subject, htmlBody, textBody, err := s.templateService.RenderTemplate(ctx, tenantID, TemplateLowBackupCodes, vars)
	if err != nil {
		return err
	}

	// Inject tracking pixel
	htmlWithTracking, eventID := s.injectTrackingPixel(htmlBody, vars, TemplateLowBackupCodes)

	s.logger.Info("Sending low backup codes email", "to", user.Email, "remaining", remaining)
	err = s.sender.SendEmail(user.Email, subject, htmlWithTracking, textBody)
	if err == nil {
		s.recordSentEvent(ctx, user, user.Email, string(TemplateLowBackupCodes), eventID)
	}
	return err
}

// SendPasswordChangedEmail sends password changed notification using templates.
func (s *TemplateAwareService) SendPasswordChangedEmail(ctx context.Context, user *storage.User) error {
	tenantID := getTenantID(user)

	branding, err := s.storage.GetEmailBranding(ctx, tenantID)
	if err != nil {
		s.logger.Warn("Failed to get branding, using defaults", "error", err)
	}
	vars := NewTemplateVars(user, branding).WithBaseURL(s.baseURL)

	subject, htmlBody, textBody, err := s.templateService.RenderTemplate(ctx, tenantID, TemplatePasswordChanged, vars)
	if err != nil {
		return err
	}

	// Inject tracking pixel
	htmlWithTracking, eventID := s.injectTrackingPixel(htmlBody, vars, TemplatePasswordChanged)

	s.logger.Info("Sending password changed email", "to", user.Email)
	err = s.sender.SendEmail(user.Email, subject, htmlWithTracking, textBody)
	if err == nil {
		s.recordSentEvent(ctx, user, user.Email, string(TemplatePasswordChanged), eventID)
	}
	return err
}

// SendSessionRevokedEmail sends session revoked notification using templates.
func (s *TemplateAwareService) SendSessionRevokedEmail(ctx context.Context, user *storage.User, reason string) error {
	tenantID := getTenantID(user)

	branding, err := s.storage.GetEmailBranding(ctx, tenantID)
	if err != nil {
		s.logger.Warn("Failed to get branding, using defaults", "error", err)
	}
	vars := NewTemplateVars(user, branding).WithBaseURL(s.baseURL).WithReason(reason)

	subject, htmlBody, textBody, err := s.templateService.RenderTemplate(ctx, tenantID, TemplateSessionRevoked, vars)
	if err != nil {
		return err
	}

	// Inject tracking pixel
	htmlWithTracking, eventID := s.injectTrackingPixel(htmlBody, vars, TemplateSessionRevoked)

	s.logger.Info("Sending session revoked email", "to", user.Email)
	err = s.sender.SendEmail(user.Email, subject, htmlWithTracking, textBody)
	if err == nil {
		s.recordSentEvent(ctx, user, user.Email, string(TemplateSessionRevoked), eventID)
	}
	return err
}

// SendAccountDeactivatedEmail sends account deactivation notification.
func (s *TemplateAwareService) SendAccountDeactivatedEmail(ctx context.Context, user *storage.User, reason, reactivationURL string) error {
	tenantID := getTenantID(user)

	branding, err := s.storage.GetEmailBranding(ctx, tenantID)
	if err != nil {
		s.logger.Warn("Failed to get branding, using defaults", "error", err)
	}
	vars := NewTemplateVars(user, branding).WithBaseURL(s.baseURL).WithAccountDeactivation(reason, reactivationURL)

	subject, htmlBody, textBody, err := s.templateService.RenderTemplate(ctx, tenantID, TemplateAccountDeactivated, vars)
	if err != nil {
		return err
	}

	// Inject tracking pixel
	htmlWithTracking, eventID := s.injectTrackingPixel(htmlBody, vars, TemplateAccountDeactivated)

	s.logger.Info("Sending account deactivated email", "to", user.Email)
	err = s.sender.SendEmail(user.Email, subject, htmlWithTracking, textBody)
	if err == nil {
		s.recordSentEvent(ctx, user, user.Email, string(TemplateAccountDeactivated), eventID)
	}
	return err
}

// SendEmailChangedEmail sends email change notification.
func (s *TemplateAwareService) SendEmailChangedEmail(ctx context.Context, user *storage.User, oldEmail, newEmail string) error {
	tenantID := getTenantID(user)

	branding, err := s.storage.GetEmailBranding(ctx, tenantID)
	if err != nil {
		s.logger.Warn("Failed to get branding, using defaults", "error", err)
	}
	vars := NewTemplateVars(user, branding).WithBaseURL(s.baseURL).WithEmailChange(oldEmail, newEmail)

	subject, htmlBody, textBody, err := s.templateService.RenderTemplate(ctx, tenantID, TemplateEmailChanged, vars)
	if err != nil {
		return err
	}

	// Inject tracking pixel
	htmlWithTracking, eventID := s.injectTrackingPixel(htmlBody, vars, TemplateEmailChanged)

	s.logger.Info("Sending email changed notification", "to", oldEmail, "new_email", newEmail)
	err = s.sender.SendEmail(oldEmail, subject, htmlWithTracking, textBody)
	if err == nil {
		s.recordSentEvent(ctx, user, oldEmail, string(TemplateEmailChanged), eventID)
	}
	return err
}

// SendPasswordExpiryEmail sends password expiry warning.
func (s *TemplateAwareService) SendPasswordExpiryEmail(ctx context.Context, user *storage.User, daysUntilExpiry, expiryDate, changePasswordURL string) error {
	tenantID := getTenantID(user)

	branding, err := s.storage.GetEmailBranding(ctx, tenantID)
	if err != nil {
		s.logger.Warn("Failed to get branding, using defaults", "error", err)
	}
	vars := NewTemplateVars(user, branding).WithBaseURL(s.baseURL).WithPasswordExpiry(daysUntilExpiry, expiryDate, changePasswordURL)

	subject, htmlBody, textBody, err := s.templateService.RenderTemplate(ctx, tenantID, TemplatePasswordExpiry, vars)
	if err != nil {
		return err
	}

	// Inject tracking pixel
	htmlWithTracking, eventID := s.injectTrackingPixel(htmlBody, vars, TemplatePasswordExpiry)

	s.logger.Info("Sending password expiry warning", "to", user.Email, "days_until_expiry", daysUntilExpiry)
	err = s.sender.SendEmail(user.Email, subject, htmlWithTracking, textBody)
	if err == nil {
		s.recordSentEvent(ctx, user, user.Email, string(TemplatePasswordExpiry), eventID)
	}
	return err
}

// SendSecurityAlertEmail sends security alert notification.
func (s *TemplateAwareService) SendSecurityAlertEmail(ctx context.Context, user *storage.User, title, message, details, actionURL, actionText string) error {
	tenantID := getTenantID(user)

	branding, err := s.storage.GetEmailBranding(ctx, tenantID)
	if err != nil {
		s.logger.Warn("Failed to get branding, using defaults", "error", err)
	}
	vars := NewTemplateVars(user, branding).WithBaseURL(s.baseURL).WithSecurityAlert(title, message, details, actionURL, actionText)

	subject, htmlBody, textBody, err := s.templateService.RenderTemplate(ctx, tenantID, TemplateSecurityAlert, vars)
	if err != nil {
		return err
	}

	// Inject tracking pixel
	htmlWithTracking, eventID := s.injectTrackingPixel(htmlBody, vars, TemplateSecurityAlert)

	s.logger.Info("Sending security alert", "to", user.Email, "title", title)
	err = s.sender.SendEmail(user.Email, subject, htmlWithTracking, textBody)
	if err == nil {
		s.recordSentEvent(ctx, user, user.Email, string(TemplateSecurityAlert), eventID)
	}
	return err
}

// SendRateLimitWarningEmail sends rate limit warning notification.
func (s *TemplateAwareService) SendRateLimitWarningEmail(ctx context.Context, user *storage.User, actionType, currentCount, maxCount, timeWindow, upgradeURL string) error {
	tenantID := getTenantID(user)

	branding, err := s.storage.GetEmailBranding(ctx, tenantID)
	if err != nil {
		s.logger.Warn("Failed to get branding, using defaults", "error", err)
	}
	vars := NewTemplateVars(user, branding).WithBaseURL(s.baseURL).WithRateLimitWarning(actionType, currentCount, maxCount, timeWindow, upgradeURL)

	subject, htmlBody, textBody, err := s.templateService.RenderTemplate(ctx, tenantID, TemplateRateLimitWarning, vars)
	if err != nil {
		return err
	}

	// Inject tracking pixel
	htmlWithTracking, eventID := s.injectTrackingPixel(htmlBody, vars, TemplateRateLimitWarning)

	s.logger.Info("Sending rate limit warning", "to", user.Email, "action", actionType)
	err = s.sender.SendEmail(user.Email, subject, htmlWithTracking, textBody)
	if err == nil {
		s.recordSentEvent(ctx, user, user.Email, string(TemplateRateLimitWarning), eventID)
	}
	return err
}

// SendMagicLink sends a magic link email for passwordless authentication.
func (s *TemplateAwareService) SendMagicLink(ctx context.Context, email string, magicLinkURL string) error {
	s.logger.Info("Sending magic link email", "to", email)

	branding, err := s.storage.GetEmailBranding(ctx, nil)
	if err != nil {
		s.logger.Warn("Failed to get branding, using defaults", "error", err)
	}

	sampleUser := &storage.User{
		Email: email,
	}

	vars := NewTemplateVars(sampleUser, branding).WithMagicLink(magicLinkURL)

	subject, htmlBody, textBody, err := s.templateService.RenderTemplate(ctx, nil, TemplateMagicLink, vars)
	if err != nil {
		return err
	}

	// Inject tracking pixel
	htmlWithTracking, eventID := s.injectTrackingPixel(htmlBody, vars, TemplateMagicLink)

	err = s.sender.SendEmail(email, subject, htmlWithTracking, textBody)
	if err == nil {
		s.recordSentEvent(ctx, nil, email, string(TemplateMagicLink), eventID)
	}
	return err
}

// Verify TemplateAwareService implements Service interface
var _ Service = (*TemplateAwareService)(nil)
