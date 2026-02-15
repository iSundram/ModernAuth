// Package email provides a template-aware email service wrapper.
package email

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
)

// injectTrackingPixel injects a tracking pixel into the HTML body and stores a record in the database.
func (s *TemplateAwareService) injectTrackingPixel(ctx context.Context, htmlBody string, vars *TemplateVars, templateType TemplateType, recipient string, tenantID *uuid.UUID) (string, string) {
	pixelID := uuid.New()
	eventID := uuid.New().String()
	vars.EventID = eventID
	vars.TemplateType = string(templateType)

	// Create tracking pixel record in DB
	pixel := &storage.EmailTrackingPixel{
		ID:         pixelID,
		TenantID:   tenantID,
		Recipient:  recipient,
		TemplateID: string(templateType),
		IsOpened:   false,
		CreatedAt:  time.Now(),
	}

	if err := s.storage.CreateEmailTrackingPixel(ctx, pixel); err != nil {
		s.logger.Error("Failed to create tracking pixel record", "error", err)
		return htmlBody, eventID
	}

	renderedPixel, err := s.renderString(TrackingPixel, map[string]string{
		"BaseURL": s.baseURL,
		"PixelID": pixelID.String(),
	})
	if err != nil {
		return htmlBody, eventID
	}

	if idx := strings.LastIndex(strings.ToLower(htmlBody), "</body>"); idx != -1 {
		return htmlBody[:idx] + renderedPixel + htmlBody[idx:], eventID
	}
	return htmlBody + renderedPixel, eventID
}

// recordSentEvent records a sent email event in the database.
func (s *TemplateAwareService) recordSentEvent(ctx context.Context, user *storage.User, recipient string, templateType string, eventID string, templateID string, jobID string) {
	event := &storage.EmailEvent{
		ID:           uuid.New(),
		TenantID:     getTenantID(user),
		JobID:        &jobID,
		TemplateType: templateType,
		EventType:    "sent",
		Recipient:    recipient,
		EventID:      &eventID,
		Metadata: map[string]interface{}{
			"template_id": templateID,
		},
		CreatedAt: time.Now(),
	}
	if user != nil {
		event.UserID = &user.ID
	}

	if err := s.storage.CreateEmailEvent(ctx, event); err != nil {
		s.logger.Error("Failed to record email sent event", "error", err, "event_id", eventID)
	}
}

// recordEvent records a generic email event.
func (s *TemplateAwareService) recordEvent(ctx context.Context, user *storage.User, recipient string, templateType string, eventType string, jobID string) {
	event := &storage.EmailEvent{
		ID:           uuid.New(),
		TenantID:     getTenantID(user),
		JobID:        &jobID,
		TemplateType: templateType,
		EventType:    eventType,
		Recipient:    recipient,
		CreatedAt:    time.Now(),
	}
	if user != nil {
		event.UserID = &user.ID
	}

	if err := s.storage.CreateEmailEvent(ctx, event); err != nil {
		s.logger.Error("Failed to record email event", "error", err, "type", eventType)
	}
}

// TemplateAwareService wraps an email sender with template service support.
// It renders templates using the TemplateService and sends via the underlying sender.
type TemplateAwareService struct {
	sender          EmailSender
	templateService *TemplateService
	storage         storage.EmailTemplateStorage
	userStorage     storage.UserStorage
	baseURL         string
	logger          *slog.Logger
}

// TemplateAwareConfig holds configuration for the template-aware service.
type TemplateAwareConfig struct {
	Sender          EmailSender
	TemplateService *TemplateService
	Storage         storage.EmailTemplateStorage
	UserStorage     storage.UserStorage
	BaseURL         string
}

// NewTemplateAwareService creates a new template-aware email service.
func NewTemplateAwareService(cfg *TemplateAwareConfig) *TemplateAwareService {
	baseURL := strings.TrimSuffix(cfg.BaseURL, "/")
	return &TemplateAwareService{
		sender:          cfg.Sender,
		templateService: cfg.TemplateService,
		storage:         cfg.Storage,
		userStorage:     cfg.UserStorage,
		baseURL:         baseURL,
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

// sendTemplateEmail is a common helper to render and send templated emails.
func (s *TemplateAwareService) sendTemplateEmail(ctx context.Context, user *storage.User, recipient string, tt TemplateType, vars *TemplateVars) error {
	tenantID := getTenantID(user)

	// Check suppression list before sending
	if sup, err := s.storage.GetEmailSuppression(ctx, tenantID, recipient); err == nil && sup != nil {
		s.logger.Info("Skipping email to suppressed address", "email", recipient, "reason", sup.Reason)
		return fmt.Errorf("email address is suppressed: %s", sup.Reason)
	}

	subject, html, text, templateID, err := s.templateService.RenderTemplate(ctx, tenantID, tt, vars)
	if err != nil {
		return err
	}

	htmlWithTracking, eventID := s.injectTrackingPixel(ctx, html, vars, tt, recipient, tenantID)

	// Add click tracking to links
	htmlWithTracking = s.wrapLinksWithTracking(htmlWithTracking, eventID, string(tt), recipient, tenantID)

	jobID, err := s.sender.SendEmail(recipient, subject, htmlWithTracking, text)
	if err == nil {
		s.recordSentEvent(ctx, user, recipient, string(tt), eventID, templateID, jobID)

		// For synchronous senders (console, smtp), record delivery immediately
		// Check if it's NOT sendgrid. SendGrid URLs usually contain "sendgrid.com"
		if !strings.Contains(s.baseURL, "sendgrid.com") {
			s.recordEvent(ctx, user, recipient, string(tt), "delivered", jobID)
		}
	}
	return err
}

// SendVerificationEmail sends an email verification email using templates.
func (s *TemplateAwareService) SendVerificationEmail(ctx context.Context, user *storage.User, token string, verifyURL string) error {
	tenantID := getTenantID(user)
	branding, err := s.storage.GetEmailBranding(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get email branding", "error", err, "tenant_id", tenantID)
	}
	advanced, err := s.storage.GetEmailBrandingAdvanced(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get advanced email branding", "error", err, "tenant_id", tenantID)
	}

	vars := NewTemplateVars(user, branding, advanced).WithBaseURL(s.baseURL).WithVerification(token, verifyURL)
	return s.sendTemplateEmail(ctx, user, user.Email, TemplateVerification, vars)
}

// SendPasswordResetEmail sends a password reset email using templates.
func (s *TemplateAwareService) SendPasswordResetEmail(ctx context.Context, user *storage.User, token string, resetURL string) error {
	tenantID := getTenantID(user)
	branding, err := s.storage.GetEmailBranding(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get email branding", "error", err, "tenant_id", tenantID)
	}
	advanced, err := s.storage.GetEmailBrandingAdvanced(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get advanced email branding", "error", err, "tenant_id", tenantID)
	}

	vars := NewTemplateVars(user, branding, advanced).WithBaseURL(s.baseURL).WithPasswordReset(token, resetURL)
	return s.sendTemplateEmail(ctx, user, user.Email, TemplatePasswordReset, vars)
}

// SendWelcomeEmail sends a welcome email using templates.
func (s *TemplateAwareService) SendWelcomeEmail(ctx context.Context, user *storage.User) error {
	tenantID := getTenantID(user)
	branding, err := s.storage.GetEmailBranding(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get email branding", "error", err, "tenant_id", tenantID)
	}
	advanced, err := s.storage.GetEmailBrandingAdvanced(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get advanced email branding", "error", err, "tenant_id", tenantID)
	}

	vars := NewTemplateVars(user, branding, advanced).WithBaseURL(s.baseURL)
	return s.sendTemplateEmail(ctx, user, user.Email, TemplateWelcome, vars)
}

// SendLoginAlertEmail sends a login alert email using templates.
func (s *TemplateAwareService) SendLoginAlertEmail(ctx context.Context, user *storage.User, device *DeviceInfo) error {
	tenantID := getTenantID(user)
	branding, err := s.storage.GetEmailBranding(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get email branding", "error", err, "tenant_id", tenantID)
	}
	advanced, err := s.storage.GetEmailBrandingAdvanced(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get advanced email branding", "error", err, "tenant_id", tenantID)
	}

	vars := NewTemplateVars(user, branding, advanced).WithBaseURL(s.baseURL).WithDevice(device)
	return s.sendTemplateEmail(ctx, user, user.Email, TemplateLoginAlert, vars)
}

// SendInvitationEmail sends an invitation email using templates.
func (s *TemplateAwareService) SendInvitationEmail(ctx context.Context, invitation *InvitationEmail) error {
	branding, err := s.storage.GetEmailBranding(ctx, nil)
	if err != nil {
		s.logger.Error("Failed to get email branding", "error", err)
	}
	advanced, err := s.storage.GetEmailBrandingAdvanced(ctx, nil)
	if err != nil {
		s.logger.Error("Failed to get advanced email branding", "error", err)
	}

	vars := NewTemplateVars(nil, branding, advanced).WithBaseURL(s.baseURL).WithInvitation(invitation)
	return s.sendTemplateEmail(ctx, nil, invitation.Email, TemplateInvitation, vars)
}

// SendMFAEnabledEmail sends MFA enabled notification using templates.
func (s *TemplateAwareService) SendMFAEnabledEmail(ctx context.Context, user *storage.User) error {
	tenantID := getTenantID(user)
	branding, err := s.storage.GetEmailBranding(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get email branding", "error", err, "tenant_id", tenantID)
	}
	advanced, err := s.storage.GetEmailBrandingAdvanced(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get advanced email branding", "error", err, "tenant_id", tenantID)
	}

	vars := NewTemplateVars(user, branding, advanced).WithBaseURL(s.baseURL)
	return s.sendTemplateEmail(ctx, user, user.Email, TemplateMFAEnabled, vars)
}

// SendMFADisabledEmail sends MFA disabled notification using templates.
func (s *TemplateAwareService) SendMFADisabledEmail(ctx context.Context, user *storage.User) error {
	tenantID := getTenantID(user)
	branding, err := s.storage.GetEmailBranding(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get email branding", "error", err, "tenant_id", tenantID)
	}
	advanced, err := s.storage.GetEmailBrandingAdvanced(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get advanced email branding", "error", err, "tenant_id", tenantID)
	}

	vars := NewTemplateVars(user, branding, advanced).WithBaseURL(s.baseURL)
	return s.sendTemplateEmail(ctx, user, user.Email, TemplateMFADisabled, vars)
}

// SendMFACodeEmail sends MFA verification code.
func (s *TemplateAwareService) SendMFACodeEmail(ctx context.Context, email string, code string) error {
	var tenantID *uuid.UUID

	// Try to look up user to get tenant ID for branding
	if s.userStorage != nil {
		if user, err := s.userStorage.GetUserByEmail(ctx, email); err == nil && user != nil {
			tenantID = user.TenantID
		}
	}

	branding, err := s.storage.GetEmailBranding(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get email branding", "error", err, "tenant_id", tenantID)
	}
	advanced, err := s.storage.GetEmailBrandingAdvanced(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get advanced email branding", "error", err, "tenant_id", tenantID)
	}

	vars := NewTemplateVars(nil, branding, advanced).WithBaseURL(s.baseURL).WithMFACode(code)
	return s.sendTemplateEmail(ctx, nil, email, TemplateMFACode, vars)
}

// SendLowBackupCodesEmail sends notification when backup codes are running low.
func (s *TemplateAwareService) SendLowBackupCodesEmail(ctx context.Context, user *storage.User, remaining int) error {
	tenantID := getTenantID(user)
	branding, err := s.storage.GetEmailBranding(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get email branding", "error", err, "tenant_id", tenantID)
	}
	advanced, err := s.storage.GetEmailBrandingAdvanced(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get advanced email branding", "error", err, "tenant_id", tenantID)
	}

	vars := NewTemplateVars(user, branding, advanced).WithBaseURL(s.baseURL).WithRemainingCodes(remaining)
	return s.sendTemplateEmail(ctx, user, user.Email, TemplateLowBackupCodes, vars)
}

// SendPasswordChangedEmail sends password changed notification using templates.
func (s *TemplateAwareService) SendPasswordChangedEmail(ctx context.Context, user *storage.User) error {
	tenantID := getTenantID(user)
	branding, err := s.storage.GetEmailBranding(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get email branding", "error", err, "tenant_id", tenantID)
	}
	advanced, err := s.storage.GetEmailBrandingAdvanced(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get advanced email branding", "error", err, "tenant_id", tenantID)
	}

	vars := NewTemplateVars(user, branding, advanced).WithBaseURL(s.baseURL)
	return s.sendTemplateEmail(ctx, user, user.Email, TemplatePasswordChanged, vars)
}

// SendSessionRevokedEmail sends session revoked notification using templates.
func (s *TemplateAwareService) SendSessionRevokedEmail(ctx context.Context, user *storage.User, reason string) error {
	tenantID := getTenantID(user)
	branding, err := s.storage.GetEmailBranding(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get email branding", "error", err, "tenant_id", tenantID)
	}
	advanced, err := s.storage.GetEmailBrandingAdvanced(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get advanced email branding", "error", err, "tenant_id", tenantID)
	}

	vars := NewTemplateVars(user, branding, advanced).WithBaseURL(s.baseURL).WithReason(reason)
	return s.sendTemplateEmail(ctx, user, user.Email, TemplateSessionRevoked, vars)
}

// SendAccountDeactivatedEmail sends account deactivation notification.
func (s *TemplateAwareService) SendAccountDeactivatedEmail(ctx context.Context, user *storage.User, reason, reactivationURL string) error {
	tenantID := getTenantID(user)
	branding, err := s.storage.GetEmailBranding(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get email branding", "error", err, "tenant_id", tenantID)
	}
	advanced, err := s.storage.GetEmailBrandingAdvanced(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get advanced email branding", "error", err, "tenant_id", tenantID)
	}

	vars := NewTemplateVars(user, branding, advanced).WithBaseURL(s.baseURL).WithAccountDeactivation(reason, reactivationURL)
	return s.sendTemplateEmail(ctx, user, user.Email, TemplateAccountDeactivated, vars)
}

// SendEmailChangedEmail sends email change notification.
func (s *TemplateAwareService) SendEmailChangedEmail(ctx context.Context, user *storage.User, oldEmail, newEmail string) error {
	tenantID := getTenantID(user)
	branding, err := s.storage.GetEmailBranding(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get email branding", "error", err, "tenant_id", tenantID)
	}
	advanced, err := s.storage.GetEmailBrandingAdvanced(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get advanced email branding", "error", err, "tenant_id", tenantID)
	}

	vars := NewTemplateVars(user, branding, advanced).WithBaseURL(s.baseURL).WithEmailChange(oldEmail, newEmail)
	return s.sendTemplateEmail(ctx, user, oldEmail, TemplateEmailChanged, vars)
}

// SendPasswordExpiryEmail sends password expiry warning.
func (s *TemplateAwareService) SendPasswordExpiryEmail(ctx context.Context, user *storage.User, daysUntilExpiry, expiryDate, changePasswordURL string) error {
	tenantID := getTenantID(user)
	branding, err := s.storage.GetEmailBranding(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get email branding", "error", err, "tenant_id", tenantID)
	}
	advanced, err := s.storage.GetEmailBrandingAdvanced(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get advanced email branding", "error", err, "tenant_id", tenantID)
	}

	vars := NewTemplateVars(user, branding, advanced).WithBaseURL(s.baseURL).WithPasswordExpiry(daysUntilExpiry, expiryDate, changePasswordURL)
	return s.sendTemplateEmail(ctx, user, user.Email, TemplatePasswordExpiry, vars)
}

// SendSecurityAlertEmail sends security alert notification.
func (s *TemplateAwareService) SendSecurityAlertEmail(ctx context.Context, user *storage.User, title, message, details, actionURL, actionText string) error {
	tenantID := getTenantID(user)
	branding, err := s.storage.GetEmailBranding(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get email branding", "error", err, "tenant_id", tenantID)
	}
	advanced, err := s.storage.GetEmailBrandingAdvanced(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get advanced email branding", "error", err, "tenant_id", tenantID)
	}

	vars := NewTemplateVars(user, branding, advanced).WithBaseURL(s.baseURL).WithSecurityAlert(title, message, details, actionURL, actionText)
	return s.sendTemplateEmail(ctx, user, user.Email, TemplateSecurityAlert, vars)
}

// SendRateLimitWarningEmail sends rate limit warning notification.
func (s *TemplateAwareService) SendRateLimitWarningEmail(ctx context.Context, user *storage.User, actionType, currentCount, maxCount, timeWindow, upgradeURL string) error {
	tenantID := getTenantID(user)
	branding, err := s.storage.GetEmailBranding(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get email branding", "error", err, "tenant_id", tenantID)
	}
	advanced, err := s.storage.GetEmailBrandingAdvanced(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get advanced email branding", "error", err, "tenant_id", tenantID)
	}

	vars := NewTemplateVars(user, branding, advanced).WithBaseURL(s.baseURL).WithRateLimitWarning(actionType, currentCount, maxCount, timeWindow, upgradeURL)
	return s.sendTemplateEmail(ctx, user, user.Email, TemplateRateLimitWarning, vars)
}

// SendMagicLink sends a magic link email for passwordless authentication.
func (s *TemplateAwareService) SendMagicLink(ctx context.Context, email string, magicLinkURL string) error {
	var tenantID *uuid.UUID

	// Try to look up user to get tenant ID for branding
	if s.userStorage != nil {
		if user, err := s.userStorage.GetUserByEmail(ctx, email); err == nil && user != nil {
			tenantID = user.TenantID
		}
	}

	branding, err := s.storage.GetEmailBranding(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get email branding", "error", err, "tenant_id", tenantID)
	}
	advanced, err := s.storage.GetEmailBrandingAdvanced(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get advanced email branding", "error", err, "tenant_id", tenantID)
	}

	sampleUser := &storage.User{Email: email, TenantID: tenantID}
	vars := NewTemplateVars(sampleUser, branding, advanced).WithMagicLink(magicLinkURL)
	return s.sendTemplateEmail(ctx, sampleUser, email, TemplateMagicLink, vars)
}

var hrefRegexp = regexp.MustCompile(`href="([^"]+)"`)

// wrapLinksWithTracking rewrites URLs in the HTML body to route through the tracking endpoint.
func (s *TemplateAwareService) wrapLinksWithTracking(htmlBody, eventID, templateType, recipient string, tenantID *uuid.UUID) string {
	if s.baseURL == "" {
		return htmlBody
	}

	tid := "global"
	if tenantID != nil {
		tid = tenantID.String()
	}

	return hrefRegexp.ReplaceAllStringFunc(htmlBody, func(match string) string {
		submatch := hrefRegexp.FindStringSubmatch(match)
		if len(submatch) < 2 {
			return match
		}

		originalURL := submatch[1]
		// Don't track relative URLs or mailto/tel
		if strings.HasPrefix(originalURL, "#") || strings.HasPrefix(originalURL, "mailto:") || strings.HasPrefix(originalURL, "tel:") {
			return match
		}

		// Don't track URLs that are already tracking URLs
		if strings.Contains(originalURL, "/v1/email/track") {
			return match
		}

		trackingURL := fmt.Sprintf("%s/v1/email/track/click/%s?url=%s&recipient=%s&tenant_id=%s&event_id=%s",
			s.baseURL, templateType, url.QueryEscape(originalURL), url.QueryEscape(recipient), tid, eventID)
		return fmt.Sprintf(`href="%s"`, trackingURL)
	})
}

// Verify TemplateAwareService implements Service interface
var _ Service = (*TemplateAwareService)(nil)
