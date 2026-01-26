// Package email provides the template service for email rendering.
package email

import (
	"bytes"
	"context"
	"html/template"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
)

// TemplateType defines the types of email templates.
type TemplateType string

const (
	TemplateVerification    TemplateType = "verification"
	TemplatePasswordReset   TemplateType = "password_reset"
	TemplateWelcome         TemplateType = "welcome"
	TemplateLoginAlert      TemplateType = "login_alert"
	TemplateInvitation      TemplateType = "invitation"
	TemplateMFAEnabled      TemplateType = "mfa_enabled"
	TemplatePasswordChanged TemplateType = "password_changed"
	TemplateSessionRevoked  TemplateType = "session_revoked"
)

// AllTemplateTypes returns all available template types.
func AllTemplateTypes() []TemplateType {
	return []TemplateType{
		TemplateVerification,
		TemplatePasswordReset,
		TemplateWelcome,
		TemplateLoginAlert,
		TemplateInvitation,
		TemplateMFAEnabled,
		TemplatePasswordChanged,
		TemplateSessionRevoked,
	}
}

// TemplateService handles email template loading and rendering.
type TemplateService struct {
	storage storage.EmailTemplateStorage
	logger  *slog.Logger

	// Cache for compiled templates
	cache    map[string]*cachedTemplate
	cacheMu  sync.RWMutex
	cacheTTL time.Duration
}

type cachedTemplate struct {
	template  *storage.EmailTemplate
	branding  *storage.EmailBranding
	expiresAt time.Time
}

// NewTemplateService creates a new template service.
func NewTemplateService(store storage.EmailTemplateStorage) *TemplateService {
	return &TemplateService{
		storage:  store,
		logger:   slog.Default().With("component", "email_template_service"),
		cache:    make(map[string]*cachedTemplate),
		cacheTTL: 5 * time.Minute,
	}
}

// cacheKey generates a cache key for tenant+type combination.
func cacheKey(tenantID *uuid.UUID, templateType TemplateType) string {
	tid := "global"
	if tenantID != nil {
		tid = tenantID.String()
	}
	return tid + ":" + string(templateType)
}

// GetTemplate retrieves a template by type, with tenant-specific override support.
func (s *TemplateService) GetTemplate(ctx context.Context, tenantID *uuid.UUID, templateType TemplateType) (*storage.EmailTemplate, error) {
	key := cacheKey(tenantID, templateType)

	// Check cache
	s.cacheMu.RLock()
	if cached, ok := s.cache[key]; ok && time.Now().Before(cached.expiresAt) {
		s.cacheMu.RUnlock()
		if cached.template != nil {
			return cached.template, nil
		}
	} else {
		s.cacheMu.RUnlock()
	}

	// Load from database
	template, err := s.storage.GetEmailTemplate(ctx, tenantID, string(templateType))
	if err != nil {
		return nil, err
	}

	// If no tenant-specific template, try global
	if template == nil && tenantID != nil {
		template, err = s.storage.GetEmailTemplate(ctx, nil, string(templateType))
		if err != nil {
			return nil, err
		}
	}

	// Cache result (even if nil, to avoid repeated DB lookups)
	s.cacheMu.Lock()
	s.cache[key] = &cachedTemplate{
		template:  template,
		expiresAt: time.Now().Add(s.cacheTTL),
	}
	s.cacheMu.Unlock()

	return template, nil
}

// GetBranding retrieves branding for a tenant.
func (s *TemplateService) GetBranding(ctx context.Context, tenantID *uuid.UUID) (*storage.EmailBranding, error) {
	key := "branding:" + cacheKey(tenantID, "")

	// Check cache
	s.cacheMu.RLock()
	if cached, ok := s.cache[key]; ok && time.Now().Before(cached.expiresAt) {
		s.cacheMu.RUnlock()
		return cached.branding, nil
	}
	s.cacheMu.RUnlock()

	// Load from database
	branding, err := s.storage.GetEmailBranding(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	// Cache result
	s.cacheMu.Lock()
	s.cache[key] = &cachedTemplate{
		branding:  branding,
		expiresAt: time.Now().Add(s.cacheTTL),
	}
	s.cacheMu.Unlock()

	return branding, nil
}

// RenderTemplate renders a template with the given variables.
func (s *TemplateService) RenderTemplate(ctx context.Context, tenantID *uuid.UUID, templateType TemplateType, vars *TemplateVars) (subject, htmlBody, textBody string, err error) {
	// Get custom template from DB
	customTemplate, err := s.GetTemplate(ctx, tenantID, templateType)
	if err != nil {
		s.logger.Error("Failed to get custom template", "type", templateType, "error", err)
		// Fall back to default
	}

	if customTemplate != nil && customTemplate.IsActive {
		// Render custom template
		subject, err = s.renderString(customTemplate.Subject, vars)
		if err != nil {
			return "", "", "", err
		}
		htmlBody, err = s.renderString(customTemplate.HTMLBody, vars)
		if err != nil {
			return "", "", "", err
		}
		if customTemplate.TextBody != nil {
			textBody, err = s.renderString(*customTemplate.TextBody, vars)
			if err != nil {
				return "", "", "", err
			}
		}
		return subject, htmlBody, textBody, nil
	}

	// Use built-in default template
	return s.renderDefaultTemplate(templateType, vars)
}

// renderString renders a template string with variables.
func (s *TemplateService) renderString(templateStr string, vars *TemplateVars) (string, error) {
	tmpl, err := template.New("email").Parse(templateStr)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, vars); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// renderDefaultTemplate renders the built-in default template.
func (s *TemplateService) renderDefaultTemplate(templateType TemplateType, vars *TemplateVars) (subject, htmlBody, textBody string, err error) {
	switch templateType {
	case TemplateVerification:
		subject = "Verify your email address"
		htmlBody, err = s.renderString(verificationEmailHTML, vars)
		if err != nil {
			return "", "", "", err
		}
		textBody = "Hi " + vars.FullName + ",\n\nPlease verify your email address by clicking the link below:\n\n" + vars.VerifyURL + "\n\nIf you didn't create an account, you can safely ignore this email.\n\nThanks,\nThe " + vars.AppName + " Team"

	case TemplatePasswordReset:
		subject = "Reset your password"
		htmlBody, err = s.renderString(passwordResetEmailHTML, vars)
		if err != nil {
			return "", "", "", err
		}
		textBody = "Hi " + vars.FullName + ",\n\nYou requested to reset your password. Click the link below:\n\n" + vars.ResetURL + "\n\nThis link will expire in 1 hour.\n\nIf you didn't request this, you can safely ignore this email.\n\nThanks,\nThe " + vars.AppName + " Team"

	case TemplateWelcome:
		subject = "Welcome to " + vars.AppName
		htmlBody, err = s.renderString(welcomeEmailHTML, vars)
		if err != nil {
			return "", "", "", err
		}
		textBody = "Hi " + vars.FullName + ",\n\nWelcome to " + vars.AppName + "! Your account has been created successfully.\n\nThanks,\nThe " + vars.AppName + " Team"

	case TemplateLoginAlert:
		subject = "New login to your account"
		htmlBody, err = s.renderString(loginAlertEmailHTML, vars)
		if err != nil {
			return "", "", "", err
		}
		textBody = "Hi " + vars.FullName + ",\n\nWe noticed a new login to your account:\n\nDevice: " + vars.DeviceName + "\nBrowser: " + vars.Browser + "\nOS: " + vars.OS + "\nIP Address: " + vars.IPAddress + "\nLocation: " + vars.Location + "\nTime: " + vars.Time + "\n\nIf this wasn't you, please change your password immediately.\n\nThanks,\nThe " + vars.AppName + " Team"

	case TemplateInvitation:
		subject = "You've been invited to join " + vars.TenantName
		htmlBody, err = s.renderString(invitationEmailHTML, vars)
		if err != nil {
			return "", "", "", err
		}
		textBody = "Hi,\n\n" + vars.InviterName + " has invited you to join " + vars.TenantName + ".\n\n" + vars.Message + "\n\nClick the link below to accept:\n" + vars.InviteURL + "\n\nThis invitation expires on " + vars.ExpiresAt + ".\n\nThanks,\nThe " + vars.AppName + " Team"

	case TemplateMFAEnabled:
		subject = "Two-factor authentication enabled"
		htmlBody, err = s.renderString(mfaEnabledEmailHTML, vars)
		if err != nil {
			return "", "", "", err
		}
		textBody = "Hi " + vars.FullName + ",\n\nTwo-factor authentication has been enabled on your account. Your account is now more secure.\n\nIf you didn't do this, please contact support immediately.\n\nThanks,\nThe " + vars.AppName + " Team"

	case TemplatePasswordChanged:
		subject = "Your password was changed"
		htmlBody, err = s.renderString(passwordChangedEmailHTML, vars)
		if err != nil {
			return "", "", "", err
		}
		textBody = "Hi " + vars.FullName + ",\n\nYour password has been changed. If you didn't do this, please reset your password immediately and contact support.\n\nThanks,\nThe " + vars.AppName + " Team"

	case TemplateSessionRevoked:
		subject = "Your session was terminated"
		htmlBody, err = s.renderString(sessionRevokedEmailHTML, vars)
		if err != nil {
			return "", "", "", err
		}
		textBody = "Hi " + vars.FullName + ",\n\nYour session has been terminated.\n\nReason: " + vars.Reason + "\n\nIf you didn't do this, please check your account security.\n\nThanks,\nThe " + vars.AppName + " Team"

	default:
		s.logger.Warn("Unknown template type", "type", templateType)
		return "", "", "", nil
	}

	return subject, htmlBody, textBody, nil
}

// InvalidateCache clears the cache for a specific tenant and template type.
func (s *TemplateService) InvalidateCache(tenantID *uuid.UUID, templateType TemplateType) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	key := cacheKey(tenantID, templateType)
	delete(s.cache, key)

	// Also invalidate branding cache
	brandingKey := "branding:" + cacheKey(tenantID, "")
	delete(s.cache, brandingKey)
}

// InvalidateAllCache clears the entire cache.
func (s *TemplateService) InvalidateAllCache() {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	s.cache = make(map[string]*cachedTemplate)
}
