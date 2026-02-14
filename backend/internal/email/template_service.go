// Package email provides the template service for email rendering.
package email

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
)

// TemplateType defines the types of email templates.
type TemplateType string

const (
	TemplateVerification       TemplateType = "verification"
	TemplatePasswordReset      TemplateType = "password_reset"
	TemplateWelcome            TemplateType = "welcome"
	TemplateLoginAlert         TemplateType = "login_alert"
	TemplateInvitation         TemplateType = "invitation"
	TemplateMFAEnabled         TemplateType = "mfa_enabled"
	TemplateMFADisabled        TemplateType = "mfa_disabled"
	TemplateMFACode            TemplateType = "mfa_code"
	TemplateLowBackupCodes     TemplateType = "low_backup_codes"
	TemplatePasswordChanged    TemplateType = "password_changed"
	TemplateSessionRevoked     TemplateType = "session_revoked"
	TemplateAccountDeactivated TemplateType = "account_deactivated"
	TemplateEmailChanged       TemplateType = "email_changed"
	TemplatePasswordExpiry     TemplateType = "password_expiry"
	TemplateSecurityAlert      TemplateType = "security_alert"
	TemplateRateLimitWarning   TemplateType = "rate_limit_warning"
	TemplateMagicLink          TemplateType = "magic_link"
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
		TemplateMFADisabled,
		TemplateMFACode,
		TemplateLowBackupCodes,
		TemplatePasswordChanged,
		TemplateSessionRevoked,
		TemplateAccountDeactivated,
		TemplateEmailChanged,
		TemplatePasswordExpiry,
		TemplateSecurityAlert,
		TemplateRateLimitWarning,
		TemplateMagicLink,
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
func (s *TemplateService) RenderTemplate(ctx context.Context, tenantID *uuid.UUID, templateType TemplateType, vars *TemplateVars) (subject, htmlBody, textBody string, templateID string, err error) {
	// Pre-render footer if it contains variables
	if strings.Contains(vars.FooterText, "{{") {
		renderedFooter, err := s.renderString(vars.FooterText, vars)
		if err == nil {
			vars.FooterText = renderedFooter
		}
	}

	// Load advanced branding
	advanced, _ := s.storage.GetEmailBrandingAdvanced(ctx, tenantID)
	if advanced != nil {
		if vars.HeaderImageURL == "" && advanced.HeaderImageURL != nil {
			vars.HeaderImageURL = *advanced.HeaderImageURL
		}
		if vars.CustomCSS == "" && advanced.CustomCSS != nil {
			vars.CustomCSS = *advanced.CustomCSS
		}
		if vars.FontFamily == "" && advanced.FontFamily != nil {
			vars.FontFamily = *advanced.FontFamily
		}
		if vars.FontFamilyURL == "" && advanced.FontFamilyURL != nil {
			vars.FontFamilyURL = *advanced.FontFamilyURL
		}
		if vars.FacebookURL == "" && advanced.SocialLinks != nil && advanced.SocialLinks.Facebook != nil {
			vars.FacebookURL = *advanced.SocialLinks.Facebook
		}
	}

	// Check for active A/B tests
	variantID := ""
	abTests, err := s.storage.ListEmailABTests(ctx, tenantID)
	if err == nil {
		for _, test := range abTests {
			if test.TemplateType == string(templateType) && test.IsActive {
				if s.selectDeterministicVariant(vars.Email, test.WeightA) {
					variantID = test.VariantA
				} else {
					variantID = test.VariantB
				}
				break
			}
		}
	}

	// Get custom template from DB
	var customTemplate *storage.EmailTemplate
	if variantID != "" {
		customTemplate, err = s.storage.GetEmailTemplate(ctx, tenantID, variantID)
	}

	if customTemplate == nil {
		customTemplate, err = s.GetTemplate(ctx, tenantID, templateType)
	}

	if customTemplate != nil && customTemplate.IsActive {
		subject, err = s.renderString(customTemplate.Subject, vars)
		if err != nil {
			return "", "", "", "", err
		}

		htmlBody = customTemplate.HTMLBody
		if !strings.Contains(strings.ToLower(htmlBody), "<html") {
			htmlBody, err = s.renderWithLayout(customTemplate.Subject, customTemplate.HTMLBody, vars)
		} else {
			htmlBody, err = s.renderString(htmlBody, vars)
		}

		if err != nil {
			return "", "", "", "", err
		}

		if customTemplate.TextBody != nil {
			textBody, err = s.renderString(*customTemplate.TextBody, vars)
			if err != nil {
				return "", "", "", "", err
			}
		}
		return subject, htmlBody, textBody, customTemplate.ID.String(), nil
	}

	// Use built-in default template
	subject, htmlBody, textBody, err = s.renderDefaultTemplate(templateType, vars)
	return subject, htmlBody, textBody, "default:" + string(templateType), err
}

// GetDefaultTemplateContent returns the raw HTML and Text content of a default template.

func (s *TemplateService) GetDefaultTemplateContent(templateType TemplateType) (html, text string, err error) {

	templateName := string(templateType)

	

	htmlPath := fmt.Sprintf("defaults/%s.html", templateName)

	htmlBytes, err := DefaultTemplatesFS.ReadFile(htmlPath)

	if err != nil {

		return "", "", fmt.Errorf("default template not found: %s", htmlPath)

	}



	textPath := fmt.Sprintf("defaults/%s.txt", templateName)

	textBytes, _ := DefaultTemplatesFS.ReadFile(textPath)



	return string(htmlBytes), string(textBytes), nil

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



// selectDeterministicVariant returns true if variant A should be selected based on email hash.



func (s *TemplateService) selectDeterministicVariant(email string, weightA float64) bool {




	if email == "" {
		return (float64(time.Now().UnixNano()%100) / 100.0) < weightA
	}
	// Simple hash-based selection
	var hash uint32 = 0
	for i := 0; i < len(email); i++ {
		hash = uint32(email[i]) + (hash << 6) + (hash << 16) - hash
	}
	return float64(hash%100) < (weightA * 100)
}

// renderWithLayout wraps content in the master layout.
func (s *TemplateService) renderWithLayout(title, content string, vars *TemplateVars) (string, error) {
	layoutContent, err := DefaultTemplatesFS.ReadFile("defaults/layout.html")
	if err != nil {
		return "", err
	}

	tmpl, err := template.New("layout").Parse(string(layoutContent))
	if err != nil {
		return "", err
	}

	// Add the content block
	_, err = tmpl.New("content").Parse(content)
	if err != nil {
		return "", err
	}

	// Add the title block
	_, err = tmpl.New("title").Parse(title)
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
	templateName := string(templateType)
	lang := vars.LanguageCode
	if lang == "" {
		lang = "en"
	}

	// Try localized HTML template first
	var htmlContent []byte
	if lang != "en" {
		htmlPath := fmt.Sprintf("defaults/%s_%s.html", templateName, lang)
		htmlContent, _ = DefaultTemplatesFS.ReadFile(htmlPath)
	}

	// Fallback to default HTML
	if len(htmlContent) == 0 {
		htmlPath := fmt.Sprintf("defaults/%s.html", templateName)
		htmlContent, err = DefaultTemplatesFS.ReadFile(htmlPath)
		if err != nil {
			return "", "", "", fmt.Errorf("default template not found: %s", htmlPath)
		}
	}

	// Try localized Text template first
	var textContent []byte
	if lang != "en" {
		textPath := fmt.Sprintf("defaults/%s_%s.txt", templateName, lang)
		textContent, _ = DefaultTemplatesFS.ReadFile(textPath)
	}

	// Fallback to default Text
	if len(textContent) == 0 {
		textPath := fmt.Sprintf("defaults/%s.txt", templateName)
		textContent, _ = DefaultTemplatesFS.ReadFile(textPath)
	}

	// Parse layout and template
	layoutContent, err := DefaultTemplatesFS.ReadFile("defaults/layout.html")
	if err != nil {
		return "", "", "", err
	}

	tmpl, err := template.New("layout").Parse(string(layoutContent))
	if err != nil {
		return "", "", "", err
	}

	_, err = tmpl.Parse(string(htmlContent))
	if err != nil {
		return "", "", "", err
	}

	// Execute HTML
	var htmlBuf bytes.Buffer
	if err := tmpl.Execute(&htmlBuf, vars); err != nil {
		return "", "", "", err
	}
	htmlBody = htmlBuf.String()

	// Execute Text
	textTmpl, err := template.New("text").Parse(string(textContent))
	if err != nil {
		textBody = string(textContent) // Fallback to raw if parse fails
	} else {
		var textBuf bytes.Buffer
		if err := textTmpl.Execute(&textBuf, vars); err != nil {
			textBody = string(textContent)
		} else {
			textBody = textBuf.String()
		}
	}

	// Subject extraction - we need a way to get the default subject
	// For now, we'll keep a map or just use the title block from the template
	subject = GetTemplateDefaultSubject(templateType, vars)

	return subject, htmlBody, textBody, nil
}

// GetTemplateDefaultSubject returns the default subject for a template type.
func GetTemplateDefaultSubject(t TemplateType, vars *TemplateVars) string {
	appName := "ModernAuth"
	if vars != nil && vars.AppName != "" {
		appName = vars.AppName
	}

	switch t {
	case TemplateVerification:
		return "Verify your email address"
	case TemplatePasswordReset:
		return "Reset your password"
	case TemplateWelcome:
		return "Welcome to " + appName
	case TemplateLoginAlert:
		return "New login to your account"
	case TemplateInvitation:
		tenantName := "Organization"
		if vars != nil && vars.TenantName != "" {
			tenantName = vars.TenantName
		}
		return "You've been invited to join " + tenantName
	case TemplateMFAEnabled:
		return "Two-factor authentication enabled"
	case TemplateMFADisabled:
		return "Two-factor authentication disabled"
	case TemplateMFACode:
		return "Your Verification Code"
	case TemplateLowBackupCodes:
		return "Action Required: Low backup codes remaining"
	case TemplatePasswordChanged:
		return "Your password was changed"
	case TemplateSessionRevoked:
		return "Your session was terminated"
	case TemplateAccountDeactivated:
		return "Account Deactivated"
	case TemplateEmailChanged:
		return "Email Address Changed"
	case TemplatePasswordExpiry:
		return "Password Expiring Soon"
	case TemplateSecurityAlert:
		if vars != nil && vars.AlertTitle != "" {
			return vars.AlertTitle
		}
		return "Security Alert"
	case TemplateRateLimitWarning:
		return "Rate Limit Approaching"
	case TemplateMagicLink:
		return "Sign in to your account"
	default:
		return "Notification from " + appName
	}
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

// PrewarmCache pre-warms the template cache for a tenant.
func (s *TemplateService) PrewarmCache(ctx context.Context, tenantID *uuid.UUID) {
	for _, templateType := range AllTemplateTypes() {
		go func(tt TemplateType) {
			_, _ = s.GetTemplate(ctx, tenantID, tt)
		}(templateType)
	}
	_, _ = s.GetBranding(ctx, tenantID)
}

// DetectLanguage detects the language from various sources.
func DetectLanguage(ctx context.Context, acceptLanguage, userLanguage string) string {
	if userLanguage != "" {
		return extractPrimaryLanguage(userLanguage)
	}

	if acceptLanguage != "" {
		return extractPrimaryLanguage(acceptLanguage)
	}

	return "en"
}

func extractPrimaryLanguage(lang string) string {
	if len(lang) >= 2 {
		return lang[:2]
	}
	return "en"
}

// GetLocalizedTemplate retrieves a template with language-specific override.
func (s *TemplateService) GetLocalizedTemplate(ctx context.Context, tenantID *uuid.UUID, templateType TemplateType, langCode string) (*storage.EmailTemplate, error) {
	if langCode == "" || langCode == "en" {
		return s.GetTemplate(ctx, tenantID, templateType)
	}

	localizedType := TemplateType(string(templateType) + "_" + langCode)
	template, err := s.storage.GetEmailTemplate(ctx, tenantID, string(localizedType))
	if err != nil {
		return nil, err
	}

	if template != nil && template.IsActive {
		return template, nil
	}

	return s.GetTemplate(ctx, tenantID, templateType)
}
