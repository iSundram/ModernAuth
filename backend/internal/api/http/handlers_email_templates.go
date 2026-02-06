// Package http provides email template admin HTTP handlers.
package http

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/email"
	"github.com/iSundram/ModernAuth/internal/storage"
	tenantpkg "github.com/iSundram/ModernAuth/internal/tenant"
)

// EmailSender interface for sending emails.
type EmailSender interface {
	SendEmail(to, subject, htmlBody, textBody string) error
}

// EmailTemplateHandler handles email template admin endpoints.
type EmailTemplateHandler struct {
	storage         storage.EmailTemplateStorage
	templateService *email.TemplateService
	emailSender     EmailSender
}

// NewEmailTemplateHandler creates a new email template handler.
func NewEmailTemplateHandler(store storage.EmailTemplateStorage, templateService *email.TemplateService) *EmailTemplateHandler {
	return &EmailTemplateHandler{
		storage:         store,
		templateService: templateService,
	}
}

// SetEmailSender sets the email sender for test emails.
func (h *EmailTemplateHandler) SetEmailSender(sender EmailSender) {
	h.emailSender = sender
}

// EmailTemplateRequest represents a request to create/update a template.
type EmailTemplateRequest struct {
	Subject  string  `json:"subject" validate:"required,min=1,max=200"`
	HTMLBody string  `json:"html_body" validate:"required,min=1"`
	TextBody *string `json:"text_body,omitempty"`
	IsActive *bool   `json:"is_active,omitempty"`
}

// EmailTemplateResponse represents an email template in API responses.
type EmailTemplateResponse struct {
	ID        string  `json:"id"`
	TenantID  *string `json:"tenant_id,omitempty"`
	Type      string  `json:"type"`
	Subject   string  `json:"subject"`
	HTMLBody  string  `json:"html_body"`
	TextBody  *string `json:"text_body,omitempty"`
	IsActive  bool    `json:"is_active"`
	CreatedAt string  `json:"created_at"`
	UpdatedAt string  `json:"updated_at"`
}

// EmailBrandingRequest represents a request to update branding.
type EmailBrandingRequest struct {
	AppName        string  `json:"app_name" validate:"required,min=1,max=100"`
	LogoURL        *string `json:"logo_url,omitempty" validate:"omitempty,url"`
	PrimaryColor   string  `json:"primary_color" validate:"required,hexcolor"`
	SecondaryColor string  `json:"secondary_color" validate:"required,hexcolor"`
	CompanyName    *string `json:"company_name,omitempty" validate:"omitempty,max=100"`
	SupportEmail   *string `json:"support_email,omitempty" validate:"omitempty,email"`
	FooterText     *string `json:"footer_text,omitempty" validate:"omitempty,max=500"`
}

// EmailBrandingResponse represents email branding in API responses.
type EmailBrandingResponse struct {
	ID             string  `json:"id"`
	TenantID       *string `json:"tenant_id,omitempty"`
	AppName        string  `json:"app_name"`
	LogoURL        *string `json:"logo_url,omitempty"`
	PrimaryColor   string  `json:"primary_color"`
	SecondaryColor string  `json:"secondary_color"`
	CompanyName    *string `json:"company_name,omitempty"`
	SupportEmail   *string `json:"support_email,omitempty"`
	FooterText     *string `json:"footer_text,omitempty"`
	CreatedAt      string  `json:"created_at"`
	UpdatedAt      string  `json:"updated_at"`
}

// TemplatePreviewRequest represents a preview request.
type TemplatePreviewRequest struct {
	// Sample user data for preview
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
	Email     string `json:"email,omitempty"`
}

// TemplatePreviewResponse represents a rendered preview.
type TemplatePreviewResponse struct {
	Subject  string `json:"subject"`
	HTMLBody string `json:"html_body"`
	TextBody string `json:"text_body"`
}

// ListTemplates lists all email templates.
func (h *EmailTemplateHandler) ListTemplates(w http.ResponseWriter, r *http.Request) {
	tenantID := getTenantIDFromContext(r.Context())

	templates, err := h.storage.ListEmailTemplates(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to list templates"})
		return
	}

	// Build response with all template types (including defaults)
	response := make([]map[string]interface{}, 0)
	templateMap := make(map[string]*storage.EmailTemplate)
	for _, t := range templates {
		templateMap[t.Type] = t
	}

	for _, tt := range email.AllTemplateTypes() {
		item := map[string]interface{}{
			"type":        string(tt),
			"has_custom":  false,
			"is_active":   true,
			"description": getTemplateDescription(tt),
		}
		if t, ok := templateMap[string(tt)]; ok {
			item["has_custom"] = true
			item["is_active"] = t.IsActive
			item["id"] = t.ID.String()
			item["updated_at"] = t.UpdatedAt.Format("2006-01-02T15:04:05Z")
		}
		response = append(response, item)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"templates": response})
}

// GetTemplate gets a specific email template.
func (h *EmailTemplateHandler) GetTemplate(w http.ResponseWriter, r *http.Request) {
	templateType := chi.URLParam(r, "type")
	if !isValidTemplateType(templateType) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid template type"})
		return
	}

	tenantID := getTenantIDFromContext(r.Context())

	template, err := h.storage.GetEmailTemplate(r.Context(), tenantID, templateType)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to get template"})
		return
	}

	// If no custom template, return default
	if template == nil {
		defaultSubject, defaultHTML, defaultText := getDefaultTemplate(email.TemplateType(templateType))
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"type":       templateType,
			"subject":    defaultSubject,
			"html_body":  defaultHTML,
			"text_body":  defaultText,
			"is_active":  true,
			"is_default": true,
		})
		return
	}

	writeJSON(w, http.StatusOK, templateToResponse(template))
}

// UpdateTemplate creates or updates an email template.
func (h *EmailTemplateHandler) UpdateTemplate(w http.ResponseWriter, r *http.Request) {
	templateType := chi.URLParam(r, "type")
	if !isValidTemplateType(templateType) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid template type"})
		return
	}

	var req EmailTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	if errors := ValidateStruct(req); errors != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "Validation failed",
			"details": errors,
		})
		return
	}

	tenantID := getTenantIDFromContext(r.Context())

	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}

	existingTemplate, err := h.storage.GetEmailTemplate(r.Context(), tenantID, templateType)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to get existing template"})
		return
	}

	if existingTemplate != nil {
		version := &storage.EmailTemplateVersion{
			TemplateID:   existingTemplate.ID,
			TenantID:     tenantID,
			TemplateType: templateType,
			Version:      1,
			Subject:      existingTemplate.Subject,
			HTMLBody:     existingTemplate.HTMLBody,
			TextBody:     existingTemplate.TextBody,
		}

		list, err := h.storage.ListEmailTemplateVersions(r.Context(), tenantID, templateType, 1, 0)
		if err == nil && len(list) > 0 {
			version.Version = list[0].Version + 1
		}

		if changeReason := r.URL.Query().Get("change_reason"); changeReason != "" {
			cr := changeReason
			version.ChangeReason = &cr
		}

		if err := h.storage.CreateEmailTemplateVersion(r.Context(), version); err != nil {
			slog.Warn("Failed to create template version", "error", err)
		}
	}

	template := &storage.EmailTemplate{
		TenantID: tenantID,
		Type:     templateType,
		Subject:  req.Subject,
		HTMLBody: req.HTMLBody,
		TextBody: req.TextBody,
		IsActive: isActive,
	}

	if err := h.storage.UpsertEmailTemplate(r.Context(), template); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to save template"})
		return
	}

	h.templateService.InvalidateCache(tenantID, email.TemplateType(templateType))

	writeJSON(w, http.StatusOK, templateToResponse(template))
}

// DeleteTemplate deletes a custom template (reverts to default).
func (h *EmailTemplateHandler) DeleteTemplate(w http.ResponseWriter, r *http.Request) {
	templateType := chi.URLParam(r, "type")
	if !isValidTemplateType(templateType) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid template type"})
		return
	}

	tenantID := getTenantIDFromContext(r.Context())

	if err := h.storage.DeleteEmailTemplate(r.Context(), tenantID, templateType); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to delete template"})
		return
	}

	// Invalidate cache
	h.templateService.InvalidateCache(tenantID, email.TemplateType(templateType))

	writeJSON(w, http.StatusOK, map[string]string{"message": "Template deleted, reverted to default"})
}

// PreviewTemplate renders a template with sample data.
func (h *EmailTemplateHandler) PreviewTemplate(w http.ResponseWriter, r *http.Request) {
	templateType := chi.URLParam(r, "type")
	if !isValidTemplateType(templateType) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid template type"})
		return
	}

	var req TemplatePreviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Use defaults if no body provided
		req = TemplatePreviewRequest{
			FirstName: "John",
			LastName:  "Doe",
			Email:     "john.doe@example.com",
		}
	}

	tenantID := getTenantIDFromContext(r.Context())

	// Get branding
	branding, _ := h.storage.GetEmailBranding(r.Context(), tenantID)

	// Create sample user
	firstName := req.FirstName
	if firstName == "" {
		firstName = "John"
	}
	lastName := req.LastName
	if lastName == "" {
		lastName = "Doe"
	}
	userEmail := req.Email
	if userEmail == "" {
		userEmail = "john.doe@example.com"
	}

	sampleUser := &storage.User{
		Email:     userEmail,
		FirstName: &firstName,
		LastName:  &lastName,
	}

	// Create template variables
	vars := email.NewTemplateVars(sampleUser, branding)

	// Add sample context variables based on type
	switch email.TemplateType(templateType) {
	case email.TemplateVerification:
		vars.WithVerification("sample-token-123", "https://example.com/verify?token=sample-token-123")
	case email.TemplatePasswordReset:
		vars.WithPasswordReset("sample-token-456", "https://example.com/reset?token=sample-token-456")
	case email.TemplateWelcome:
		vars.WithBaseURL("https://example.com")
	case email.TemplateLoginAlert:
		vars.WithDevice(&email.DeviceInfo{
			DeviceName: "MacBook Pro",
			Browser:    "Chrome 120",
			OS:         "macOS Sonoma",
			IPAddress:  "192.168.1.100",
			Location:   "San Francisco, CA",
			Time:       "January 24, 2026 at 10:30 AM",
		})
	case email.TemplateInvitation:
		vars.WithInvitation(&email.InvitationEmail{
			InviterName: "Jane Smith",
			TenantName:  "Acme Corp",
			InviteURL:   "https://example.com/invite?token=sample-invite",
			Message:     "Welcome to the team!",
			ExpiresAt:   "January 31, 2026",
		})
	case email.TemplateSessionRevoked:
		vars.WithReason("Logged out from all devices")
	}

	// Render template
	subject, htmlBody, textBody, err := h.templateService.RenderTemplate(r.Context(), tenantID, email.TemplateType(templateType), vars)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to render template: " + err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, TemplatePreviewResponse{
		Subject:  subject,
		HTMLBody: htmlBody,
		TextBody: textBody,
	})
}

// GetBranding gets email branding settings.
func (h *EmailTemplateHandler) GetBranding(w http.ResponseWriter, r *http.Request) {
	tenantID := getTenantIDFromContext(r.Context())

	branding, err := h.storage.GetEmailBranding(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to get branding"})
		return
	}

	writeJSON(w, http.StatusOK, brandingToResponse(branding))
}

// UpdateBranding updates email branding settings.
func (h *EmailTemplateHandler) UpdateBranding(w http.ResponseWriter, r *http.Request) {
	var req EmailBrandingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	if errors := ValidateStruct(req); errors != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "Validation failed",
			"details": errors,
		})
		return
	}

	tenantID := getTenantIDFromContext(r.Context())

	branding := &storage.EmailBranding{
		TenantID:       tenantID,
		AppName:        req.AppName,
		LogoURL:        req.LogoURL,
		PrimaryColor:   req.PrimaryColor,
		SecondaryColor: req.SecondaryColor,
		CompanyName:    req.CompanyName,
		SupportEmail:   req.SupportEmail,
		FooterText:     req.FooterText,
	}

	if err := h.storage.UpsertEmailBranding(r.Context(), branding); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to save branding"})
		return
	}

	// Invalidate all template caches for this tenant
	h.templateService.InvalidateCache(tenantID, "")

	writeJSON(w, http.StatusOK, brandingToResponse(branding))
}

// ListAvailableVariables returns available template variables.
func (h *EmailTemplateHandler) ListAvailableVariables(w http.ResponseWriter, r *http.Request) {
	variables := map[string]interface{}{
		"user": []map[string]string{
			{"name": "FirstName", "description": "User's first name"},
			{"name": "LastName", "description": "User's last name"},
			{"name": "FullName", "description": "User's full name (first + last, with fallbacks)"},
			{"name": "Email", "description": "User's email address"},
			{"name": "Username", "description": "User's username (if set)"},
		},
		"branding": []map[string]string{
			{"name": "AppName", "description": "Application name"},
			{"name": "AppLogo", "description": "Logo URL"},
			{"name": "PrimaryColor", "description": "Primary brand color (hex)"},
			{"name": "SecondaryColor", "description": "Secondary brand color (hex)"},
			{"name": "CompanyName", "description": "Company name"},
			{"name": "SupportEmail", "description": "Support email address"},
			{"name": "FooterText", "description": "Custom footer text"},
			{"name": "CurrentYear", "description": "Current year (auto-generated)"},
		},
		"context": map[string][]map[string]string{
			"verification":     {{"name": "VerifyURL", "description": "Email verification URL"}, {"name": "Token", "description": "Verification token"}},
			"password_reset":   {{"name": "ResetURL", "description": "Password reset URL"}, {"name": "Token", "description": "Reset token"}},
			"welcome":          {{"name": "BaseURL", "description": "Application base URL"}},
			"login_alert":      {{"name": "DeviceName", "description": "Device name"}, {"name": "Browser", "description": "Browser name"}, {"name": "OS", "description": "Operating system"}, {"name": "IPAddress", "description": "IP address"}, {"name": "Location", "description": "Location"}, {"name": "Time", "description": "Login time"}},
			"invitation":       {{"name": "InviterName", "description": "Inviter's name"}, {"name": "TenantName", "description": "Organization name"}, {"name": "InviteURL", "description": "Invitation URL"}, {"name": "Message", "description": "Personal message"}, {"name": "ExpiresAt", "description": "Expiration date"}},
			"session_revoked":  {{"name": "Reason", "description": "Revocation reason"}},
			"mfa_enabled":      {},
			"password_changed": {},
		},
	}

	writeJSON(w, http.StatusOK, variables)
}

// Helper functions

func getTenantIDFromContext(ctx context.Context) *uuid.UUID {
	return tenantpkg.GetTenantIDFromContext(ctx)
}

func isValidTemplateType(t string) bool {
	for _, tt := range email.AllTemplateTypes() {
		if string(tt) == t {
			return true
		}
	}
	return false
}

func getTemplateDescription(t email.TemplateType) string {
	descriptions := map[email.TemplateType]string{
		email.TemplateVerification:    "Email verification message",
		email.TemplatePasswordReset:   "Password reset instructions",
		email.TemplateWelcome:         "Welcome message for new users",
		email.TemplateLoginAlert:      "New device login notification",
		email.TemplateInvitation:      "Tenant/organization invitation",
		email.TemplateMFAEnabled:      "MFA enabled confirmation",
		email.TemplatePasswordChanged: "Password change notification",
		email.TemplateSessionRevoked:  "Session revocation notice",
	}
	return descriptions[t]
}

func getDefaultTemplate(t email.TemplateType) (subject, html, text string) {
	// Return simplified defaults for API display
	switch t {
	case email.TemplateVerification:
		return "Verify your email address", "[Default HTML template]", "Hi {{.FullName}}, Please verify your email..."
	case email.TemplatePasswordReset:
		return "Reset your password", "[Default HTML template]", "Hi {{.FullName}}, Click to reset your password..."
	case email.TemplateWelcome:
		return "Welcome to {{.AppName}}", "[Default HTML template]", "Hi {{.FullName}}, Welcome to {{.AppName}}..."
	case email.TemplateLoginAlert:
		return "New login to your account", "[Default HTML template]", "Hi {{.FullName}}, New login detected..."
	case email.TemplateInvitation:
		return "You've been invited to join {{.TenantName}}", "[Default HTML template]", "You've been invited..."
	case email.TemplateMFAEnabled:
		return "Two-factor authentication enabled", "[Default HTML template]", "Hi {{.FullName}}, 2FA has been enabled..."
	case email.TemplatePasswordChanged:
		return "Your password was changed", "[Default HTML template]", "Hi {{.FullName}}, Your password was changed..."
	case email.TemplateSessionRevoked:
		return "Your session was terminated", "[Default HTML template]", "Hi {{.FullName}}, Your session was terminated..."
	default:
		return "", "", ""
	}
}

func templateToResponse(t *storage.EmailTemplate) EmailTemplateResponse {
	resp := EmailTemplateResponse{
		ID:        t.ID.String(),
		Type:      t.Type,
		Subject:   t.Subject,
		HTMLBody:  t.HTMLBody,
		TextBody:  t.TextBody,
		IsActive:  t.IsActive,
		CreatedAt: t.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt: t.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}
	if t.TenantID != nil {
		tid := t.TenantID.String()
		resp.TenantID = &tid
	}
	return resp
}

func brandingToResponse(b *storage.EmailBranding) EmailBrandingResponse {
	resp := EmailBrandingResponse{
		ID:             b.ID.String(),
		AppName:        b.AppName,
		LogoURL:        b.LogoURL,
		PrimaryColor:   b.PrimaryColor,
		SecondaryColor: b.SecondaryColor,
		CompanyName:    b.CompanyName,
		SupportEmail:   b.SupportEmail,
		FooterText:     b.FooterText,
		CreatedAt:      b.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:      b.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}
	if b.TenantID != nil {
		tid := b.TenantID.String()
		resp.TenantID = &tid
	}
	return resp
}

// ============================================================================
// Test Email
// ============================================================================

// SendTestEmailRequest represents a test email request.
type SendTestEmailRequest struct {
	RecipientEmail string `json:"recipient_email" validate:"required,email"`
}

// SendTestEmail sends a test email with the template.
func (h *EmailTemplateHandler) SendTestEmail(w http.ResponseWriter, r *http.Request) {
	templateType := chi.URLParam(r, "type")
	if !isValidTemplateType(templateType) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid template type"})
		return
	}

	var req SendTestEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	if errors := ValidateStruct(req); errors != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "Validation failed",
			"details": errors,
		})
		return
	}

	tenantID := getTenantIDFromContext(r.Context())

	// Get branding
	branding, _ := h.storage.GetEmailBranding(r.Context(), tenantID)

	// Create sample user with recipient email
	firstName := "Test"
	lastName := "User"
	sampleUser := &storage.User{
		Email:     req.RecipientEmail,
		FirstName: &firstName,
		LastName:  &lastName,
	}

	// Create template variables
	vars := email.NewTemplateVars(sampleUser, branding)

	// Add sample context variables based on type
	switch email.TemplateType(templateType) {
	case email.TemplateVerification:
		vars.WithVerification("test-token-123", "https://example.com/verify?token=test-token-123")
	case email.TemplatePasswordReset:
		vars.WithPasswordReset("test-token-456", "https://example.com/reset?token=test-token-456")
	case email.TemplateWelcome:
		vars.WithBaseURL("https://example.com")
	case email.TemplateLoginAlert:
		vars.WithDevice(&email.DeviceInfo{
			DeviceName: "MacBook Pro",
			Browser:    "Chrome 120",
			OS:         "macOS Sonoma",
			IPAddress:  "192.168.1.100",
			Location:   "San Francisco, CA",
			Time:       "Test Email - " + time.Now().Format("January 2, 2006 at 3:04 PM"),
		})
	case email.TemplateInvitation:
		vars.WithInvitation(&email.InvitationEmail{
			InviterName: "Test Admin",
			TenantName:  "Test Organization",
			InviteURL:   "https://example.com/invite?token=test-invite",
			Message:     "This is a test invitation email.",
			ExpiresAt:   time.Now().AddDate(0, 0, 7).Format("January 2, 2006"),
		})
	case email.TemplateSessionRevoked:
		vars.WithReason("Test session revocation")
	}

	// Render template
	subject, htmlBody, textBody, err := h.templateService.RenderTemplate(r.Context(), tenantID, email.TemplateType(templateType), vars)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to render template: " + err.Error()})
		return
	}

	// Send the email via the email service (if available)
	if h.emailSender != nil {
		if err := h.emailSender.SendEmail(req.RecipientEmail, subject, htmlBody, textBody); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to send test email: " + err.Error()})
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message":   "Test email sent successfully",
		"recipient": req.RecipientEmail,
	})
}

// ============================================================================
// Template Version History
// ============================================================================

// EmailTemplateVersionResponse represents a version in API responses.
type EmailTemplateVersionResponse struct {
	ID           string  `json:"id"`
	TemplateID   string  `json:"template_id"`
	Version      int     `json:"version"`
	Subject      string  `json:"subject"`
	HTMLBody     string  `json:"html_body"`
	TextBody     *string `json:"text_body,omitempty"`
	ChangedBy    *string `json:"changed_by,omitempty"`
	ChangeReason *string `json:"change_reason,omitempty"`
	CreatedAt    string  `json:"created_at"`
}

// ListTemplateVersions lists version history for a template.
func (h *EmailTemplateHandler) ListTemplateVersions(w http.ResponseWriter, r *http.Request) {
	templateType := chi.URLParam(r, "type")
	if !isValidTemplateType(templateType) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid template type"})
		return
	}

	tenantID := getTenantIDFromContext(r.Context())

	versions, err := h.storage.ListEmailTemplateVersions(r.Context(), tenantID, templateType, 50, 0)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to list versions"})
		return
	}

	response := make([]EmailTemplateVersionResponse, 0, len(versions))
	for _, v := range versions {
		resp := EmailTemplateVersionResponse{
			ID:           v.ID.String(),
			TemplateID:   v.TemplateID.String(),
			Version:      v.Version,
			Subject:      v.Subject,
			HTMLBody:     v.HTMLBody,
			TextBody:     v.TextBody,
			ChangeReason: v.ChangeReason,
			CreatedAt:    v.CreatedAt.Format("2006-01-02T15:04:05Z"),
		}
		if v.ChangedBy != nil {
			cb := v.ChangedBy.String()
			resp.ChangedBy = &cb
		}
		response = append(response, resp)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"versions": response})
}

// GetTemplateVersion gets a specific version.
func (h *EmailTemplateHandler) GetTemplateVersion(w http.ResponseWriter, r *http.Request) {
	versionIDStr := chi.URLParam(r, "versionId")
	versionID, err := uuid.Parse(versionIDStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid version ID"})
		return
	}

	version, err := h.storage.GetEmailTemplateVersion(r.Context(), versionID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to get version"})
		return
	}
	if version == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Version not found"})
		return
	}

	resp := EmailTemplateVersionResponse{
		ID:           version.ID.String(),
		TemplateID:   version.TemplateID.String(),
		Version:      version.Version,
		Subject:      version.Subject,
		HTMLBody:     version.HTMLBody,
		TextBody:     version.TextBody,
		ChangeReason: version.ChangeReason,
		CreatedAt:    version.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}
	if version.ChangedBy != nil {
		cb := version.ChangedBy.String()
		resp.ChangedBy = &cb
	}

	writeJSON(w, http.StatusOK, resp)
}

// RestoreTemplateVersionRequest represents a restore request.
type RestoreTemplateVersionRequest struct {
	ChangeReason string `json:"change_reason,omitempty"`
}

// RestoreTemplateVersion restores a template to a previous version.
func (h *EmailTemplateHandler) RestoreTemplateVersion(w http.ResponseWriter, r *http.Request) {
	templateType := chi.URLParam(r, "type")
	if !isValidTemplateType(templateType) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid template type"})
		return
	}

	versionIDStr := chi.URLParam(r, "versionId")
	versionID, err := uuid.Parse(versionIDStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid version ID"})
		return
	}

	var req RestoreTemplateVersionRequest
	json.NewDecoder(r.Body).Decode(&req) // Optional body

	tenantID := getTenantIDFromContext(r.Context())

	// Get the version to restore
	version, err := h.storage.GetEmailTemplateVersion(r.Context(), versionID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to get version"})
		return
	}
	if version == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Version not found"})
		return
	}

	// Create new template with restored content
	template := &storage.EmailTemplate{
		TenantID: tenantID,
		Type:     templateType,
		Subject:  version.Subject,
		HTMLBody: version.HTMLBody,
		TextBody: version.TextBody,
		IsActive: true,
	}

	if err := h.storage.UpsertEmailTemplate(r.Context(), template); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to restore template"})
		return
	}

	// Invalidate cache
	h.templateService.InvalidateCache(tenantID, email.TemplateType(templateType))

	writeJSON(w, http.StatusOK, map[string]string{
		"message":          "Template restored successfully",
		"restored_version": versionIDStr,
	})
}

// ============================================================================
// Template Validation
// ============================================================================

// ValidateTemplateRequest represents a template validation request.
type ValidateTemplateRequest struct {
	Subject  string  `json:"subject" validate:"required"`
	HTMLBody string  `json:"html_body" validate:"required"`
	TextBody *string `json:"text_body,omitempty"`
}

// ValidateTemplateResponse represents validation results.
type ValidateTemplateResponse struct {
	Valid  bool     `json:"valid"`
	Errors []string `json:"errors,omitempty"`
}

// ValidateTemplate validates template syntax without saving.
func (h *EmailTemplateHandler) ValidateTemplate(w http.ResponseWriter, r *http.Request) {
	templateType := chi.URLParam(r, "type")
	if !isValidTemplateType(templateType) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid template type"})
		return
	}

	var req ValidateTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	var validationErrors []string

	// Validate subject template
	if _, err := template.New("subject").Parse(req.Subject); err != nil {
		validationErrors = append(validationErrors, "Subject template error: "+err.Error())
	}

	// Validate HTML body template
	if _, err := template.New("html").Parse(req.HTMLBody); err != nil {
		validationErrors = append(validationErrors, "HTML body template error: "+err.Error())
	}

	// Validate text body template if provided
	if req.TextBody != nil && *req.TextBody != "" {
		if _, err := template.New("text").Parse(*req.TextBody); err != nil {
			validationErrors = append(validationErrors, "Text body template error: "+err.Error())
		}
	}

	response := ValidateTemplateResponse{
		Valid:  len(validationErrors) == 0,
		Errors: validationErrors,
	}

	writeJSON(w, http.StatusOK, response)
}

// ============================================================================
// Email Stats
// ============================================================================

// GetEmailStats retrieves email statistics.
func (h *EmailTemplateHandler) GetEmailStats(w http.ResponseWriter, r *http.Request) {
	tenantID := getTenantIDFromContext(r.Context())

	// Default to 30 days
	days := 30
	if daysStr := r.URL.Query().Get("days"); daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 && d <= 365 {
			days = d
		}
	}

	stats, err := h.storage.GetEmailStats(r.Context(), tenantID, days)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to get email stats"})
		return
	}

	writeJSON(w, http.StatusOK, stats)
}

// ============================================================================
// Email Bounces
// ============================================================================

// ListEmailBounces lists bounce records.
func (h *EmailTemplateHandler) ListEmailBounces(w http.ResponseWriter, r *http.Request) {
	tenantID := getTenantIDFromContext(r.Context())
	bounceType := r.URL.Query().Get("type")

	bounces, err := h.storage.ListEmailBounces(r.Context(), tenantID, bounceType, 100, 0)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to list bounces"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"bounces": bounces})
}

// ============================================================================
// Email Suppressions
// ============================================================================

// ListSuppressions lists suppressed emails.
func (h *EmailTemplateHandler) ListSuppressions(w http.ResponseWriter, r *http.Request) {
	tenantID := getTenantIDFromContext(r.Context())

	suppressions, err := h.storage.ListEmailSuppressions(r.Context(), tenantID, 100, 0)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to list suppressions"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"suppressions": suppressions})
}

// AddSuppressionRequest represents a suppression add request.
type AddSuppressionRequest struct {
	Email  string `json:"email" validate:"required,email"`
	Reason string `json:"reason" validate:"required,oneof=hard_bounce complaint unsubscribe manual"`
}

// AddSuppression adds an email to the suppression list.
func (h *EmailTemplateHandler) AddSuppression(w http.ResponseWriter, r *http.Request) {
	var req AddSuppressionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	if errors := ValidateStruct(req); errors != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "Validation failed",
			"details": errors,
		})
		return
	}

	tenantID := getTenantIDFromContext(r.Context())
	source := "admin"

	suppression := &storage.EmailSuppression{
		TenantID: tenantID,
		Email:    req.Email,
		Reason:   req.Reason,
		Source:   &source,
	}

	if err := h.storage.CreateEmailSuppression(r.Context(), suppression); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to add suppression"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Email added to suppression list"})
}

// RemoveSuppression removes an email from the suppression list.
func (h *EmailTemplateHandler) RemoveSuppression(w http.ResponseWriter, r *http.Request) {
	email := chi.URLParam(r, "email")
	if email == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Email required"})
		return
	}

	tenantID := getTenantIDFromContext(r.Context())

	if err := h.storage.DeleteEmailSuppression(r.Context(), tenantID, email); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to remove suppression"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Email removed from suppression list"})
}

// ============================================================================
// Email A/B Testing
// ============================================================================

// EmailABTestRequest represents an A/B test creation request.
type EmailABTestRequest struct {
	TemplateType string  `json:"template_type" validate:"required"`
	Name         string  `json:"name" validate:"required,min=1,max=100"`
	VariantA     string  `json:"variant_a" validate:"required"`
	VariantB     string  `json:"variant_b" validate:"required"`
	WeightA      float64 `json:"weight_a,omitempty"`
	WeightB      float64 `json:"weight_b,omitempty"`
}

// EmailABTestResponse represents an A/B test in API responses.
type EmailABTestResponse struct {
	ID            string  `json:"id"`
	TenantID      *string `json:"tenant_id,omitempty"`
	TemplateType  string  `json:"template_type"`
	Name          string  `json:"name"`
	VariantA      string  `json:"variant_a"`
	VariantB      string  `json:"variant_b"`
	WeightA       float64 `json:"weight_a"`
	WeightB       float64 `json:"weight_b"`
	IsActive      bool    `json:"is_active"`
	WinnerVariant *string `json:"winner_variant,omitempty"`
	StartDate     *string `json:"start_date,omitempty"`
	EndDate       *string `json:"end_date,omitempty"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
}

// ListABTests lists all A/B tests.
func (h *EmailTemplateHandler) ListABTests(w http.ResponseWriter, r *http.Request) {
	tenantID := getTenantIDFromContext(r.Context())

	tests, err := h.storage.ListEmailABTests(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to list A/B tests"})
		return
	}

	response := make([]EmailABTestResponse, 0, len(tests))
	for _, t := range tests {
		resp := EmailABTestResponse{
			ID:           t.ID.String(),
			TemplateType: t.TemplateType,
			Name:         t.Name,
			VariantA:     t.VariantA,
			VariantB:     t.VariantB,
			WeightA:      t.WeightA,
			WeightB:      t.WeightB,
			IsActive:     t.IsActive,
			CreatedAt:    t.CreatedAt.Format("2006-01-02T15:04:05Z"),
			UpdatedAt:    t.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		}
		if t.TenantID != nil {
			tid := t.TenantID.String()
			resp.TenantID = &tid
		}
		if t.WinnerVariant != nil {
			resp.WinnerVariant = t.WinnerVariant
		}
		if t.StartDate != nil {
			resp.StartDate = t.StartDate
		}
		if t.EndDate != nil {
			resp.EndDate = t.EndDate
		}
		response = append(response, resp)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"tests": response})
}

// CreateABTest creates a new A/B test.
func (h *EmailTemplateHandler) CreateABTest(w http.ResponseWriter, r *http.Request) {
	var req EmailABTestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	if errors := ValidateStruct(req); errors != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "Validation failed",
			"details": errors,
		})
		return
	}

	tenantID := getTenantIDFromContext(r.Context())

	weightA := req.WeightA
	weightB := req.WeightB
	if weightA == 0 && weightB == 0 {
		weightA = 50
		weightB = 50
	} else if weightA == 0 {
		weightA = 100 - weightB
	} else if weightB == 0 {
		weightB = 100 - weightA
	}

	test := &storage.EmailABTest{
		TenantID:     tenantID,
		TemplateType: req.TemplateType,
		Name:         req.Name,
		VariantA:     req.VariantA,
		VariantB:     req.VariantB,
		WeightA:      weightA,
		WeightB:      weightB,
		IsActive:     true,
	}

	if err := h.storage.CreateEmailABTest(r.Context(), test); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to create A/B test"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":      test.ID.String(),
		"message": "A/B test created successfully",
	})
}

// GetABTest gets a specific A/B test.
func (h *EmailTemplateHandler) GetABTest(w http.ResponseWriter, r *http.Request) {
	testID := chi.URLParam(r, "testId")
	testUUID, err := uuid.Parse(testID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid test ID"})
		return
	}

	test, err := h.storage.GetEmailABTest(r.Context(), testUUID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to get A/B test"})
		return
	}
	if test == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "A/B test not found"})
		return
	}

	resp := EmailABTestResponse{
		ID:           test.ID.String(),
		TemplateType: test.TemplateType,
		Name:         test.Name,
		VariantA:     test.VariantA,
		VariantB:     test.VariantB,
		WeightA:      test.WeightA,
		WeightB:      test.WeightB,
		IsActive:     test.IsActive,
		CreatedAt:    test.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:    test.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}
	if test.TenantID != nil {
		tid := test.TenantID.String()
		resp.TenantID = &tid
	}
	if test.WinnerVariant != nil {
		resp.WinnerVariant = test.WinnerVariant
	}
	if test.StartDate != nil {
		resp.StartDate = test.StartDate
	}
	if test.EndDate != nil {
		resp.EndDate = test.EndDate
	}

	writeJSON(w, http.StatusOK, resp)
}

// DeclareWinnerRequest represents a request to declare a winner.
type DeclareWinnerRequest struct {
	Variant string `json:"variant" validate:"required,oneof=a b"`
}

// DeclareWinner declares a winner for an A/B test.
func (h *EmailTemplateHandler) DeclareABTestWinner(w http.ResponseWriter, r *http.Request) {
	testID := chi.URLParam(r, "testId")
	testUUID, err := uuid.Parse(testID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid test ID"})
		return
	}

	var req DeclareWinnerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	if req.Variant != "a" && req.Variant != "b" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Variant must be 'a' or 'b'"})
		return
	}

	test, err := h.storage.GetEmailABTest(r.Context(), testUUID)
	if err != nil || test == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "A/B test not found"})
		return
	}

	test.WinnerVariant = &req.Variant
	test.IsActive = false
	now := time.Now().Format("2006-01-02")
	test.EndDate = &now

	if err := h.storage.UpdateEmailABTest(r.Context(), test); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to update A/B test"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message":        "Winner declared successfully",
		"winner_variant": req.Variant,
	})
}

// ============================================================================
// Email Branding - Advanced
// ============================================================================

// EmailBrandingAdvancedRequest represents advanced branding settings.
type EmailBrandingAdvancedRequest struct {
	SocialLinks *SocialLinks `json:"social_links,omitempty"`
	CustomCSS   *string      `json:"custom_css,omitempty"`
	HeaderImage *string      `json:"header_image_url,omitempty"`
	FontFamily  *string      `json:"font_family,omitempty"`
	FontURL     *string      `json:"font_family_url,omitempty"`
}

// SocialLinks represents social media links.
type SocialLinks struct {
	Facebook  *string `json:"facebook,omitempty"`
	Twitter   *string `json:"twitter,omitempty"`
	LinkedIn  *string `json:"linkedin,omitempty"`
	Instagram *string `json:"instagram,omitempty"`
}

// EmailBrandingAdvancedResponse represents advanced branding in API responses.
type EmailBrandingAdvancedResponse struct {
	ID          string       `json:"id"`
	TenantID    *string      `json:"tenant_id,omitempty"`
	SocialLinks *SocialLinks `json:"social_links,omitempty"`
	CustomCSS   *string      `json:"custom_css,omitempty"`
	HeaderImage *string      `json:"header_image_url,omitempty"`
	FontFamily  *string      `json:"font_family,omitempty"`
	FontURL     *string      `json:"font_family_url,omitempty"`
	CreatedAt   string       `json:"created_at"`
	UpdatedAt   string       `json:"updated_at"`
}

// GetAdvancedBranding gets advanced email branding settings.
func (h *EmailTemplateHandler) GetAdvancedBranding(w http.ResponseWriter, r *http.Request) {
	tenantID := getTenantIDFromContext(r.Context())

	branding, err := h.storage.GetEmailBrandingAdvanced(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to get advanced branding"})
		return
	}

	resp := EmailBrandingAdvancedResponse{
		ID:          branding.ID.String(),
		CustomCSS:   branding.CustomCSS,
		HeaderImage: branding.HeaderImageURL,
		FontFamily:  branding.FontFamily,
		FontURL:     branding.FontFamilyURL,
		CreatedAt:   branding.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:   branding.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}
	if branding.TenantID != nil {
		tid := branding.TenantID.String()
		resp.TenantID = &tid
	}
	if branding.SocialLinks != nil {
		resp.SocialLinks = &SocialLinks{
			Facebook:  branding.SocialLinks.Facebook,
			Twitter:   branding.SocialLinks.Twitter,
			LinkedIn:  branding.SocialLinks.LinkedIn,
			Instagram: branding.SocialLinks.Instagram,
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// UpdateAdvancedBranding updates advanced email branding settings.
func (h *EmailTemplateHandler) UpdateAdvancedBranding(w http.ResponseWriter, r *http.Request) {
	var req EmailBrandingAdvancedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	tenantID := getTenantIDFromContext(r.Context())

	socialLinks := (*storage.EmailSocialLinks)(nil)
	if req.SocialLinks != nil {
		socialLinks = &storage.EmailSocialLinks{
			Facebook:  req.SocialLinks.Facebook,
			Twitter:   req.SocialLinks.Twitter,
			LinkedIn:  req.SocialLinks.LinkedIn,
			Instagram: req.SocialLinks.Instagram,
		}
	}

	branding := &storage.EmailBrandingAdvanced{
		TenantID:       tenantID,
		SocialLinks:    socialLinks,
		CustomCSS:      req.CustomCSS,
		HeaderImageURL: req.HeaderImage,
		FontFamily:     req.FontFamily,
		FontFamilyURL:  req.FontURL,
	}

	if err := h.storage.UpsertEmailBrandingAdvanced(r.Context(), branding); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to save advanced branding"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Advanced branding updated successfully"})
}

// ============================================================================
// Email Stats Export
// ============================================================================

// ExportEmailStats exports email statistics.
func (h *EmailTemplateHandler) ExportEmailStats(w http.ResponseWriter, r *http.Request) {
	tenantID := getTenantIDFromContext(r.Context())
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	days := 30
	if daysStr := r.URL.Query().Get("days"); daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 && d <= 365 {
			days = d
		}
	}

	stats, err := h.storage.GetEmailStats(r.Context(), tenantID, days)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to get email stats"})
		return
	}

	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=email-stats.csv")

		fmt.Fprintln(w, "Metric,Value")
		fmt.Fprintf(w, "Total Sent,%d\n", stats.TotalSent)
		fmt.Fprintf(w, "Total Delivered,%d\n", stats.TotalDelivered)
		fmt.Fprintf(w, "Total Opened,%d\n", stats.TotalOpened)
		fmt.Fprintf(w, "Total Clicked,%d\n", stats.TotalClicked)
		fmt.Fprintf(w, "Total Bounced,%d\n", stats.TotalBounced)
		fmt.Fprintf(w, "Total Dropped,%d\n", stats.TotalDropped)
		fmt.Fprintln(w, "\nBy Template,Count")
		for template, count := range stats.ByTemplate {
			fmt.Fprintf(w, "%s,%d\n", template, count)
		}
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=email-stats.json")
		writeJSON(w, http.StatusOK, stats)
	}
}

// ============================================================================
// Template Import/Export
// ============================================================================

// ExportTemplates exports all email templates.
func (h *EmailTemplateHandler) ExportTemplates(w http.ResponseWriter, r *http.Request) {
	tenantID := getTenantIDFromContext(r.Context())

	templates, err := h.storage.ListEmailTemplates(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to list templates"})
		return
	}

	branding, err := h.storage.GetEmailBranding(r.Context(), tenantID)
	if err != nil {
		branding = &storage.EmailBranding{}
	}

	export := map[string]interface{}{
		"version":     "1.0",
		"exported_at": time.Now().Format("2006-01-02T15:04:05Z"),
		"templates":   templates,
		"branding": map[string]interface{}{
			"app_name":        branding.AppName,
			"logo_url":        branding.LogoURL,
			"primary_color":   branding.PrimaryColor,
			"secondary_color": branding.SecondaryColor,
			"company_name":    branding.CompanyName,
			"support_email":   branding.SupportEmail,
			"footer_text":     branding.FooterText,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=email-templates.json")
	writeJSON(w, http.StatusOK, export)
}

// ImportTemplatesRequest represents a template import request.
type ImportTemplatesRequest struct {
	Templates []map[string]interface{} `json:"templates"`
	Branding  map[string]interface{}   `json:"branding"`
}

// ImportTemplates imports email templates.
func (h *EmailTemplateHandler) ImportTemplates(w http.ResponseWriter, r *http.Request) {
	var req ImportTemplatesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	tenantID := getTenantIDFromContext(r.Context())
	imported := 0
	errors := []string{}

	for _, t := range req.Templates {
		templateType, ok := t["type"].(string)
		if !ok {
			errors = append(errors, "Template missing type field")
			continue
		}

		subject, _ := t["subject"].(string)
		htmlBody, _ := t["html_body"].(string)
		textBody, _ := t["text_body"].(string)
		isActive := true

		if v, ok := t["is_active"].(bool); ok {
			isActive = v
		}

		template := &storage.EmailTemplate{
			TenantID: tenantID,
			Type:     templateType,
			Subject:  subject,
			HTMLBody: htmlBody,
			TextBody: &textBody,
			IsActive: isActive,
		}

		if err := h.storage.UpsertEmailTemplate(r.Context(), template); err != nil {
			errors = append(errors, fmt.Sprintf("Failed to import %s: %v", templateType, err))
			continue
		}
		imported++
	}

	if req.Branding != nil {
		branding := &storage.EmailBranding{
			TenantID: tenantID,
		}
		if v, ok := req.Branding["app_name"].(string); ok {
			branding.AppName = v
		}
		if v, ok := req.Branding["primary_color"].(string); ok {
			branding.PrimaryColor = v
		}
		if v, ok := req.Branding["secondary_color"].(string); ok {
			branding.SecondaryColor = v
		}
		h.storage.UpsertEmailBranding(r.Context(), branding)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"imported": imported,
		"errors":   errors,
		"message":  fmt.Sprintf("Imported %d templates", imported),
	})
}

// ============================================================================
// Preview All Templates
// ============================================================================

// PreviewAllTemplates returns previews of all templates.
func (h *EmailTemplateHandler) PreviewAllTemplates(w http.ResponseWriter, r *http.Request) {
	tenantID := getTenantIDFromContext(r.Context())

	branding, _ := h.storage.GetEmailBranding(r.Context(), tenantID)

	sampleUser := &storage.User{
		Email:     "preview@example.com",
		FirstName: ptr("John"),
		LastName:  ptr("Doe"),
	}

	previews := make(map[string]map[string]string)

	for _, tt := range email.AllTemplateTypes() {
		vars := email.NewTemplateVars(sampleUser, branding)
		subject, htmlBody, textBody, err := h.templateService.RenderTemplate(r.Context(), tenantID, tt, vars)
		if err != nil {
			continue
		}
		previews[string(tt)] = map[string]string{
			"subject":   subject,
			"html_body": htmlBody,
			"text_body": textBody,
		}
	}

	writeJSON(w, http.StatusOK, previews)
}

func ptr(s string) *string {
	return &s
}

// ============================================================================
// Email Tracking Pixel
// ============================================================================

// TrackEmailOpen handles the tracking pixel URL.
// GET /v1/email/track/open/{pixelID}
func (h *EmailTemplateHandler) TrackEmailOpen(w http.ResponseWriter, r *http.Request) {
	pixelID := chi.URLParam(r, "pixelID")
	pixelUUID, err := uuid.Parse(pixelID)
	if err != nil {
		http.ServeFile(w, r, "")
		return
	}

	pixel, err := h.storage.GetEmailTrackingPixel(r.Context(), pixelUUID)
	if err != nil || pixel == nil || pixel.IsOpened {
		http.ServeFile(w, r, "")
		return
	}

	if err := h.storage.MarkTrackingPixelOpened(r.Context(), pixelUUID); err != nil {
		slog.Warn("Failed to mark tracking pixel as opened", "error", err)
	}

	var jobID *string
	if pixel.EmailJobID != nil {
		s := pixel.EmailJobID.String()
		jobID = &s
	}

	event := &storage.EmailEvent{
		TenantID:     pixel.TenantID,
		JobID:        jobID,
		TemplateType: pixel.TemplateID,
		EventType:    "opened",
		Recipient:    pixel.Recipient,
		CreatedAt:    time.Now(),
	}
	h.storage.CreateEmailEvent(r.Context(), event)

	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("Surrogate-Control", "no-store")

	// 1x1 transparent GIF
	transparentGIF := []byte{
		0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00,
		0x80, 0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x21,
		0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00,
		0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44,
		0x01, 0x00, 0x3b,
	}
	w.Write(transparentGIF)
}

// TrackEmailClick handles click tracking redirects.
// GET /v1/email/track/click/{trackingID}
func (h *EmailTemplateHandler) TrackEmailClick(w http.ResponseWriter, r *http.Request) {
	trackingID := chi.URLParam(r, "trackingID")
	originalURL := r.URL.Query().Get("url")

	if originalURL == "" {
		http.Error(w, "Missing URL parameter", http.StatusBadRequest)
		return
	}

	event := &storage.EmailEvent{
		TenantID:     nil,
		TemplateType: trackingID,
		EventType:    "clicked",
		Recipient:    "",
		CreatedAt:    time.Now(),
	}
	h.storage.CreateEmailEvent(r.Context(), event)

	http.Redirect(w, r, originalURL, http.StatusFound)
}
