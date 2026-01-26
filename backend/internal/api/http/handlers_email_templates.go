// Package http provides email template admin HTTP handlers.
package http

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/email"
	"github.com/iSundram/ModernAuth/internal/storage"
	tenantpkg "github.com/iSundram/ModernAuth/internal/tenant"
)

// EmailTemplateHandler handles email template admin endpoints.
type EmailTemplateHandler struct {
	storage         storage.EmailTemplateStorage
	templateService *email.TemplateService
}

// NewEmailTemplateHandler creates a new email template handler.
func NewEmailTemplateHandler(store storage.EmailTemplateStorage, templateService *email.TemplateService) *EmailTemplateHandler {
	return &EmailTemplateHandler{
		storage:         store,
		templateService: templateService,
	}
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

	// Invalidate cache
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
