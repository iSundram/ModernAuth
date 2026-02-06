// Package email provides template variable resolution.
package email

import (
	"strconv"
	"strings"
	"time"

	"github.com/iSundram/ModernAuth/internal/storage"
)

// TemplateVars holds all variables available for email templates.
type TemplateVars struct {
	// User variables
	FirstName string
	LastName  string
	FullName  string
	Email     string
	Username  string

	// Branding variables
	AppName        string
	AppLogo        string
	PrimaryColor   string
	SecondaryColor string
	CompanyName    string
	SupportEmail   string
	FooterText     string
	CurrentYear    string

	// Common context variables
	UnsubscribeURL string
	CurrentDate    string
	CurrentTime    string
	UTCOffset      string
	LanguageCode   string

	// Context variables (set per email type)
	VerifyURL      string
	ResetURL       string
	BaseURL        string
	Token          string
	DeviceName     string
	Browser        string
	OS             string
	IPAddress      string
	Location       string
	Time           string
	InviterName    string
	TenantName     string
	InviteURL      string
	Message        string
	ExpiresAt      string
	Reason         string
	MFACode        string
	RemainingCodes string

	// Account deactivation
	ReactivationURL string

	// Email change
	OldEmail string
	NewEmail string

	// Password expiry
	DaysUntilExpiry   string
	ExpiryDate        string
	ChangePasswordURL string

	// Security alert
	AlertTitle   string
	AlertMessage string
	AlertDetails string
	ActionURL    string
	ActionText   string

	// Rate limit warning
	ActionType   string
	CurrentCount string
	MaxCount     string
	TimeWindow   string
	UpgradeURL   string

	// Magic link
	MagicLinkURL string
}

// NewTemplateVars creates template variables from user and branding data.
func NewTemplateVars(user *storage.User, branding *storage.EmailBranding) *TemplateVars {
	now := time.Now()
	vars := &TemplateVars{
		CurrentYear:  strconv.Itoa(now.Year()),
		CurrentDate:  now.Format("January 2, 2006"),
		CurrentTime:  now.Format("3:04 PM"),
		UTCOffset:    now.Format("-0700"),
		LanguageCode: "en",
	}

	// Set user variables
	if user != nil {
		vars.Email = user.Email

		if user.FirstName != nil && *user.FirstName != "" {
			vars.FirstName = *user.FirstName
		}
		if user.LastName != nil && *user.LastName != "" {
			vars.LastName = *user.LastName
		}
		if user.Username != nil && *user.Username != "" {
			vars.Username = *user.Username
		}

		// Build full name with fallbacks
		vars.FullName = buildFullName(user)
	}

	// Set branding variables
	if branding != nil {
		vars.AppName = branding.AppName
		vars.PrimaryColor = branding.PrimaryColor
		vars.SecondaryColor = branding.SecondaryColor

		if branding.LogoURL != nil {
			vars.AppLogo = *branding.LogoURL
		}
		if branding.CompanyName != nil {
			vars.CompanyName = *branding.CompanyName
		} else {
			vars.CompanyName = branding.AppName
		}
		if branding.SupportEmail != nil {
			vars.SupportEmail = *branding.SupportEmail
		}
		if branding.FooterText != nil {
			vars.FooterText = *branding.FooterText
		} else {
			vars.FooterText = "© " + vars.CurrentYear + " " + vars.CompanyName + ". All rights reserved."
		}
	} else {
		// Default branding with new color scheme
		vars.AppName = "ModernAuth"
		vars.PrimaryColor = "#2B2B2B"   // Dark
		vars.SecondaryColor = "#B3B3B3" // Medium gray
		vars.CompanyName = "ModernAuth"
		vars.FooterText = "© " + vars.CurrentYear + " ModernAuth. All rights reserved."
	}

	return vars
}

// buildFullName constructs a display name from user data with fallbacks.
func buildFullName(user *storage.User) string {
	if user.FirstName != nil && *user.FirstName != "" {
		if user.LastName != nil && *user.LastName != "" {
			return *user.FirstName + " " + *user.LastName
		}
		return *user.FirstName
	}
	if user.Username != nil && *user.Username != "" {
		return *user.Username
	}
	// Extract name from email
	parts := strings.Split(user.Email, "@")
	return parts[0]
}

// WithVerification sets verification-specific variables.
func (v *TemplateVars) WithVerification(token, verifyURL string) *TemplateVars {
	v.Token = token
	v.VerifyURL = verifyURL
	return v
}

// WithPasswordReset sets password reset-specific variables.
func (v *TemplateVars) WithPasswordReset(token, resetURL string) *TemplateVars {
	v.Token = token
	v.ResetURL = resetURL
	return v
}

// WithBaseURL sets the base URL.
func (v *TemplateVars) WithBaseURL(baseURL string) *TemplateVars {
	v.BaseURL = baseURL
	return v
}

// WithDevice sets device-specific variables for login alerts.
func (v *TemplateVars) WithDevice(device *DeviceInfo) *TemplateVars {
	if device != nil {
		v.DeviceName = device.DeviceName
		v.Browser = device.Browser
		v.OS = device.OS
		v.IPAddress = device.IPAddress
		v.Location = device.Location
		v.Time = device.Time
	}
	return v
}

// WithInvitation sets invitation-specific variables.
func (v *TemplateVars) WithInvitation(invitation *InvitationEmail) *TemplateVars {
	if invitation != nil {
		v.InviterName = invitation.InviterName
		v.TenantName = invitation.TenantName
		v.InviteURL = invitation.InviteURL
		v.Message = invitation.Message
		v.ExpiresAt = invitation.ExpiresAt
	}
	return v
}

// WithReason sets the reason for session revocation.
func (v *TemplateVars) WithReason(reason string) *TemplateVars {
	v.Reason = reason
	return v
}

// WithMFACode sets the MFA code for verification emails.
func (v *TemplateVars) WithMFACode(code string) *TemplateVars {
	v.MFACode = code
	return v
}

// WithRemainingCodes sets the number of remaining backup codes.
func (v *TemplateVars) WithRemainingCodes(remaining int) *TemplateVars {
	v.RemainingCodes = strconv.Itoa(remaining)
	return v
}

// WithAccountDeactivation sets account deactivation-specific variables.
func (v *TemplateVars) WithAccountDeactivation(reason, reactivationURL string) *TemplateVars {
	v.Reason = reason
	v.ReactivationURL = reactivationURL
	return v
}

// WithEmailChange sets email change-specific variables.
func (v *TemplateVars) WithEmailChange(oldEmail, newEmail string) *TemplateVars {
	v.OldEmail = oldEmail
	v.NewEmail = newEmail
	return v
}

// WithPasswordExpiry sets password expiry-specific variables.
func (v *TemplateVars) WithPasswordExpiry(daysUntilExpiry, expiryDate, changePasswordURL string) *TemplateVars {
	v.DaysUntilExpiry = daysUntilExpiry
	v.ExpiryDate = expiryDate
	v.ChangePasswordURL = changePasswordURL
	return v
}

// WithSecurityAlert sets security alert-specific variables.
func (v *TemplateVars) WithSecurityAlert(title, message, details, actionURL, actionText string) *TemplateVars {
	v.AlertTitle = title
	v.AlertMessage = message
	v.AlertDetails = details
	v.ActionURL = actionURL
	v.ActionText = actionText
	return v
}

// WithRateLimitWarning sets rate limit warning-specific variables.
func (v *TemplateVars) WithRateLimitWarning(actionType, currentCount, maxCount, timeWindow, upgradeURL string) *TemplateVars {
	v.ActionType = actionType
	v.CurrentCount = currentCount
	v.MaxCount = maxCount
	v.TimeWindow = timeWindow
	v.UpgradeURL = upgradeURL
	return v
}

// WithMagicLink sets magic link-specific variables.
func (v *TemplateVars) WithMagicLink(magicLinkURL string) *TemplateVars {
	v.MagicLinkURL = magicLinkURL
	return v
}

// WithUnsubscribeURL sets the unsubscribe URL.
func (v *TemplateVars) WithUnsubscribeURL(url string) *TemplateVars {
	v.UnsubscribeURL = url
	return v
}

// WithLanguage sets the language code for localization.
func (v *TemplateVars) WithLanguage(langCode string) *TemplateVars {
	v.LanguageCode = langCode
	return v
}
