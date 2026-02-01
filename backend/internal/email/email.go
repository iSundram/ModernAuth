// Package email provides email service abstraction for ModernAuth.
package email

import (
	"context"

	"github.com/iSundram/ModernAuth/internal/storage"
)

// Service defines the email service interface.
type Service interface {
	// SendVerificationEmail sends an email verification email.
	SendVerificationEmail(ctx context.Context, user *storage.User, token string, verifyURL string) error

	// SendPasswordResetEmail sends a password reset email.
	SendPasswordResetEmail(ctx context.Context, user *storage.User, token string, resetURL string) error

	// SendWelcomeEmail sends a welcome email to a new user.
	SendWelcomeEmail(ctx context.Context, user *storage.User) error

	// SendLoginAlertEmail sends an alert for a new device login.
	SendLoginAlertEmail(ctx context.Context, user *storage.User, device *DeviceInfo) error

	// SendInvitationEmail sends an invitation email.
	SendInvitationEmail(ctx context.Context, invitation *InvitationEmail) error

	// SendMFAEnabledEmail sends notification that MFA was enabled.
	SendMFAEnabledEmail(ctx context.Context, user *storage.User) error

	// SendMFACodeEmail sends an MFA verification code to user's email.
	SendMFACodeEmail(ctx context.Context, userID string, code string) error

	// SendLowBackupCodesEmail sends notification when backup codes are running low.
	SendLowBackupCodesEmail(ctx context.Context, user *storage.User, remaining int) error

	// SendPasswordChangedEmail sends notification that password was changed.
	SendPasswordChangedEmail(ctx context.Context, user *storage.User) error

	// SendSessionRevokedEmail sends notification about session revocation.
	SendSessionRevokedEmail(ctx context.Context, user *storage.User, reason string) error

	// SendMagicLink sends a magic link email for passwordless authentication.
	SendMagicLink(email string, magicLinkURL string) error
}

// DeviceInfo contains device information for login alerts.
type DeviceInfo struct {
	DeviceName string
	Browser    string
	OS         string
	IPAddress  string
	Location   string
	Time       string
}

// InvitationEmail contains data for sending invitation emails.
type InvitationEmail struct {
	Email       string
	InviterName string
	TenantName  string
	InviteURL   string
	Message     string
	ExpiresAt   string
}

// Template represents an email template.
type Template struct {
	Subject  string
	HTMLBody string
	TextBody string
}

// Config holds email service configuration.
type Config struct {
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	FromEmail    string
	FromName     string
	BaseURL      string
}
