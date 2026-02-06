// Package email provides a console email service for development.
package email

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/iSundram/ModernAuth/internal/storage"
)

// ConsoleService is an email service that logs emails to console (for development).
type ConsoleService struct {
	logger *slog.Logger
}

// NewConsoleService creates a new console email service.
func NewConsoleService() *ConsoleService {
	return &ConsoleService{
		logger: slog.Default().With("component", "email_service"),
	}
}

// SendEmail logs an email to console (implements EmailSender interface).
func (s *ConsoleService) SendEmail(to, subject, htmlBody, textBody string) error {
	s.logger.Info("Email",
		"to", to,
		"subject", subject,
	)
	fmt.Printf("\n=== EMAIL ===\n")
	fmt.Printf("To: %s\n", to)
	fmt.Printf("Subject: %s\n", subject)
	fmt.Printf("Text Body:\n%s\n", textBody)
	fmt.Printf("=============\n\n")
	return nil
}

// maskToken masks a token for logging, showing only first and last 4 chars.
func maskToken(token string) string {
	if len(token) <= 8 {
		return "***"
	}
	return token[:4] + "..." + token[len(token)-4:]
}

// SendVerificationEmail logs a verification email to console.
func (s *ConsoleService) SendVerificationEmail(ctx context.Context, user *storage.User, token string, verifyURL string) error {
	s.logger.Info("Verification Email",
		"to", user.Email,
		"subject", "Verify your email address",
		"token", maskToken(token),
	)
	fmt.Printf("\n=== VERIFICATION EMAIL ===\n")
	fmt.Printf("To: %s\n", user.Email)
	fmt.Printf("Subject: Verify your email address\n")
	fmt.Printf("Token: %s\n", maskToken(token))
	fmt.Printf("URL: %s\n", verifyURL)
	fmt.Printf("==========================\n\n")
	return nil
}

// SendPasswordResetEmail logs a password reset email to console.
func (s *ConsoleService) SendPasswordResetEmail(ctx context.Context, user *storage.User, token string, resetURL string) error {
	s.logger.Info("Password Reset Email",
		"to", user.Email,
		"subject", "Reset your password",
		"token", maskToken(token),
	)
	fmt.Printf("\n=== PASSWORD RESET EMAIL ===\n")
	fmt.Printf("To: %s\n", user.Email)
	fmt.Printf("Subject: Reset your password\n")
	fmt.Printf("Token: %s\n", maskToken(token))
	fmt.Printf("URL: %s\n", resetURL)
	fmt.Printf("============================\n\n")
	return nil
}

// SendWelcomeEmail logs a welcome email to console.
func (s *ConsoleService) SendWelcomeEmail(ctx context.Context, user *storage.User) error {
	s.logger.Info("Welcome Email",
		"to", user.Email,
		"subject", "Welcome to ModernAuth",
	)
	fmt.Printf("\n=== WELCOME EMAIL ===\n")
	fmt.Printf("To: %s\n", user.Email)
	fmt.Printf("Subject: Welcome to ModernAuth\n")
	fmt.Printf("=====================\n\n")
	return nil
}

// SendLoginAlertEmail logs a login alert email to console.
func (s *ConsoleService) SendLoginAlertEmail(ctx context.Context, user *storage.User, device *DeviceInfo) error {
	s.logger.Info("Login Alert Email",
		"to", user.Email,
		"subject", "New login to your account",
		"device", device.DeviceName,
		"ip", device.IPAddress,
	)
	fmt.Printf("\n=== LOGIN ALERT EMAIL ===\n")
	fmt.Printf("To: %s\n", user.Email)
	fmt.Printf("Subject: New login to your account\n")
	fmt.Printf("Device: %s\n", device.DeviceName)
	fmt.Printf("Browser: %s\n", device.Browser)
	fmt.Printf("OS: %s\n", device.OS)
	fmt.Printf("IP: %s\n", device.IPAddress)
	fmt.Printf("Location: %s\n", device.Location)
	fmt.Printf("Time: %s\n", device.Time)
	fmt.Printf("=========================\n\n")
	return nil
}

// SendInvitationEmail logs an invitation email to console.
func (s *ConsoleService) SendInvitationEmail(ctx context.Context, invitation *InvitationEmail) error {
	s.logger.Info("Invitation Email",
		"to", invitation.Email,
		"subject", fmt.Sprintf("You've been invited to join %s", invitation.TenantName),
		"inviter", invitation.InviterName,
	)
	fmt.Printf("\n=== INVITATION EMAIL ===\n")
	fmt.Printf("To: %s\n", invitation.Email)
	fmt.Printf("Subject: You've been invited to join %s\n", invitation.TenantName)
	fmt.Printf("Inviter: %s\n", invitation.InviterName)
	fmt.Printf("Message: %s\n", invitation.Message)
	fmt.Printf("URL: %s\n", invitation.InviteURL)
	fmt.Printf("Expires: %s\n", invitation.ExpiresAt)
	fmt.Printf("========================\n\n")
	return nil
}

// SendMFAEnabledEmail logs an MFA enabled notification to console.
func (s *ConsoleService) SendMFAEnabledEmail(ctx context.Context, user *storage.User) error {
	s.logger.Info("MFA Enabled Email",
		"to", user.Email,
		"subject", "Two-factor authentication enabled",
	)
	fmt.Printf("\n=== MFA ENABLED EMAIL ===\n")
	fmt.Printf("To: %s\n", user.Email)
	fmt.Printf("Subject: Two-factor authentication enabled\n")
	fmt.Printf("=========================\n")
	return nil
}

// SendMFACodeEmail logs an MFA code email to console.
func (s *ConsoleService) SendMFACodeEmail(ctx context.Context, email, code string) error {
	s.logger.Info("MFA Code Email",
		"to", email,
		"subject", "Your verification code",
		"code", "******",
	)
	fmt.Printf("\n=== MFA CODE EMAIL ===\n")
	fmt.Printf("To: %s\n", email)
	fmt.Printf("Subject: Your verification code\n")
	fmt.Printf("Code: ******\n")
	fmt.Printf("=====================\n")
	return nil
}

// SendLowBackupCodesEmail logs a low backup codes notification to console.
func (s *ConsoleService) SendLowBackupCodesEmail(ctx context.Context, user *storage.User, remaining int) error {
	s.logger.Info("Low Backup Codes Email",
		"to", user.Email,
		"subject", "Action Required: Low backup codes remaining",
		"remaining", remaining,
	)
	fmt.Printf("\n=== LOW BACKUP CODES EMAIL ===\n")
	fmt.Printf("To: %s\n", user.Email)
	fmt.Printf("Subject: Action Required: Low backup codes remaining\n")
	fmt.Printf("Remaining Codes: %d\n", remaining)
	fmt.Printf("==============================\n\n")
	return nil
}

// SendPasswordChangedEmail logs a password changed notification to console.
func (s *ConsoleService) SendPasswordChangedEmail(ctx context.Context, user *storage.User) error {
	s.logger.Info("Password Changed Email",
		"to", user.Email,
		"subject", "Your password was changed",
	)
	fmt.Printf("\n=== PASSWORD CHANGED EMAIL ===\n")
	fmt.Printf("To: %s\n", user.Email)
	fmt.Printf("Subject: Your password was changed\n")
	fmt.Printf("==============================\n\n")
	return nil
}

// SendSessionRevokedEmail logs a session revoked notification to console.
func (s *ConsoleService) SendSessionRevokedEmail(ctx context.Context, user *storage.User, reason string) error {
	s.logger.Info("Session Revoked Email",
		"to", user.Email,
		"subject", "Your session was terminated",
		"reason", reason,
	)
	fmt.Printf("\n=== SESSION REVOKED EMAIL ===\n")
	fmt.Printf("To: %s\n", user.Email)
	fmt.Printf("Subject: Your session was terminated\n")
	fmt.Printf("Reason: %s\n", reason)
	fmt.Printf("=============================\n\n")
	return nil
}

// SendMagicLink logs a magic link email to console.
func (s *ConsoleService) SendMagicLink(ctx context.Context, email string, magicLinkURL string) error {
	s.logger.Info("Magic Link Email",
		"to", email,
		"subject", "Sign in to your account",
		"url", "[MASKED]",
	)
	fmt.Printf("\n=== MAGIC LINK EMAIL ===\n")
	fmt.Printf("To: %s\n", email)
	fmt.Printf("Subject: Sign in to your account\n")
	fmt.Printf("Magic Link URL: [Use email provider logs for actual URL]\n")
	fmt.Printf("========================\n\n")
	return nil
}

// SendAccountDeactivatedEmail logs an account deactivation email to console.
func (s *ConsoleService) SendAccountDeactivatedEmail(ctx context.Context, user *storage.User, reason, reactivationURL string) error {
	s.logger.Info("Account Deactivated Email",
		"to", user.Email,
		"subject", "Account Deactivated",
		"reason", reason,
	)
	fmt.Printf("\n=== ACCOUNT DEACTIVATED EMAIL ===\n")
	fmt.Printf("To: %s\n", user.Email)
	fmt.Printf("Subject: Account Deactivated\n")
	fmt.Printf("Reason: %s\n", reason)
	fmt.Printf("=================================\n\n")
	return nil
}

// SendEmailChangedEmail logs an email change notification to console.
func (s *ConsoleService) SendEmailChangedEmail(ctx context.Context, user *storage.User, oldEmail, newEmail string) error {
	s.logger.Info("Email Changed Email",
		"to", oldEmail,
		"subject", "Email Address Changed",
		"old_email", oldEmail,
		"new_email", newEmail,
	)
	fmt.Printf("\n=== EMAIL CHANGED EMAIL ===\n")
	fmt.Printf("To: %s\n", oldEmail)
	fmt.Printf("Subject: Email Address Changed\n")
	fmt.Printf("Old Email: %s\n", oldEmail)
	fmt.Printf("New Email: %s\n", newEmail)
	fmt.Printf("=============================\n\n")
	return nil
}

// SendPasswordExpiryEmail logs a password expiry warning to console.
func (s *ConsoleService) SendPasswordExpiryEmail(ctx context.Context, user *storage.User, daysUntilExpiry, expiryDate, changePasswordURL string) error {
	s.logger.Info("Password Expiry Email",
		"to", user.Email,
		"subject", "Password Expiring Soon",
		"days_until_expiry", daysUntilExpiry,
	)
	fmt.Printf("\n=== PASSWORD EXPIRY EMAIL ===\n")
	fmt.Printf("To: %s\n", user.Email)
	fmt.Printf("Subject: Password Expiring Soon\n")
	fmt.Printf("Days Until Expiry: %s\n", daysUntilExpiry)
	fmt.Printf("Expiry Date: %s\n", expiryDate)
	fmt.Printf("=============================\n\n")
	return nil
}

// SendSecurityAlertEmail logs a security alert to console.
func (s *ConsoleService) SendSecurityAlertEmail(ctx context.Context, user *storage.User, title, message, details, actionURL, actionText string) error {
	s.logger.Info("Security Alert Email",
		"to", user.Email,
		"subject", title,
		"alert_title", title,
	)
	fmt.Printf("\n=== SECURITY ALERT EMAIL ===\n")
	fmt.Printf("To: %s\n", user.Email)
	fmt.Printf("Subject: %s\n", title)
	fmt.Printf("Message: %s\n", message)
	fmt.Printf("Details: %s\n", details)
	fmt.Printf("==============================\n\n")
	return nil
}

// SendRateLimitWarningEmail logs a rate limit warning to console.
func (s *ConsoleService) SendRateLimitWarningEmail(ctx context.Context, user *storage.User, actionType, currentCount, maxCount, timeWindow, upgradeURL string) error {
	s.logger.Info("Rate Limit Warning Email",
		"to", user.Email,
		"subject", "Rate Limit Approaching",
		"action", actionType,
	)
	fmt.Printf("\n=== RATE LIMIT WARNING EMAIL ===\n")
	fmt.Printf("To: %s\n", user.Email)
	fmt.Printf("Subject: Rate Limit Approaching\n")
	fmt.Printf("Action Type: %s\n", actionType)
	fmt.Printf("Current: %s / %s\n", currentCount, maxCount)
	fmt.Printf("Time Window: %s\n", timeWindow)
	fmt.Printf("===================================\n\n")
	return nil
}

// Verify ConsoleService implements Service interface
var _ Service = (*ConsoleService)(nil)
