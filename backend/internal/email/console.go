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

// SendVerificationEmail logs a verification email to console.
func (s *ConsoleService) SendVerificationEmail(ctx context.Context, user *storage.User, token string, verifyURL string) error {
	s.logger.Info("📧 Verification Email",
		"to", user.Email,
		"subject", "Verify your email address",
		"token", token,
		"verify_url", verifyURL,
	)
	fmt.Printf("\n=== VERIFICATION EMAIL ===\n")
	fmt.Printf("To: %s\n", user.Email)
	fmt.Printf("Subject: Verify your email address\n")
	fmt.Printf("Token: %s\n", token)
	fmt.Printf("URL: %s\n", verifyURL)
	fmt.Printf("==========================\n\n")
	return nil
}

// SendPasswordResetEmail logs a password reset email to console.
func (s *ConsoleService) SendPasswordResetEmail(ctx context.Context, user *storage.User, token string, resetURL string) error {
	s.logger.Info("📧 Password Reset Email",
		"to", user.Email,
		"subject", "Reset your password",
		"token", token,
		"reset_url", resetURL,
	)
	fmt.Printf("\n=== PASSWORD RESET EMAIL ===\n")
	fmt.Printf("To: %s\n", user.Email)
	fmt.Printf("Subject: Reset your password\n")
	fmt.Printf("Token: %s\n", token)
	fmt.Printf("URL: %s\n", resetURL)
	fmt.Printf("============================\n\n")
	return nil
}

// SendWelcomeEmail logs a welcome email to console.
func (s *ConsoleService) SendWelcomeEmail(ctx context.Context, user *storage.User) error {
	s.logger.Info("📧 Welcome Email",
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
	s.logger.Info("📧 Login Alert Email",
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
	s.logger.Info("📧 Invitation Email",
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
	s.logger.Info("📧 MFA Enabled Email",
		"to", user.Email,
		"subject", "Two-factor authentication enabled",
	)
	fmt.Printf("\n=== MFA ENABLED EMAIL ===\n")
	fmt.Printf("To: %s\n", user.Email)
	fmt.Printf("Subject: Two-factor authentication enabled\n")
	fmt.Printf("=========================\n\n")
	return nil
}

// SendPasswordChangedEmail logs a password changed notification to console.
func (s *ConsoleService) SendPasswordChangedEmail(ctx context.Context, user *storage.User) error {
	s.logger.Info("📧 Password Changed Email",
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
	s.logger.Info("📧 Session Revoked Email",
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

// Verify ConsoleService implements Service interface
var _ Service = (*ConsoleService)(nil)
