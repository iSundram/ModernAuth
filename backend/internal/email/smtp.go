// Package email provides SMTP email service for ModernAuth.
package email

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"html/template"
	"log/slog"
	"net/smtp"
	"strings"

	"github.com/iSundram/ModernAuth/internal/storage"
)

// SMTPService is an email service that sends emails via SMTP.
type SMTPService struct {
	config *Config
	logger *slog.Logger
}

// NewSMTPService creates a new SMTP email service.
func NewSMTPService(config *Config) *SMTPService {
	return &SMTPService{
		config: config,
		logger: slog.Default().With("component", "smtp_email_service"),
	}
}

// SendEmail sends an email using SMTP (implements EmailSender interface).
func (s *SMTPService) SendEmail(to, subject, htmlBody, textBody string) error {
	return s.sendEmail(to, subject, htmlBody, textBody)
}

// sendEmail sends an email using SMTP.
func (s *SMTPService) sendEmail(to, subject, htmlBody, textBody string) error {
	from := s.config.FromEmail
	if s.config.FromName != "" {
		from = fmt.Sprintf("%s <%s>", s.config.FromName, s.config.FromEmail)
	}

	s.logger.Info("Sending email via SMTP",
		"to", to,
		"subject", subject,
		"smtp_host", s.config.SMTPHost,
		"smtp_port", s.config.SMTPPort,
	)

	// Build the email message with MIME headers
	var msg bytes.Buffer
	msg.WriteString(fmt.Sprintf("From: %s\r\n", from))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", to))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	msg.WriteString("MIME-Version: 1.0\r\n")

	if htmlBody != "" {
		// Multipart message with both HTML and plain text
		boundary := "boundary-modernauth-email"
		msg.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n\r\n", boundary))

		if textBody != "" {
			msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
			msg.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n\r\n")
			msg.WriteString(textBody)
			msg.WriteString("\r\n")
		}

		msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		msg.WriteString("Content-Type: text/html; charset=\"utf-8\"\r\n\r\n")
		msg.WriteString(htmlBody)
		msg.WriteString("\r\n")
		msg.WriteString(fmt.Sprintf("--%s--\r\n", boundary))
	} else {
		msg.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n\r\n")
		msg.WriteString(textBody)
	}

	// Connect to SMTP server
	addr := fmt.Sprintf("%s:%d", s.config.SMTPHost, s.config.SMTPPort)

	var auth smtp.Auth
	if s.config.SMTPUsername != "" && s.config.SMTPPassword != "" {
		auth = smtp.PlainAuth("", s.config.SMTPUsername, s.config.SMTPPassword, s.config.SMTPHost)
	}

	// Use TLS for ports 465, regular SMTP for others
	if s.config.SMTPPort == 465 {
		if err := s.sendEmailTLS(addr, auth, s.config.FromEmail, []string{to}, msg.Bytes()); err != nil {
			s.logger.Error("Failed to send email via SMTP (TLS)",
				"to", to,
				"subject", subject,
				"error", err,
			)
			return err
		}
		return nil
	}

	if err := smtp.SendMail(addr, auth, s.config.FromEmail, []string{to}, msg.Bytes()); err != nil {
		s.logger.Error("Failed to send email via SMTP",
			"to", to,
			"subject", subject,
			"error", err,
		)
		return err
	}

	return nil
}

// sendEmailTLS sends email using implicit TLS (port 465).
func (s *SMTPService) sendEmailTLS(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
	tlsConfig := &tls.Config{
		ServerName: s.config.SMTPHost,
	}

	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, s.config.SMTPHost)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}
	defer client.Close()

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}
	}

	if err := client.Mail(from); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}

	for _, recipient := range to {
		if err := client.Rcpt(recipient); err != nil {
			return fmt.Errorf("failed to set recipient: %w", err)
		}
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to open data writer: %w", err)
	}

	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("failed to close data writer: %w", err)
	}

	return client.Quit()
}

// SendVerificationEmail sends an email verification email.
func (s *SMTPService) SendVerificationEmail(ctx context.Context, user *storage.User, token string, verifyURL string) error {
	subject := "Verify your email address"

	data := map[string]string{
		"Name":      getUserName(user),
		"VerifyURL": verifyURL,
		"Token":     token,
	}

	htmlBody, err := s.renderTemplate(verificationEmailHTML, data)
	if err != nil {
		return err
	}

	textBody := fmt.Sprintf(
		"Hi %s,\n\nPlease verify your email address by clicking the link below:\n\n%s\n\nIf you didn't create an account, you can safely ignore this email.\n\nThanks,\nThe ModernAuth Team",
		getUserName(user), verifyURL,
	)

	s.logger.Info("Sending verification email", "to", user.Email)
	return s.sendEmail(user.Email, subject, htmlBody, textBody)
}

// SendPasswordResetEmail sends a password reset email.
func (s *SMTPService) SendPasswordResetEmail(ctx context.Context, user *storage.User, token string, resetURL string) error {
	subject := "Reset your password"

	data := map[string]string{
		"Name":     getUserName(user),
		"ResetURL": resetURL,
		"Token":    token,
	}

	htmlBody, err := s.renderTemplate(passwordResetEmailHTML, data)
	if err != nil {
		return err
	}

	textBody := fmt.Sprintf(
		"Hi %s,\n\nYou requested to reset your password. Click the link below:\n\n%s\n\nThis link will expire in 1 hour.\n\nIf you didn't request this, you can safely ignore this email.\n\nThanks,\nThe ModernAuth Team",
		getUserName(user), resetURL,
	)

	s.logger.Info("Sending password reset email", "to", user.Email)
	return s.sendEmail(user.Email, subject, htmlBody, textBody)
}

// SendWelcomeEmail sends a welcome email to a new user.
func (s *SMTPService) SendWelcomeEmail(ctx context.Context, user *storage.User) error {
	subject := "Welcome to ModernAuth"

	data := map[string]string{
		"Name":    getUserName(user),
		"BaseURL": s.config.BaseURL,
	}

	htmlBody, err := s.renderTemplate(welcomeEmailHTML, data)
	if err != nil {
		return err
	}

	textBody := fmt.Sprintf(
		"Hi %s,\n\nWelcome to ModernAuth! Your account has been created successfully.\n\nThanks,\nThe ModernAuth Team",
		getUserName(user),
	)

	s.logger.Info("Sending welcome email", "to", user.Email)
	return s.sendEmail(user.Email, subject, htmlBody, textBody)
}

// SendLoginAlertEmail sends an alert for a new device login.
func (s *SMTPService) SendLoginAlertEmail(ctx context.Context, user *storage.User, device *DeviceInfo) error {
	subject := "New login to your account"

	data := map[string]string{
		"Name":       getUserName(user),
		"DeviceName": device.DeviceName,
		"Browser":    device.Browser,
		"OS":         device.OS,
		"IPAddress":  device.IPAddress,
		"Location":   device.Location,
		"Time":       device.Time,
	}

	htmlBody, err := s.renderTemplate(loginAlertEmailHTML, data)
	if err != nil {
		return err
	}

	textBody := fmt.Sprintf(
		"Hi %s,\n\nWe noticed a new login to your account:\n\nDevice: %s\nBrowser: %s\nOS: %s\nIP Address: %s\nLocation: %s\nTime: %s\n\nIf this wasn't you, please change your password immediately.\n\nThanks,\nThe ModernAuth Team",
		getUserName(user), device.DeviceName, device.Browser, device.OS, device.IPAddress, device.Location, device.Time,
	)

	s.logger.Info("Sending login alert email", "to", user.Email, "device", device.DeviceName)
	return s.sendEmail(user.Email, subject, htmlBody, textBody)
}

// SendInvitationEmail sends an invitation email.
func (s *SMTPService) SendInvitationEmail(ctx context.Context, invitation *InvitationEmail) error {
	subject := fmt.Sprintf("You've been invited to join %s", invitation.TenantName)

	data := map[string]string{
		"InviterName": invitation.InviterName,
		"TenantName":  invitation.TenantName,
		"InviteURL":   invitation.InviteURL,
		"Message":     invitation.Message,
		"ExpiresAt":   invitation.ExpiresAt,
	}

	htmlBody, err := s.renderTemplate(invitationEmailHTML, data)
	if err != nil {
		return err
	}

	textBody := fmt.Sprintf(
		"Hi,\n\n%s has invited you to join %s.\n\n%s\n\nClick the link below to accept:\n%s\n\nThis invitation expires on %s.\n\nThanks,\nThe ModernAuth Team",
		invitation.InviterName, invitation.TenantName, invitation.Message, invitation.InviteURL, invitation.ExpiresAt,
	)

	s.logger.Info("Sending invitation email", "to", invitation.Email)
	return s.sendEmail(invitation.Email, subject, htmlBody, textBody)
}

// SendMFAEnabledEmail sends notification that MFA was enabled.
func (s *SMTPService) SendMFAEnabledEmail(ctx context.Context, user *storage.User) error {
	subject := "Two-factor authentication enabled"

	data := map[string]string{
		"Name": getUserName(user),
	}

	htmlBody, err := s.renderTemplate(mfaEnabledEmailHTML, data)
	if err != nil {
		return err
	}

	textBody := fmt.Sprintf(
		"Hi %s,\n\nTwo-factor authentication has been enabled on your account. Your account is now more secure.\n\nIf you didn't do this, please contact support immediately.\n\nThanks,\nThe ModernAuth Team",
		getUserName(user),
	)

	s.logger.Info("Sending MFA enabled email", "to", user.Email)
	return s.sendEmail(user.Email, subject, htmlBody, textBody)
}

// SendPasswordChangedEmail sends notification that password was changed.
func (s *SMTPService) SendPasswordChangedEmail(ctx context.Context, user *storage.User) error {
	subject := "Your password was changed"

	data := map[string]string{
		"Name": getUserName(user),
	}

	htmlBody, err := s.renderTemplate(passwordChangedEmailHTML, data)
	if err != nil {
		return err
	}

	textBody := fmt.Sprintf(
		"Hi %s,\n\nYour password has been changed. If you didn't do this, please reset your password immediately and contact support.\n\nThanks,\nThe ModernAuth Team",
		getUserName(user),
	)

	s.logger.Info("Sending password changed email", "to", user.Email)
	return s.sendEmail(user.Email, subject, htmlBody, textBody)
}

// SendSessionRevokedEmail sends notification about session revocation.
func (s *SMTPService) SendSessionRevokedEmail(ctx context.Context, user *storage.User, reason string) error {
	subject := "Your session was terminated"

	data := map[string]string{
		"Name":   getUserName(user),
		"Reason": reason,
	}

	htmlBody, err := s.renderTemplate(sessionRevokedEmailHTML, data)
	if err != nil {
		return err
	}

	textBody := fmt.Sprintf(
		"Hi %s,\n\nYour session has been terminated.\n\nReason: %s\n\nIf you didn't do this, please check your account security.\n\nThanks,\nThe ModernAuth Team",
		getUserName(user), reason,
	)

	s.logger.Info("Sending session revoked email", "to", user.Email)
	return s.sendEmail(user.Email, subject, htmlBody, textBody)
}

// renderTemplate renders an HTML template with the given data.
func (s *SMTPService) renderTemplate(templateStr string, data map[string]string) (string, error) {
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

// getUserName returns the user's display name.
func getUserName(user *storage.User) string {
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

// Verify SMTPService implements Service interface
var _ Service = (*SMTPService)(nil)
