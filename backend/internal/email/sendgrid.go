// Package email provides SendGrid email service for ModernAuth.
package email

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/iSundram/ModernAuth/internal/storage"
)

// SendGridService is an email service that sends emails via SendGrid API.
type SendGridService struct {
	apiKey     string
	fromEmail  string
	fromName   string
	baseURL    string
	httpClient *http.Client
	logger     *slog.Logger
}

// SendGridConfig holds SendGrid configuration.
type SendGridConfig struct {
	APIKey    string
	FromEmail string
	FromName  string
	BaseURL   string
}

// NewSendGridService creates a new SendGrid email service.
func NewSendGridService(cfg *SendGridConfig) *SendGridService {
	return &SendGridService{
		apiKey:    cfg.APIKey,
		fromEmail: cfg.FromEmail,
		fromName:  cfg.FromName,
		baseURL:   cfg.BaseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: slog.Default().With("component", "sendgrid_email_service"),
	}
}

// SendGrid API request structures
type sendGridRequest struct {
	Personalizations []sendGridPersonalization `json:"personalizations"`
	From             sendGridEmail             `json:"from"`
	Subject          string                    `json:"subject"`
	Content          []sendGridContent         `json:"content"`
}

type sendGridPersonalization struct {
	To []sendGridEmail `json:"to"`
}

type sendGridEmail struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}

type sendGridContent struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// SendEmail sends an email using SendGrid API v3 (implements EmailSender interface).
func (s *SendGridService) SendEmail(to, subject, htmlBody, textBody string) error {
	return s.sendEmail(to, subject, htmlBody, textBody)
}

// sendEmail sends an email using SendGrid API v3.
func (s *SendGridService) sendEmail(to, subject, htmlBody, textBody string) error {
	req := sendGridRequest{
		Personalizations: []sendGridPersonalization{
			{
				To: []sendGridEmail{{Email: to}},
			},
		},
		From: sendGridEmail{
			Email: s.fromEmail,
			Name:  s.fromName,
		},
		Subject: subject,
		Content: []sendGridContent{},
	}

	// Add text content first (fallback), then HTML
	if textBody != "" {
		req.Content = append(req.Content, sendGridContent{
			Type:  "text/plain",
			Value: textBody,
		})
	}
	if htmlBody != "" {
		req.Content = append(req.Content, sendGridContent{
			Type:  "text/html",
			Value: htmlBody,
		})
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal SendGrid request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", "https://api.sendgrid.com/v3/mail/send", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+s.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")

	s.logger.Info("Sending email via SendGrid", "to", to, "subject", subject)

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		s.logger.Error("SendGrid request failed", "error", err)
		return fmt.Errorf("SendGrid request failed: %w", err)
	}
	defer resp.Body.Close()

	// SendGrid returns 202 Accepted on success
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		s.logger.Error("SendGrid API error",
			"status", resp.StatusCode,
			"response", string(respBody),
		)
		return fmt.Errorf("SendGrid API error: status %d", resp.StatusCode)
	}

	s.logger.Info("Email sent successfully via SendGrid", "to", to)
	return nil
}

// renderTemplate renders an HTML template with the given data.
func (s *SendGridService) renderTemplate(templateStr string, data map[string]string) (string, error) {
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
func sendGridGetUserName(user *storage.User) string {
	if user.FirstName != nil && *user.FirstName != "" {
		if user.LastName != nil && *user.LastName != "" {
			return *user.FirstName + " " + *user.LastName
		}
		return *user.FirstName
	}
	if user.Username != nil && *user.Username != "" {
		return *user.Username
	}
	parts := strings.Split(user.Email, "@")
	return parts[0]
}

// SendVerificationEmail sends an email verification email.
func (s *SendGridService) SendVerificationEmail(ctx context.Context, user *storage.User, token string, verifyURL string) error {
	subject := "Verify your email address"

	data := map[string]string{
		"FullName":   sendGridGetUserName(user),
		"VerifyURL":  verifyURL,
		"Token":      token,
		"FooterText": "Thanks, The ModernAuth Team",
	}

	htmlBody, err := s.renderTemplate(verificationEmailHTML, data)
	if err != nil {
		return err
	}

	textBody := fmt.Sprintf(
		"Hi %s,\n\nPlease verify your email address by clicking the link below:\n\n%s\n\nIf you didn't create an account, you can safely ignore this email.\n\nThanks,\nThe ModernAuth Team",
		sendGridGetUserName(user), verifyURL,
	)

	return s.sendEmail(user.Email, subject, htmlBody, textBody)
}

// SendPasswordResetEmail sends a password reset email.
func (s *SendGridService) SendPasswordResetEmail(ctx context.Context, user *storage.User, token string, resetURL string) error {
	subject := "Reset your password"

	data := map[string]string{
		"FullName":   sendGridGetUserName(user),
		"ResetURL":   resetURL,
		"Token":      token,
		"FooterText": "Thanks, The ModernAuth Team",
	}

	htmlBody, err := s.renderTemplate(passwordResetEmailHTML, data)
	if err != nil {
		return err
	}

	textBody := fmt.Sprintf(
		"Hi %s,\n\nYou requested to reset your password. Click the link below:\n\n%s\n\nThis link will expire in 1 hour.\n\nIf you didn't request this, you can safely ignore this email.\n\nThanks,\nThe ModernAuth Team",
		sendGridGetUserName(user), resetURL,
	)

	return s.sendEmail(user.Email, subject, htmlBody, textBody)
}

// SendWelcomeEmail sends a welcome email to a new user.
func (s *SendGridService) SendWelcomeEmail(ctx context.Context, user *storage.User) error {
	subject := "Welcome to ModernAuth"

	data := map[string]string{
		"FullName":   sendGridGetUserName(user),
		"AppName":    "ModernAuth",
		"BaseURL":    s.baseURL,
		"FooterText": "Thanks, The ModernAuth Team",
	}

	htmlBody, err := s.renderTemplate(welcomeEmailHTML, data)
	if err != nil {
		return err
	}

	textBody := fmt.Sprintf(
		"Hi %s,\n\nWelcome to ModernAuth! Your account has been created successfully.\n\nThanks,\nThe ModernAuth Team",
		sendGridGetUserName(user),
	)

	return s.sendEmail(user.Email, subject, htmlBody, textBody)
}

// SendLoginAlertEmail sends an alert for a new device login.
func (s *SendGridService) SendLoginAlertEmail(ctx context.Context, user *storage.User, device *DeviceInfo) error {
	subject := "New login to your account"

	data := map[string]string{
		"FullName":   sendGridGetUserName(user),
		"DeviceName": device.DeviceName,
		"Browser":    device.Browser,
		"OS":         device.OS,
		"IPAddress":  device.IPAddress,
		"Location":   device.Location,
		"Time":       device.Time,
		"FooterText": "Thanks, The ModernAuth Team",
	}

	htmlBody, err := s.renderTemplate(loginAlertEmailHTML, data)
	if err != nil {
		return err
	}

	textBody := fmt.Sprintf(
		"Hi %s,\n\nWe noticed a new login to your account:\n\nDevice: %s\nBrowser: %s\nOS: %s\nIP Address: %s\nLocation: %s\nTime: %s\n\nIf this wasn't you, please change your password immediately.\n\nThanks,\nThe ModernAuth Team",
		sendGridGetUserName(user), device.DeviceName, device.Browser, device.OS, device.IPAddress, device.Location, device.Time,
	)

	return s.sendEmail(user.Email, subject, htmlBody, textBody)
}

// SendInvitationEmail sends an invitation email.
func (s *SendGridService) SendInvitationEmail(ctx context.Context, invitation *InvitationEmail) error {
	subject := fmt.Sprintf("You've been invited to join %s", invitation.TenantName)

	data := map[string]string{
		"InviterName": invitation.InviterName,
		"TenantName":  invitation.TenantName,
		"InviteURL":   invitation.InviteURL,
		"Message":     invitation.Message,
		"ExpiresAt":   invitation.ExpiresAt,
		"FooterText":  "Thanks, The ModernAuth Team",
	}

	htmlBody, err := s.renderTemplate(invitationEmailHTML, data)
	if err != nil {
		return err
	}

	textBody := fmt.Sprintf(
		"Hi,\n\n%s has invited you to join %s.\n\n%s\n\nClick the link below to accept:\n%s\n\nThis invitation expires on %s.\n\nThanks,\nThe ModernAuth Team",
		invitation.InviterName, invitation.TenantName, invitation.Message, invitation.InviteURL, invitation.ExpiresAt,
	)

	return s.sendEmail(invitation.Email, subject, htmlBody, textBody)
}

// SendMFAEnabledEmail sends notification that MFA was enabled.
func (s *SendGridService) SendMFAEnabledEmail(ctx context.Context, user *storage.User) error {
	subject := "Two-factor authentication enabled"

	data := map[string]string{
		"FullName":   sendGridGetUserName(user),
		"FooterText": "Thanks, The ModernAuth Team",
	}

	htmlBody, err := s.renderTemplate(mfaEnabledEmailHTML, data)
	if err != nil {
		return err
	}

	textBody := fmt.Sprintf(
		"Hi %s,\n\nTwo-factor authentication has been enabled on your account. Your account is now more secure.\n\nIf you didn't do this, please contact support immediately.\n\nThanks,\nThe ModernAuth Team",
		sendGridGetUserName(user),
	)

	return s.sendEmail(user.Email, subject, htmlBody, textBody)
}

// SendMFACodeEmail sends MFA verification code email.
func (s *SendGridService) SendMFACodeEmail(ctx context.Context, userID string, code string) error {
	subject := "Your Verification Code"

	htmlBody := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 24px;">Your Verification Code</h1>
    </div>
    <div style="background: #ffffff; padding: 30px; border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 10px 10px;">
        <p>Use the following verification code to complete your login:</p>
        <div style="background: #f5f5f5; padding: 25px; border-radius: 10px; margin: 25px 0; text-align: center; border: 2px dashed #667eea;">
            <p style="font-size: 36px; font-weight: bold; letter-spacing: 8px; color: #667eea; margin: 0;">%s</p>
        </div>
        <p style="color: #666; font-size: 14px;">This code will expire in 10 minutes.</p>
        <p style="color: #e74c3c; font-size: 14px;"><strong>Security Note:</strong> If you didn't request this code, please ignore this email or contact support if you're concerned.</p>
        <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 30px 0;">
        <p style="color: #999; font-size: 12px; text-align: center;">Thanks,<br>The ModernAuth Team</p>
    </div>
</body>
</html>`, code)

	textBody := fmt.Sprintf("Hi,\n\nUse the following verification code to complete your login:\n\n%s\n\nThis code will expire in 10 minutes.\n\nIf you didn't request this code, please ignore this email.\n\nThanks,\nThe ModernAuth Team", code)

	return s.sendEmail(userID, subject, htmlBody, textBody)
}

// SendLowBackupCodesEmail sends notification when backup codes are running low.
func (s *SendGridService) SendLowBackupCodesEmail(ctx context.Context, user *storage.User, remaining int) error {
	subject := "Action Required: Low backup codes remaining"

	data := map[string]string{
		"FullName":   sendGridGetUserName(user),
		"Remaining":  fmt.Sprintf("%d", remaining),
		"FooterText": "Thanks, The ModernAuth Team",
	}

	htmlBody, err := s.renderTemplate(lowBackupCodesEmailHTML, data)
	if err != nil {
		return err
	}

	textBody := fmt.Sprintf(
		"Hi %s,\n\nYou have only %d backup codes remaining for two-factor authentication.\n\nWe recommend generating new backup codes as soon as possible to avoid being locked out of your account.\n\nTo generate new backup codes, go to your account security settings.\n\nThanks,\nThe ModernAuth Team",
		sendGridGetUserName(user), remaining,
	)

	return s.sendEmail(user.Email, subject, htmlBody, textBody)
}

// SendPasswordChangedEmail sends notification that password was changed.
func (s *SendGridService) SendPasswordChangedEmail(ctx context.Context, user *storage.User) error {
	subject := "Your password was changed"

	data := map[string]string{
		"FullName":   sendGridGetUserName(user),
		"FooterText": "Thanks, The ModernAuth Team",
	}

	htmlBody, err := s.renderTemplate(passwordChangedEmailHTML, data)
	if err != nil {
		return err
	}

	textBody := fmt.Sprintf(
		"Hi %s,\n\nYour password has been changed. If you didn't do this, please reset your password immediately and contact support.\n\nThanks,\nThe ModernAuth Team",
		sendGridGetUserName(user),
	)

	return s.sendEmail(user.Email, subject, htmlBody, textBody)
}

// SendSessionRevokedEmail sends notification about session revocation.
func (s *SendGridService) SendSessionRevokedEmail(ctx context.Context, user *storage.User, reason string) error {
	subject := "Your session was terminated"

	data := map[string]string{
		"FullName":   sendGridGetUserName(user),
		"Reason":     reason,
		"FooterText": "Thanks, The ModernAuth Team",
	}

	htmlBody, err := s.renderTemplate(sessionRevokedEmailHTML, data)
	if err != nil {
		return err
	}

	textBody := fmt.Sprintf(
		"Hi %s,\n\nYour session has been terminated.\n\nReason: %s\n\nIf you didn't do this, please check your account security.\n\nThanks,\nThe ModernAuth Team",
		sendGridGetUserName(user), reason,
	)

	return s.sendEmail(user.Email, subject, htmlBody, textBody)
}

// SendMagicLink sends a magic link email for passwordless authentication.
func (s *SendGridService) SendMagicLink(email string, magicLinkURL string) error {
	subject := "Sign in to your account"

	// Extract name from email for personalization
	emailName := email
	if parts := strings.Split(email, "@"); len(parts) > 0 {
		emailName = parts[0]
	}

	data := map[string]string{
		"Name":         emailName,
		"MagicLinkURL": magicLinkURL,
	}

	htmlBody, err := s.renderTemplate(sendGridMagicLinkEmailHTML, data)
	if err != nil {
		return err
	}

	textBody := fmt.Sprintf(
		"Hi %s,\n\nClick the link below to sign in to your account:\n\n%s\n\nThis link will expire in 15 minutes.\n\nIf you didn't request this, you can safely ignore this email.\n\nThanks,\nThe ModernAuth Team",
		emailName, magicLinkURL,
	)

	return s.sendEmail(email, subject, htmlBody, textBody)
}

// Magic link email HTML template for SendGrid
const sendGridMagicLinkEmailHTML = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Sign in to your account</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0;">Sign In</h1>
    </div>
    <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px;">
        <p>Hi {{.Name}},</p>
        <p>Click the button below to sign in to your account:</p>
        <div style="text-align: center; margin: 30px 0;">
            <a href="{{.MagicLinkURL}}" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-weight: bold;">Sign In</a>
        </div>
        <p style="color: #666; font-size: 14px;">This link will expire in 15 minutes.</p>
        <p style="color: #666; font-size: 14px;">If you didn't request this, you can safely ignore this email.</p>
        <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
        <p style="color: #999; font-size: 12px; text-align: center;">
            If the button doesn't work, copy and paste this link:<br>
            <a href="{{.MagicLinkURL}}" style="color: #667eea;">{{.MagicLinkURL}}</a>
        </p>
    </div>
</body>
</html>
`

// Verify SendGridService implements Service interface
var _ Service = (*SendGridService)(nil)
