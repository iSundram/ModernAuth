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
		"Name":      sendGridGetUserName(user),
		"VerifyURL": verifyURL,
		"Token":     token,
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
		"Name":     sendGridGetUserName(user),
		"ResetURL": resetURL,
		"Token":    token,
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
		"Name":    sendGridGetUserName(user),
		"BaseURL": s.baseURL,
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
		"Name":       sendGridGetUserName(user),
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
		"Name": sendGridGetUserName(user),
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

// SendPasswordChangedEmail sends notification that password was changed.
func (s *SendGridService) SendPasswordChangedEmail(ctx context.Context, user *storage.User) error {
	subject := "Your password was changed"

	data := map[string]string{
		"Name": sendGridGetUserName(user),
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
		"Name":   sendGridGetUserName(user),
		"Reason": reason,
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

// Verify SendGridService implements Service interface
var _ Service = (*SendGridService)(nil)
