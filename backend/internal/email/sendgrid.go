// Package email provides SendGrid email service for ModernAuth.
package email

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// SendGridService is an email service that sends emails via SendGrid API.
type SendGridService struct {
	apiKey     string
	fromEmail  string
	fromName   string
	replyTo    string
	baseURL    string
	httpClient *http.Client
	logger     *slog.Logger
}

// SendGridConfig holds SendGrid configuration.
type SendGridConfig struct {
	APIKey    string
	FromEmail string
	FromName  string
	ReplyTo   string
	BaseURL   string
}

// NewSendGridService creates a new SendGrid email service.
func NewSendGridService(cfg *SendGridConfig) *SendGridService {
	return &SendGridService{
		apiKey:    cfg.APIKey,
		fromEmail: cfg.FromEmail,
		fromName:  cfg.FromName,
		replyTo:   cfg.ReplyTo,
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
	ReplyTo          *sendGridEmail            `json:"reply_to,omitempty"`
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

// SendEmail sends an email using SendGrid API v3.
func (s *SendGridService) SendEmail(to, subject, htmlBody, textBody string) (string, error) {
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

	// Add Reply-To if configured
	if s.replyTo != "" {
		req.ReplyTo = &sendGridEmail{Email: s.replyTo}
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
		return "", fmt.Errorf("failed to marshal SendGrid request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", "https://api.sendgrid.com/v3/mail/send", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+s.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")

	s.logger.Info("Sending email via SendGrid", "to", to, "subject", subject)

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		s.logger.Error("SendGrid request failed", "error", err)
		return "", fmt.Errorf("SendGrid request failed: %w", err)
	}
	defer resp.Body.Close()

	// Get message ID from header
	msgID := resp.Header.Get("X-Message-Id")

	// SendGrid returns 202 Accepted on success
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		s.logger.Error("SendGrid API error",
			"status", resp.StatusCode,
			"response", string(respBody),
		)
		return msgID, fmt.Errorf("SendGrid API error: status %d", resp.StatusCode)
	}

	s.logger.Info("Email sent successfully via SendGrid", "to", to, "msg_id", msgID)
	return msgID, nil
}

// Verify SendGridService implements EmailSender interface
var _ EmailSender = (*SendGridService)(nil)
