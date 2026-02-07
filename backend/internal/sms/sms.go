package sms

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// Service defines the interface for sending SMS messages.
type Service interface {
	SendSMS(ctx context.Context, to string, message string) error
}

// Config holds SMS service configuration.
type Config struct {
	Provider          string
	TwilioAccountSID  string
	TwilioAuthToken   string
	TwilioPhoneNumber string
}

// NewService creates a new SMS service based on the configuration.
func NewService(cfg *Config) Service {
	if cfg.Provider == "twilio" && cfg.TwilioAccountSID != "" && cfg.TwilioAuthToken != "" {
		return &TwilioService{
			accountSID: cfg.TwilioAccountSID,
			authToken:  cfg.TwilioAuthToken,
			fromNumber: cfg.TwilioPhoneNumber,
			client:     &http.Client{},
			logger:     slog.Default().With("component", "sms_twilio"),
		}
	}
	return &ConsoleService{
		logger: slog.Default().With("component", "sms_console"),
	}
}

// TwilioService sends SMS via Twilio REST API.
type TwilioService struct {
	accountSID string
	authToken  string
	fromNumber string
	client     *http.Client
	logger     *slog.Logger
}

// SendSMS sends an SMS message via Twilio.
func (s *TwilioService) SendSMS(ctx context.Context, to string, message string) error {
	apiURL := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", s.accountSID)

	data := url.Values{}
	data.Set("To", to)
	data.Set("From", s.fromNumber)
	data.Set("Body", message)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(s.accountSID, s.authToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send SMS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		s.logger.Error("Twilio API error", "status", resp.StatusCode, "body", string(body))
		return fmt.Errorf("twilio API error: status %d", resp.StatusCode)
	}

	s.logger.Info("SMS sent successfully", "to", to)
	return nil
}

// ConsoleService logs SMS messages to stdout (for development).
type ConsoleService struct {
	logger *slog.Logger
}

// SendSMS logs the SMS message to the console.
func (s *ConsoleService) SendSMS(ctx context.Context, to string, message string) error {
	s.logger.Info("=== SMS Message (Console Mode) ===",
		"to", to,
		"message", message,
	)
	fmt.Printf("\n📱 SMS to %s:\n%s\n\n", to, message)
	return nil
}
