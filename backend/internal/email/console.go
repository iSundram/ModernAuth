// Package email provides a console email service for development.
package email

import (
	"fmt"
	"log/slog"
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

// SendEmail logs an email to console.
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

// Verify ConsoleService implements EmailSender interface
var _ EmailSender = (*ConsoleService)(nil)
