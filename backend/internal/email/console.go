// Package email provides a console email service for development.
package email

import (
	"fmt"
	"log/slog"

	"github.com/google/uuid"
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
func (s *ConsoleService) SendEmail(to, subject, htmlBody, textBody string) (string, error) {
	msgID := uuid.New().String()
	s.logger.Info("Email",
		"to", to,
		"subject", subject,
		"msg_id", msgID,
	)
	fmt.Printf("\n=== EMAIL [%s] ===\n", msgID)
	fmt.Printf("To: %s\n", to)
	fmt.Printf("Subject: %s\n", subject)
	fmt.Printf("Text Body:\n%s\n", textBody)
	fmt.Printf("=============\n\n")
	return msgID, nil
}

// Verify ConsoleService implements EmailSender interface
var _ EmailSender = (*ConsoleService)(nil)
