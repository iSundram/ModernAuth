// Package email provides SMTP email service for ModernAuth.
package email

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/smtp"

	"github.com/google/uuid"
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

// SendEmail sends an email using SMTP.
func (s *SMTPService) SendEmail(to, subject, htmlBody, textBody string) (string, error) {
	msgID := uuid.New().String()
	from := s.config.FromEmail
	if s.config.FromName != "" {
		from = fmt.Sprintf("%s <%s>", s.config.FromName, s.config.FromEmail)
	}

	s.logger.Info("Sending email via SMTP",
		"to", to,
		"subject", subject,
		"msg_id", msgID,
		"smtp_host", s.config.SMTPHost,
		"smtp_port", s.config.SMTPPort,
	)

	// Build the email message with MIME headers
	var msg bytes.Buffer
	msg.WriteString(fmt.Sprintf("Message-ID: <%s@modernauth.internal>\r\n", msgID))
	msg.WriteString(fmt.Sprintf("From: %s\r\n", from))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", to))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	msg.WriteString("MIME-Version: 1.0\r\n")

	if htmlBody != "" {
		// Multipart message with both HTML and plain text
		boundaryBytes := make([]byte, 16)
		if _, err := rand.Read(boundaryBytes); err != nil {
			return msgID, fmt.Errorf("failed to generate boundary: %w", err)
		}
		boundary := "boundary-" + hex.EncodeToString(boundaryBytes)
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
		err := s.sendEmailTLS(addr, auth, s.config.FromEmail, []string{to}, msg.Bytes())
		return msgID, err
	}

	if err := smtp.SendMail(addr, auth, s.config.FromEmail, []string{to}, msg.Bytes()); err != nil {
		s.logger.Error("Failed to send email via SMTP",
			"to", to,
			"subject", subject,
			"error", err,
		)
		return msgID, err
	}

	return msgID, nil
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

// Verify SMTPService implements EmailSender interface
var _ EmailSender = (*SMTPService)(nil)
