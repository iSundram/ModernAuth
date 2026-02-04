package storage

import (
	"time"

	"github.com/google/uuid"
)

// EmailTemplate represents a customizable email template.
type EmailTemplate struct {
	ID        uuid.UUID  `json:"id"`
	TenantID  *uuid.UUID `json:"tenant_id,omitempty"`
	Type      string     `json:"type"`
	Subject   string     `json:"subject"`
	HTMLBody  string     `json:"html_body"`
	TextBody  *string    `json:"text_body,omitempty"`
	IsActive  bool       `json:"is_active"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// EmailBranding represents email branding settings for a tenant.
type EmailBranding struct {
	ID             uuid.UUID  `json:"id"`
	TenantID       *uuid.UUID `json:"tenant_id,omitempty"`
	AppName        string     `json:"app_name"`
	LogoURL        *string    `json:"logo_url,omitempty"`
	PrimaryColor   string     `json:"primary_color"`
	SecondaryColor string     `json:"secondary_color"`
	CompanyName    *string    `json:"company_name,omitempty"`
	SupportEmail   *string    `json:"support_email,omitempty"`
	FooterText     *string    `json:"footer_text,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// EmailDeadLetter represents a failed email in the dead letter queue.
type EmailDeadLetter struct {
	ID           uuid.UUID              `json:"id"`
	TenantID     *uuid.UUID             `json:"tenant_id,omitempty"`
	JobType      string                 `json:"job_type"`
	Recipient    string                 `json:"recipient"`
	Subject      *string                `json:"subject,omitempty"`
	Payload      map[string]interface{} `json:"payload"`
	ErrorMessage string                 `json:"error_message"`
	Attempts     int                    `json:"attempts"`
	CreatedAt    time.Time              `json:"created_at"`
	FailedAt     time.Time              `json:"failed_at"`
	RetriedAt    *time.Time             `json:"retried_at,omitempty"`
	Resolved     bool                   `json:"resolved"`
}

// EmailTemplateVersion represents a historical version of an email template.
type EmailTemplateVersion struct {
	ID           uuid.UUID  `json:"id"`
	TemplateID   uuid.UUID  `json:"template_id"`
	TenantID     *uuid.UUID `json:"tenant_id,omitempty"`
	TemplateType string     `json:"template_type"`
	Version      int        `json:"version"`
	Subject      string     `json:"subject"`
	HTMLBody     string     `json:"html_body"`
	TextBody     *string    `json:"text_body,omitempty"`
	ChangedBy    *uuid.UUID `json:"changed_by,omitempty"`
	ChangeReason *string    `json:"change_reason,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// EmailBounce represents a bounced email record.
type EmailBounce struct {
	ID            uuid.UUID  `json:"id"`
	TenantID      *uuid.UUID `json:"tenant_id,omitempty"`
	Email         string     `json:"email"`
	BounceType    string     `json:"bounce_type"`    // hard, soft, complaint, unsubscribe
	BounceSubtype *string    `json:"bounce_subtype"` // general, no_email, suppressed
	EventID       *string    `json:"event_id"`       // ID from provider
	TemplateType  *string    `json:"template_type"`
	ErrorMessage  *string    `json:"error_message"`
	CreatedAt     time.Time  `json:"created_at"`
}

// EmailEvent represents an email tracking event.
type EmailEvent struct {
	ID           uuid.UUID              `json:"id"`
	TenantID     *uuid.UUID             `json:"tenant_id,omitempty"`
	JobID        *string                `json:"job_id,omitempty"`
	TemplateType string                 `json:"template_type"`
	EventType    string                 `json:"event_type"` // sent, delivered, opened, clicked, bounced, dropped
	Recipient    string                 `json:"recipient"`
	UserID       *uuid.UUID             `json:"user_id,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	EventID      *string                `json:"event_id,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
}

// EmailSuppression represents a suppressed email address.
type EmailSuppression struct {
	ID        uuid.UUID  `json:"id"`
	TenantID  *uuid.UUID `json:"tenant_id,omitempty"`
	Email     string     `json:"email"`
	Reason    string     `json:"reason"` // hard_bounce, complaint, unsubscribe, manual
	Source    *string    `json:"source"` // sendgrid_webhook, admin, user_request
	CreatedAt time.Time  `json:"created_at"`
}

// EmailStats represents aggregated email statistics.
type EmailStats struct {
	TotalSent      int            `json:"total_sent"`
	TotalDelivered int            `json:"total_delivered"`
	TotalOpened    int            `json:"total_opened"`
	TotalClicked   int            `json:"total_clicked"`
	TotalBounced   int            `json:"total_bounced"`
	TotalDropped   int            `json:"total_dropped"`
	ByTemplate     map[string]int `json:"by_template"`
	ByDay          map[string]int `json:"by_day"`
}
