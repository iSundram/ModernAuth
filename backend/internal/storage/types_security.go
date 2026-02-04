package storage

import (
	"time"

	"github.com/google/uuid"
)

// PasswordHistory represents a password history entry for preventing reuse.
type PasswordHistory struct {
	ID           uuid.UUID `json:"id"`
	UserID       uuid.UUID `json:"user_id"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}

// MagicLink represents a passwordless magic link token.
type MagicLink struct {
	ID        uuid.UUID  `json:"id"`
	UserID    *uuid.UUID `json:"user_id,omitempty"`
	Email     string     `json:"email"`
	TokenHash string     `json:"-"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	IPAddress *string    `json:"ip_address,omitempty"`
	UserAgent *string    `json:"user_agent,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// ImpersonationSession represents an admin impersonation session.
type ImpersonationSession struct {
	ID           uuid.UUID  `json:"id"`
	SessionID    uuid.UUID  `json:"session_id"`
	AdminUserID  uuid.UUID  `json:"admin_user_id"`
	TargetUserID uuid.UUID  `json:"target_user_id"`
	Reason       *string    `json:"reason,omitempty"`
	StartedAt    time.Time  `json:"started_at"`
	EndedAt      *time.Time `json:"ended_at,omitempty"`
	IPAddress    *string    `json:"ip_address,omitempty"`
	UserAgent    *string    `json:"user_agent,omitempty"`
}

// RiskAssessment represents a login risk assessment.
type RiskAssessment struct {
	ID              uuid.UUID              `json:"id"`
	UserID          uuid.UUID              `json:"user_id"`
	SessionID       *uuid.UUID             `json:"session_id,omitempty"`
	RiskScore       int                    `json:"risk_score"`
	RiskLevel       string                 `json:"risk_level"` // low, medium, high
	Factors         map[string]interface{} `json:"factors"`
	ActionTaken     string                 `json:"action_taken"` // allowed, mfa_required, blocked, warned
	IPAddress       *string                `json:"ip_address,omitempty"`
	UserAgent       *string                `json:"user_agent,omitempty"`
	LocationCountry *string                `json:"location_country,omitempty"`
	LocationCity    *string                `json:"location_city,omitempty"`
	CreatedAt       time.Time              `json:"created_at"`
}
