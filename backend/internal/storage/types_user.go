// Package storage defines the storage interfaces for ModernAuth.
package storage

import (
	"time"

	"github.com/google/uuid"
)

// User represents a user in the system.
type User struct {
	ID                uuid.UUID              `json:"id"`
	TenantID          *uuid.UUID             `json:"tenant_id,omitempty"`
	Email             string                 `json:"email"`
	Phone             *string                `json:"phone,omitempty"`
	Username          *string                `json:"username,omitempty"`
	FirstName         *string                `json:"first_name,omitempty"`
	LastName          *string                `json:"last_name,omitempty"`
	AvatarURL         *string                `json:"avatar_url,omitempty"`
	HashedPassword    string                 `json:"-"`
	IsEmailVerified   bool                   `json:"is_email_verified"`
	IsActive          bool                   `json:"is_active"`
	Timezone          string                 `json:"timezone"`
	Locale            string                 `json:"locale"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
	LastLoginAt       *time.Time             `json:"last_login_at,omitempty"`
	PasswordChangedAt *time.Time             `json:"password_changed_at,omitempty"`
	CreatedAt         time.Time              `json:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at"`
}

// Session represents an authentication session.
type Session struct {
	ID          uuid.UUID              `json:"id"`
	UserID      uuid.UUID              `json:"user_id"`
	TenantID    *uuid.UUID             `json:"tenant_id,omitempty"`
	DeviceID    *uuid.UUID             `json:"device_id,omitempty"`
	Fingerprint *string                `json:"fingerprint,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	ExpiresAt   time.Time              `json:"expires_at"`
	Revoked     bool                   `json:"revoked"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// RefreshToken represents a refresh token.
type RefreshToken struct {
	ID         uuid.UUID  `json:"id"`
	SessionID  uuid.UUID  `json:"session_id"`
	TokenHash  string     `json:"-"`
	IssuedAt   time.Time  `json:"issued_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	Revoked    bool       `json:"revoked"`
	ReplacedBy *uuid.UUID `json:"replaced_by,omitempty"`
}

// AuditLog represents an audit log entry.
type AuditLog struct {
	ID        uuid.UUID              `json:"id"`
	TenantID  *uuid.UUID             `json:"tenant_id,omitempty"`
	UserID    *uuid.UUID             `json:"user_id,omitempty"`
	ActorID   *uuid.UUID             `json:"actor_id,omitempty"`
	EventType string                 `json:"event_type"`
	IP        *string                `json:"ip,omitempty"`
	UserAgent *string                `json:"user_agent,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
}
