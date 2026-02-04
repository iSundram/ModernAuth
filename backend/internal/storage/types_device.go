package storage

import (
	"time"

	"github.com/google/uuid"
)

// UserDevice represents a user's device for session management.
type UserDevice struct {
	ID                uuid.UUID  `json:"id"`
	UserID            uuid.UUID  `json:"user_id"`
	DeviceFingerprint *string    `json:"device_fingerprint,omitempty"`
	DeviceName        *string    `json:"device_name,omitempty"`
	DeviceType        *string    `json:"device_type,omitempty"`
	Browser           *string    `json:"browser,omitempty"`
	BrowserVersion    *string    `json:"browser_version,omitempty"`
	OS                *string    `json:"os,omitempty"`
	OSVersion         *string    `json:"os_version,omitempty"`
	IPAddress         *string    `json:"ip_address,omitempty"`
	LocationCountry   *string    `json:"location_country,omitempty"`
	LocationCity      *string    `json:"location_city,omitempty"`
	IsTrusted         bool       `json:"is_trusted"`
	IsCurrent         bool       `json:"is_current"`
	LastSeenAt        *time.Time `json:"last_seen_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
}

// LoginHistory represents a login attempt record.
type LoginHistory struct {
	ID              uuid.UUID  `json:"id"`
	UserID          uuid.UUID  `json:"user_id"`
	TenantID        *uuid.UUID `json:"tenant_id,omitempty"`
	SessionID       *uuid.UUID `json:"session_id,omitempty"`
	DeviceID        *uuid.UUID `json:"device_id,omitempty"`
	IPAddress       *string    `json:"ip_address,omitempty"`
	UserAgent       *string    `json:"user_agent,omitempty"`
	LocationCountry *string    `json:"location_country,omitempty"`
	LocationCity    *string    `json:"location_city,omitempty"`
	LoginMethod     *string    `json:"login_method,omitempty"` // password, mfa, social, magic_link, api_key
	Status          string     `json:"status"`                 // success, failed, blocked, mfa_required
	FailureReason   *string    `json:"failure_reason,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}
