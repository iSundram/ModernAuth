package storage

import (
	"time"

	"github.com/google/uuid"
)

// APIKey represents an API key for service-to-service authentication.
type APIKey struct {
	ID          uuid.UUID  `json:"id"`
	TenantID    *uuid.UUID `json:"tenant_id,omitempty"`
	UserID      *uuid.UUID `json:"user_id,omitempty"`
	Name        string     `json:"name"`
	Description *string    `json:"description,omitempty"`
	KeyPrefix   string     `json:"key_prefix"`
	KeyHash     string     `json:"-"`
	Scopes      []string   `json:"scopes,omitempty"`
	RateLimit   *int       `json:"rate_limit,omitempty"`
	AllowedIPs  []string   `json:"allowed_ips,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	LastUsedIP  *string    `json:"last_used_ip,omitempty"`
	IsActive    bool       `json:"is_active"`
	CreatedAt   time.Time  `json:"created_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	RevokedBy   *uuid.UUID `json:"revoked_by,omitempty"`
}
