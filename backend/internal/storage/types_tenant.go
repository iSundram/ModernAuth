package storage

import (
	"time"

	"github.com/google/uuid"
)

// Tenant represents a tenant in a multi-tenant system.
type Tenant struct {
	ID        uuid.UUID              `json:"id"`
	Name      string                 `json:"name"`
	Slug      string                 `json:"slug"`
	Domain    *string                `json:"domain,omitempty"`
	LogoURL   *string                `json:"logo_url,omitempty"`
	Settings  map[string]interface{} `json:"settings,omitempty"`
	Plan      string                 `json:"plan"`
	IsActive  bool                   `json:"is_active"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
}

// UserGroup represents a group of users within a tenant.
type UserGroup struct {
	ID          uuid.UUID              `json:"id"`
	TenantID    *uuid.UUID             `json:"tenant_id,omitempty"`
	Name        string                 `json:"name"`
	Description *string                `json:"description,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// UserGroupMember represents a user's membership in a group.
type UserGroupMember struct {
	UserID   uuid.UUID `json:"user_id"`
	GroupID  uuid.UUID `json:"group_id"`
	Role     string    `json:"role"` // owner, admin, member
	JoinedAt time.Time `json:"joined_at"`
}

// UserInvitation represents an invitation to join the system.
type UserInvitation struct {
	ID         uuid.UUID   `json:"id"`
	TenantID   *uuid.UUID  `json:"tenant_id,omitempty"`
	Email      string      `json:"email"`
	FirstName  *string     `json:"first_name,omitempty"`
	LastName   *string     `json:"last_name,omitempty"`
	RoleIDs    []uuid.UUID `json:"role_ids,omitempty"`
	GroupIDs   []uuid.UUID `json:"group_ids,omitempty"`
	TokenHash  string      `json:"-"`
	InvitedBy  *uuid.UUID  `json:"invited_by,omitempty"`
	Message    *string     `json:"message,omitempty"`
	ExpiresAt  time.Time   `json:"expires_at"`
	AcceptedAt *time.Time  `json:"accepted_at,omitempty"`
	CreatedAt  time.Time   `json:"created_at"`
}
