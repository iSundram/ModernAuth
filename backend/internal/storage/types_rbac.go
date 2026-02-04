package storage

import (
	"time"

	"github.com/google/uuid"
)

// Role represents a role in the RBAC system.
type Role struct {
	ID          uuid.UUID  `json:"id"`
	TenantID    *uuid.UUID `json:"tenant_id,omitempty"`
	Name        string     `json:"name"`
	Description *string    `json:"description,omitempty"`
	IsSystem    bool       `json:"is_system"`
	CreatedAt   time.Time  `json:"created_at"`
}

// Permission represents a permission in the RBAC system.
type Permission struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description *string   `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// UserRole represents a user-role assignment.
type UserRole struct {
	UserID     uuid.UUID  `json:"user_id"`
	RoleID     uuid.UUID  `json:"role_id"`
	AssignedAt time.Time  `json:"assigned_at"`
	AssignedBy *uuid.UUID `json:"assigned_by,omitempty"`
}
