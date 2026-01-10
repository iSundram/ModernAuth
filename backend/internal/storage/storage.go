// Package storage defines the storage interfaces for ModernAuth.
package storage

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// User represents a user in the system.
type User struct {
	ID              uuid.UUID  `json:"id"`
	Email           string     `json:"email"`
	Phone           *string    `json:"phone,omitempty"`
	Username        *string    `json:"username,omitempty"`
	HashedPassword  string     `json:"-"`
	IsEmailVerified bool       `json:"is_email_verified"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// Session represents an authentication session.
type Session struct {
	ID          uuid.UUID              `json:"id"`
	UserID      uuid.UUID              `json:"user_id"`
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
	UserID    *uuid.UUID             `json:"user_id,omitempty"`
	ActorID   *uuid.UUID             `json:"actor_id,omitempty"`
	EventType string                 `json:"event_type"`
	IP        *string                `json:"ip,omitempty"`
	UserAgent *string                `json:"user_agent,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
}

// MFASettings represents a user's MFA settings.
type MFASettings struct {
	UserID         uuid.UUID `json:"user_id"`
	TOTPSecret     *string   `json:"-"`
	IsTOTPEnabled  bool      `json:"is_totp_enabled"`
	BackupCodes    []string  `json:"-"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// VerificationToken represents an email verification or password reset token.
type VerificationToken struct {
	ID        uuid.UUID `json:"id"`
	UserID    uuid.UUID `json:"user_id"`
	TokenHash string    `json:"-"`
	TokenType string    `json:"token_type"` // "email_verification" or "password_reset"
	ExpiresAt time.Time `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Storage defines the interface for data persistence.
type Storage interface {
	UserStorage
	SessionStorage
	RefreshTokenStorage
	AuditLogStorage
	MFAStorage
	VerificationTokenStorage
}

// UserStorage defines user-related storage operations.
type UserStorage interface {
	CreateUser(ctx context.Context, user *User) error
	GetUserByID(ctx context.Context, id uuid.UUID) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id uuid.UUID) error
}

// SessionStorage defines session-related storage operations.
type SessionStorage interface {
	CreateSession(ctx context.Context, session *Session) error
	GetSessionByID(ctx context.Context, id uuid.UUID) (*Session, error)
	RevokeSession(ctx context.Context, id uuid.UUID) error
	RevokeUserSessions(ctx context.Context, userID uuid.UUID) error
}

// RefreshTokenStorage defines refresh token storage operations.
type RefreshTokenStorage interface {
	CreateRefreshToken(ctx context.Context, token *RefreshToken) error
	GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, id uuid.UUID, replacedBy *uuid.UUID) error
	RevokeSessionRefreshTokens(ctx context.Context, sessionID uuid.UUID) error
}

// AuditLogStorage defines audit log storage operations.
type AuditLogStorage interface {
	CreateAuditLog(ctx context.Context, log *AuditLog) error
	GetAuditLogs(ctx context.Context, userID *uuid.UUID, limit, offset int) ([]*AuditLog, error)
}

// MFAStorage defines MFA-related storage operations.
type MFAStorage interface {
	GetMFASettings(ctx context.Context, userID uuid.UUID) (*MFASettings, error)
	UpdateMFASettings(ctx context.Context, settings *MFASettings) error
}

// VerificationTokenStorage defines verification token storage operations.
type VerificationTokenStorage interface {
	CreateVerificationToken(ctx context.Context, token *VerificationToken) error
	GetVerificationTokenByHash(ctx context.Context, tokenHash string, tokenType string) (*VerificationToken, error)
	MarkVerificationTokenUsed(ctx context.Context, id uuid.UUID) error
	DeleteExpiredVerificationTokens(ctx context.Context) error
}
