package storage

import (
	"time"

	"github.com/google/uuid"
)

// MFASettings represents a user's MFA settings.
type MFASettings struct {
	UserID                 uuid.UUID       `json:"user_id"`
	TOTPSecret             *string         `json:"-"`
	IsTOTPEnabled          bool            `json:"is_totp_enabled"`
	IsEmailMFAEnabled      bool            `json:"is_email_mfa_enabled"`
	IsSMSMFAEnabled        bool            `json:"is_sms_mfa_enabled"`
	PreferredMethod        string          `json:"preferred_method"`
	BackupCodes            []string        `json:"-"`
	TOTPSetupAt            *time.Time      `json:"totp_setup_at,omitempty"`
	LowBackupCodesNotified bool            `json:"-"`
	UpdatedAt              time.Time       `json:"updated_at"`
	UsedTOTPCodes          map[string]bool `json:"-"` // Tracks used TOTP codes within valid window
}

// MFAChallenge represents a pending MFA verification challenge.
type MFAChallenge struct {
	ID        uuid.UUID  `json:"id"`
	UserID    uuid.UUID  `json:"user_id"`
	SessionID *uuid.UUID `json:"session_id,omitempty"`
	Type      string     `json:"type"` // totp, email, sms, webauthn
	Code      *string    `json:"-"`
	ExpiresAt time.Time  `json:"expires_at"`
	Verified  bool       `json:"verified"`
	CreatedAt time.Time  `json:"created_at"`
}

// WebAuthnCredential represents a stored WebAuthn/Passkey credential.
type WebAuthnCredential struct {
	ID              uuid.UUID  `json:"id"`
	UserID          uuid.UUID  `json:"user_id"`
	CredentialID    []byte     `json:"-"`
	PublicKey       []byte     `json:"-"`
	AttestationType string     `json:"attestation_type,omitempty"`
	Transport       []string   `json:"transport,omitempty"`
	AAGUID          []byte     `json:"-"`
	SignCount       uint32     `json:"sign_count"`
	CloneWarning    bool       `json:"clone_warning"`
	Name            string     `json:"name"`
	CreatedAt       time.Time  `json:"created_at"`
	LastUsedAt      *time.Time `json:"last_used_at,omitempty"`
}

// VerificationToken represents an email verification or password reset token.
type VerificationToken struct {
	ID        uuid.UUID  `json:"id"`
	UserID    uuid.UUID  `json:"user_id"`
	TokenHash string     `json:"-"`
	TokenType string     `json:"token_type"` // "email_verification" or "password_reset"
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}
