package storage

import (
	"time"

	"github.com/google/uuid"
)

// SocialProvider represents a social login provider configuration.
type SocialProvider struct {
	ID                    uuid.UUID              `json:"id"`
	TenantID              *uuid.UUID             `json:"tenant_id,omitempty"`
	Provider              string                 `json:"provider"` // google, github, microsoft, etc.
	ClientID              string                 `json:"client_id"`
	ClientSecretEncrypted string                 `json:"-"`
	Scopes                []string               `json:"scopes,omitempty"`
	AdditionalParams      map[string]interface{} `json:"additional_params,omitempty"`
	IsActive              bool                   `json:"is_active"`
	CreatedAt             time.Time              `json:"created_at"`
	UpdatedAt             time.Time              `json:"updated_at"`
}

// UserProvider represents a linked social/external identity.
type UserProvider struct {
	ID                    uuid.UUID              `json:"id"`
	UserID                uuid.UUID              `json:"user_id"`
	Provider              string                 `json:"provider"`
	ProviderUserID        string                 `json:"provider_user_id"`
	AccessTokenEncrypted  *string                `json:"-"`
	RefreshTokenEncrypted *string                `json:"-"`
	TokenExpiresAt        *time.Time             `json:"token_expires_at,omitempty"`
	ProfileData           map[string]interface{} `json:"profile_data,omitempty"`
	CreatedAt             time.Time              `json:"created_at"`
	UpdatedAt             time.Time              `json:"updated_at"`
}

// SocialLoginState represents an OAuth state token for CSRF protection.
type SocialLoginState struct {
	ID           uuid.UUID              `json:"id"`
	TenantID     *uuid.UUID             `json:"tenant_id,omitempty"`
	Provider     string                 `json:"provider"`
	StateHash    string                 `json:"-"`
	RedirectURI  string                 `json:"redirect_uri,omitempty"`
	CodeVerifier string                 `json:"-"` // PKCE
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	ExpiresAt    time.Time              `json:"expires_at"`
	CreatedAt    time.Time              `json:"created_at"`
}
