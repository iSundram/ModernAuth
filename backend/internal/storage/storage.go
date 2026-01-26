// Package storage defines the storage interfaces for ModernAuth.
package storage

import (
	"context"
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
	ID        uuid.UUID  `json:"id"`
	UserID    uuid.UUID  `json:"user_id"`
	TokenHash string     `json:"-"`
	TokenType string     `json:"token_type"` // "email_verification" or "password_reset"
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

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

// UserDevice represents a user's device for session management.
type UserDevice struct {
	ID               uuid.UUID  `json:"id"`
	UserID           uuid.UUID  `json:"user_id"`
	DeviceFingerprint *string   `json:"device_fingerprint,omitempty"`
	DeviceName       *string    `json:"device_name,omitempty"`
	DeviceType       *string    `json:"device_type,omitempty"`
	Browser          *string    `json:"browser,omitempty"`
	BrowserVersion   *string    `json:"browser_version,omitempty"`
	OS               *string    `json:"os,omitempty"`
	OSVersion        *string    `json:"os_version,omitempty"`
	IPAddress        *string    `json:"ip_address,omitempty"`
	LocationCountry  *string    `json:"location_country,omitempty"`
	LocationCity     *string    `json:"location_city,omitempty"`
	IsTrusted        bool       `json:"is_trusted"`
	IsCurrent        bool       `json:"is_current"`
	LastSeenAt       *time.Time `json:"last_seen_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
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

// Webhook represents a webhook subscription.
type Webhook struct {
	ID             uuid.UUID              `json:"id"`
	TenantID       *uuid.UUID             `json:"tenant_id,omitempty"`
	Name           string                 `json:"name"`
	Description    *string                `json:"description,omitempty"`
	URL            string                 `json:"url"`
	Secret         string                 `json:"-"`
	Events         []string               `json:"events"`
	Headers        map[string]interface{} `json:"headers,omitempty"`
	IsActive       bool                   `json:"is_active"`
	RetryCount     int                    `json:"retry_count"`
	TimeoutSeconds int                    `json:"timeout_seconds"`
	CreatedBy      *uuid.UUID             `json:"created_by,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
}

// WebhookDelivery represents a webhook delivery attempt.
type WebhookDelivery struct {
	ID                 uuid.UUID              `json:"id"`
	WebhookID          uuid.UUID              `json:"webhook_id"`
	EventID            uuid.UUID              `json:"event_id"`
	EventType          string                 `json:"event_type"`
	Payload            map[string]interface{} `json:"payload"`
	ResponseStatusCode *int                   `json:"response_status_code,omitempty"`
	ResponseTimeMs     *int                   `json:"response_time_ms,omitempty"`
	AttemptNumber      int                    `json:"attempt_number"`
	Status             string                 `json:"status"` // pending, success, failed, retrying
	ErrorMessage       *string                `json:"error_message,omitempty"`
	NextRetryAt        *time.Time             `json:"next_retry_at,omitempty"`
	CreatedAt          time.Time              `json:"created_at"`
	CompletedAt        *time.Time             `json:"completed_at,omitempty"`
}

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

// SystemSetting represents a dynamic application configuration.
type SystemSetting struct {
	Key         string      `json:"key"`
	Value       interface{} `json:"value"`
	Category    string      `json:"category"`
	IsSecret    bool        `json:"is_secret"`
	Description string      `json:"description"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

// Storage defines the interface for data persistence.
type Storage interface {
	UserStorage
	SessionStorage
	RefreshTokenStorage
	AuditLogStorage
	MFAStorage
	VerificationTokenStorage
	RBACStorage
	TenantStorage
	DeviceStorage
	APIKeyStorage
	WebhookStorage
	InvitationStorage
	SystemSettingsStorage
}

// SystemSettingsStorage defines settings-related storage operations.
type SystemSettingsStorage interface {
	GetSetting(ctx context.Context, key string) (*SystemSetting, error)
	ListSettings(ctx context.Context, category string) ([]*SystemSetting, error)
	UpdateSetting(ctx context.Context, key string, value interface{}) error
}

// UserStorage defines user-related storage operations.
type UserStorage interface {
	CreateUser(ctx context.Context, user *User) error
	GetUserByID(ctx context.Context, id uuid.UUID) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	ListUsers(ctx context.Context, limit, offset int) ([]*User, error)
	CountUsers(ctx context.Context) (int, error)
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id uuid.UUID) error
}

// SessionStorage defines session-related storage operations.
type SessionStorage interface {
	CreateSession(ctx context.Context, session *Session) error
	GetSessionByID(ctx context.Context, id uuid.UUID) (*Session, error)
	GetUserSessions(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*Session, error)
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
	GetAuditLogs(ctx context.Context, userID *uuid.UUID, eventType *string, limit, offset int) ([]*AuditLog, error)
	DeleteOldAuditLogs(ctx context.Context, olderThan time.Time) (int64, error)
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

// RBACStorage defines role-based access control storage operations.
type RBACStorage interface {
	// Role operations
	CreateRole(ctx context.Context, role *Role) error
	GetRoleByID(ctx context.Context, id uuid.UUID) (*Role, error)
	GetRoleByName(ctx context.Context, name string) (*Role, error)
	ListRoles(ctx context.Context) ([]*Role, error)
	UpdateRole(ctx context.Context, role *Role) error
	DeleteRole(ctx context.Context, id uuid.UUID) error

	// User role operations
	GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*Role, error)
	AssignRoleToUser(ctx context.Context, userID, roleID uuid.UUID, assignedBy *uuid.UUID) error
	RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error
	UserHasRole(ctx context.Context, userID uuid.UUID, roleName string) (bool, error)

	// Permission operations
	GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*Permission, error)
	GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]*Permission, error)
	UserHasPermission(ctx context.Context, userID uuid.UUID, permissionName string) (bool, error)
	AssignPermissionToRole(ctx context.Context, roleID, permissionID uuid.UUID) error
	RemovePermissionFromRole(ctx context.Context, roleID, permissionID uuid.UUID) error
	GetPermissionByID(ctx context.Context, id uuid.UUID) (*Permission, error)
	GetPermissionByName(ctx context.Context, name string) (*Permission, error)
	ListPermissions(ctx context.Context) ([]*Permission, error)
}

// TenantStorage defines tenant-related storage operations.
type TenantStorage interface {
	CreateTenant(ctx context.Context, tenant *Tenant) error
	GetTenantByID(ctx context.Context, id uuid.UUID) (*Tenant, error)
	GetTenantBySlug(ctx context.Context, slug string) (*Tenant, error)
	GetTenantByDomain(ctx context.Context, domain string) (*Tenant, error)
	ListTenants(ctx context.Context, limit, offset int) ([]*Tenant, error)
	UpdateTenant(ctx context.Context, tenant *Tenant) error
	DeleteTenant(ctx context.Context, id uuid.UUID) error
	
	// Tenant user operations
	ListTenantUsers(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*User, error)
	CountTenantUsers(ctx context.Context, tenantID uuid.UUID) (int, error)
}

// DeviceStorage defines device-related storage operations.
type DeviceStorage interface {
	CreateDevice(ctx context.Context, device *UserDevice) error
	GetDeviceByID(ctx context.Context, id uuid.UUID) (*UserDevice, error)
	GetDeviceByFingerprint(ctx context.Context, userID uuid.UUID, fingerprint string) (*UserDevice, error)
	ListUserDevices(ctx context.Context, userID uuid.UUID) ([]*UserDevice, error)
	UpdateDevice(ctx context.Context, device *UserDevice) error
	DeleteDevice(ctx context.Context, id uuid.UUID) error
	TrustDevice(ctx context.Context, id uuid.UUID, trusted bool) error
	
	// Login history
	CreateLoginHistory(ctx context.Context, history *LoginHistory) error
	GetLoginHistory(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*LoginHistory, error)
}

// APIKeyStorage defines API key storage operations.
type APIKeyStorage interface {
	CreateAPIKey(ctx context.Context, key *APIKey) error
	GetAPIKeyByID(ctx context.Context, id uuid.UUID) (*APIKey, error)
	GetAPIKeyByHash(ctx context.Context, keyHash string) (*APIKey, error)
	ListAPIKeys(ctx context.Context, userID *uuid.UUID, tenantID *uuid.UUID, limit, offset int) ([]*APIKey, error)
	UpdateAPIKey(ctx context.Context, key *APIKey) error
	RevokeAPIKey(ctx context.Context, id uuid.UUID, revokedBy *uuid.UUID) error
	UpdateAPIKeyLastUsed(ctx context.Context, id uuid.UUID, ip string) error
}

// WebhookStorage defines webhook storage operations.
type WebhookStorage interface {
	CreateWebhook(ctx context.Context, webhook *Webhook) error
	GetWebhookByID(ctx context.Context, id uuid.UUID) (*Webhook, error)
	ListWebhooks(ctx context.Context, tenantID *uuid.UUID, limit, offset int) ([]*Webhook, error)
	ListWebhooksByEvent(ctx context.Context, tenantID *uuid.UUID, eventType string) ([]*Webhook, error)
	UpdateWebhook(ctx context.Context, webhook *Webhook) error
	DeleteWebhook(ctx context.Context, id uuid.UUID) error
	
	// Webhook deliveries
	CreateWebhookDelivery(ctx context.Context, delivery *WebhookDelivery) error
	UpdateWebhookDelivery(ctx context.Context, delivery *WebhookDelivery) error
	GetPendingDeliveries(ctx context.Context, limit int) ([]*WebhookDelivery, error)
	GetWebhookDeliveries(ctx context.Context, webhookID uuid.UUID, limit, offset int) ([]*WebhookDelivery, error)
}

// InvitationStorage defines invitation storage operations.
type InvitationStorage interface {
	CreateInvitation(ctx context.Context, invitation *UserInvitation) error
	GetInvitationByID(ctx context.Context, id uuid.UUID) (*UserInvitation, error)
	GetInvitationByToken(ctx context.Context, tokenHash string) (*UserInvitation, error)
	GetInvitationByEmail(ctx context.Context, tenantID *uuid.UUID, email string) (*UserInvitation, error)
	ListInvitations(ctx context.Context, tenantID *uuid.UUID, limit, offset int) ([]*UserInvitation, error)
	UpdateInvitation(ctx context.Context, invitation *UserInvitation) error
	AcceptInvitation(ctx context.Context, id uuid.UUID) error
	DeleteInvitation(ctx context.Context, id uuid.UUID) error
	DeleteExpiredInvitations(ctx context.Context) error
}

// UserGroupStorage defines user group storage operations.
type UserGroupStorage interface {
	CreateGroup(ctx context.Context, group *UserGroup) error
	GetGroupByID(ctx context.Context, id uuid.UUID) (*UserGroup, error)
	ListGroups(ctx context.Context, tenantID *uuid.UUID, limit, offset int) ([]*UserGroup, error)
	UpdateGroup(ctx context.Context, group *UserGroup) error
	DeleteGroup(ctx context.Context, id uuid.UUID) error
	
	// Group membership
	AddUserToGroup(ctx context.Context, userID, groupID uuid.UUID, role string) error
	RemoveUserFromGroup(ctx context.Context, userID, groupID uuid.UUID) error
	GetGroupMembers(ctx context.Context, groupID uuid.UUID, limit, offset int) ([]*UserGroupMember, error)
	GetUserGroups(ctx context.Context, userID uuid.UUID) ([]*UserGroup, error)
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

// OAuthStateStorage defines OAuth state storage operations for CSRF protection.
type OAuthStateStorage interface {
	CreateOAuthState(ctx context.Context, state *SocialLoginState) error
	GetOAuthStateByHash(ctx context.Context, stateHash string) (*SocialLoginState, error)
	DeleteOAuthState(ctx context.Context, id uuid.UUID) error
	DeleteExpiredOAuthStates(ctx context.Context) error
}

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

// EmailTemplateStorage defines email template storage operations.
type EmailTemplateStorage interface {
	// Template operations
	GetEmailTemplate(ctx context.Context, tenantID *uuid.UUID, templateType string) (*EmailTemplate, error)
	ListEmailTemplates(ctx context.Context, tenantID *uuid.UUID) ([]*EmailTemplate, error)
	UpsertEmailTemplate(ctx context.Context, template *EmailTemplate) error
	DeleteEmailTemplate(ctx context.Context, tenantID *uuid.UUID, templateType string) error

	// Branding operations
	GetEmailBranding(ctx context.Context, tenantID *uuid.UUID) (*EmailBranding, error)
	UpsertEmailBranding(ctx context.Context, branding *EmailBranding) error

	// Dead letter queue operations
	CreateEmailDeadLetter(ctx context.Context, dl *EmailDeadLetter) error
	ListEmailDeadLetters(ctx context.Context, tenantID *uuid.UUID, resolved bool, limit, offset int) ([]*EmailDeadLetter, error)
	MarkEmailDeadLetterResolved(ctx context.Context, id uuid.UUID) error
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
