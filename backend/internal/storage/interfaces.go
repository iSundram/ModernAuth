package storage

import (
	"context"
	"time"

	"github.com/google/uuid"
)

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
	UserGroupStorage
	PreferencesStorage
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
	GetUserByEmailAndTenant(ctx context.Context, email string, tenantID *uuid.UUID) (*User, error)
	ListUsers(ctx context.Context, limit, offset int) ([]*User, error)
	ListUsersByTenant(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*User, error)
	CountUsers(ctx context.Context) (int, error)
	CountUsersByTenant(ctx context.Context, tenantID uuid.UUID) (int, error)
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
	ListAuditLogsByTenant(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*AuditLog, error)
	ListAuditLogsByEventTypes(ctx context.Context, eventTypes []string, limit, offset int) ([]*AuditLog, error)
	CountAuditLogsByEventTypes(ctx context.Context, eventTypes []string) (int, error)
}

// MFAStorage defines MFA-related storage operations.
type MFAStorage interface {
	GetMFASettings(ctx context.Context, userID uuid.UUID) (*MFASettings, error)
	UpdateMFASettings(ctx context.Context, settings *MFASettings) error

	// MFA Challenges
	CreateMFAChallenge(ctx context.Context, challenge *MFAChallenge) error
	GetMFAChallenge(ctx context.Context, id uuid.UUID) (*MFAChallenge, error)
	GetPendingMFAChallenge(ctx context.Context, userID uuid.UUID, challengeType string) (*MFAChallenge, error)
	MarkMFAChallengeVerified(ctx context.Context, id uuid.UUID) error
	DeleteExpiredMFAChallenges(ctx context.Context) error

	// WebAuthn Credentials
	CreateWebAuthnCredential(ctx context.Context, cred *WebAuthnCredential) error
	GetWebAuthnCredentials(ctx context.Context, userID uuid.UUID) ([]*WebAuthnCredential, error)
	GetWebAuthnCredentialByID(ctx context.Context, credentialID []byte) (*WebAuthnCredential, error)
	UpdateWebAuthnCredentialSignCount(ctx context.Context, credentialID []byte, signCount uint32) error
	DeleteWebAuthnCredential(ctx context.Context, id uuid.UUID) error

	// Device MFA Trust
	SetDeviceMFATrust(ctx context.Context, deviceID uuid.UUID, trustedUntil time.Time, trustToken string) error
	ClearDeviceMFATrust(ctx context.Context, deviceID uuid.UUID) error
	GetDeviceMFATrust(ctx context.Context, userID uuid.UUID, deviceFingerprint string) (*time.Time, error)
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
	GetUserRolesByTenant(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) ([]*Role, error)
	AssignRoleToUser(ctx context.Context, userID, roleID uuid.UUID, assignedBy *uuid.UUID) error
	AssignRoleToUserInTenant(ctx context.Context, userID, roleID, tenantID uuid.UUID, assignedBy *uuid.UUID) error
	RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error
	RemoveRoleFromUserInTenant(ctx context.Context, userID, roleID, tenantID uuid.UUID) error
	UserHasRole(ctx context.Context, userID uuid.UUID, roleName string) (bool, error)
	UserHasRoleInTenant(ctx context.Context, userID uuid.UUID, roleName string, tenantID uuid.UUID) (bool, error)

	// Permission operations
	GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*Permission, error)
	GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]*Permission, error)
	UserHasPermission(ctx context.Context, userID uuid.UUID, permissionName string) (bool, error)
	UserHasPermissionInTenant(ctx context.Context, userID uuid.UUID, permissionName string, tenantID uuid.UUID) (bool, error)
	AssignPermissionToRole(ctx context.Context, roleID, permissionID uuid.UUID) error
	RemovePermissionFromRole(ctx context.Context, roleID, permissionID uuid.UUID) error
	GetPermissionByID(ctx context.Context, id uuid.UUID) (*Permission, error)
	GetRoleByIDAndTenant(ctx context.Context, id uuid.UUID, tenantID *uuid.UUID) (*Role, error)
	GetPermissionByName(ctx context.Context, name string) (*Permission, error)
	GetRoleByNameAndTenant(ctx context.Context, name string, tenantID *uuid.UUID) (*Role, error)
	ListPermissions(ctx context.Context) ([]*Permission, error)
	ListRolesByTenant(ctx context.Context, tenantID uuid.UUID) ([]*Role, error)
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

// OAuthStateStorage defines OAuth state storage operations for CSRF protection.
type OAuthStateStorage interface {
	CreateOAuthState(ctx context.Context, state *SocialLoginState) error
	GetOAuthStateByHash(ctx context.Context, stateHash string) (*SocialLoginState, error)
	DeleteOAuthState(ctx context.Context, id uuid.UUID) error
	DeleteExpiredOAuthStates(ctx context.Context) error
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

	// Version history operations
	CreateEmailTemplateVersion(ctx context.Context, version *EmailTemplateVersion) error
	ListEmailTemplateVersions(ctx context.Context, tenantID *uuid.UUID, templateType string, limit, offset int) ([]*EmailTemplateVersion, error)
	GetEmailTemplateVersion(ctx context.Context, id uuid.UUID) (*EmailTemplateVersion, error)

	// Bounce tracking operations
	CreateEmailBounce(ctx context.Context, bounce *EmailBounce) error
	ListEmailBounces(ctx context.Context, tenantID *uuid.UUID, bounceType string, limit, offset int) ([]*EmailBounce, error)
	GetEmailBounceByEmail(ctx context.Context, tenantID *uuid.UUID, email string) (*EmailBounce, error)

	// Email event tracking
	CreateEmailEvent(ctx context.Context, event *EmailEvent) error
	GetEmailStats(ctx context.Context, tenantID *uuid.UUID, days int) (*EmailStats, error)

	// Suppression list operations
	CreateEmailSuppression(ctx context.Context, suppression *EmailSuppression) error
	GetEmailSuppression(ctx context.Context, tenantID *uuid.UUID, email string) (*EmailSuppression, error)
	DeleteEmailSuppression(ctx context.Context, tenantID *uuid.UUID, email string) error
	ListEmailSuppressions(ctx context.Context, tenantID *uuid.UUID, limit, offset int) ([]*EmailSuppression, error)

	// A/B Testing operations
	ListEmailABTests(ctx context.Context, tenantID *uuid.UUID) ([]*EmailABTest, error)
	CreateEmailABTest(ctx context.Context, test *EmailABTest) error
	GetEmailABTest(ctx context.Context, id uuid.UUID) (*EmailABTest, error)
	UpdateEmailABTest(ctx context.Context, test *EmailABTest) error
	DeleteEmailABTest(ctx context.Context, id uuid.UUID) error

	// Advanced Branding operations
	GetEmailBrandingAdvanced(ctx context.Context, tenantID *uuid.UUID) (*EmailBrandingAdvanced, error)
	UpsertEmailBrandingAdvanced(ctx context.Context, branding *EmailBrandingAdvanced) error

	// Tracking pixel operations
	CreateEmailTrackingPixel(ctx context.Context, pixel *EmailTrackingPixel) error
	GetEmailTrackingPixel(ctx context.Context, id uuid.UUID) (*EmailTrackingPixel, error)
	MarkTrackingPixelOpened(ctx context.Context, id uuid.UUID) error
}

// PasswordHistoryStorage defines password history storage operations.
type PasswordHistoryStorage interface {
	AddPasswordHistory(ctx context.Context, userID uuid.UUID, passwordHash string) error
	GetPasswordHistory(ctx context.Context, userID uuid.UUID, limit int) ([]*PasswordHistory, error)
	CleanupOldPasswordHistory(ctx context.Context, userID uuid.UUID, keepCount int) error
}

// MagicLinkStorage defines magic link storage operations.
type MagicLinkStorage interface {
	CreateMagicLink(ctx context.Context, link *MagicLink) error
	GetMagicLinkByHash(ctx context.Context, tokenHash string) (*MagicLink, error)
	MarkMagicLinkUsed(ctx context.Context, id uuid.UUID) error
	DeleteExpiredMagicLinks(ctx context.Context) error
	CountRecentMagicLinks(ctx context.Context, email string, since time.Time) (int, error)
}

// ImpersonationStorage defines impersonation storage operations.
type ImpersonationStorage interface {
	CreateImpersonationSession(ctx context.Context, session *ImpersonationSession) error
	GetImpersonationSession(ctx context.Context, sessionID uuid.UUID) (*ImpersonationSession, error)
	EndImpersonationSession(ctx context.Context, sessionID uuid.UUID) error
	ListImpersonationSessions(ctx context.Context, adminUserID *uuid.UUID, targetUserID *uuid.UUID, limit, offset int) ([]*ImpersonationSession, error)
}

// RiskAssessmentStorage defines risk assessment storage operations.
type RiskAssessmentStorage interface {
	CreateRiskAssessment(ctx context.Context, assessment *RiskAssessment) error
	GetRecentRiskAssessments(ctx context.Context, userID uuid.UUID, limit int) ([]*RiskAssessment, error)
	GetRiskAssessmentStats(ctx context.Context, userID uuid.UUID, since time.Time) (map[string]int, error)
}

// PreferencesStorage defines user preferences storage operations.
type PreferencesStorage interface {
	GetPreferences(ctx context.Context, userID uuid.UUID) (*UserPreferences, error)
	CreatePreferences(ctx context.Context, prefs *UserPreferences) error
	UpdatePreferences(ctx context.Context, prefs *UserPreferences) error
	GetOrCreatePreferences(ctx context.Context, userID uuid.UUID) (*UserPreferences, error)
}
