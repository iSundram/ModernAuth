package tenant

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockStorage is a mock implementation of storage.Storage
type MockStorage struct {
	mock.Mock
}

// UserStorage
func (m *MockStorage) CreateUser(ctx context.Context, user *storage.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}
func (m *MockStorage) GetUserByID(ctx context.Context, id uuid.UUID) (*storage.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.User), args.Error(1)
}
func (m *MockStorage) GetUserByEmail(ctx context.Context, email string) (*storage.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.User), args.Error(1)
}
func (m *MockStorage) GetUserByEmailAndTenant(ctx context.Context, email string, tenantID *uuid.UUID) (*storage.User, error) {
	args := m.Called(ctx, email, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.User), args.Error(1)
}
func (m *MockStorage) ListUsers(ctx context.Context, limit, offset int) ([]*storage.User, error) {
	args := m.Called(ctx, limit, offset)
	return args.Get(0).([]*storage.User), args.Error(1)
}
func (m *MockStorage) ListUsersByTenant(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*storage.User, error) {
	args := m.Called(ctx, tenantID, limit, offset)
	return args.Get(0).([]*storage.User), args.Error(1)
}
func (m *MockStorage) CountUsers(ctx context.Context) (int, error) {
	args := m.Called(ctx)
	return args.Int(0), args.Error(1)
}
func (m *MockStorage) CountUsersByTenant(ctx context.Context, tenantID uuid.UUID) (int, error) {
	args := m.Called(ctx, tenantID)
	return args.Int(0), args.Error(1)
}
func (m *MockStorage) UpdateUser(ctx context.Context, user *storage.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}
func (m *MockStorage) DeleteUser(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// SessionStorage
func (m *MockStorage) CreateSession(ctx context.Context, session *storage.Session) error {
	args := m.Called(ctx, session)
	return args.Error(0)
}
func (m *MockStorage) GetSessionByID(ctx context.Context, id uuid.UUID) (*storage.Session, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.Session), args.Error(1)
}
func (m *MockStorage) GetUserSessions(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*storage.Session, error) {
	args := m.Called(ctx, userID, limit, offset)
	return args.Get(0).([]*storage.Session), args.Error(1)
}
func (m *MockStorage) RevokeSession(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
func (m *MockStorage) RevokeUserSessions(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

// RefreshTokenStorage
func (m *MockStorage) CreateRefreshToken(ctx context.Context, token *storage.RefreshToken) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}
func (m *MockStorage) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*storage.RefreshToken, error) {
	args := m.Called(ctx, tokenHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.RefreshToken), args.Error(1)
}
func (m *MockStorage) RevokeRefreshToken(ctx context.Context, id uuid.UUID, replacedBy *uuid.UUID) error {
	args := m.Called(ctx, id, replacedBy)
	return args.Error(0)
}
func (m *MockStorage) RevokeSessionRefreshTokens(ctx context.Context, sessionID uuid.UUID) error {
	args := m.Called(ctx, sessionID)
	return args.Error(0)
}

// AuditLogStorage
func (m *MockStorage) CreateAuditLog(ctx context.Context, log *storage.AuditLog) error {
	args := m.Called(ctx, log)
	return args.Error(0)
}
func (m *MockStorage) GetAuditLogs(ctx context.Context, userID *uuid.UUID, eventType *string, limit, offset int) ([]*storage.AuditLog, error) {
	args := m.Called(ctx, userID, eventType, limit, offset)
	return args.Get(0).([]*storage.AuditLog), args.Error(1)
}
func (m *MockStorage) DeleteOldAuditLogs(ctx context.Context, olderThan time.Time) (int64, error) {
	args := m.Called(ctx, olderThan)
	return args.Get(0).(int64), args.Error(1)
}
func (m *MockStorage) ListAuditLogsByTenant(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*storage.AuditLog, error) {
	args := m.Called(ctx, tenantID, limit, offset)
	return args.Get(0).([]*storage.AuditLog), args.Error(1)
}
func (m *MockStorage) ListAuditLogsByEventTypes(ctx context.Context, eventTypes []string, limit, offset int) ([]*storage.AuditLog, error) {
	args := m.Called(ctx, eventTypes, limit, offset)
	return args.Get(0).([]*storage.AuditLog), args.Error(1)
}
func (m *MockStorage) CountAuditLogsByEventTypes(ctx context.Context, eventTypes []string) (int, error) {
	args := m.Called(ctx, eventTypes)
	return args.Int(0), args.Error(1)
}

// MFAStorage
func (m *MockStorage) GetMFASettings(ctx context.Context, userID uuid.UUID) (*storage.MFASettings, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.MFASettings), args.Error(1)
}
func (m *MockStorage) UpdateMFASettings(ctx context.Context, settings *storage.MFASettings) error {
	args := m.Called(ctx, settings)
	return args.Error(0)
}
func (m *MockStorage) CreateMFAChallenge(ctx context.Context, challenge *storage.MFAChallenge) error {
	args := m.Called(ctx, challenge)
	return args.Error(0)
}
func (m *MockStorage) GetMFAChallenge(ctx context.Context, id uuid.UUID) (*storage.MFAChallenge, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.MFAChallenge), args.Error(1)
}
func (m *MockStorage) GetPendingMFAChallenge(ctx context.Context, userID uuid.UUID, challengeType string) (*storage.MFAChallenge, error) {
	args := m.Called(ctx, userID, challengeType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.MFAChallenge), args.Error(1)
}
func (m *MockStorage) MarkMFAChallengeVerified(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
func (m *MockStorage) DeleteExpiredMFAChallenges(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}
func (m *MockStorage) CreateWebAuthnCredential(ctx context.Context, cred *storage.WebAuthnCredential) error {
	args := m.Called(ctx, cred)
	return args.Error(0)
}
func (m *MockStorage) GetWebAuthnCredentials(ctx context.Context, userID uuid.UUID) ([]*storage.WebAuthnCredential, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]*storage.WebAuthnCredential), args.Error(1)
}
func (m *MockStorage) GetWebAuthnCredentialByID(ctx context.Context, credentialID []byte) (*storage.WebAuthnCredential, error) {
	args := m.Called(ctx, credentialID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.WebAuthnCredential), args.Error(1)
}
func (m *MockStorage) UpdateWebAuthnCredentialSignCount(ctx context.Context, credentialID []byte, signCount uint32) error {
	args := m.Called(ctx, credentialID, signCount)
	return args.Error(0)
}
func (m *MockStorage) DeleteWebAuthnCredential(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
func (m *MockStorage) SetDeviceMFATrust(ctx context.Context, deviceID uuid.UUID, trustedUntil time.Time, trustToken string) error {
	args := m.Called(ctx, deviceID, trustedUntil, trustToken)
	return args.Error(0)
}
func (m *MockStorage) ClearDeviceMFATrust(ctx context.Context, deviceID uuid.UUID) error {
	args := m.Called(ctx, deviceID)
	return args.Error(0)
}
func (m *MockStorage) GetDeviceMFATrust(ctx context.Context, userID uuid.UUID, deviceFingerprint string) (*time.Time, error) {
	args := m.Called(ctx, userID, deviceFingerprint)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*time.Time), args.Error(1)
}

// VerificationTokenStorage
func (m *MockStorage) CreateVerificationToken(ctx context.Context, token *storage.VerificationToken) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}
func (m *MockStorage) GetVerificationTokenByHash(ctx context.Context, tokenHash string, tokenType string) (*storage.VerificationToken, error) {
	args := m.Called(ctx, tokenHash, tokenType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.VerificationToken), args.Error(1)
}
func (m *MockStorage) MarkVerificationTokenUsed(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
func (m *MockStorage) DeleteExpiredVerificationTokens(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// RBACStorage
func (m *MockStorage) CreateRole(ctx context.Context, role *storage.Role) error {
	args := m.Called(ctx, role)
	return args.Error(0)
}
func (m *MockStorage) GetRoleByID(ctx context.Context, id uuid.UUID) (*storage.Role, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.Role), args.Error(1)
}
func (m *MockStorage) GetRoleByName(ctx context.Context, name string) (*storage.Role, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.Role), args.Error(1)
}
func (m *MockStorage) ListRoles(ctx context.Context) ([]*storage.Role, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*storage.Role), args.Error(1)
}
func (m *MockStorage) UpdateRole(ctx context.Context, role *storage.Role) error {
	args := m.Called(ctx, role)
	return args.Error(0)
}
func (m *MockStorage) DeleteRole(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
func (m *MockStorage) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*storage.Role, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]*storage.Role), args.Error(1)
}
func (m *MockStorage) GetUserRolesByTenant(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) ([]*storage.Role, error) {
	args := m.Called(ctx, userID, tenantID)
	return args.Get(0).([]*storage.Role), args.Error(1)
}
func (m *MockStorage) AssignRoleToUser(ctx context.Context, userID, roleID uuid.UUID, assignedBy *uuid.UUID) error {
	args := m.Called(ctx, userID, roleID, assignedBy)
	return args.Error(0)
}
func (m *MockStorage) AssignRoleToUserInTenant(ctx context.Context, userID, roleID, tenantID uuid.UUID, assignedBy *uuid.UUID) error {
	args := m.Called(ctx, userID, roleID, tenantID, assignedBy)
	return args.Error(0)
}
func (m *MockStorage) RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error {
	args := m.Called(ctx, userID, roleID)
	return args.Error(0)
}
func (m *MockStorage) RemoveRoleFromUserInTenant(ctx context.Context, userID, roleID, tenantID uuid.UUID) error {
	args := m.Called(ctx, userID, roleID, tenantID)
	return args.Error(0)
}
func (m *MockStorage) UserHasRole(ctx context.Context, userID uuid.UUID, roleName string) (bool, error) {
	args := m.Called(ctx, userID, roleName)
	return args.Bool(0), args.Error(1)
}
func (m *MockStorage) UserHasRoleInTenant(ctx context.Context, userID uuid.UUID, roleName string, tenantID uuid.UUID) (bool, error) {
	args := m.Called(ctx, userID, roleName, tenantID)
	return args.Bool(0), args.Error(1)
}
func (m *MockStorage) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*storage.Permission, error) {
	args := m.Called(ctx, roleID)
	return args.Get(0).([]*storage.Permission), args.Error(1)
}
func (m *MockStorage) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]*storage.Permission, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]*storage.Permission), args.Error(1)
}
func (m *MockStorage) UserHasPermission(ctx context.Context, userID uuid.UUID, permissionName string) (bool, error) {
	args := m.Called(ctx, userID, permissionName)
	return args.Bool(0), args.Error(1)
}
func (m *MockStorage) UserHasPermissionInTenant(ctx context.Context, userID uuid.UUID, permissionName string, tenantID uuid.UUID) (bool, error) {
	args := m.Called(ctx, userID, permissionName, tenantID)
	return args.Bool(0), args.Error(1)
}
func (m *MockStorage) AssignPermissionToRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	args := m.Called(ctx, roleID, permissionID)
	return args.Error(0)
}
func (m *MockStorage) RemovePermissionFromRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	args := m.Called(ctx, roleID, permissionID)
	return args.Error(0)
}
func (m *MockStorage) GetPermissionByID(ctx context.Context, id uuid.UUID) (*storage.Permission, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.Permission), args.Error(1)
}
func (m *MockStorage) GetRoleByIDAndTenant(ctx context.Context, id uuid.UUID, tenantID *uuid.UUID) (*storage.Role, error) {
	args := m.Called(ctx, id, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.Role), args.Error(1)
}
func (m *MockStorage) GetPermissionByName(ctx context.Context, name string) (*storage.Permission, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.Permission), args.Error(1)
}
func (m *MockStorage) GetRoleByNameAndTenant(ctx context.Context, name string, tenantID *uuid.UUID) (*storage.Role, error) {
	args := m.Called(ctx, name, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.Role), args.Error(1)
}
func (m *MockStorage) ListPermissions(ctx context.Context) ([]*storage.Permission, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*storage.Permission), args.Error(1)
}
func (m *MockStorage) ListRolesByTenant(ctx context.Context, tenantID uuid.UUID) ([]*storage.Role, error) {
	args := m.Called(ctx, tenantID)
	return args.Get(0).([]*storage.Role), args.Error(1)
}

// TenantStorage
func (m *MockStorage) CreateTenant(ctx context.Context, tenant *storage.Tenant) error {
	args := m.Called(ctx, tenant)
	return args.Error(0)
}
func (m *MockStorage) GetTenantByID(ctx context.Context, id uuid.UUID) (*storage.Tenant, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.Tenant), args.Error(1)
}
func (m *MockStorage) GetTenantBySlug(ctx context.Context, slug string) (*storage.Tenant, error) {
	args := m.Called(ctx, slug)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.Tenant), args.Error(1)
}
func (m *MockStorage) GetTenantByDomain(ctx context.Context, domain string) (*storage.Tenant, error) {
	args := m.Called(ctx, domain)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.Tenant), args.Error(1)
}
func (m *MockStorage) ListTenants(ctx context.Context, limit, offset int) ([]*storage.Tenant, error) {
	args := m.Called(ctx, limit, offset)
	return args.Get(0).([]*storage.Tenant), args.Error(1)
}
func (m *MockStorage) UpdateTenant(ctx context.Context, tenant *storage.Tenant) error {
	args := m.Called(ctx, tenant)
	return args.Error(0)
}
func (m *MockStorage) DeleteTenant(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
func (m *MockStorage) ListTenantUsers(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*storage.User, error) {
	args := m.Called(ctx, tenantID, limit, offset)
	return args.Get(0).([]*storage.User), args.Error(1)
}
func (m *MockStorage) CountTenantUsers(ctx context.Context, tenantID uuid.UUID) (int, error) {
	args := m.Called(ctx, tenantID)
	return args.Int(0), args.Error(1)
}

// DeviceStorage
func (m *MockStorage) CreateDevice(ctx context.Context, device *storage.UserDevice) error {
	args := m.Called(ctx, device)
	return args.Error(0)
}
func (m *MockStorage) GetDeviceByID(ctx context.Context, id uuid.UUID) (*storage.UserDevice, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.UserDevice), args.Error(1)
}
func (m *MockStorage) GetDeviceByFingerprint(ctx context.Context, userID uuid.UUID, fingerprint string) (*storage.UserDevice, error) {
	args := m.Called(ctx, userID, fingerprint)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.UserDevice), args.Error(1)
}
func (m *MockStorage) ListUserDevices(ctx context.Context, userID uuid.UUID) ([]*storage.UserDevice, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]*storage.UserDevice), args.Error(1)
}
func (m *MockStorage) UpdateDevice(ctx context.Context, device *storage.UserDevice) error {
	args := m.Called(ctx, device)
	return args.Error(0)
}
func (m *MockStorage) DeleteDevice(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
func (m *MockStorage) TrustDevice(ctx context.Context, id uuid.UUID, trusted bool) error {
	args := m.Called(ctx, id, trusted)
	return args.Error(0)
}
func (m *MockStorage) CreateLoginHistory(ctx context.Context, history *storage.LoginHistory) error {
	args := m.Called(ctx, history)
	return args.Error(0)
}
func (m *MockStorage) GetLoginHistory(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*storage.LoginHistory, error) {
	args := m.Called(ctx, userID, limit, offset)
	return args.Get(0).([]*storage.LoginHistory), args.Error(1)
}

// APIKeyStorage
func (m *MockStorage) CreateAPIKey(ctx context.Context, key *storage.APIKey) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}
func (m *MockStorage) GetAPIKeyByID(ctx context.Context, id uuid.UUID) (*storage.APIKey, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.APIKey), args.Error(1)
}
func (m *MockStorage) GetAPIKeyByHash(ctx context.Context, keyHash string) (*storage.APIKey, error) {
	args := m.Called(ctx, keyHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.APIKey), args.Error(1)
}
func (m *MockStorage) ListAPIKeys(ctx context.Context, userID *uuid.UUID, tenantID *uuid.UUID, limit, offset int) ([]*storage.APIKey, error) {
	args := m.Called(ctx, userID, tenantID, limit, offset)
	return args.Get(0).([]*storage.APIKey), args.Error(1)
}
func (m *MockStorage) UpdateAPIKey(ctx context.Context, key *storage.APIKey) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}
func (m *MockStorage) RevokeAPIKey(ctx context.Context, id uuid.UUID, revokedBy *uuid.UUID) error {
	args := m.Called(ctx, id, revokedBy)
	return args.Error(0)
}
func (m *MockStorage) UpdateAPIKeyLastUsed(ctx context.Context, id uuid.UUID, ip string) error {
	args := m.Called(ctx, id, ip)
	return args.Error(0)
}

// WebhookStorage
func (m *MockStorage) CreateWebhook(ctx context.Context, webhook *storage.Webhook) error {
	args := m.Called(ctx, webhook)
	return args.Error(0)
}
func (m *MockStorage) GetWebhookByID(ctx context.Context, id uuid.UUID) (*storage.Webhook, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.Webhook), args.Error(1)
}
func (m *MockStorage) ListWebhooks(ctx context.Context, tenantID *uuid.UUID, limit, offset int) ([]*storage.Webhook, error) {
	args := m.Called(ctx, tenantID, limit, offset)
	return args.Get(0).([]*storage.Webhook), args.Error(1)
}
func (m *MockStorage) ListWebhooksByEvent(ctx context.Context, tenantID *uuid.UUID, eventType string) ([]*storage.Webhook, error) {
	args := m.Called(ctx, tenantID, eventType)
	return args.Get(0).([]*storage.Webhook), args.Error(1)
}
func (m *MockStorage) UpdateWebhook(ctx context.Context, webhook *storage.Webhook) error {
	args := m.Called(ctx, webhook)
	return args.Error(0)
}
func (m *MockStorage) DeleteWebhook(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
func (m *MockStorage) CreateWebhookDelivery(ctx context.Context, delivery *storage.WebhookDelivery) error {
	args := m.Called(ctx, delivery)
	return args.Error(0)
}
func (m *MockStorage) UpdateWebhookDelivery(ctx context.Context, delivery *storage.WebhookDelivery) error {
	args := m.Called(ctx, delivery)
	return args.Error(0)
}
func (m *MockStorage) GetPendingDeliveries(ctx context.Context, limit int) ([]*storage.WebhookDelivery, error) {
	args := m.Called(ctx, limit)
	return args.Get(0).([]*storage.WebhookDelivery), args.Error(1)
}
func (m *MockStorage) GetWebhookDeliveries(ctx context.Context, webhookID uuid.UUID, limit, offset int) ([]*storage.WebhookDelivery, error) {
	args := m.Called(ctx, webhookID, limit, offset)
	return args.Get(0).([]*storage.WebhookDelivery), args.Error(1)
}

// InvitationStorage
func (m *MockStorage) CreateInvitation(ctx context.Context, invitation *storage.UserInvitation) error {
	args := m.Called(ctx, invitation)
	return args.Error(0)
}
func (m *MockStorage) GetInvitationByID(ctx context.Context, id uuid.UUID) (*storage.UserInvitation, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.UserInvitation), args.Error(1)
}
func (m *MockStorage) GetInvitationByToken(ctx context.Context, tokenHash string) (*storage.UserInvitation, error) {
	args := m.Called(ctx, tokenHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.UserInvitation), args.Error(1)
}
func (m *MockStorage) GetInvitationByEmail(ctx context.Context, tenantID *uuid.UUID, email string) (*storage.UserInvitation, error) {
	args := m.Called(ctx, tenantID, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.UserInvitation), args.Error(1)
}
func (m *MockStorage) ListInvitations(ctx context.Context, tenantID *uuid.UUID, limit, offset int) ([]*storage.UserInvitation, error) {
	args := m.Called(ctx, tenantID, limit, offset)
	return args.Get(0).([]*storage.UserInvitation), args.Error(1)
}
func (m *MockStorage) UpdateInvitation(ctx context.Context, invitation *storage.UserInvitation) error {
	args := m.Called(ctx, invitation)
	return args.Error(0)
}
func (m *MockStorage) AcceptInvitation(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
func (m *MockStorage) DeleteInvitation(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
func (m *MockStorage) DeleteExpiredInvitations(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// SystemSettingsStorage
func (m *MockStorage) GetSetting(ctx context.Context, key string) (*storage.SystemSetting, error) {
	args := m.Called(ctx, key)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.SystemSetting), args.Error(1)
}
func (m *MockStorage) ListSettings(ctx context.Context, category string) ([]*storage.SystemSetting, error) {
	args := m.Called(ctx, category)
	return args.Get(0).([]*storage.SystemSetting), args.Error(1)
}
func (m *MockStorage) UpdateSetting(ctx context.Context, key string, value interface{}) error {
	args := m.Called(ctx, key, value)
	return args.Error(0)
}

// UserGroupStorage
func (m *MockStorage) CreateGroup(ctx context.Context, group *storage.UserGroup) error {
	args := m.Called(ctx, group)
	return args.Error(0)
}
func (m *MockStorage) GetGroupByID(ctx context.Context, id uuid.UUID) (*storage.UserGroup, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.UserGroup), args.Error(1)
}
func (m *MockStorage) ListGroups(ctx context.Context, tenantID *uuid.UUID, limit, offset int) ([]*storage.UserGroup, error) {
	args := m.Called(ctx, tenantID, limit, offset)
	return args.Get(0).([]*storage.UserGroup), args.Error(1)
}
func (m *MockStorage) UpdateGroup(ctx context.Context, group *storage.UserGroup) error {
	args := m.Called(ctx, group)
	return args.Error(0)
}
func (m *MockStorage) DeleteGroup(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
func (m *MockStorage) AddUserToGroup(ctx context.Context, userID, groupID uuid.UUID, role string) error {
	args := m.Called(ctx, userID, groupID, role)
	return args.Error(0)
}
func (m *MockStorage) RemoveUserFromGroup(ctx context.Context, userID, groupID uuid.UUID) error {
	args := m.Called(ctx, userID, groupID)
	return args.Error(0)
}
func (m *MockStorage) GetGroupMembers(ctx context.Context, groupID uuid.UUID, limit, offset int) ([]*storage.UserGroupMember, error) {
	args := m.Called(ctx, groupID, limit, offset)
	return args.Get(0).([]*storage.UserGroupMember), args.Error(1)
}
func (m *MockStorage) GetUserGroups(ctx context.Context, userID uuid.UUID) ([]*storage.UserGroup, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]*storage.UserGroup), args.Error(1)
}

// OAuthStateStorage
func (m *MockStorage) CreateOAuthState(ctx context.Context, state *storage.SocialLoginState) error {
	args := m.Called(ctx, state)
	return args.Error(0)
}
func (m *MockStorage) GetOAuthStateByHash(ctx context.Context, stateHash string) (*storage.SocialLoginState, error) {
	args := m.Called(ctx, stateHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.SocialLoginState), args.Error(1)
}
func (m *MockStorage) DeleteOAuthState(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
func (m *MockStorage) DeleteExpiredOAuthStates(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// EmailTemplateStorage
func (m *MockStorage) GetEmailTemplate(ctx context.Context, tenantID *uuid.UUID, templateType string) (*storage.EmailTemplate, error) {
	args := m.Called(ctx, tenantID, templateType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.EmailTemplate), args.Error(1)
}
func (m *MockStorage) ListEmailTemplates(ctx context.Context, tenantID *uuid.UUID) ([]*storage.EmailTemplate, error) {
	args := m.Called(ctx, tenantID)
	return args.Get(0).([]*storage.EmailTemplate), args.Error(1)
}
func (m *MockStorage) UpsertEmailTemplate(ctx context.Context, template *storage.EmailTemplate) error {
	args := m.Called(ctx, template)
	return args.Error(0)
}
func (m *MockStorage) DeleteEmailTemplate(ctx context.Context, tenantID *uuid.UUID, templateType string) error {
	args := m.Called(ctx, tenantID, templateType)
	return args.Error(0)
}
func (m *MockStorage) GetEmailBranding(ctx context.Context, tenantID *uuid.UUID) (*storage.EmailBranding, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.EmailBranding), args.Error(1)
}
func (m *MockStorage) UpsertEmailBranding(ctx context.Context, branding *storage.EmailBranding) error {
	args := m.Called(ctx, branding)
	return args.Error(0)
}
func (m *MockStorage) CreateEmailDeadLetter(ctx context.Context, dl *storage.EmailDeadLetter) error {
	args := m.Called(ctx, dl)
	return args.Error(0)
}
func (m *MockStorage) ListEmailDeadLetters(ctx context.Context, tenantID *uuid.UUID, resolved bool, limit, offset int) ([]*storage.EmailDeadLetter, error) {
	args := m.Called(ctx, tenantID, resolved, limit, offset)
	return args.Get(0).([]*storage.EmailDeadLetter), args.Error(1)
}
func (m *MockStorage) MarkEmailDeadLetterResolved(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
func (m *MockStorage) CreateEmailTemplateVersion(ctx context.Context, version *storage.EmailTemplateVersion) error {
	args := m.Called(ctx, version)
	return args.Error(0)
}
func (m *MockStorage) ListEmailTemplateVersions(ctx context.Context, tenantID *uuid.UUID, templateType string, limit, offset int) ([]*storage.EmailTemplateVersion, error) {
	args := m.Called(ctx, tenantID, templateType, limit, offset)
	return args.Get(0).([]*storage.EmailTemplateVersion), args.Error(1)
}
func (m *MockStorage) GetEmailTemplateVersion(ctx context.Context, id uuid.UUID) (*storage.EmailTemplateVersion, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.EmailTemplateVersion), args.Error(1)
}
func (m *MockStorage) CreateEmailBounce(ctx context.Context, bounce *storage.EmailBounce) error {
	args := m.Called(ctx, bounce)
	return args.Error(0)
}
func (m *MockStorage) ListEmailBounces(ctx context.Context, tenantID *uuid.UUID, bounceType string, limit, offset int) ([]*storage.EmailBounce, error) {
	args := m.Called(ctx, tenantID, bounceType, limit, offset)
	return args.Get(0).([]*storage.EmailBounce), args.Error(1)
}
func (m *MockStorage) GetEmailBounceByEmail(ctx context.Context, tenantID *uuid.UUID, email string) (*storage.EmailBounce, error) {
	args := m.Called(ctx, tenantID, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.EmailBounce), args.Error(1)
}
func (m *MockStorage) CreateEmailEvent(ctx context.Context, event *storage.EmailEvent) error {
	args := m.Called(ctx, event)
	return args.Error(0)
}
func (m *MockStorage) GetEmailStats(ctx context.Context, tenantID *uuid.UUID, days int) (*storage.EmailStats, error) {
	args := m.Called(ctx, tenantID, days)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.EmailStats), args.Error(1)
}
func (m *MockStorage) CreateEmailSuppression(ctx context.Context, suppression *storage.EmailSuppression) error {
	args := m.Called(ctx, suppression)
	return args.Error(0)
}
func (m *MockStorage) GetEmailSuppression(ctx context.Context, tenantID *uuid.UUID, email string) (*storage.EmailSuppression, error) {
	args := m.Called(ctx, tenantID, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.EmailSuppression), args.Error(1)
}
func (m *MockStorage) DeleteEmailSuppression(ctx context.Context, tenantID *uuid.UUID, email string) error {
	args := m.Called(ctx, tenantID, email)
	return args.Error(0)
}
func (m *MockStorage) ListEmailSuppressions(ctx context.Context, tenantID *uuid.UUID, limit, offset int) ([]*storage.EmailSuppression, error) {
	args := m.Called(ctx, tenantID, limit, offset)
	return args.Get(0).([]*storage.EmailSuppression), args.Error(1)
}
func (m *MockStorage) ListEmailABTests(ctx context.Context, tenantID *uuid.UUID) ([]*storage.EmailABTest, error) {
	args := m.Called(ctx, tenantID)
	return args.Get(0).([]*storage.EmailABTest), args.Error(1)
}
func (m *MockStorage) CreateEmailABTest(ctx context.Context, test *storage.EmailABTest) error {
	args := m.Called(ctx, test)
	return args.Error(0)
}
func (m *MockStorage) GetEmailABTest(ctx context.Context, id uuid.UUID) (*storage.EmailABTest, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.EmailABTest), args.Error(1)
}
func (m *MockStorage) UpdateEmailABTest(ctx context.Context, test *storage.EmailABTest) error {
	args := m.Called(ctx, test)
	return args.Error(0)
}
func (m *MockStorage) DeleteEmailABTest(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
func (m *MockStorage) GetEmailBrandingAdvanced(ctx context.Context, tenantID *uuid.UUID) (*storage.EmailBrandingAdvanced, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.EmailBrandingAdvanced), args.Error(1)
}
func (m *MockStorage) UpsertEmailBrandingAdvanced(ctx context.Context, branding *storage.EmailBrandingAdvanced) error {
	args := m.Called(ctx, branding)
	return args.Error(0)
}
func (m *MockStorage) CreateEmailTrackingPixel(ctx context.Context, pixel *storage.EmailTrackingPixel) error {
	args := m.Called(ctx, pixel)
	return args.Error(0)
}
func (m *MockStorage) GetEmailTrackingPixel(ctx context.Context, id uuid.UUID) (*storage.EmailTrackingPixel, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.EmailTrackingPixel), args.Error(1)
}
func (m *MockStorage) MarkTrackingPixelOpened(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// PasswordHistoryStorage
func (m *MockStorage) AddPasswordHistory(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	args := m.Called(ctx, userID, passwordHash)
	return args.Error(0)
}
func (m *MockStorage) GetPasswordHistory(ctx context.Context, userID uuid.UUID, limit int) ([]*storage.PasswordHistory, error) {
	args := m.Called(ctx, userID, limit)
	return args.Get(0).([]*storage.PasswordHistory), args.Error(1)
}
func (m *MockStorage) CleanupOldPasswordHistory(ctx context.Context, userID uuid.UUID, keepCount int) error {
	args := m.Called(ctx, userID, keepCount)
	return args.Error(0)
}

// MagicLinkStorage
func (m *MockStorage) CreateMagicLink(ctx context.Context, link *storage.MagicLink) error {
	args := m.Called(ctx, link)
	return args.Error(0)
}
func (m *MockStorage) GetMagicLinkByHash(ctx context.Context, tokenHash string) (*storage.MagicLink, error) {
	args := m.Called(ctx, tokenHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.MagicLink), args.Error(1)
}
func (m *MockStorage) MarkMagicLinkUsed(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
func (m *MockStorage) DeleteExpiredMagicLinks(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}
func (m *MockStorage) CountRecentMagicLinks(ctx context.Context, email string, since time.Time) (int, error) {
	args := m.Called(ctx, email, since)
	return args.Int(0), args.Error(1)
}

// ImpersonationStorage
func (m *MockStorage) CreateImpersonationSession(ctx context.Context, session *storage.ImpersonationSession) error {
	args := m.Called(ctx, session)
	return args.Error(0)
}
func (m *MockStorage) GetImpersonationSession(ctx context.Context, sessionID uuid.UUID) (*storage.ImpersonationSession, error) {
	args := m.Called(ctx, sessionID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.ImpersonationSession), args.Error(1)
}
func (m *MockStorage) EndImpersonationSession(ctx context.Context, sessionID uuid.UUID) error {
	args := m.Called(ctx, sessionID)
	return args.Error(0)
}
func (m *MockStorage) ListImpersonationSessions(ctx context.Context, adminUserID *uuid.UUID, targetUserID *uuid.UUID, limit, offset int) ([]*storage.ImpersonationSession, error) {
	args := m.Called(ctx, adminUserID, targetUserID, limit, offset)
	return args.Get(0).([]*storage.ImpersonationSession), args.Error(1)
}

// RiskAssessmentStorage
func (m *MockStorage) CreateRiskAssessment(ctx context.Context, assessment *storage.RiskAssessment) error {
	args := m.Called(ctx, assessment)
	return args.Error(0)
}
func (m *MockStorage) GetRecentRiskAssessments(ctx context.Context, userID uuid.UUID, limit int) ([]*storage.RiskAssessment, error) {
	args := m.Called(ctx, userID, limit)
	return args.Get(0).([]*storage.RiskAssessment), args.Error(1)
}
func (m *MockStorage) GetRiskAssessmentStats(ctx context.Context, userID uuid.UUID, since time.Time) (map[string]int, error) {
	args := m.Called(ctx, userID, since)
	return args.Get(0).(map[string]int), args.Error(1)
}

// PreferencesStorage
func (m *MockStorage) GetPreferences(ctx context.Context, userID uuid.UUID) (*storage.UserPreferences, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.UserPreferences), args.Error(1)
}
func (m *MockStorage) CreatePreferences(ctx context.Context, prefs *storage.UserPreferences) error {
	args := m.Called(ctx, prefs)
	return args.Error(0)
}
func (m *MockStorage) UpdatePreferences(ctx context.Context, prefs *storage.UserPreferences) error {
	args := m.Called(ctx, prefs)
	return args.Error(0)
}
func (m *MockStorage) GetOrCreatePreferences(ctx context.Context, userID uuid.UUID) (*storage.UserPreferences, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*storage.UserPreferences), args.Error(1)
}

func TestUpdateFeatures_CustomFlags(t *testing.T) {
	mockStorage := new(MockStorage)
	service := NewService(mockStorage)
	ctx := context.Background()

	tenantID := uuid.New()
	initialFeatures := map[string]interface{}{
		"features": map[string]interface{}{
			"sso_enabled":  true,
			"mfa_required": true,
			"custom_flags": map[string]interface{}{
				"existing_flag": true,
			},
		},
	}

	tenant := &storage.Tenant{
		ID:       tenantID,
		Settings: initialFeatures,
	}

	// Setup expectations
	mockStorage.On("GetTenantByID", ctx, tenantID).Return(tenant, nil)
	mockStorage.On("UpdateTenant", ctx, mock.MatchedBy(func(t *storage.Tenant) bool {
		features := t.Settings["features"].(map[string]interface{})
		customFlags := features["custom_flags"].(map[string]interface{})

		// Verify standard flags are preserved
		if features["sso_enabled"] != true {
			return false
		}

		// Verify custom flags are merged correctly
		if customFlags["existing_flag"] != true {
			return false
		}
		if customFlags["new_flag"] != true {
			return false
		}
		return true
	})).Return(nil)

	// Prepare update request
	newFlag := true
	req := &UpdateFeaturesRequest{
		CustomFlags: map[string]interface{}{
			"new_flag": newFlag,
		},
	}

	// Execute
	updatedFeatures, err := service.UpdateFeatures(ctx, tenantID, req)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, updatedFeatures)
	assert.True(t, updatedFeatures.SSOEnabled, "SSO should remain enabled")
	assert.True(t, updatedFeatures.MFARequired, "MFA should remain required")
	assert.True(t, updatedFeatures.CustomFlags["existing_flag"].(bool), "Existing flag should be preserved")
	assert.True(t, updatedFeatures.CustomFlags["new_flag"].(bool), "New flag should be added")

	mockStorage.AssertExpectations(t)
}
