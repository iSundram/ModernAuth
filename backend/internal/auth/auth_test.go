package auth

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
)

// MockStorage implements the storage.Storage interface for testing.
type MockStorage struct {
	mu            sync.RWMutex
	users         map[uuid.UUID]*storage.User
	usersByEmail  map[string]*storage.User
	sessions      map[uuid.UUID]*storage.Session
	refreshTokens map[string]*storage.RefreshToken
	refreshByID   map[uuid.UUID]*storage.RefreshToken
	auditLogs     []*storage.AuditLog
}

func NewMockStorage() *MockStorage {
	return &MockStorage{
		users:         make(map[uuid.UUID]*storage.User),
		usersByEmail:  make(map[string]*storage.User),
		sessions:      make(map[uuid.UUID]*storage.Session),
		refreshTokens: make(map[string]*storage.RefreshToken),
		refreshByID:   make(map[uuid.UUID]*storage.RefreshToken),
		auditLogs:     []*storage.AuditLog{},
	}
}

func (m *MockStorage) CreateUser(ctx context.Context, user *storage.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[user.ID] = user
	m.usersByEmail[user.Email] = user
	return nil
}

func (m *MockStorage) GetUserByID(ctx context.Context, id uuid.UUID) (*storage.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.users[id], nil
}

func (m *MockStorage) GetUserByEmail(ctx context.Context, email string) (*storage.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.usersByEmail[email], nil
}

func (m *MockStorage) UpdateUser(ctx context.Context, user *storage.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[user.ID] = user
	m.usersByEmail[user.Email] = user
	return nil
}

func (m *MockStorage) DeleteUser(ctx context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if user, ok := m.users[id]; ok {
		delete(m.usersByEmail, user.Email)
		delete(m.users, id)
	}
	return nil
}

func (m *MockStorage) ListUsers(ctx context.Context, limit, offset int) ([]*storage.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	users := make([]*storage.User, 0, len(m.users))
	for _, user := range m.users {
		users = append(users, user)
	}
	// Apply simple pagination
	if offset > len(users) {
		return []*storage.User{}, nil
	}
	end := offset + limit
	if end > len(users) {
		end = len(users)
	}
	return users[offset:end], nil
}

func (m *MockStorage) CountUsers(ctx context.Context) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.users), nil
}

func (m *MockStorage) CreateSession(ctx context.Context, session *storage.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[session.ID] = session
	return nil
}

func (m *MockStorage) GetSessionByID(ctx context.Context, id uuid.UUID) (*storage.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[id], nil
}

func (m *MockStorage) RevokeSession(ctx context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if session, ok := m.sessions[id]; ok {
		session.Revoked = true
	}
	return nil
}

func (m *MockStorage) RevokeUserSessions(ctx context.Context, userID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, session := range m.sessions {
		if session.UserID == userID {
			session.Revoked = true
		}
	}
	return nil
}

func (m *MockStorage) CreateRefreshToken(ctx context.Context, token *storage.RefreshToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshTokens[token.TokenHash] = token
	m.refreshByID[token.ID] = token
	return nil
}

func (m *MockStorage) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*storage.RefreshToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.refreshTokens[tokenHash], nil
}

func (m *MockStorage) RevokeRefreshToken(ctx context.Context, id uuid.UUID, replacedBy *uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if token, ok := m.refreshByID[id]; ok {
		token.Revoked = true
		token.ReplacedBy = replacedBy
	}
	return nil
}

func (m *MockStorage) RevokeSessionRefreshTokens(ctx context.Context, sessionID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, token := range m.refreshByID {
		if token.SessionID == sessionID {
			token.Revoked = true
		}
	}
	return nil
}

func (m *MockStorage) CreateAuditLog(ctx context.Context, log *storage.AuditLog) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.auditLogs = append(m.auditLogs, log)
	return nil
}

func (m *MockStorage) GetAuditLogs(ctx context.Context, userID *uuid.UUID, eventType *string, limit, offset int) ([]*storage.AuditLog, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*storage.AuditLog
	for _, log := range m.auditLogs {
		if userID == nil || (log.UserID != nil && *log.UserID == *userID) {
			result = append(result, log)
		}
	}
	// Apply pagination
	start := offset
	if start > len(result) {
		return []*storage.AuditLog{}, nil
	}
	end := start + limit
	if end > len(result) {
		end = len(result)
	}
	return result[start:end], nil
}

func (m *MockStorage) DeleteOldAuditLogs(ctx context.Context, olderThan time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var deleted int64
	var remaining []*storage.AuditLog
	for _, log := range m.auditLogs {
		if log.CreatedAt.Before(olderThan) {
			deleted++
		} else {
			remaining = append(remaining, log)
		}
	}
	m.auditLogs = remaining
	return deleted, nil
}

func (m *MockStorage) GetMFASettings(ctx context.Context, userID uuid.UUID) (*storage.MFASettings, error) {
	return nil, nil
}

func (m *MockStorage) UpdateMFASettings(ctx context.Context, settings *storage.MFASettings) error {
	return nil
}

func (m *MockStorage) CreateVerificationToken(ctx context.Context, token *storage.VerificationToken) error {
	return nil
}

func (m *MockStorage) GetVerificationTokenByHash(ctx context.Context, tokenHash string, tokenType string) (*storage.VerificationToken, error) {
	return nil, nil
}

func (m *MockStorage) MarkVerificationTokenUsed(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *MockStorage) DeleteExpiredVerificationTokens(ctx context.Context) error {
	return nil
}

// RBAC mock implementations
func (m *MockStorage) GetRoleByID(ctx context.Context, id uuid.UUID) (*storage.Role, error) {
	return nil, nil
}

func (m *MockStorage) GetRoleByName(ctx context.Context, name string) (*storage.Role, error) {
	return nil, nil
}

func (m *MockStorage) ListRoles(ctx context.Context) ([]*storage.Role, error) {
	return []*storage.Role{}, nil
}

func (m *MockStorage) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*storage.Role, error) {
	return []*storage.Role{}, nil
}

func (m *MockStorage) AssignRoleToUser(ctx context.Context, userID, roleID uuid.UUID, assignedBy *uuid.UUID) error {
	return nil
}

func (m *MockStorage) RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error {
	return nil
}

func (m *MockStorage) UserHasRole(ctx context.Context, userID uuid.UUID, roleName string) (bool, error) {
	return false, nil
}

func (m *MockStorage) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*storage.Permission, error) {
	return []*storage.Permission{}, nil
}

func (m *MockStorage) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]*storage.Permission, error) {
	return []*storage.Permission{}, nil
}

func (m *MockStorage) UserHasPermission(ctx context.Context, userID uuid.UUID, permissionName string) (bool, error) {
	return false, nil
}

func (m *MockStorage) CreateRole(ctx context.Context, role *storage.Role) error {
	return nil
}

func (m *MockStorage) UpdateRole(ctx context.Context, role *storage.Role) error {
	return nil
}

func (m *MockStorage) DeleteRole(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *MockStorage) AssignPermissionToRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	return nil
}

func (m *MockStorage) RemovePermissionFromRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	return nil
}

func (m *MockStorage) GetPermissionByID(ctx context.Context, id uuid.UUID) (*storage.Permission, error) {
	return nil, nil
}

func (m *MockStorage) GetPermissionByName(ctx context.Context, name string) (*storage.Permission, error) {
	return nil, nil
}

func (m *MockStorage) ListPermissions(ctx context.Context) ([]*storage.Permission, error) {
	return []*storage.Permission{}, nil
}

// SystemSettingsStorage mock implementations
func (m *MockStorage) GetSetting(ctx context.Context, key string) (*storage.SystemSetting, error) {
	return nil, nil
}

func (m *MockStorage) ListSettings(ctx context.Context, category string) ([]*storage.SystemSetting, error) {
	return []*storage.SystemSetting{}, nil
}

func (m *MockStorage) UpdateSetting(ctx context.Context, key string, value interface{}) error {
	return nil
}

func (m *MockStorage) GetUserSessions(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*storage.Session, error) {
	return []*storage.Session{}, nil
}

// TenantStorage mock implementations
func (m *MockStorage) CreateTenant(ctx context.Context, tenant *storage.Tenant) error {
	return nil
}
func (m *MockStorage) GetTenantByID(ctx context.Context, id uuid.UUID) (*storage.Tenant, error) {
	return nil, nil
}
func (m *MockStorage) GetTenantBySlug(ctx context.Context, slug string) (*storage.Tenant, error) {
	return nil, nil
}
func (m *MockStorage) GetTenantByDomain(ctx context.Context, domain string) (*storage.Tenant, error) {
	return nil, nil
}
func (m *MockStorage) ListTenants(ctx context.Context, limit, offset int) ([]*storage.Tenant, error) {
	return []*storage.Tenant{}, nil
}
func (m *MockStorage) UpdateTenant(ctx context.Context, tenant *storage.Tenant) error {
	return nil
}
func (m *MockStorage) DeleteTenant(ctx context.Context, id uuid.UUID) error {
	return nil
}
func (m *MockStorage) ListTenantUsers(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*storage.User, error) {
	return []*storage.User{}, nil
}
func (m *MockStorage) CountTenantUsers(ctx context.Context, tenantID uuid.UUID) (int, error) {
	return 0, nil
}

// DeviceStorage mock implementations
func (m *MockStorage) CreateDevice(ctx context.Context, device *storage.UserDevice) error {
	return nil
}
func (m *MockStorage) GetDeviceByID(ctx context.Context, id uuid.UUID) (*storage.UserDevice, error) {
	return nil, nil
}
func (m *MockStorage) GetDeviceByFingerprint(ctx context.Context, userID uuid.UUID, fingerprint string) (*storage.UserDevice, error) {
	return nil, nil
}
func (m *MockStorage) ListUserDevices(ctx context.Context, userID uuid.UUID) ([]*storage.UserDevice, error) {
	return []*storage.UserDevice{}, nil
}
func (m *MockStorage) UpdateDevice(ctx context.Context, device *storage.UserDevice) error {
	return nil
}
func (m *MockStorage) DeleteDevice(ctx context.Context, id uuid.UUID) error {
	return nil
}
func (m *MockStorage) TrustDevice(ctx context.Context, id uuid.UUID, trusted bool) error {
	return nil
}
func (m *MockStorage) CreateLoginHistory(ctx context.Context, history *storage.LoginHistory) error {
	return nil
}
func (m *MockStorage) GetLoginHistory(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*storage.LoginHistory, error) {
	return []*storage.LoginHistory{}, nil
}

// APIKeyStorage mock implementations
func (m *MockStorage) CreateAPIKey(ctx context.Context, key *storage.APIKey) error {
	return nil
}
func (m *MockStorage) GetAPIKeyByID(ctx context.Context, id uuid.UUID) (*storage.APIKey, error) {
	return nil, nil
}
func (m *MockStorage) GetAPIKeyByHash(ctx context.Context, keyHash string) (*storage.APIKey, error) {
	return nil, nil
}
func (m *MockStorage) ListAPIKeys(ctx context.Context, userID *uuid.UUID, tenantID *uuid.UUID, limit, offset int) ([]*storage.APIKey, error) {
	return []*storage.APIKey{}, nil
}
func (m *MockStorage) UpdateAPIKey(ctx context.Context, key *storage.APIKey) error {
	return nil
}
func (m *MockStorage) RevokeAPIKey(ctx context.Context, id uuid.UUID, revokedBy *uuid.UUID) error {
	return nil
}
func (m *MockStorage) UpdateAPIKeyLastUsed(ctx context.Context, id uuid.UUID, ip string) error {
	return nil
}

// WebhookStorage mock implementations
func (m *MockStorage) CreateWebhook(ctx context.Context, webhook *storage.Webhook) error {
	return nil
}
func (m *MockStorage) GetWebhookByID(ctx context.Context, id uuid.UUID) (*storage.Webhook, error) {
	return nil, nil
}
func (m *MockStorage) ListWebhooks(ctx context.Context, tenantID *uuid.UUID, limit, offset int) ([]*storage.Webhook, error) {
	return []*storage.Webhook{}, nil
}
func (m *MockStorage) ListWebhooksByEvent(ctx context.Context, tenantID *uuid.UUID, eventType string) ([]*storage.Webhook, error) {
	return []*storage.Webhook{}, nil
}
func (m *MockStorage) UpdateWebhook(ctx context.Context, webhook *storage.Webhook) error {
	return nil
}
func (m *MockStorage) DeleteWebhook(ctx context.Context, id uuid.UUID) error {
	return nil
}
func (m *MockStorage) CreateWebhookDelivery(ctx context.Context, delivery *storage.WebhookDelivery) error {
	return nil
}
func (m *MockStorage) UpdateWebhookDelivery(ctx context.Context, delivery *storage.WebhookDelivery) error {
	return nil
}
func (m *MockStorage) GetPendingDeliveries(ctx context.Context, limit int) ([]*storage.WebhookDelivery, error) {
	return []*storage.WebhookDelivery{}, nil
}
func (m *MockStorage) GetWebhookDeliveries(ctx context.Context, webhookID uuid.UUID, limit, offset int) ([]*storage.WebhookDelivery, error) {
	return []*storage.WebhookDelivery{}, nil
}

// InvitationStorage mock implementations
func (m *MockStorage) CreateInvitation(ctx context.Context, invitation *storage.UserInvitation) error {
	return nil
}
func (m *MockStorage) GetInvitationByID(ctx context.Context, id uuid.UUID) (*storage.UserInvitation, error) {
	return nil, nil
}
func (m *MockStorage) GetInvitationByToken(ctx context.Context, tokenHash string) (*storage.UserInvitation, error) {
	return nil, nil
}
func (m *MockStorage) GetInvitationByEmail(ctx context.Context, tenantID *uuid.UUID, email string) (*storage.UserInvitation, error) {
	return nil, nil
}
func (m *MockStorage) ListInvitations(ctx context.Context, tenantID *uuid.UUID, limit, offset int) ([]*storage.UserInvitation, error) {
	return []*storage.UserInvitation{}, nil
}
func (m *MockStorage) AcceptInvitation(ctx context.Context, id uuid.UUID) error {
	return nil
}
func (m *MockStorage) UpdateInvitation(ctx context.Context, invitation *storage.UserInvitation) error {
	return nil
}
func (m *MockStorage) DeleteInvitation(ctx context.Context, id uuid.UUID) error {
	return nil
}
func (m *MockStorage) DeleteExpiredInvitations(ctx context.Context) error {
	return nil
}

// MFA Enhancement mock methods
func (m *MockStorage) CreateMFAChallenge(ctx context.Context, challenge *storage.MFAChallenge) error {
	return nil
}
func (m *MockStorage) GetMFAChallenge(ctx context.Context, id uuid.UUID) (*storage.MFAChallenge, error) {
	return nil, nil
}
func (m *MockStorage) GetPendingMFAChallenge(ctx context.Context, userID uuid.UUID, challengeType string) (*storage.MFAChallenge, error) {
	return nil, nil
}
func (m *MockStorage) MarkMFAChallengeVerified(ctx context.Context, id uuid.UUID) error {
	return nil
}
func (m *MockStorage) DeleteExpiredMFAChallenges(ctx context.Context) error {
	return nil
}
func (m *MockStorage) CreateWebAuthnCredential(ctx context.Context, cred *storage.WebAuthnCredential) error {
	return nil
}
func (m *MockStorage) GetWebAuthnCredentials(ctx context.Context, userID uuid.UUID) ([]*storage.WebAuthnCredential, error) {
	return nil, nil
}
func (m *MockStorage) GetWebAuthnCredentialByID(ctx context.Context, credentialID []byte) (*storage.WebAuthnCredential, error) {
	return nil, nil
}
func (m *MockStorage) UpdateWebAuthnCredentialSignCount(ctx context.Context, credentialID []byte, signCount uint32) error {
	return nil
}
func (m *MockStorage) DeleteWebAuthnCredential(ctx context.Context, id uuid.UUID) error {
	return nil
}
func (m *MockStorage) SetDeviceMFATrust(ctx context.Context, deviceID uuid.UUID, trustedUntil time.Time, trustToken string) error {
	return nil
}
func (m *MockStorage) ClearDeviceMFATrust(ctx context.Context, deviceID uuid.UUID) error {
	return nil
}
func (m *MockStorage) GetDeviceMFATrust(ctx context.Context, userID uuid.UUID, deviceFingerprint string) (*time.Time, error) {
	return nil, nil
}

func (m *MockStorage) ListAuditLogsByTenant(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*storage.AuditLog, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if offset >= len(m.auditLogs) {
		return []*storage.AuditLog{}, nil
	}
	end := offset + limit
	if end > len(m.auditLogs) {
		end = len(m.auditLogs)
	}
	return m.auditLogs[offset:end], nil
}

func setupTestAuthService() (*AuthService, *MockStorage) {
	mockStorage := NewMockStorage()
	tokenConfig := &TokenConfig{
		Issuer:          "test",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		SigningKey:      []byte("test-secret-key-at-least-32-chars"),
		SigningMethod:   DefaultTokenConfig().SigningMethod,
	}
	tokenService := NewTokenService(tokenConfig)
	authService := NewAuthService(mockStorage, tokenService, nil, 24*time.Hour)
	return authService, mockStorage
}

func TestRegister(t *testing.T) {
	authService, _ := setupTestAuthService()
	ctx := context.Background()

	req := &RegisterRequest{
		Email:    "test@example.com",
		Password: "SecurePassword123!",
		Username: "testuser",
	}

	result, err := authService.Register(ctx, req)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	if result.User == nil {
		t.Fatal("Expected user in result")
	}
	if result.User.Email != req.Email {
		t.Errorf("Expected email '%s', got '%s'", req.Email, result.User.Email)
	}
	if result.TokenPair == nil {
		t.Fatal("Expected tokens in result")
	}
	if result.TokenPair.AccessToken == "" {
		t.Error("Expected access token")
	}
	if result.TokenPair.RefreshToken == "" {
		t.Error("Expected refresh token")
	}
}

func TestRegisterDuplicateEmail(t *testing.T) {
	authService, _ := setupTestAuthService()
	ctx := context.Background()

	req := &RegisterRequest{
		Email:    "duplicate@example.com",
		Password: "SecurePassword123!",
	}

	// First registration should succeed
	_, err := authService.Register(ctx, req)
	if err != nil {
		t.Fatalf("First register failed: %v", err)
	}

	// Second registration with same email should fail
	_, err = authService.Register(ctx, req)
	if err != ErrUserExists {
		t.Errorf("Expected ErrUserExists, got: %v", err)
	}
}

func TestLogin(t *testing.T) {
	authService, _ := setupTestAuthService()
	ctx := context.Background()

	// First register
	registerReq := &RegisterRequest{
		Email:    "login@example.com",
		Password: "SecurePassword123!",
	}
	_, err := authService.Register(ctx, registerReq)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Then login
	loginReq := &LoginRequest{
		Email:    "login@example.com",
		Password: "SecurePassword123!",
	}
	result, err := authService.Login(ctx, loginReq)
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if result.User == nil {
		t.Fatal("Expected user in result")
	}
	if result.TokenPair == nil {
		t.Fatal("Expected tokens in result")
	}
}

func TestLoginInvalidPassword(t *testing.T) {
	authService, _ := setupTestAuthService()
	ctx := context.Background()

	// First register
	registerReq := &RegisterRequest{
		Email:    "invalid-pw@example.com",
		Password: "SecurePassword123!",
	}
	_, err := authService.Register(ctx, registerReq)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Then login with wrong password
	loginReq := &LoginRequest{
		Email:    "invalid-pw@example.com",
		Password: "WrongPassword",
	}
	_, err = authService.Login(ctx, loginReq)
	if err != ErrInvalidCredentials {
		t.Errorf("Expected ErrInvalidCredentials, got: %v", err)
	}
}

func TestLoginUserNotFound(t *testing.T) {
	authService, _ := setupTestAuthService()
	ctx := context.Background()

	loginReq := &LoginRequest{
		Email:    "nonexistent@example.com",
		Password: "Password123!",
	}
	_, err := authService.Login(ctx, loginReq)
	if err != ErrInvalidCredentials {
		t.Errorf("Expected ErrInvalidCredentials, got: %v", err)
	}
}

func TestRefresh(t *testing.T) {
	authService, _ := setupTestAuthService()
	ctx := context.Background()

	// Register and get tokens
	registerReq := &RegisterRequest{
		Email:    "refresh@example.com",
		Password: "SecurePassword123!",
	}
	result, err := authService.Register(ctx, registerReq)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Refresh tokens
	refreshReq := &RefreshRequest{
		RefreshToken: result.TokenPair.RefreshToken,
	}
	newTokens, err := authService.Refresh(ctx, refreshReq)
	if err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	if newTokens.AccessToken == "" {
		t.Error("Expected new access token")
	}
	if newTokens.RefreshToken == "" {
		t.Error("Expected new refresh token")
	}
	if newTokens.RefreshToken == result.TokenPair.RefreshToken {
		t.Error("New refresh token should be different from old one")
	}
}

func TestRefreshTokenReuse(t *testing.T) {
	authService, _ := setupTestAuthService()
	ctx := context.Background()

	// Register and get tokens
	registerReq := &RegisterRequest{
		Email:    "reuse@example.com",
		Password: "SecurePassword123!",
	}
	result, err := authService.Register(ctx, registerReq)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	oldRefreshToken := result.TokenPair.RefreshToken

	// First refresh should succeed
	refreshReq := &RefreshRequest{
		RefreshToken: oldRefreshToken,
	}
	_, err = authService.Refresh(ctx, refreshReq)
	if err != nil {
		t.Fatalf("First refresh failed: %v", err)
	}

	// Second refresh with same token should fail (token reuse)
	_, err = authService.Refresh(ctx, refreshReq)
	if err != ErrRefreshTokenReused {
		t.Errorf("Expected ErrRefreshTokenReused, got: %v", err)
	}
}

func TestRefreshInvalidToken(t *testing.T) {
	authService, _ := setupTestAuthService()
	ctx := context.Background()

	refreshReq := &RefreshRequest{
		RefreshToken: "rt_invalid_token_12345",
	}
	_, err := authService.Refresh(ctx, refreshReq)
	if err != ErrRefreshTokenNotFound {
		t.Errorf("Expected ErrRefreshTokenNotFound, got: %v", err)
	}
}

func TestLogout(t *testing.T) {
	authService, mockStorage := setupTestAuthService()
	ctx := context.Background()

	// Register and get tokens
	registerReq := &RegisterRequest{
		Email:    "logout@example.com",
		Password: "SecurePassword123!",
	}
	result, err := authService.Register(ctx, registerReq)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Parse the access token to get session ID
	claims, err := authService.tokenService.ValidateAccessToken(result.TokenPair.AccessToken)
	if err != nil {
		t.Fatalf("Failed to validate access token: %v", err)
	}

	sessionID, _ := uuid.Parse(claims.SessionID)

	// Logout
	logoutReq := &LogoutRequest{
		SessionID: sessionID,
	}
	err = authService.Logout(ctx, logoutReq)
	if err != nil {
		t.Fatalf("Logout failed: %v", err)
	}

	// Verify session is revoked
	session, _ := mockStorage.GetSessionByID(ctx, sessionID)
	if session != nil && !session.Revoked {
		t.Error("Session should be revoked after logout")
	}

	// Verify refresh token no longer works
	refreshReq := &RefreshRequest{
		RefreshToken: result.TokenPair.RefreshToken,
	}
	_, err = authService.Refresh(ctx, refreshReq)
	if err == nil {
		t.Error("Refresh should fail after logout")
	}
}

func TestLogoutNonexistentSession(t *testing.T) {
	authService, _ := setupTestAuthService()
	ctx := context.Background()

	logoutReq := &LogoutRequest{
		SessionID: uuid.New(),
	}
	err := authService.Logout(ctx, logoutReq)
	if err != ErrSessionNotFound {
		t.Errorf("Expected ErrSessionNotFound, got: %v", err)
	}
}
