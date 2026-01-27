package http

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/auth"
	"github.com/iSundram/ModernAuth/internal/email"
	"github.com/iSundram/ModernAuth/internal/storage"
)

// mockStorage implements the storage.Storage interface for testing.
type mockStorage struct {
	mu            sync.RWMutex
	users         map[uuid.UUID]*storage.User
	usersByEmail  map[string]*storage.User
	sessions      map[uuid.UUID]*storage.Session
	refreshTokens map[string]*storage.RefreshToken
	refreshByID   map[uuid.UUID]*storage.RefreshToken
	auditLogs     []*storage.AuditLog
}

func newMockStorage() *mockStorage {
	return &mockStorage{
		users:         make(map[uuid.UUID]*storage.User),
		usersByEmail:  make(map[string]*storage.User),
		sessions:      make(map[uuid.UUID]*storage.Session),
		refreshTokens: make(map[string]*storage.RefreshToken),
		refreshByID:   make(map[uuid.UUID]*storage.RefreshToken),
		auditLogs:     []*storage.AuditLog{},
	}
}

func (m *mockStorage) CreateUser(ctx context.Context, user *storage.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[user.ID] = user
	m.usersByEmail[user.Email] = user
	return nil
}

func (m *mockStorage) GetUserByID(ctx context.Context, id uuid.UUID) (*storage.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.users[id], nil
}

func (m *mockStorage) GetUserByEmail(ctx context.Context, email string) (*storage.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.usersByEmail[email], nil
}

func (m *mockStorage) UpdateUser(ctx context.Context, user *storage.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[user.ID] = user
	m.usersByEmail[user.Email] = user
	return nil
}

func (m *mockStorage) DeleteUser(ctx context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if user, ok := m.users[id]; ok {
		delete(m.usersByEmail, user.Email)
		delete(m.users, id)
	}
	return nil
}

func (m *mockStorage) ListUsers(ctx context.Context, limit, offset int) ([]*storage.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	users := make([]*storage.User, 0, len(m.users))
	for _, user := range m.users {
		users = append(users, user)
	}
	if offset > len(users) {
		return []*storage.User{}, nil
	}
	end := offset + limit
	if end > len(users) {
		end = len(users)
	}
	return users[offset:end], nil
}

func (m *mockStorage) CountUsers(ctx context.Context) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.users), nil
}

func (m *mockStorage) CreateSession(ctx context.Context, session *storage.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[session.ID] = session
	return nil
}

func (m *mockStorage) GetSessionByID(ctx context.Context, id uuid.UUID) (*storage.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[id], nil
}

func (m *mockStorage) RevokeSession(ctx context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if session, ok := m.sessions[id]; ok {
		session.Revoked = true
	}
	return nil
}

func (m *mockStorage) RevokeUserSessions(ctx context.Context, userID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, session := range m.sessions {
		if session.UserID == userID {
			session.Revoked = true
		}
	}
	return nil
}

func (m *mockStorage) CreateRefreshToken(ctx context.Context, token *storage.RefreshToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshTokens[token.TokenHash] = token
	m.refreshByID[token.ID] = token
	return nil
}

func (m *mockStorage) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*storage.RefreshToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.refreshTokens[tokenHash], nil
}

func (m *mockStorage) RevokeRefreshToken(ctx context.Context, id uuid.UUID, replacedBy *uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if token, ok := m.refreshByID[id]; ok {
		token.Revoked = true
		token.ReplacedBy = replacedBy
	}
	return nil
}

func (m *mockStorage) RevokeSessionRefreshTokens(ctx context.Context, sessionID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, token := range m.refreshByID {
		if token.SessionID == sessionID {
			token.Revoked = true
		}
	}
	return nil
}

func (m *mockStorage) CreateAuditLog(ctx context.Context, log *storage.AuditLog) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.auditLogs = append(m.auditLogs, log)
	return nil
}

func (m *mockStorage) GetAuditLogs(ctx context.Context, userID *uuid.UUID, eventType *string, limit, offset int) ([]*storage.AuditLog, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*storage.AuditLog
	for _, log := range m.auditLogs {
		if userID == nil || (log.UserID != nil && *log.UserID == *userID) {
			result = append(result, log)
		}
	}
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

func (m *mockStorage) DeleteOldAuditLogs(ctx context.Context, olderThan time.Time) (int64, error) {
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

func (m *mockStorage) GetMFASettings(ctx context.Context, userID uuid.UUID) (*storage.MFASettings, error) {
	return nil, nil
}

func (m *mockStorage) UpdateMFASettings(ctx context.Context, settings *storage.MFASettings) error {
	return nil
}

func (m *mockStorage) CreateVerificationToken(ctx context.Context, token *storage.VerificationToken) error {
	return nil
}

func (m *mockStorage) GetVerificationTokenByHash(ctx context.Context, tokenHash string, tokenType string) (*storage.VerificationToken, error) {
	return nil, nil
}

func (m *mockStorage) MarkVerificationTokenUsed(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockStorage) DeleteExpiredVerificationTokens(ctx context.Context) error {
	return nil
}

// RBAC mock implementations
func (m *mockStorage) GetRoleByID(ctx context.Context, id uuid.UUID) (*storage.Role, error) {
	return nil, nil
}

func (m *mockStorage) GetRoleByName(ctx context.Context, name string) (*storage.Role, error) {
	return nil, nil
}

func (m *mockStorage) ListRoles(ctx context.Context) ([]*storage.Role, error) {
	return []*storage.Role{}, nil
}

func (m *mockStorage) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*storage.Role, error) {
	return []*storage.Role{}, nil
}

func (m *mockStorage) AssignRoleToUser(ctx context.Context, userID, roleID uuid.UUID, assignedBy *uuid.UUID) error {
	return nil
}

func (m *mockStorage) RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error {
	return nil
}

func (m *mockStorage) UserHasRole(ctx context.Context, userID uuid.UUID, roleName string) (bool, error) {
	return false, nil
}

func (m *mockStorage) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*storage.Permission, error) {
	return []*storage.Permission{}, nil
}

func (m *mockStorage) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]*storage.Permission, error) {
	return []*storage.Permission{}, nil
}

func (m *mockStorage) UserHasPermission(ctx context.Context, userID uuid.UUID, permissionName string) (bool, error) {
	return false, nil
}

func (m *mockStorage) CreateRole(ctx context.Context, role *storage.Role) error {
	return nil
}

func (m *mockStorage) UpdateRole(ctx context.Context, role *storage.Role) error {
	return nil
}

func (m *mockStorage) DeleteRole(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockStorage) AssignPermissionToRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	return nil
}

func (m *mockStorage) RemovePermissionFromRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	return nil
}

func (m *mockStorage) GetPermissionByID(ctx context.Context, id uuid.UUID) (*storage.Permission, error) {
	return nil, nil
}

func (m *mockStorage) GetPermissionByName(ctx context.Context, name string) (*storage.Permission, error) {
	return nil, nil
}

func (m *mockStorage) ListPermissions(ctx context.Context) ([]*storage.Permission, error) {
	return []*storage.Permission{}, nil
}

// SystemSettingsStorage mock implementations
func (m *mockStorage) GetSetting(ctx context.Context, key string) (*storage.SystemSetting, error) {
	return nil, nil
}

func (m *mockStorage) ListSettings(ctx context.Context, category string) ([]*storage.SystemSetting, error) {
	return []*storage.SystemSetting{}, nil
}

func (m *mockStorage) UpdateSetting(ctx context.Context, key string, value interface{}) error {
	return nil
}

func (m *mockStorage) GetUserSessions(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*storage.Session, error) {
	return []*storage.Session{}, nil
}

// TenantStorage mock implementations
func (m *mockStorage) CreateTenant(ctx context.Context, tenant *storage.Tenant) error {
	return nil
}
func (m *mockStorage) GetTenantByID(ctx context.Context, id uuid.UUID) (*storage.Tenant, error) {
	return nil, nil
}
func (m *mockStorage) GetTenantBySlug(ctx context.Context, slug string) (*storage.Tenant, error) {
	return nil, nil
}
func (m *mockStorage) GetTenantByDomain(ctx context.Context, domain string) (*storage.Tenant, error) {
	return nil, nil
}
func (m *mockStorage) ListTenants(ctx context.Context, limit, offset int) ([]*storage.Tenant, error) {
	return []*storage.Tenant{}, nil
}
func (m *mockStorage) UpdateTenant(ctx context.Context, tenant *storage.Tenant) error {
	return nil
}
func (m *mockStorage) DeleteTenant(ctx context.Context, id uuid.UUID) error {
	return nil
}
func (m *mockStorage) ListTenantUsers(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*storage.User, error) {
	return []*storage.User{}, nil
}
func (m *mockStorage) CountTenantUsers(ctx context.Context, tenantID uuid.UUID) (int, error) {
	return 0, nil
}

// DeviceStorage mock implementations
func (m *mockStorage) CreateDevice(ctx context.Context, device *storage.UserDevice) error {
	return nil
}
func (m *mockStorage) GetDeviceByID(ctx context.Context, id uuid.UUID) (*storage.UserDevice, error) {
	return nil, nil
}
func (m *mockStorage) GetDeviceByFingerprint(ctx context.Context, userID uuid.UUID, fingerprint string) (*storage.UserDevice, error) {
	return nil, nil
}
func (m *mockStorage) ListUserDevices(ctx context.Context, userID uuid.UUID) ([]*storage.UserDevice, error) {
	return []*storage.UserDevice{}, nil
}
func (m *mockStorage) UpdateDevice(ctx context.Context, device *storage.UserDevice) error {
	return nil
}
func (m *mockStorage) DeleteDevice(ctx context.Context, id uuid.UUID) error {
	return nil
}
func (m *mockStorage) TrustDevice(ctx context.Context, id uuid.UUID, trusted bool) error {
	return nil
}
func (m *mockStorage) CreateLoginHistory(ctx context.Context, history *storage.LoginHistory) error {
	return nil
}
func (m *mockStorage) GetLoginHistory(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*storage.LoginHistory, error) {
	return []*storage.LoginHistory{}, nil
}

// APIKeyStorage mock implementations
func (m *mockStorage) CreateAPIKey(ctx context.Context, key *storage.APIKey) error {
	return nil
}
func (m *mockStorage) GetAPIKeyByID(ctx context.Context, id uuid.UUID) (*storage.APIKey, error) {
	return nil, nil
}
func (m *mockStorage) GetAPIKeyByHash(ctx context.Context, keyHash string) (*storage.APIKey, error) {
	return nil, nil
}
func (m *mockStorage) ListAPIKeys(ctx context.Context, userID *uuid.UUID, tenantID *uuid.UUID, limit, offset int) ([]*storage.APIKey, error) {
	return []*storage.APIKey{}, nil
}
func (m *mockStorage) UpdateAPIKey(ctx context.Context, key *storage.APIKey) error {
	return nil
}
func (m *mockStorage) RevokeAPIKey(ctx context.Context, id uuid.UUID, revokedBy *uuid.UUID) error {
	return nil
}
func (m *mockStorage) UpdateAPIKeyLastUsed(ctx context.Context, id uuid.UUID, ip string) error {
	return nil
}

// WebhookStorage mock implementations
func (m *mockStorage) CreateWebhook(ctx context.Context, webhook *storage.Webhook) error {
	return nil
}
func (m *mockStorage) GetWebhookByID(ctx context.Context, id uuid.UUID) (*storage.Webhook, error) {
	return nil, nil
}
func (m *mockStorage) ListWebhooks(ctx context.Context, tenantID *uuid.UUID, limit, offset int) ([]*storage.Webhook, error) {
	return []*storage.Webhook{}, nil
}
func (m *mockStorage) ListWebhooksByEvent(ctx context.Context, tenantID *uuid.UUID, eventType string) ([]*storage.Webhook, error) {
	return []*storage.Webhook{}, nil
}
func (m *mockStorage) UpdateWebhook(ctx context.Context, webhook *storage.Webhook) error {
	return nil
}
func (m *mockStorage) DeleteWebhook(ctx context.Context, id uuid.UUID) error {
	return nil
}
func (m *mockStorage) CreateWebhookDelivery(ctx context.Context, delivery *storage.WebhookDelivery) error {
	return nil
}
func (m *mockStorage) UpdateWebhookDelivery(ctx context.Context, delivery *storage.WebhookDelivery) error {
	return nil
}
func (m *mockStorage) GetPendingDeliveries(ctx context.Context, limit int) ([]*storage.WebhookDelivery, error) {
	return []*storage.WebhookDelivery{}, nil
}
func (m *mockStorage) GetWebhookDeliveries(ctx context.Context, webhookID uuid.UUID, limit, offset int) ([]*storage.WebhookDelivery, error) {
	return []*storage.WebhookDelivery{}, nil
}

// InvitationStorage mock implementations
func (m *mockStorage) CreateInvitation(ctx context.Context, invitation *storage.UserInvitation) error {
	return nil
}
func (m *mockStorage) GetInvitationByID(ctx context.Context, id uuid.UUID) (*storage.UserInvitation, error) {
	return nil, nil
}
func (m *mockStorage) GetInvitationByToken(ctx context.Context, tokenHash string) (*storage.UserInvitation, error) {
	return nil, nil
}
func (m *mockStorage) GetInvitationByEmail(ctx context.Context, tenantID *uuid.UUID, email string) (*storage.UserInvitation, error) {
	return nil, nil
}
func (m *mockStorage) ListInvitations(ctx context.Context, tenantID *uuid.UUID, limit, offset int) ([]*storage.UserInvitation, error) {
	return []*storage.UserInvitation{}, nil
}
func (m *mockStorage) AcceptInvitation(ctx context.Context, id uuid.UUID) error {
	return nil
}
func (m *mockStorage) UpdateInvitation(ctx context.Context, invitation *storage.UserInvitation) error {
	return nil
}
func (m *mockStorage) DeleteInvitation(ctx context.Context, id uuid.UUID) error {
	return nil
}
func (m *mockStorage) DeleteExpiredInvitations(ctx context.Context) error {
	return nil
}

// MFA Enhancement mock methods
func (m *mockStorage) CreateMFAChallenge(ctx context.Context, challenge *storage.MFAChallenge) error {
	return nil
}
func (m *mockStorage) GetMFAChallenge(ctx context.Context, id uuid.UUID) (*storage.MFAChallenge, error) {
	return nil, nil
}
func (m *mockStorage) GetPendingMFAChallenge(ctx context.Context, userID uuid.UUID, challengeType string) (*storage.MFAChallenge, error) {
	return nil, nil
}
func (m *mockStorage) MarkMFAChallengeVerified(ctx context.Context, id uuid.UUID) error {
	return nil
}
func (m *mockStorage) DeleteExpiredMFAChallenges(ctx context.Context) error {
	return nil
}
func (m *mockStorage) CreateWebAuthnCredential(ctx context.Context, cred *storage.WebAuthnCredential) error {
	return nil
}
func (m *mockStorage) GetWebAuthnCredentials(ctx context.Context, userID uuid.UUID) ([]*storage.WebAuthnCredential, error) {
	return nil, nil
}
func (m *mockStorage) GetWebAuthnCredentialByID(ctx context.Context, credentialID []byte) (*storage.WebAuthnCredential, error) {
	return nil, nil
}
func (m *mockStorage) UpdateWebAuthnCredentialSignCount(ctx context.Context, credentialID []byte, signCount uint32) error {
	return nil
}
func (m *mockStorage) DeleteWebAuthnCredential(ctx context.Context, id uuid.UUID) error {
	return nil
}
func (m *mockStorage) SetDeviceMFATrust(ctx context.Context, deviceID uuid.UUID, trustedUntil time.Time, trustToken string) error {
	return nil
}
func (m *mockStorage) ClearDeviceMFATrust(ctx context.Context, deviceID uuid.UUID) error {
	return nil
}
func (m *mockStorage) GetDeviceMFATrust(ctx context.Context, userID uuid.UUID, deviceFingerprint string) (*time.Time, error) {
	return nil, nil
}

func setupTestHandler() *Handler {
	ms := newMockStorage()
	tokenConfig := &auth.TokenConfig{
		Issuer:          "test",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		SigningKey:      []byte("test-secret-key-at-least-32-chars"),
		SigningMethod:   auth.DefaultTokenConfig().SigningMethod,
	}
	tokenService := auth.NewTokenService(tokenConfig)
	authService := auth.NewAuthService(ms, tokenService, 24*time.Hour)
	emailService := email.NewConsoleService()
	return NewHandler(authService, tokenService, ms, nil, nil, nil, emailService)
}

func TestHealthCheck(t *testing.T) {
	handler := setupTestHandler()
	router := handler.Router()

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if response["status"] != "healthy" {
		t.Errorf("Expected status 'healthy', got '%s'", response["status"])
	}
}

func TestRegisterHandler(t *testing.T) {
	handler := setupTestHandler()
	router := handler.Router()

	body := RegisterRequest{
		Email:    "test@example.com",
		Password: "SecurePassword123!",
		Username: "testuser",
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/v1/auth/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusCreated, w.Code, w.Body.String())
	}

	var response RegisterResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if response.User.Email != body.Email {
		t.Errorf("Expected email '%s', got '%s'", body.Email, response.User.Email)
	}
	if response.Tokens.AccessToken == "" {
		t.Error("Expected access token")
	}
	if response.Tokens.RefreshToken == "" {
		t.Error("Expected refresh token")
	}
}

func TestRegisterHandlerValidation(t *testing.T) {
	handler := setupTestHandler()
	router := handler.Router()

	testCases := []struct {
		name           string
		body           RegisterRequest
		expectedStatus int
	}{
		{
			name:           "missing email",
			body:           RegisterRequest{Password: "SecurePassword123!"},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "missing password",
			body:           RegisterRequest{Email: "test@example.com"},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "password too short",
			body:           RegisterRequest{Email: "test@example.com", Password: "short"},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jsonBody, _ := json.Marshal(tc.body)
			req := httptest.NewRequest("POST", "/v1/auth/register", bytes.NewBuffer(jsonBody))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d", tc.expectedStatus, w.Code)
			}
		})
	}
}

func TestRegisterDuplicateEmail(t *testing.T) {
	handler := setupTestHandler()
	router := handler.Router()

	body := RegisterRequest{
		Email:    "duplicate@example.com",
		Password: "SecurePassword123!",
	}
	jsonBody, _ := json.Marshal(body)

	// First registration
	req := httptest.NewRequest("POST", "/v1/auth/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("First registration failed: %s", w.Body.String())
	}

	// Second registration with same email
	req = httptest.NewRequest("POST", "/v1/auth/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("Expected status %d, got %d", http.StatusConflict, w.Code)
	}
}

func TestLoginHandler(t *testing.T) {
	handler := setupTestHandler()
	router := handler.Router()

	// First register
	registerBody := RegisterRequest{
		Email:    "login@example.com",
		Password: "SecurePassword123!",
	}
	jsonBody, _ := json.Marshal(registerBody)
	req := httptest.NewRequest("POST", "/v1/auth/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Then login
	loginBody := LoginRequest{
		Email:    "login@example.com",
		Password: "SecurePassword123!",
	}
	jsonBody, _ = json.Marshal(loginBody)
	req = httptest.NewRequest("POST", "/v1/auth/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var response LoginResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if response.User.Email != loginBody.Email {
		t.Errorf("Expected email '%s', got '%s'", loginBody.Email, response.User.Email)
	}
	if response.Tokens.AccessToken == "" {
		t.Error("Expected access token")
	}
}

func TestLoginInvalidCredentials(t *testing.T) {
	handler := setupTestHandler()
	router := handler.Router()

	// First register
	registerBody := RegisterRequest{
		Email:    "invalid@example.com",
		Password: "SecurePassword123!",
	}
	jsonBody, _ := json.Marshal(registerBody)
	req := httptest.NewRequest("POST", "/v1/auth/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Login with wrong password
	loginBody := LoginRequest{
		Email:    "invalid@example.com",
		Password: "WrongPassword",
	}
	jsonBody, _ = json.Marshal(loginBody)
	req = httptest.NewRequest("POST", "/v1/auth/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestRefreshHandler(t *testing.T) {
	handler := setupTestHandler()
	router := handler.Router()

	// First register
	registerBody := RegisterRequest{
		Email:    "refresh@example.com",
		Password: "SecurePassword123!",
	}
	jsonBody, _ := json.Marshal(registerBody)
	req := httptest.NewRequest("POST", "/v1/auth/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var registerResponse RegisterResponse
	json.Unmarshal(w.Body.Bytes(), &registerResponse)

	// Then refresh
	refreshBody := RefreshRequest{
		RefreshToken: registerResponse.Tokens.RefreshToken,
	}
	jsonBody, _ = json.Marshal(refreshBody)
	req = httptest.NewRequest("POST", "/v1/auth/refresh", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var response RefreshResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if response.AccessToken == "" {
		t.Error("Expected access token")
	}
	if response.RefreshToken == "" {
		t.Error("Expected refresh token")
	}
	if response.RefreshToken == registerResponse.Tokens.RefreshToken {
		t.Error("New refresh token should be different")
	}
}

func TestRefreshInvalidToken(t *testing.T) {
	handler := setupTestHandler()
	router := handler.Router()

	refreshBody := RefreshRequest{
		RefreshToken: "rt_invalid_token",
	}
	jsonBody, _ := json.Marshal(refreshBody)
	req := httptest.NewRequest("POST", "/v1/auth/refresh", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestLogoutHandler(t *testing.T) {
	handler := setupTestHandler()
	router := handler.Router()

	// First register
	registerBody := RegisterRequest{
		Email:    "logout@example.com",
		Password: "SecurePassword123!",
	}
	jsonBody, _ := json.Marshal(registerBody)
	req := httptest.NewRequest("POST", "/v1/auth/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var registerResponse RegisterResponse
	json.Unmarshal(w.Body.Bytes(), &registerResponse)

	// Logout with Authorization header
	req = httptest.NewRequest("POST", "/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+registerResponse.Tokens.AccessToken)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, w.Code, w.Body.String())
	}
}

func TestLogoutNoAuth(t *testing.T) {
	handler := setupTestHandler()
	router := handler.Router()

	req := httptest.NewRequest("POST", "/v1/auth/logout", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}
