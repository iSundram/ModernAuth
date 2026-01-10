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

func (m *mockStorage) ListUsers(ctx context.Context) ([]*storage.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	users := make([]*storage.User, 0, len(m.users))
	for _, user := range m.users {
		users = append(users, user)
	}
	return users, nil
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

func (m *mockStorage) GetAuditLogs(ctx context.Context, userID *uuid.UUID, limit, offset int) ([]*storage.AuditLog, error) {
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
	return NewHandler(authService, tokenService, nil, nil, nil)
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
