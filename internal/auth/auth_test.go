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

func (m *MockStorage) GetAuditLogs(ctx context.Context, userID *uuid.UUID, limit, offset int) ([]*storage.AuditLog, error) {
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
	authService := NewAuthService(mockStorage, tokenService, 24*time.Hour)
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
