package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNewTokenService(t *testing.T) {
	// Test with nil config (should use defaults)
	ts := NewTokenService(nil)
	if ts == nil {
		t.Fatal("NewTokenService should not return nil")
	}
	if ts.config.Issuer != "modernauth" {
		t.Errorf("Expected issuer 'modernauth', got '%s'", ts.config.Issuer)
	}

	// Test with custom config
	customConfig := &TokenConfig{
		Issuer:          "custom-issuer",
		AccessTokenTTL:  30 * time.Minute,
		RefreshTokenTTL: 24 * time.Hour,
		SigningKey:      []byte("test-secret-key-at-least-32-chars"),
	}
	ts = NewTokenService(customConfig)
	if ts.config.Issuer != "custom-issuer" {
		t.Errorf("Expected issuer 'custom-issuer', got '%s'", ts.config.Issuer)
	}
}

func TestGenerateAccessToken(t *testing.T) {
	config := &TokenConfig{
		Issuer:         "test-issuer",
		AccessTokenTTL: 15 * time.Minute,
		SigningKey:     []byte("test-secret-key-at-least-32-chars"),
		SigningMethod:  DefaultTokenConfig().SigningMethod,
	}
	ts := NewTokenService(config)

	userID := uuid.New()
	sessionID := uuid.New()
	scopes := []string{"read", "write"}

	token, expiresAt, err := ts.GenerateAccessToken(userID, sessionID, scopes)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	if token == "" {
		t.Error("Generated token should not be empty")
	}

	// Verify expiration time is in the future
	if expiresAt.Before(time.Now()) {
		t.Error("Token expiration should be in the future")
	}

	// Verify expiration is approximately correct
	expectedExpiry := time.Now().Add(15 * time.Minute)
	if expiresAt.Sub(expectedExpiry) > time.Second {
		t.Error("Token expiration time is not as expected")
	}
}

func TestGenerateRefreshToken(t *testing.T) {
	config := &TokenConfig{
		RefreshTokenTTL: 7 * 24 * time.Hour,
		SigningKey:      []byte("test-secret-key-at-least-32-chars"),
	}
	ts := NewTokenService(config)

	token, expiresAt, err := ts.GenerateRefreshToken()
	if err != nil {
		t.Fatalf("GenerateRefreshToken failed: %v", err)
	}

	// Verify token format
	if len(token) < 10 {
		t.Error("Refresh token should be longer")
	}
	if token[:3] != "rt_" {
		t.Error("Refresh token should start with 'rt_'")
	}

	// Verify expiration
	if expiresAt.Before(time.Now()) {
		t.Error("Refresh token expiration should be in the future")
	}

	// Test uniqueness
	token2, _, _ := ts.GenerateRefreshToken()
	if token == token2 {
		t.Error("Each refresh token should be unique")
	}
}

func TestGenerateTokenPair(t *testing.T) {
	config := &TokenConfig{
		Issuer:          "test-issuer",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		SigningKey:      []byte("test-secret-key-at-least-32-chars"),
		SigningMethod:   DefaultTokenConfig().SigningMethod,
	}
	ts := NewTokenService(config)

	userID := uuid.New()
	sessionID := uuid.New()
	scopes := []string{"read"}

	pair, err := ts.GenerateTokenPair(userID, sessionID, scopes)
	if err != nil {
		t.Fatalf("GenerateTokenPair failed: %v", err)
	}

	if pair.AccessToken == "" {
		t.Error("Access token should not be empty")
	}
	if pair.RefreshToken == "" {
		t.Error("Refresh token should not be empty")
	}
	if pair.TokenType != "Bearer" {
		t.Errorf("Expected token type 'Bearer', got '%s'", pair.TokenType)
	}
	if pair.ExpiresIn != int64((15 * time.Minute).Seconds()) {
		t.Errorf("Unexpected ExpiresIn value: %d", pair.ExpiresIn)
	}
}

func TestValidateAccessToken(t *testing.T) {
	config := &TokenConfig{
		Issuer:         "test-issuer",
		AccessTokenTTL: 15 * time.Minute,
		SigningKey:     []byte("test-secret-key-at-least-32-chars"),
		SigningMethod:  DefaultTokenConfig().SigningMethod,
	}
	ts := NewTokenService(config)

	userID := uuid.New()
	sessionID := uuid.New()
	scopes := []string{"read", "write"}

	token, _, err := ts.GenerateAccessToken(userID, sessionID, scopes)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	// Validate the token
	claims, err := ts.ValidateAccessToken(token)
	if err != nil {
		t.Fatalf("ValidateAccessToken failed: %v", err)
	}

	// Verify claims
	if claims.UserID != userID.String() {
		t.Errorf("Expected UserID '%s', got '%s'", userID.String(), claims.UserID)
	}
	if claims.SessionID != sessionID.String() {
		t.Errorf("Expected SessionID '%s', got '%s'", sessionID.String(), claims.SessionID)
	}
	if len(claims.Scopes) != 2 {
		t.Errorf("Expected 2 scopes, got %d", len(claims.Scopes))
	}
}

func TestValidateAccessTokenExpired(t *testing.T) {
	config := &TokenConfig{
		Issuer:         "test-issuer",
		AccessTokenTTL: -1 * time.Hour, // Already expired
		SigningKey:     []byte("test-secret-key-at-least-32-chars"),
		SigningMethod:  DefaultTokenConfig().SigningMethod,
	}
	ts := NewTokenService(config)

	userID := uuid.New()
	sessionID := uuid.New()

	token, _, _ := ts.GenerateAccessToken(userID, sessionID, nil)

	_, err := ts.ValidateAccessToken(token)
	if err != ErrExpiredToken {
		t.Errorf("Expected ErrExpiredToken, got: %v", err)
	}
}

func TestValidateAccessTokenInvalid(t *testing.T) {
	config := &TokenConfig{
		Issuer:         "test-issuer",
		AccessTokenTTL: 15 * time.Minute,
		SigningKey:     []byte("test-secret-key-at-least-32-chars"),
		SigningMethod:  DefaultTokenConfig().SigningMethod,
	}
	ts := NewTokenService(config)

	testCases := []struct {
		name  string
		token string
	}{
		{"empty token", ""},
		{"garbage token", "not.a.valid.token"},
		{"malformed JWT", "eyJhbGciOiJIUzI1NiJ9.invalid.signature"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ts.ValidateAccessToken(tc.token)
			if err == nil {
				t.Errorf("Expected error for %s", tc.name)
			}
		})
	}
}

func TestValidateAccessTokenWrongKey(t *testing.T) {
	config1 := &TokenConfig{
		Issuer:         "test-issuer",
		AccessTokenTTL: 15 * time.Minute,
		SigningKey:     []byte("test-secret-key-at-least-32-chars"),
		SigningMethod:  DefaultTokenConfig().SigningMethod,
	}
	ts1 := NewTokenService(config1)

	config2 := &TokenConfig{
		Issuer:         "test-issuer",
		AccessTokenTTL: 15 * time.Minute,
		SigningKey:     []byte("different-secret-key-32-chars---"),
		SigningMethod:  DefaultTokenConfig().SigningMethod,
	}
	ts2 := NewTokenService(config2)

	userID := uuid.New()
	sessionID := uuid.New()

	token, _, _ := ts1.GenerateAccessToken(userID, sessionID, nil)

	_, err := ts2.ValidateAccessToken(token)
	if err == nil {
		t.Error("Expected error when validating with wrong key")
	}
}

func BenchmarkGenerateAccessToken(b *testing.B) {
	config := &TokenConfig{
		Issuer:         "bench-issuer",
		AccessTokenTTL: 15 * time.Minute,
		SigningKey:     []byte("benchmark-secret-key-32-chars---"),
		SigningMethod:  DefaultTokenConfig().SigningMethod,
	}
	ts := NewTokenService(config)
	userID := uuid.New()
	sessionID := uuid.New()
	scopes := []string{"read", "write"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := ts.GenerateAccessToken(userID, sessionID, scopes)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkValidateAccessToken(b *testing.B) {
	config := &TokenConfig{
		Issuer:         "bench-issuer",
		AccessTokenTTL: 15 * time.Minute,
		SigningKey:     []byte("benchmark-secret-key-32-chars---"),
		SigningMethod:  DefaultTokenConfig().SigningMethod,
	}
	ts := NewTokenService(config)
	userID := uuid.New()
	sessionID := uuid.New()
	token, _, _ := ts.GenerateAccessToken(userID, sessionID, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ts.ValidateAccessToken(token)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerateRefreshToken(b *testing.B) {
	config := &TokenConfig{
		RefreshTokenTTL: 7 * 24 * time.Hour,
	}
	ts := NewTokenService(config)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := ts.GenerateRefreshToken()
		if err != nil {
			b.Fatal(err)
		}
	}
}
