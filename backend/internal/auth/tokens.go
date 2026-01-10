// Package auth provides authentication services for ModernAuth.
package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	// ErrInvalidToken indicates that the token is invalid.
	ErrInvalidToken = errors.New("invalid token")
	// ErrExpiredToken indicates that the token has expired.
	ErrExpiredToken = errors.New("token has expired")
	// ErrInvalidClaims indicates that the token claims are invalid.
	ErrInvalidClaims = errors.New("invalid token claims")
)

// TokenConfig holds configuration for token generation.
type TokenConfig struct {
	Issuer           string
	AccessTokenTTL   time.Duration
	RefreshTokenTTL  time.Duration
	SigningKey       []byte
	SigningMethod    jwt.SigningMethod
}

// DefaultTokenConfig returns default token configuration.
func DefaultTokenConfig() *TokenConfig {
	return &TokenConfig{
		Issuer:          "modernauth",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		SigningMethod:   jwt.SigningMethodHS256,
	}
}

// TokenService handles token operations.
type TokenService struct {
	config *TokenConfig
}

// NewTokenService creates a new token service.
func NewTokenService(config *TokenConfig) *TokenService {
	if config == nil {
		config = DefaultTokenConfig()
	}
	return &TokenService{config: config}
}

// Claims represents the JWT claims for access tokens.
type Claims struct {
	jwt.RegisteredClaims
	UserID    string   `json:"uid,omitempty"`
	SessionID string   `json:"sid,omitempty"`
	Scopes    []string `json:"scope,omitempty"`
}

// TokenPair represents a pair of access and refresh tokens.
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int64     `json:"expires_in"`
	ExpiresAt    time.Time `json:"-"`
}

// GenerateAccessToken generates a new JWT access token.
func (s *TokenService) GenerateAccessToken(userID, sessionID uuid.UUID, scopes []string) (string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(s.config.AccessTokenTTL)

	jti, err := generateJTI()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to generate JTI: %w", err)
	}

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.config.Issuer,
			Subject:   userID.String(),
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
		},
		UserID:    userID.String(),
		SessionID: sessionID.String(),
		Scopes:    scopes,
	}

	token := jwt.NewWithClaims(s.config.SigningMethod, claims)
	signedToken, err := token.SignedString(s.config.SigningKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign token: %w", err)
	}

	return signedToken, expiresAt, nil
}

// GenerateRefreshToken generates a new opaque refresh token.
func (s *TokenService) GenerateRefreshToken() (string, time.Time, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	token := "rt_" + base64.URLEncoding.EncodeToString(bytes)
	expiresAt := time.Now().Add(s.config.RefreshTokenTTL)

	return token, expiresAt, nil
}

// GenerateTokenPair generates both access and refresh tokens.
func (s *TokenService) GenerateTokenPair(userID, sessionID uuid.UUID, scopes []string) (*TokenPair, error) {
	accessToken, expiresAt, err := s.GenerateAccessToken(userID, sessionID, scopes)
	if err != nil {
		return nil, err
	}

	refreshToken, _, err := s.GenerateRefreshToken()
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.config.AccessTokenTTL.Seconds()),
		ExpiresAt:    expiresAt,
	}, nil
}

// ValidateAccessToken validates a JWT access token and returns its claims.
func (s *TokenService) ValidateAccessToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.config.SigningKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidClaims
	}

	return claims, nil
}

// generateJTI generates a unique token identifier.
func generateJTI() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// GetConfig returns the token configuration (useful for testing).
func (s *TokenService) GetConfig() *TokenConfig {
	return s.config
}
