// Package apikey provides API key management for ModernAuth.
package apikey

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
	"github.com/iSundram/ModernAuth/internal/utils"
)

var (
	// ErrAPIKeyNotFound indicates the API key was not found.
	ErrAPIKeyNotFound = errors.New("api key not found")
	// ErrAPIKeyRevoked indicates the API key has been revoked.
	ErrAPIKeyRevoked = errors.New("api key has been revoked")
	// ErrAPIKeyExpired indicates the API key has expired.
	ErrAPIKeyExpired = errors.New("api key has expired")
	// ErrAPIKeyInactive indicates the API key is inactive.
	ErrAPIKeyInactive = errors.New("api key is inactive")
	// ErrIPNotAllowed indicates the IP is not in the allowlist.
	ErrIPNotAllowed = errors.New("ip address not allowed")
	// ErrInsufficientScope indicates the API key lacks required scope.
	ErrInsufficientScope = errors.New("insufficient scope")
)

// Service provides API key management operations.
type Service struct {
	storage storage.APIKeyStorage
	logger  *slog.Logger
}

// NewService creates a new API key service.
func NewService(store storage.APIKeyStorage) *Service {
	return &Service{
		storage: store,
		logger:  slog.Default().With("component", "apikey_service"),
	}
}

// CreateAPIKeyRequest represents a request to create an API key.
type CreateAPIKeyRequest struct {
	TenantID    *uuid.UUID `json:"tenant_id,omitempty"`
	UserID      *uuid.UUID `json:"user_id,omitempty"`
	Name        string     `json:"name"`
	Description *string    `json:"description,omitempty"`
	Scopes      []string   `json:"scopes,omitempty"`
	RateLimit   *int       `json:"rate_limit,omitempty"`
	AllowedIPs  []string   `json:"allowed_ips,omitempty"`
	ExpiresIn   *int       `json:"expires_in,omitempty"` // seconds
}

// CreateAPIKeyResult contains the created API key and the raw key (only returned once).
type CreateAPIKeyResult struct {
	APIKey *storage.APIKey `json:"api_key"`
	Key    string          `json:"key"` // Raw key, only shown once
}

// CreateAPIKey creates a new API key.
func (s *Service) CreateAPIKey(ctx context.Context, req *CreateAPIKeyRequest) (*CreateAPIKeyResult, error) {
	// Generate the raw key
	rawKey, err := generateAPIKey()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	var expiresAt *time.Time
	if req.ExpiresIn != nil && *req.ExpiresIn > 0 {
		exp := now.Add(time.Duration(*req.ExpiresIn) * time.Second)
		expiresAt = &exp
	}

	apiKey := &storage.APIKey{
		ID:          uuid.New(),
		TenantID:    req.TenantID,
		UserID:      req.UserID,
		Name:        req.Name,
		Description: req.Description,
		KeyPrefix:   rawKey[:12], // First 12 chars as prefix for identification
		KeyHash:     utils.HashToken(rawKey),
		Scopes:      req.Scopes,
		RateLimit:   req.RateLimit,
		AllowedIPs:  req.AllowedIPs,
		ExpiresAt:   expiresAt,
		IsActive:    true,
		CreatedAt:   now,
	}

	if err := s.storage.CreateAPIKey(ctx, apiKey); err != nil {
		return nil, err
	}

	s.logger.Info("API key created", "key_id", apiKey.ID, "name", apiKey.Name)

	return &CreateAPIKeyResult{
		APIKey: apiKey,
		Key:    rawKey,
	}, nil
}

// ValidateAPIKey validates an API key and returns the associated key info.
func (s *Service) ValidateAPIKey(ctx context.Context, rawKey string, requiredScopes []string, clientIP string) (*storage.APIKey, error) {
	keyHash := utils.HashToken(rawKey)

	apiKey, err := s.storage.GetAPIKeyByHash(ctx, keyHash)
	if err != nil {
		return nil, err
	}
	if apiKey == nil {
		return nil, ErrAPIKeyNotFound
	}

	// Check if revoked
	if apiKey.RevokedAt != nil {
		return nil, ErrAPIKeyRevoked
	}

	// Check if active
	if !apiKey.IsActive {
		return nil, ErrAPIKeyInactive
	}

	// Check expiration
	if apiKey.ExpiresAt != nil && time.Now().After(*apiKey.ExpiresAt) {
		return nil, ErrAPIKeyExpired
	}

	// Check IP allowlist
	if len(apiKey.AllowedIPs) > 0 && clientIP != "" {
		if !isIPAllowed(clientIP, apiKey.AllowedIPs) {
			s.logger.Warn("API key used from unauthorized IP", "key_id", apiKey.ID, "ip", clientIP)
			return nil, ErrIPNotAllowed
		}
	}

	// Check scopes
	if len(requiredScopes) > 0 {
		if !hasRequiredScopes(apiKey.Scopes, requiredScopes) {
			return nil, ErrInsufficientScope
		}
	}

	// Update last used (async, don't block the request)
	go func() {
		if err := s.storage.UpdateAPIKeyLastUsed(context.Background(), apiKey.ID, clientIP); err != nil {
			s.logger.Error("Failed to update API key last used", "error", err, "key_id", apiKey.ID)
		}
	}()

	return apiKey, nil
}

// GetAPIKey retrieves an API key by ID.
func (s *Service) GetAPIKey(ctx context.Context, id uuid.UUID) (*storage.APIKey, error) {
	apiKey, err := s.storage.GetAPIKeyByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if apiKey == nil {
		return nil, ErrAPIKeyNotFound
	}
	return apiKey, nil
}

// ListAPIKeys lists API keys for a user or tenant.
func (s *Service) ListAPIKeys(ctx context.Context, userID *uuid.UUID, tenantID *uuid.UUID, limit, offset int) ([]*storage.APIKey, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	return s.storage.ListAPIKeys(ctx, userID, tenantID, limit, offset)
}

// RevokeAPIKey revokes an API key.
func (s *Service) RevokeAPIKey(ctx context.Context, id uuid.UUID, revokedBy *uuid.UUID) error {
	apiKey, err := s.storage.GetAPIKeyByID(ctx, id)
	if err != nil {
		return err
	}
	if apiKey == nil {
		return ErrAPIKeyNotFound
	}

	if err := s.storage.RevokeAPIKey(ctx, id, revokedBy); err != nil {
		return err
	}

	s.logger.Info("API key revoked", "key_id", id)
	return nil
}

// RotateAPIKey revokes an existing key and creates a new one with the same settings.
func (s *Service) RotateAPIKey(ctx context.Context, id uuid.UUID, rotatedBy *uuid.UUID) (*CreateAPIKeyResult, error) {
	oldKey, err := s.storage.GetAPIKeyByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if oldKey == nil {
		return nil, ErrAPIKeyNotFound
	}

	// Create new key with same settings
	result, err := s.CreateAPIKey(ctx, &CreateAPIKeyRequest{
		TenantID:    oldKey.TenantID,
		UserID:      oldKey.UserID,
		Name:        oldKey.Name + " (rotated)",
		Description: oldKey.Description,
		Scopes:      oldKey.Scopes,
		RateLimit:   oldKey.RateLimit,
		AllowedIPs:  oldKey.AllowedIPs,
	})
	if err != nil {
		return nil, err
	}

	// Revoke old key
	if err := s.storage.RevokeAPIKey(ctx, id, rotatedBy); err != nil {
		s.logger.Error("Failed to revoke old key during rotation", "error", err, "old_key_id", id)
	}

	s.logger.Info("API key rotated", "old_key_id", id, "new_key_id", result.APIKey.ID)
	return result, nil
}

// generateAPIKey generates a new random API key.
func generateAPIKey() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	// Format: mk_live_<base64-encoded-random-bytes>
	return "mk_live_" + base64.URLEncoding.EncodeToString(bytes), nil
}

// isIPAllowed checks if the client IP is in the allowed list.
func isIPAllowed(clientIP string, allowedIPs []string) bool {
	clientIPParsed := net.ParseIP(clientIP)
	if clientIPParsed == nil {
		return false
	}

	for _, allowed := range allowedIPs {
		// Check if it's a CIDR range
		if _, ipNet, err := net.ParseCIDR(allowed); err == nil {
			if ipNet.Contains(clientIPParsed) {
				return true
			}
			continue
		}

		// Check if it's a single IP
		if allowedIP := net.ParseIP(allowed); allowedIP != nil {
			if allowedIP.Equal(clientIPParsed) {
				return true
			}
		}
	}
	return false
}

// hasRequiredScopes checks if the key has all required scopes.
func hasRequiredScopes(keyScopes, requiredScopes []string) bool {
	scopeSet := make(map[string]bool)
	for _, scope := range keyScopes {
		scopeSet[scope] = true
	}
	// Check for wildcard scope
	if scopeSet["*"] {
		return true
	}
	for _, required := range requiredScopes {
		if !scopeSet[required] {
			return false
		}
	}
	return true
}
