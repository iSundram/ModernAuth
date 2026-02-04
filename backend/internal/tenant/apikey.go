package tenant

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
)

// TenantAPIKey represents an API key for a tenant.
type TenantAPIKey struct {
	ID         uuid.UUID  `json:"id"`
	TenantID   uuid.UUID  `json:"tenant_id"`
	Name       string     `json:"name"`
	KeyHash    string     `json:"-"`
	KeyPrefix  string     `json:"key_prefix"`
	Scopes     []string   `json:"scopes,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// CreateAPIKeyRequest represents a request to create an API key.
type CreateAPIKeyRequest struct {
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes,omitempty"`
	ExpiresIn *int     `json:"expires_in,omitempty"` // seconds
}

// CreateAPIKeyResult contains the created key and raw key (shown once).
type CreateAPIKeyResult struct {
	APIKey *TenantAPIKey
	RawKey string
}

// ListAPIKeys lists API keys for a tenant.
func (s *Service) ListAPIKeys(ctx context.Context, tenantID uuid.UUID) ([]*TenantAPIKey, error) {
	tenant, err := s.storage.GetTenantByID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if tenant == nil {
		return nil, ErrTenantNotFound
	}

	// Get API keys from settings (stored as JSON array)
	keys := s.getAPIKeysFromSettings(tenant.Settings)
	return keys, nil
}

// CreateAPIKey creates a new API key for a tenant.
func (s *Service) CreateAPIKey(ctx context.Context, tenantID uuid.UUID, req *CreateAPIKeyRequest) (*CreateAPIKeyResult, error) {
	tenant, err := s.storage.GetTenantByID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if tenant == nil {
		return nil, ErrTenantNotFound
	}

	// Generate a secure random key
	rawKey := generateAPIKey()
	keyHash := hashAPIKey(rawKey)
	keyPrefix := rawKey[:8] + "..."

	now := time.Now()
	var expiresAt *time.Time
	if req.ExpiresIn != nil && *req.ExpiresIn > 0 {
		exp := now.Add(time.Duration(*req.ExpiresIn) * time.Second)
		expiresAt = &exp
	}

	apiKey := &TenantAPIKey{
		ID:        uuid.New(),
		TenantID:  tenantID,
		Name:      req.Name,
		KeyHash:   keyHash,
		KeyPrefix: keyPrefix,
		Scopes:    req.Scopes,
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}

	// Store in tenant settings
	if err := s.addAPIKeyToSettings(ctx, tenant, apiKey); err != nil {
		return nil, err
	}

	s.logger.Info("API key created", "tenant_id", tenantID, "key_id", apiKey.ID, "name", req.Name)

	return &CreateAPIKeyResult{
		APIKey: apiKey,
		RawKey: rawKey,
	}, nil
}

// RevokeAPIKey revokes an API key.
func (s *Service) RevokeAPIKey(ctx context.Context, tenantID, keyID uuid.UUID) error {
	tenant, err := s.storage.GetTenantByID(ctx, tenantID)
	if err != nil {
		return err
	}
	if tenant == nil {
		return ErrTenantNotFound
	}

	if err := s.removeAPIKeyFromSettings(ctx, tenant, keyID); err != nil {
		return err
	}

	s.logger.Info("API key revoked", "tenant_id", tenantID, "key_id", keyID)
	return nil
}

func generateAPIKey() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return "ma_" + hex.EncodeToString(bytes)
}

func hashAPIKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}

func (s *Service) getAPIKeysFromSettings(settings map[string]interface{}) []*TenantAPIKey {
	keysData, ok := settings["api_keys"]
	if !ok {
		return []*TenantAPIKey{}
	}

	keysJSON, err := json.Marshal(keysData)
	if err != nil {
		return []*TenantAPIKey{}
	}

	var keys []*TenantAPIKey
	if err := json.Unmarshal(keysJSON, &keys); err != nil {
		return []*TenantAPIKey{}
	}
	return keys
}

func (s *Service) addAPIKeyToSettings(ctx context.Context, tenant *storage.Tenant, key *TenantAPIKey) error {
	keys := s.getAPIKeysFromSettings(tenant.Settings)
	keys = append(keys, key)

	if tenant.Settings == nil {
		tenant.Settings = make(map[string]interface{})
	}
	tenant.Settings["api_keys"] = keys
	tenant.UpdatedAt = time.Now()

	return s.storage.UpdateTenant(ctx, tenant)
}

func (s *Service) removeAPIKeyFromSettings(ctx context.Context, tenant *storage.Tenant, keyID uuid.UUID) error {
	keys := s.getAPIKeysFromSettings(tenant.Settings)
	found := false
	newKeys := make([]*TenantAPIKey, 0, len(keys))
	for _, k := range keys {
		if k.ID != keyID {
			newKeys = append(newKeys, k)
		} else {
			found = true
		}
	}

	if !found {
		return ErrAPIKeyNotFound
	}

	if tenant.Settings == nil {
		tenant.Settings = make(map[string]interface{})
	}
	tenant.Settings["api_keys"] = newKeys
	tenant.UpdatedAt = time.Now()

	return s.storage.UpdateTenant(ctx, tenant)
}
