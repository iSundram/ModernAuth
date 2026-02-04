package pg

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/iSundram/ModernAuth/internal/storage"
)

// ============================================================================
// APIKeyStorage methods
// ============================================================================

func (s *PostgresStorage) CreateAPIKey(ctx context.Context, key *storage.APIKey) error {
	query := `
		INSERT INTO api_keys (id, tenant_id, user_id, name, description, key_prefix, key_hash, scopes,
		                      rate_limit, allowed_ips, expires_at, last_used_at, last_used_ip, is_active,
		                      created_at, revoked_at, revoked_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
	`
	_, err := s.pool.Exec(ctx, query,
		key.ID, key.TenantID, key.UserID, key.Name, key.Description, key.KeyPrefix, key.KeyHash,
		key.Scopes, key.RateLimit, key.AllowedIPs, key.ExpiresAt, key.LastUsedAt, key.LastUsedIP,
		key.IsActive, key.CreatedAt, key.RevokedAt, key.RevokedBy,
	)
	return err
}

func (s *PostgresStorage) GetAPIKeyByID(ctx context.Context, id uuid.UUID) (*storage.APIKey, error) {
	query := `
		SELECT id, tenant_id, user_id, name, description, key_prefix, key_hash, scopes, rate_limit,
		       allowed_ips, expires_at, last_used_at, last_used_ip, is_active, created_at, revoked_at, revoked_by
		FROM api_keys WHERE id = $1
	`
	key := &storage.APIKey{}
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&key.ID, &key.TenantID, &key.UserID, &key.Name, &key.Description, &key.KeyPrefix, &key.KeyHash,
		&key.Scopes, &key.RateLimit, &key.AllowedIPs, &key.ExpiresAt, &key.LastUsedAt, &key.LastUsedIP,
		&key.IsActive, &key.CreatedAt, &key.RevokedAt, &key.RevokedBy,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return key, nil
}

func (s *PostgresStorage) GetAPIKeyByHash(ctx context.Context, keyHash string) (*storage.APIKey, error) {
	query := `
		SELECT id, tenant_id, user_id, name, description, key_prefix, key_hash, scopes, rate_limit,
		       allowed_ips, expires_at, last_used_at, last_used_ip, is_active, created_at, revoked_at, revoked_by
		FROM api_keys WHERE key_hash = $1
	`
	key := &storage.APIKey{}
	err := s.pool.QueryRow(ctx, query, keyHash).Scan(
		&key.ID, &key.TenantID, &key.UserID, &key.Name, &key.Description, &key.KeyPrefix, &key.KeyHash,
		&key.Scopes, &key.RateLimit, &key.AllowedIPs, &key.ExpiresAt, &key.LastUsedAt, &key.LastUsedIP,
		&key.IsActive, &key.CreatedAt, &key.RevokedAt, &key.RevokedBy,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return key, nil
}

func (s *PostgresStorage) ListAPIKeys(ctx context.Context, userID *uuid.UUID, tenantID *uuid.UUID, limit, offset int) ([]*storage.APIKey, error) {
	var query string
	var args []interface{}

	if userID != nil && tenantID != nil {
		query = `
			SELECT id, tenant_id, user_id, name, description, key_prefix, key_hash, scopes, rate_limit,
			       allowed_ips, expires_at, last_used_at, last_used_ip, is_active, created_at, revoked_at, revoked_by
			FROM api_keys WHERE user_id = $1 AND tenant_id = $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4
		`
		args = []interface{}{*userID, *tenantID, limit, offset}
	} else if userID != nil {
		query = `
			SELECT id, tenant_id, user_id, name, description, key_prefix, key_hash, scopes, rate_limit,
			       allowed_ips, expires_at, last_used_at, last_used_ip, is_active, created_at, revoked_at, revoked_by
			FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3
		`
		args = []interface{}{*userID, limit, offset}
	} else if tenantID != nil {
		query = `
			SELECT id, tenant_id, user_id, name, description, key_prefix, key_hash, scopes, rate_limit,
			       allowed_ips, expires_at, last_used_at, last_used_ip, is_active, created_at, revoked_at, revoked_by
			FROM api_keys WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3
		`
		args = []interface{}{*tenantID, limit, offset}
	} else {
		query = `
			SELECT id, tenant_id, user_id, name, description, key_prefix, key_hash, scopes, rate_limit,
			       allowed_ips, expires_at, last_used_at, last_used_ip, is_active, created_at, revoked_at, revoked_by
			FROM api_keys ORDER BY created_at DESC LIMIT $1 OFFSET $2
		`
		args = []interface{}{limit, offset}
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []*storage.APIKey
	for rows.Next() {
		key := &storage.APIKey{}
		err := rows.Scan(
			&key.ID, &key.TenantID, &key.UserID, &key.Name, &key.Description, &key.KeyPrefix, &key.KeyHash,
			&key.Scopes, &key.RateLimit, &key.AllowedIPs, &key.ExpiresAt, &key.LastUsedAt, &key.LastUsedIP,
			&key.IsActive, &key.CreatedAt, &key.RevokedAt, &key.RevokedBy,
		)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (s *PostgresStorage) UpdateAPIKey(ctx context.Context, key *storage.APIKey) error {
	query := `
		UPDATE api_keys
		SET name = $2, description = $3, scopes = $4, rate_limit = $5, allowed_ips = $6, expires_at = $7,
		    is_active = $8
		WHERE id = $1
	`
	_, err := s.pool.Exec(ctx, query,
		key.ID, key.Name, key.Description, key.Scopes, key.RateLimit, key.AllowedIPs,
		key.ExpiresAt, key.IsActive,
	)
	return err
}

func (s *PostgresStorage) RevokeAPIKey(ctx context.Context, id uuid.UUID, revokedBy *uuid.UUID) error {
	query := `UPDATE api_keys SET is_active = false, revoked_at = now(), revoked_by = $2 WHERE id = $1`
	_, err := s.pool.Exec(ctx, query, id, revokedBy)
	return err
}

func (s *PostgresStorage) UpdateAPIKeyLastUsed(ctx context.Context, id uuid.UUID, ip string) error {
	query := `UPDATE api_keys SET last_used_at = now(), last_used_ip = $2 WHERE id = $1`
	_, err := s.pool.Exec(ctx, query, id, ip)
	return err
}
