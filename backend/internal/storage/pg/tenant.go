package pg

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/iSundram/ModernAuth/internal/storage"
)

// ============================================================================
// TenantStorage methods
// ============================================================================

func (s *PostgresStorage) extractRateLimits(settings map[string]interface{}) map[string]storage.RateLimitConfig {
	if settings == nil {
		return nil
	}
	limitsData, ok := settings["rate_limits"].(map[string]interface{})
	if !ok {
		return nil
	}
	limits := make(map[string]storage.RateLimitConfig)
	for k, v := range limitsData {
		if configMap, ok := v.(map[string]interface{}); ok {
			limit := 0
			window := 0
			if l, ok := configMap["limit"].(float64); ok {
				limit = int(l)
			}
			if w, ok := configMap["window_seconds"].(float64); ok {
				window = int(w)
			}
			limits[k] = storage.RateLimitConfig{
				Limit:         limit,
				WindowSeconds: window,
			}
		}
	}
	return limits
}

func (s *PostgresStorage) injectRateLimits(settings map[string]interface{}, limits map[string]storage.RateLimitConfig) map[string]interface{} {
	if limits == nil {
		return settings
	}
	if settings == nil {
		settings = make(map[string]interface{})
	}
	// Convert to map[string]interface{} for JSON serialization
	limitsMap := make(map[string]interface{})
	for k, v := range limits {
		limitsMap[k] = map[string]interface{}{
			"limit":          v.Limit,
			"window_seconds": v.WindowSeconds,
		}
	}
	settings["rate_limits"] = limitsMap
	return settings
}

func (s *PostgresStorage) CreateTenant(ctx context.Context, tenant *storage.Tenant) error {
	query := `
		INSERT INTO tenants (id, name, slug, domain, logo_url, settings, plan, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	// Inject RateLimits into Settings for storage
	settings := s.injectRateLimits(tenant.Settings, tenant.RateLimits)

	_, err := s.pool.Exec(ctx, query,
		tenant.ID, tenant.Name, tenant.Slug, tenant.Domain, tenant.LogoURL,
		settings, tenant.Plan, tenant.IsActive, tenant.CreatedAt, tenant.UpdatedAt,
	)
	return err
}

func (s *PostgresStorage) GetTenantByID(ctx context.Context, id uuid.UUID) (*storage.Tenant, error) {
	query := `
		SELECT id, name, slug, domain, logo_url, settings, plan, is_active, created_at, updated_at
		FROM tenants WHERE id = $1
	`
	tenant := &storage.Tenant{}
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&tenant.ID, &tenant.Name, &tenant.Slug, &tenant.Domain, &tenant.LogoURL,
		&tenant.Settings, &tenant.Plan, &tenant.IsActive, &tenant.CreatedAt, &tenant.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	// Extract RateLimits from Settings
	tenant.RateLimits = s.extractRateLimits(tenant.Settings)
	return tenant, nil
}

func (s *PostgresStorage) GetTenantBySlug(ctx context.Context, slug string) (*storage.Tenant, error) {
	query := `
		SELECT id, name, slug, domain, logo_url, settings, plan, is_active, created_at, updated_at
		FROM tenants WHERE slug = $1
	`
	tenant := &storage.Tenant{}
	err := s.pool.QueryRow(ctx, query, slug).Scan(
		&tenant.ID, &tenant.Name, &tenant.Slug, &tenant.Domain, &tenant.LogoURL,
		&tenant.Settings, &tenant.Plan, &tenant.IsActive, &tenant.CreatedAt, &tenant.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	tenant.RateLimits = s.extractRateLimits(tenant.Settings)
	return tenant, nil
}

func (s *PostgresStorage) GetTenantByDomain(ctx context.Context, domain string) (*storage.Tenant, error) {
	query := `
		SELECT id, name, slug, domain, logo_url, settings, plan, is_active, created_at, updated_at
		FROM tenants WHERE domain = $1
	`
	tenant := &storage.Tenant{}
	err := s.pool.QueryRow(ctx, query, domain).Scan(
		&tenant.ID, &tenant.Name, &tenant.Slug, &tenant.Domain, &tenant.LogoURL,
		&tenant.Settings, &tenant.Plan, &tenant.IsActive, &tenant.CreatedAt, &tenant.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	tenant.RateLimits = s.extractRateLimits(tenant.Settings)
	return tenant, nil
}

func (s *PostgresStorage) ListTenants(ctx context.Context, limit, offset int) ([]*storage.Tenant, error) {
	query := `
		SELECT id, name, slug, domain, logo_url, settings, plan, is_active, created_at, updated_at
		FROM tenants ORDER BY created_at DESC LIMIT $1 OFFSET $2
	`
	rows, err := s.pool.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tenants []*storage.Tenant
	for rows.Next() {
		tenant := &storage.Tenant{}
		err := rows.Scan(
			&tenant.ID, &tenant.Name, &tenant.Slug, &tenant.Domain, &tenant.LogoURL,
			&tenant.Settings, &tenant.Plan, &tenant.IsActive, &tenant.CreatedAt, &tenant.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		tenant.RateLimits = s.extractRateLimits(tenant.Settings)
		tenants = append(tenants, tenant)
	}
	return tenants, rows.Err()
}

func (s *PostgresStorage) UpdateTenant(ctx context.Context, tenant *storage.Tenant) error {
	query := `
		UPDATE tenants
		SET name = $2, slug = $3, domain = $4, logo_url = $5, settings = $6, plan = $7, is_active = $8, updated_at = $9
		WHERE id = $1
	`
	tenant.UpdatedAt = time.Now()
	settings := s.injectRateLimits(tenant.Settings, tenant.RateLimits)

	_, err := s.pool.Exec(ctx, query,
		tenant.ID, tenant.Name, tenant.Slug, tenant.Domain, tenant.LogoURL,
		settings, tenant.Plan, tenant.IsActive, tenant.UpdatedAt,
	)
	return err
}

func (s *PostgresStorage) DeleteTenant(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM tenants WHERE id = $1`
	_, err := s.pool.Exec(ctx, query, id)
	return err
}

func (s *PostgresStorage) ListTenantUsers(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*storage.User, error) {
	query := `
		SELECT id, tenant_id, email, phone, username, first_name, last_name, avatar_url, hashed_password,
		       is_email_verified, is_active, timezone, locale, metadata, last_login_at, password_changed_at,
		       created_at, updated_at
		FROM users WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3
	`
	rows, err := s.pool.Query(ctx, query, tenantID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*storage.User
	for rows.Next() {
		user := &storage.User{}
		err := rows.Scan(
			&user.ID, &user.TenantID, &user.Email, &user.Phone, &user.Username,
			&user.FirstName, &user.LastName, &user.AvatarURL, &user.HashedPassword,
			&user.IsEmailVerified, &user.IsActive, &user.Timezone, &user.Locale, &user.Metadata,
			&user.LastLoginAt, &user.PasswordChangedAt, &user.CreatedAt, &user.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

func (s *PostgresStorage) CountTenantUsers(ctx context.Context, tenantID uuid.UUID) (int, error) {
	query := `SELECT COUNT(*) FROM users WHERE tenant_id = $1`
	var count int
	err := s.pool.QueryRow(ctx, query, tenantID).Scan(&count)
	return count, err
}
