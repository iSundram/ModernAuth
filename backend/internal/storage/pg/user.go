package pg

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/iSundram/ModernAuth/internal/storage"
)

// CreateUser creates a new user in the database.
func (s *PostgresStorage) CreateUser(ctx context.Context, user *storage.User) error {
	query := `
		INSERT INTO users (id, email, phone, username, hashed_password, is_email_verified, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err := s.pool.Exec(ctx, query,
		user.ID,
		user.Email,
		user.Phone,
		user.Username,
		user.HashedPassword,
		user.IsEmailVerified,
		user.IsActive,
		user.CreatedAt,
		user.UpdatedAt,
	)
	return err
}

// GetUserByID retrieves a user by their ID.
func (s *PostgresStorage) GetUserByID(ctx context.Context, id uuid.UUID) (*storage.User, error) {
	query := `
		SELECT id, email, phone, username, first_name, last_name, avatar_url, hashed_password, 
		       is_email_verified, is_active, timezone, locale, metadata, last_login_at, 
		       password_changed_at, created_at, updated_at
		FROM users
		WHERE id = $1
	`
	user := &storage.User{}
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.Email,
		&user.Phone,
		&user.Username,
		&user.FirstName,
		&user.LastName,
		&user.AvatarURL,
		&user.HashedPassword,
		&user.IsEmailVerified,
		&user.IsActive,
		&user.Timezone,
		&user.Locale,
		&user.Metadata,
		&user.LastLoginAt,
		&user.PasswordChangedAt,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return user, nil
}

// GetUserByEmail retrieves a user by their email.
func (s *PostgresStorage) GetUserByEmail(ctx context.Context, email string) (*storage.User, error) {
	query := `
		SELECT id, email, phone, username, first_name, last_name, avatar_url, hashed_password, 
		       is_email_verified, is_active, timezone, locale, metadata, last_login_at, 
		       password_changed_at, created_at, updated_at, tenant_id
		FROM users
		WHERE email = $1
	`
	user := &storage.User{}
	err := s.pool.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.Phone,
		&user.Username,
		&user.FirstName,
		&user.LastName,
		&user.AvatarURL,
		&user.HashedPassword,
		&user.IsEmailVerified,
		&user.IsActive,
		&user.Timezone,
		&user.Locale,
		&user.Metadata,
		&user.LastLoginAt,
		&user.PasswordChangedAt,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.TenantID,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return user, nil
}

// GetUserByEmailAndTenant retrieves a user by their email within a specific tenant.
// This ensures proper tenant isolation for multi-tenant scenarios.
func (s *PostgresStorage) GetUserByEmailAndTenant(ctx context.Context, email string, tenantID *uuid.UUID) (*storage.User, error) {
	var query string
	var args []interface{}

	if tenantID != nil {
		query = `
			SELECT id, email, phone, username, first_name, last_name, avatar_url, hashed_password, 
			       is_email_verified, is_active, timezone, locale, metadata, last_login_at, 
			       password_changed_at, created_at, updated_at, tenant_id
			FROM users
			WHERE email = $1 AND (tenant_id = $2 OR tenant_id IS NULL)
		`
		args = []interface{}{email, *tenantID}
	} else {
		query = `
			SELECT id, email, phone, username, first_name, last_name, avatar_url, hashed_password, 
			       is_email_verified, is_active, timezone, locale, metadata, last_login_at, 
			       password_changed_at, created_at, updated_at, tenant_id
			FROM users
			WHERE email = $1 AND tenant_id IS NULL
		`
		args = []interface{}{email}
	}

	user := &storage.User{}
	err := s.pool.QueryRow(ctx, query, args...).Scan(
		&user.ID,
		&user.Email,
		&user.Phone,
		&user.Username,
		&user.FirstName,
		&user.LastName,
		&user.AvatarURL,
		&user.HashedPassword,
		&user.IsEmailVerified,
		&user.IsActive,
		&user.Timezone,
		&user.Locale,
		&user.Metadata,
		&user.LastLoginAt,
		&user.PasswordChangedAt,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.TenantID,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return user, nil
}

// ListUsers retrieves users with pagination from the database.
func (s *PostgresStorage) ListUsers(ctx context.Context, limit, offset int) ([]*storage.User, error) {
	query := `
		SELECT id, email, phone, username, first_name, last_name, avatar_url, hashed_password, 
		       is_email_verified, is_active, timezone, locale, metadata, last_login_at, 
		       password_changed_at, created_at, updated_at, tenant_id
		FROM users
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`
	rows, err := s.pool.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*storage.User
	for rows.Next() {
		user := &storage.User{}
		err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.Phone,
			&user.Username,
			&user.FirstName,
			&user.LastName,
			&user.AvatarURL,
			&user.HashedPassword,
			&user.IsEmailVerified,
			&user.IsActive,
			&user.Timezone,
			&user.Locale,
			&user.Metadata,
			&user.LastLoginAt,
			&user.PasswordChangedAt,
			&user.CreatedAt,
			&user.UpdatedAt,
			&user.TenantID,
		)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, rows.Err()
}

// ListUsersCursor retrieves users with cursor-based pagination.
// cursorID is the ID of the user to start after (for "after") or before (for "before").
// after=true means pagination forward, after=false means pagination backward.
func (s *PostgresStorage) ListUsersCursor(ctx context.Context, limit int, cursorID *uuid.UUID, after bool) ([]*storage.User, error) {
	var query string
	var args []interface{}

	if cursorID == nil {
		return s.ListUsers(ctx, limit, 0)
	}

	if after {
		query = `
			SELECT id, email, phone, username, first_name, last_name, avatar_url, hashed_password, 
			       is_email_verified, is_active, timezone, locale, metadata, last_login_at, 
			       password_changed_at, created_at, updated_at, tenant_id
			FROM users
			WHERE id > $1
			ORDER BY id ASC
			LIMIT $2
		`
		args = []interface{}{*cursorID, limit}
	} else {
		query = `
			SELECT id, email, phone, username, first_name, last_name, avatar_url, hashed_password, 
			       is_email_verified, is_active, timezone, locale, metadata, last_login_at, 
			       password_changed_at, created_at, updated_at, tenant_id
			FROM users
			WHERE id < $1
			ORDER BY id DESC
			LIMIT $2
		`
		args = []interface{}{*cursorID, limit}
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*storage.User
	for rows.Next() {
		user := &storage.User{}
		err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.Phone,
			&user.Username,
			&user.FirstName,
			&user.LastName,
			&user.AvatarURL,
			&user.HashedPassword,
			&user.IsEmailVerified,
			&user.IsActive,
			&user.Timezone,
			&user.Locale,
			&user.Metadata,
			&user.LastLoginAt,
			&user.PasswordChangedAt,
			&user.CreatedAt,
			&user.UpdatedAt,
			&user.TenantID,
		)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	if !after && len(users) > 0 {
		for i, j := 0, len(users)-1; i < j; i, j = i+1, j-1 {
			users[i], users[j] = users[j], users[i]
		}
	}

	return users, rows.Err()
}

// ListUsersByTenant retrieves users for a specific tenant with pagination.
// This ensures proper tenant isolation when listing users.
func (s *PostgresStorage) ListUsersByTenant(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*storage.User, error) {
	query := `
		SELECT id, email, phone, username, first_name, last_name, avatar_url, hashed_password, 
		       is_email_verified, is_active, timezone, locale, metadata, last_login_at, 
		       password_changed_at, created_at, updated_at, tenant_id
		FROM users
		WHERE tenant_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
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
			&user.ID,
			&user.Email,
			&user.Phone,
			&user.Username,
			&user.FirstName,
			&user.LastName,
			&user.AvatarURL,
			&user.HashedPassword,
			&user.IsEmailVerified,
			&user.IsActive,
			&user.Timezone,
			&user.Locale,
			&user.Metadata,
			&user.LastLoginAt,
			&user.PasswordChangedAt,
			&user.CreatedAt,
			&user.UpdatedAt,
			&user.TenantID,
		)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, rows.Err()
}

// CountUsersByTenant returns the count of users for a specific tenant.
func (s *PostgresStorage) CountUsersByTenant(ctx context.Context, tenantID uuid.UUID) (int, error) {
	query := `SELECT COUNT(*) FROM users WHERE tenant_id = $1`
	var count int
	err := s.pool.QueryRow(ctx, query, tenantID).Scan(&count)
	return count, err
}

// CountUsers returns the total count of users.
func (s *PostgresStorage) CountUsers(ctx context.Context) (int, error) {
	query := `SELECT COUNT(*) FROM users`
	var count int
	err := s.pool.QueryRow(ctx, query).Scan(&count)
	return count, err
}

// CountActiveUsers returns the count of active (non-suspended) users.
func (s *PostgresStorage) CountActiveUsers(ctx context.Context) (int, error) {
	query := `SELECT COUNT(*) FROM users WHERE is_active = true`
	var count int
	err := s.pool.QueryRow(ctx, query).Scan(&count)
	return count, err
}

// CountSuspendedUsers returns the count of suspended users.
func (s *PostgresStorage) CountSuspendedUsers(ctx context.Context) (int, error) {
	query := `SELECT COUNT(*) FROM users WHERE is_active = false`
	var count int
	err := s.pool.QueryRow(ctx, query).Scan(&count)
	return count, err
}

// CountUsersByRole returns the count of users grouped by their primary role.
func (s *PostgresStorage) CountUsersByRole(ctx context.Context) (map[string]int, error) {
	query := `
		SELECT COALESCE(r.name, 'user'), COUNT(ur.user_id)
		FROM user_roles ur
		LEFT JOIN roles r ON ur.role_id = r.id
		GROUP BY r.name
	`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]int)
	for rows.Next() {
		var roleName string
		var count int
		if err := rows.Scan(&roleName, &count); err != nil {
			return nil, err
		}
		if roleName == "" {
			roleName = "user"
		}
		result[roleName] = count
	}
	return result, nil
}

// UpdateUser updates an existing user.
func (s *PostgresStorage) UpdateUser(ctx context.Context, user *storage.User) error {
	query := `
		UPDATE users
		SET tenant_id = $2, email = $3, phone = $4, username = $5, hashed_password = $6, 
		    is_email_verified = $7, is_active = $8, first_name = $9, last_name = $10, 
		    avatar_url = $11, timezone = $12, locale = $13, metadata = $14, 
		    last_login_at = $15, password_changed_at = $16, updated_at = $17
		WHERE id = $1
	`
	user.UpdatedAt = time.Now()
	_, err := s.pool.Exec(ctx, query,
		user.ID,
		user.TenantID,
		user.Email,
		user.Phone,
		user.Username,
		user.HashedPassword,
		user.IsEmailVerified,
		user.IsActive,
		user.FirstName,
		user.LastName,
		user.AvatarURL,
		user.Timezone,
		user.Locale,
		user.Metadata,
		user.LastLoginAt,
		user.PasswordChangedAt,
		user.UpdatedAt,
	)
	return err
}

// DeleteUser deletes a user by their ID.
func (s *PostgresStorage) DeleteUser(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM users WHERE id = $1`
	_, err := s.pool.Exec(ctx, query, id)
	return err
}
