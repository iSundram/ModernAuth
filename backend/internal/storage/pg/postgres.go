// Package pg provides PostgreSQL implementation of the storage interfaces.
package pg

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/iSundram/ModernAuth/internal/storage"
)

// PostgresStorage implements the Storage interface using PostgreSQL.
type PostgresStorage struct {
	pool *pgxpool.Pool
}

// NewPostgresStorage creates a new PostgreSQL storage instance.
func NewPostgresStorage(pool *pgxpool.Pool) *PostgresStorage {
	return &PostgresStorage{pool: pool}
}

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
		       password_changed_at, created_at, updated_at
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
		       password_changed_at, created_at, updated_at
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
		)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, rows.Err()
}

// CountUsers returns the total count of users.
func (s *PostgresStorage) CountUsers(ctx context.Context) (int, error) {
	query := `SELECT COUNT(*) FROM users`
	var count int
	err := s.pool.QueryRow(ctx, query).Scan(&count)
	return count, err
}

// UpdateUser updates an existing user.
func (s *PostgresStorage) UpdateUser(ctx context.Context, user *storage.User) error {
	query := `
		UPDATE users
		SET tenant_id = $2, email = $3, phone = $4, username = $5, hashed_password = $6, is_email_verified = $7, is_active = $8, updated_at = $9
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

// CreateSession creates a new session.
func (s *PostgresStorage) CreateSession(ctx context.Context, session *storage.Session) error {
	query := `
		INSERT INTO sessions (id, user_id, tenant_id, device_id, fingerprint, created_at, expires_at, revoked, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err := s.pool.Exec(ctx, query,
		session.ID,
		session.UserID,
		session.TenantID,
		session.DeviceID,
		session.Fingerprint,
		session.CreatedAt,
		session.ExpiresAt,
		session.Revoked,
		session.Metadata,
	)
	return err
}

// GetSessionByID retrieves a session by its ID.
func (s *PostgresStorage) GetSessionByID(ctx context.Context, id uuid.UUID) (*storage.Session, error) {
	query := `
		SELECT id, user_id, tenant_id, device_id, fingerprint, created_at, expires_at, revoked, metadata
		FROM sessions
		WHERE id = $1
	`
	session := &storage.Session{}
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&session.ID,
		&session.UserID,
		&session.TenantID,
		&session.DeviceID,
		&session.Fingerprint,
		&session.CreatedAt,
		&session.ExpiresAt,
		&session.Revoked,
		&session.Metadata,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return session, nil
}

// GetUserSessions retrieves active sessions for a user.
func (s *PostgresStorage) GetUserSessions(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*storage.Session, error) {
	query := `
		SELECT id, user_id, tenant_id, device_id, fingerprint, created_at, expires_at, revoked, metadata
		FROM sessions
		WHERE user_id = $1 AND revoked = false AND expires_at > now()
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`
	rows, err := s.pool.Query(ctx, query, userID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*storage.Session
	for rows.Next() {
		session := &storage.Session{}
		err := rows.Scan(
			&session.ID,
			&session.UserID,
			&session.TenantID,
			&session.DeviceID,
			&session.Fingerprint,
			&session.CreatedAt,
			&session.ExpiresAt,
			&session.Revoked,
			&session.Metadata,
		)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}

	return sessions, rows.Err()
}

// RevokeSession revokes a session by its ID.
func (s *PostgresStorage) RevokeSession(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE sessions SET revoked = true WHERE id = $1`
	_, err := s.pool.Exec(ctx, query, id)
	return err
}

// RevokeUserSessions revokes all sessions for a user.
func (s *PostgresStorage) RevokeUserSessions(ctx context.Context, userID uuid.UUID) error {
	query := `UPDATE sessions SET revoked = true WHERE user_id = $1`
	_, err := s.pool.Exec(ctx, query, userID)
	return err
}

// CreateRefreshToken creates a new refresh token.
func (s *PostgresStorage) CreateRefreshToken(ctx context.Context, token *storage.RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (id, session_id, token_hash, issued_at, expires_at, revoked, replaced_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := s.pool.Exec(ctx, query,
		token.ID,
		token.SessionID,
		token.TokenHash,
		token.IssuedAt,
		token.ExpiresAt,
		token.Revoked,
		token.ReplacedBy,
	)
	return err
}

// GetRefreshTokenByHash retrieves a refresh token by its hash.
func (s *PostgresStorage) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*storage.RefreshToken, error) {
	query := `
		SELECT id, session_id, token_hash, issued_at, expires_at, revoked, replaced_by
		FROM refresh_tokens
		WHERE token_hash = $1
	`
	token := &storage.RefreshToken{}
	err := s.pool.QueryRow(ctx, query, tokenHash).Scan(
		&token.ID,
		&token.SessionID,
		&token.TokenHash,
		&token.IssuedAt,
		&token.ExpiresAt,
		&token.Revoked,
		&token.ReplacedBy,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return token, nil
}

// RevokeRefreshToken revokes a refresh token and optionally sets its replacement.
func (s *PostgresStorage) RevokeRefreshToken(ctx context.Context, id uuid.UUID, replacedBy *uuid.UUID) error {
	query := `UPDATE refresh_tokens SET revoked = true, replaced_by = $2 WHERE id = $1`
	_, err := s.pool.Exec(ctx, query, id, replacedBy)
	return err
}

// RevokeSessionRefreshTokens revokes all refresh tokens for a session.
func (s *PostgresStorage) RevokeSessionRefreshTokens(ctx context.Context, sessionID uuid.UUID) error {
	query := `UPDATE refresh_tokens SET revoked = true WHERE session_id = $1`
	_, err := s.pool.Exec(ctx, query, sessionID)
	return err
}

// CreateAuditLog creates a new audit log entry.
func (s *PostgresStorage) CreateAuditLog(ctx context.Context, log *storage.AuditLog) error {
	query := `
		INSERT INTO audit_logs (id, user_id, actor_id, event_type, ip, user_agent, data, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := s.pool.Exec(ctx, query,
		log.ID,
		log.UserID,
		log.ActorID,
		log.EventType,
		log.IP,
		log.UserAgent,
		log.Data,
		log.CreatedAt,
	)
	return err
}

// GetAuditLogs retrieves audit logs with optional user and event type filtering.
func (s *PostgresStorage) GetAuditLogs(ctx context.Context, userID *uuid.UUID, eventType *string, limit, offset int) ([]*storage.AuditLog, error) {
	var query string
	var rows pgx.Rows
	var err error
	var args []interface{}
	argIndex := 1

	// Build WHERE clause dynamically
	var conditions []string
	if userID != nil {
		conditions = append(conditions, fmt.Sprintf("user_id = $%d", argIndex))
		args = append(args, *userID)
		argIndex++
	}
	if eventType != nil {
		conditions = append(conditions, fmt.Sprintf("event_type = $%d", argIndex))
		args = append(args, *eventType)
		argIndex++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Add limit and offset
	args = append(args, limit, offset)
	query = fmt.Sprintf(`
		SELECT id, tenant_id, user_id, actor_id, event_type, ip, user_agent, data, created_at
		FROM audit_logs
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIndex, argIndex+1)

	rows, err = s.pool.Query(ctx, query, args...)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []*storage.AuditLog
	for rows.Next() {
		log := &storage.AuditLog{}
		err := rows.Scan(
			&log.ID,
			&log.TenantID,
			&log.UserID,
			&log.ActorID,
			&log.EventType,
			&log.IP,
			&log.UserAgent,
			&log.Data,
			&log.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}

	return logs, rows.Err()
}

// DeleteOldAuditLogs deletes audit logs older than the specified time.
func (s *PostgresStorage) DeleteOldAuditLogs(ctx context.Context, olderThan time.Time) (int64, error) {
	query := `DELETE FROM audit_logs WHERE created_at < $1`
	result, err := s.pool.Exec(ctx, query, olderThan)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

// GetMFASettings retrieves MFA settings for a user.
func (s *PostgresStorage) GetMFASettings(ctx context.Context, userID uuid.UUID) (*storage.MFASettings, error) {
	query := `
		SELECT user_id, totp_secret, is_totp_enabled, backup_codes, updated_at
		FROM user_mfa_settings
		WHERE user_id = $1
	`
	settings := &storage.MFASettings{}
	err := s.pool.QueryRow(ctx, query, userID).Scan(
		&settings.UserID,
		&settings.TOTPSecret,
		&settings.IsTOTPEnabled,
		&settings.BackupCodes,
		&settings.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return settings, nil
}

// UpdateMFASettings updates or creates MFA settings for a user.
func (s *PostgresStorage) UpdateMFASettings(ctx context.Context, settings *storage.MFASettings) error {
	query := `
		INSERT INTO user_mfa_settings (user_id, totp_secret, is_totp_enabled, backup_codes, updated_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (user_id) DO UPDATE
		SET totp_secret = $2, is_totp_enabled = $3, backup_codes = $4, updated_at = $5
	`
	settings.UpdatedAt = time.Now()
	_, err := s.pool.Exec(ctx, query,
		settings.UserID,
		settings.TOTPSecret,
		settings.IsTOTPEnabled,
		settings.BackupCodes,
		settings.UpdatedAt,
	)
	return err
}

// CreateVerificationToken creates a new verification token.
func (s *PostgresStorage) CreateVerificationToken(ctx context.Context, token *storage.VerificationToken) error {
	query := `
		INSERT INTO verification_tokens (id, user_id, token_hash, token_type, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := s.pool.Exec(ctx, query,
		token.ID,
		token.UserID,
		token.TokenHash,
		token.TokenType,
		token.ExpiresAt,
		token.CreatedAt,
	)
	return err
}

// GetVerificationTokenByHash retrieves a verification token by its hash and type.
func (s *PostgresStorage) GetVerificationTokenByHash(ctx context.Context, tokenHash string, tokenType string) (*storage.VerificationToken, error) {
	query := `
		SELECT id, user_id, token_hash, token_type, expires_at, used_at, created_at
		FROM verification_tokens
		WHERE token_hash = $1 AND token_type = $2
	`
	token := &storage.VerificationToken{}
	err := s.pool.QueryRow(ctx, query, tokenHash, tokenType).Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&token.TokenType,
		&token.ExpiresAt,
		&token.UsedAt,
		&token.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return token, nil
}

// MarkVerificationTokenUsed marks a verification token as used.
func (s *PostgresStorage) MarkVerificationTokenUsed(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE verification_tokens SET used_at = $2 WHERE id = $1`
	_, err := s.pool.Exec(ctx, query, id, time.Now())
	return err
}

// DeleteExpiredVerificationTokens deletes all expired verification tokens.
func (s *PostgresStorage) DeleteExpiredVerificationTokens(ctx context.Context) error {
	query := `DELETE FROM verification_tokens WHERE expires_at < $1`
	_, err := s.pool.Exec(ctx, query, time.Now())
	return err
}

// GetRoleByID retrieves a role by its ID.
func (s *PostgresStorage) GetRoleByID(ctx context.Context, id uuid.UUID) (*storage.Role, error) {
	query := `SELECT id, tenant_id, name, description, is_system, created_at FROM roles WHERE id = $1`
	role := &storage.Role{}
	err := s.pool.QueryRow(ctx, query, id).Scan(&role.ID, &role.TenantID, &role.Name, &role.Description, &role.IsSystem, &role.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return role, nil
}

// GetRoleByName retrieves a role by its name.
func (s *PostgresStorage) GetRoleByName(ctx context.Context, name string) (*storage.Role, error) {
	query := `SELECT id, tenant_id, name, description, is_system, created_at FROM roles WHERE name = $1`
	role := &storage.Role{}
	err := s.pool.QueryRow(ctx, query, name).Scan(&role.ID, &role.TenantID, &role.Name, &role.Description, &role.IsSystem, &role.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return role, nil
}

// ListRoles retrieves all roles.
func (s *PostgresStorage) ListRoles(ctx context.Context) ([]*storage.Role, error) {
	query := `SELECT id, tenant_id, name, description, is_system, created_at FROM roles ORDER BY name`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []*storage.Role
	for rows.Next() {
		role := &storage.Role{}
		if err := rows.Scan(&role.ID, &role.TenantID, &role.Name, &role.Description, &role.IsSystem, &role.CreatedAt); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

// CreateRole creates a new role.
func (s *PostgresStorage) CreateRole(ctx context.Context, role *storage.Role) error {
	query := `
		INSERT INTO roles (id, tenant_id, name, description, is_system, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := s.pool.Exec(ctx, query,
		role.ID,
		role.TenantID,
		role.Name,
		role.Description,
		role.IsSystem,
		role.CreatedAt,
	)
	return err
}

// UpdateRole updates an existing role.
func (s *PostgresStorage) UpdateRole(ctx context.Context, role *storage.Role) error {
	query := `
		UPDATE roles 
		SET name = $2, description = $3
		WHERE id = $1 AND is_system = false
	`
	result, err := s.pool.Exec(ctx, query, role.ID, role.Name, role.Description)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// DeleteRole deletes a role (only non-system roles).
func (s *PostgresStorage) DeleteRole(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM roles WHERE id = $1 AND is_system = false`
	result, err := s.pool.Exec(ctx, query, id)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// GetUserRoles retrieves all roles assigned to a user.
func (s *PostgresStorage) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*storage.Role, error) {
	query := `
		SELECT r.id, r.tenant_id, r.name, r.description, r.is_system, r.created_at
		FROM roles r
		INNER JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1
		ORDER BY r.name
	`
	rows, err := s.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []*storage.Role
	for rows.Next() {
		role := &storage.Role{}
		if err := rows.Scan(&role.ID, &role.TenantID, &role.Name, &role.Description, &role.IsSystem, &role.CreatedAt); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

// AssignRoleToUser assigns a role to a user.
func (s *PostgresStorage) AssignRoleToUser(ctx context.Context, userID, roleID uuid.UUID, assignedBy *uuid.UUID) error {
	query := `
		INSERT INTO user_roles (user_id, role_id, assigned_at, assigned_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id, role_id) DO NOTHING
	`
	_, err := s.pool.Exec(ctx, query, userID, roleID, time.Now(), assignedBy)
	return err
}

// RemoveRoleFromUser removes a role from a user.
func (s *PostgresStorage) RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error {
	query := `DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2`
	_, err := s.pool.Exec(ctx, query, userID, roleID)
	return err
}

// UserHasRole checks if a user has a specific role.
func (s *PostgresStorage) UserHasRole(ctx context.Context, userID uuid.UUID, roleName string) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM user_roles ur
			INNER JOIN roles r ON ur.role_id = r.id
			WHERE ur.user_id = $1 AND r.name = $2
		)
	`
	var exists bool
	err := s.pool.QueryRow(ctx, query, userID, roleName).Scan(&exists)
	return exists, err
}

// GetRolePermissions retrieves all permissions for a role.
func (s *PostgresStorage) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*storage.Permission, error) {
	query := `
		SELECT p.id, p.name, p.description, p.created_at
		FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		WHERE rp.role_id = $1
		ORDER BY p.name
	`
	rows, err := s.pool.Query(ctx, query, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []*storage.Permission
	for rows.Next() {
		perm := &storage.Permission{}
		if err := rows.Scan(&perm.ID, &perm.Name, &perm.Description, &perm.CreatedAt); err != nil {
			return nil, err
		}
		perms = append(perms, perm)
	}
	return perms, rows.Err()
}

// GetUserPermissions retrieves all permissions for a user (through their roles).
func (s *PostgresStorage) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]*storage.Permission, error) {
	query := `
		SELECT DISTINCT p.id, p.name, p.description, p.created_at
		FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		INNER JOIN user_roles ur ON rp.role_id = ur.role_id
		WHERE ur.user_id = $1
		ORDER BY p.name
	`
	rows, err := s.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []*storage.Permission
	for rows.Next() {
		perm := &storage.Permission{}
		if err := rows.Scan(&perm.ID, &perm.Name, &perm.Description, &perm.CreatedAt); err != nil {
			return nil, err
		}
		perms = append(perms, perm)
	}
	return perms, rows.Err()
}

// AssignPermissionToRole assigns a permission to a role.
func (s *PostgresStorage) AssignPermissionToRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	query := `
		INSERT INTO role_permissions (role_id, permission_id)
		VALUES ($1, $2)
		ON CONFLICT (role_id, permission_id) DO NOTHING
	`
	_, err := s.pool.Exec(ctx, query, roleID, permissionID)
	return err
}

// RemovePermissionFromRole removes a permission from a role.
func (s *PostgresStorage) RemovePermissionFromRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	query := `DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = $2`
	_, err := s.pool.Exec(ctx, query, roleID, permissionID)
	return err
}

// GetPermissionByID retrieves a permission by its ID.
func (s *PostgresStorage) GetPermissionByID(ctx context.Context, id uuid.UUID) (*storage.Permission, error) {
	query := `SELECT id, name, description, created_at FROM permissions WHERE id = $1`
	perm := &storage.Permission{}
	err := s.pool.QueryRow(ctx, query, id).Scan(&perm.ID, &perm.Name, &perm.Description, &perm.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return perm, nil
}

// GetPermissionByName retrieves a permission by its name.
func (s *PostgresStorage) GetPermissionByName(ctx context.Context, name string) (*storage.Permission, error) {
	query := `SELECT id, name, description, created_at FROM permissions WHERE name = $1`
	perm := &storage.Permission{}
	err := s.pool.QueryRow(ctx, query, name).Scan(&perm.ID, &perm.Name, &perm.Description, &perm.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return perm, nil
}

// ListPermissions retrieves all permissions.
func (s *PostgresStorage) ListPermissions(ctx context.Context) ([]*storage.Permission, error) {
	query := `SELECT id, name, description, created_at FROM permissions ORDER BY name`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []*storage.Permission
	for rows.Next() {
		perm := &storage.Permission{}
		if err := rows.Scan(&perm.ID, &perm.Name, &perm.Description, &perm.CreatedAt); err != nil {
			return nil, err
		}
		perms = append(perms, perm)
	}
	return perms, rows.Err()
}

// UserHasPermission checks if a user has a specific permission.
func (s *PostgresStorage) UserHasPermission(ctx context.Context, userID uuid.UUID, permissionName string) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM permissions p
			INNER JOIN role_permissions rp ON p.id = rp.permission_id
			INNER JOIN user_roles ur ON rp.role_id = ur.role_id
			WHERE ur.user_id = $1 AND p.name = $2
		)
	`
	var exists bool
	err := s.pool.QueryRow(ctx, query, userID, permissionName).Scan(&exists)
	return exists, err
}

// ============================================================================
// TenantStorage methods
// ============================================================================

func (s *PostgresStorage) CreateTenant(ctx context.Context, tenant *storage.Tenant) error {
	query := `
		INSERT INTO tenants (id, name, slug, domain, logo_url, settings, plan, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	_, err := s.pool.Exec(ctx, query,
		tenant.ID, tenant.Name, tenant.Slug, tenant.Domain, tenant.LogoURL,
		tenant.Settings, tenant.Plan, tenant.IsActive, tenant.CreatedAt, tenant.UpdatedAt,
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
	_, err := s.pool.Exec(ctx, query,
		tenant.ID, tenant.Name, tenant.Slug, tenant.Domain, tenant.LogoURL,
		tenant.Settings, tenant.Plan, tenant.IsActive, tenant.UpdatedAt,
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

// ============================================================================
// DeviceStorage methods
// ============================================================================

func (s *PostgresStorage) CreateDevice(ctx context.Context, device *storage.UserDevice) error {
	query := `
		INSERT INTO user_devices (id, user_id, device_fingerprint, device_name, device_type, browser, browser_version,
		                          os, os_version, ip_address, location_country, location_city, is_trusted, is_current,
		                          last_seen_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
	`
	_, err := s.pool.Exec(ctx, query,
		device.ID, device.UserID, device.DeviceFingerprint, device.DeviceName, device.DeviceType,
		device.Browser, device.BrowserVersion, device.OS, device.OSVersion, device.IPAddress,
		device.LocationCountry, device.LocationCity, device.IsTrusted, device.IsCurrent,
		device.LastSeenAt, device.CreatedAt,
	)
	return err
}

func (s *PostgresStorage) GetDeviceByID(ctx context.Context, id uuid.UUID) (*storage.UserDevice, error) {
	query := `
		SELECT id, user_id, device_fingerprint, device_name, device_type, browser, browser_version,
		       os, os_version, ip_address, location_country, location_city, is_trusted, is_current,
		       last_seen_at, created_at
		FROM user_devices WHERE id = $1
	`
	device := &storage.UserDevice{}
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&device.ID, &device.UserID, &device.DeviceFingerprint, &device.DeviceName, &device.DeviceType,
		&device.Browser, &device.BrowserVersion, &device.OS, &device.OSVersion, &device.IPAddress,
		&device.LocationCountry, &device.LocationCity, &device.IsTrusted, &device.IsCurrent,
		&device.LastSeenAt, &device.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return device, nil
}

func (s *PostgresStorage) GetDeviceByFingerprint(ctx context.Context, userID uuid.UUID, fingerprint string) (*storage.UserDevice, error) {
	query := `
		SELECT id, user_id, device_fingerprint, device_name, device_type, browser, browser_version,
		       os, os_version, ip_address, location_country, location_city, is_trusted, is_current,
		       last_seen_at, created_at
		FROM user_devices WHERE user_id = $1 AND device_fingerprint = $2
	`
	device := &storage.UserDevice{}
	err := s.pool.QueryRow(ctx, query, userID, fingerprint).Scan(
		&device.ID, &device.UserID, &device.DeviceFingerprint, &device.DeviceName, &device.DeviceType,
		&device.Browser, &device.BrowserVersion, &device.OS, &device.OSVersion, &device.IPAddress,
		&device.LocationCountry, &device.LocationCity, &device.IsTrusted, &device.IsCurrent,
		&device.LastSeenAt, &device.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return device, nil
}

func (s *PostgresStorage) ListUserDevices(ctx context.Context, userID uuid.UUID) ([]*storage.UserDevice, error) {
	query := `
		SELECT id, user_id, device_fingerprint, device_name, device_type, browser, browser_version,
		       os, os_version, ip_address, location_country, location_city, is_trusted, is_current,
		       last_seen_at, created_at
		FROM user_devices WHERE user_id = $1 ORDER BY last_seen_at DESC NULLS LAST, created_at DESC
	`
	rows, err := s.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []*storage.UserDevice
	for rows.Next() {
		device := &storage.UserDevice{}
		err := rows.Scan(
			&device.ID, &device.UserID, &device.DeviceFingerprint, &device.DeviceName, &device.DeviceType,
			&device.Browser, &device.BrowserVersion, &device.OS, &device.OSVersion, &device.IPAddress,
			&device.LocationCountry, &device.LocationCity, &device.IsTrusted, &device.IsCurrent,
			&device.LastSeenAt, &device.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}
	return devices, rows.Err()
}

func (s *PostgresStorage) UpdateDevice(ctx context.Context, device *storage.UserDevice) error {
	query := `
		UPDATE user_devices
		SET device_name = $2, device_type = $3, browser = $4, browser_version = $5, os = $6, os_version = $7,
		    ip_address = $8, location_country = $9, location_city = $10, is_trusted = $11, is_current = $12,
		    last_seen_at = $13
		WHERE id = $1
	`
	_, err := s.pool.Exec(ctx, query,
		device.ID, device.DeviceName, device.DeviceType, device.Browser, device.BrowserVersion,
		device.OS, device.OSVersion, device.IPAddress, device.LocationCountry, device.LocationCity,
		device.IsTrusted, device.IsCurrent, device.LastSeenAt,
	)
	return err
}

func (s *PostgresStorage) DeleteDevice(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM user_devices WHERE id = $1`
	_, err := s.pool.Exec(ctx, query, id)
	return err
}

func (s *PostgresStorage) TrustDevice(ctx context.Context, id uuid.UUID, trusted bool) error {
	query := `UPDATE user_devices SET is_trusted = $2 WHERE id = $1`
	_, err := s.pool.Exec(ctx, query, id, trusted)
	return err
}

func (s *PostgresStorage) CreateLoginHistory(ctx context.Context, history *storage.LoginHistory) error {
	query := `
		INSERT INTO login_history (id, user_id, tenant_id, session_id, device_id, ip_address, user_agent,
		                          location_country, location_city, login_method, status, failure_reason, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`
	_, err := s.pool.Exec(ctx, query,
		history.ID, history.UserID, history.TenantID, history.SessionID, history.DeviceID,
		history.IPAddress, history.UserAgent, history.LocationCountry, history.LocationCity,
		history.LoginMethod, history.Status, history.FailureReason, history.CreatedAt,
	)
	return err
}

func (s *PostgresStorage) GetLoginHistory(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*storage.LoginHistory, error) {
	query := `
		SELECT id, user_id, tenant_id, session_id, device_id, ip_address, user_agent,
		       location_country, location_city, login_method, status, failure_reason, created_at
		FROM login_history WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3
	`
	rows, err := s.pool.Query(ctx, query, userID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []*storage.LoginHistory
	for rows.Next() {
		h := &storage.LoginHistory{}
		err := rows.Scan(
			&h.ID, &h.UserID, &h.TenantID, &h.SessionID, &h.DeviceID,
			&h.IPAddress, &h.UserAgent, &h.LocationCountry, &h.LocationCity,
			&h.LoginMethod, &h.Status, &h.FailureReason, &h.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		history = append(history, h)
	}
	return history, rows.Err()
}

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

// ============================================================================
// WebhookStorage methods
// ============================================================================

func (s *PostgresStorage) CreateWebhook(ctx context.Context, webhook *storage.Webhook) error {
	query := `
		INSERT INTO webhooks (id, tenant_id, name, description, url, secret, events, headers, is_active,
		                      retry_count, timeout_seconds, created_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`
	_, err := s.pool.Exec(ctx, query,
		webhook.ID, webhook.TenantID, webhook.Name, webhook.Description, webhook.URL, webhook.Secret,
		webhook.Events, webhook.Headers, webhook.IsActive, webhook.RetryCount, webhook.TimeoutSeconds,
		webhook.CreatedBy, webhook.CreatedAt, webhook.UpdatedAt,
	)
	return err
}

func (s *PostgresStorage) GetWebhookByID(ctx context.Context, id uuid.UUID) (*storage.Webhook, error) {
	query := `
		SELECT id, tenant_id, name, description, url, secret, events, headers, is_active, retry_count,
		       timeout_seconds, created_by, created_at, updated_at
		FROM webhooks WHERE id = $1
	`
	webhook := &storage.Webhook{}
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&webhook.ID, &webhook.TenantID, &webhook.Name, &webhook.Description, &webhook.URL, &webhook.Secret,
		&webhook.Events, &webhook.Headers, &webhook.IsActive, &webhook.RetryCount, &webhook.TimeoutSeconds,
		&webhook.CreatedBy, &webhook.CreatedAt, &webhook.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return webhook, nil
}

func (s *PostgresStorage) ListWebhooks(ctx context.Context, tenantID *uuid.UUID, limit, offset int) ([]*storage.Webhook, error) {
	var query string
	var args []interface{}
	
	if tenantID != nil {
		query = `
			SELECT id, tenant_id, name, description, url, secret, events, headers, is_active, retry_count,
			       timeout_seconds, created_by, created_at, updated_at
			FROM webhooks WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3
		`
		args = []interface{}{*tenantID, limit, offset}
	} else {
		query = `
			SELECT id, tenant_id, name, description, url, secret, events, headers, is_active, retry_count,
			       timeout_seconds, created_by, created_at, updated_at
			FROM webhooks ORDER BY created_at DESC LIMIT $1 OFFSET $2
		`
		args = []interface{}{limit, offset}
	}
	
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var webhooks []*storage.Webhook
	for rows.Next() {
		webhook := &storage.Webhook{}
		err := rows.Scan(
			&webhook.ID, &webhook.TenantID, &webhook.Name, &webhook.Description, &webhook.URL, &webhook.Secret,
			&webhook.Events, &webhook.Headers, &webhook.IsActive, &webhook.RetryCount, &webhook.TimeoutSeconds,
			&webhook.CreatedBy, &webhook.CreatedAt, &webhook.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		webhooks = append(webhooks, webhook)
	}
	return webhooks, rows.Err()
}

func (s *PostgresStorage) ListWebhooksByEvent(ctx context.Context, tenantID *uuid.UUID, eventType string) ([]*storage.Webhook, error) {
	var query string
	var args []interface{}
	
	if tenantID != nil {
		query = `
			SELECT id, tenant_id, name, description, url, secret, events, headers, is_active, retry_count,
			       timeout_seconds, created_by, created_at, updated_at
			FROM webhooks WHERE tenant_id = $1 AND is_active = true AND $2 = ANY(events)
		`
		args = []interface{}{*tenantID, eventType}
	} else {
		query = `
			SELECT id, tenant_id, name, description, url, secret, events, headers, is_active, retry_count,
			       timeout_seconds, created_by, created_at, updated_at
			FROM webhooks WHERE is_active = true AND $1 = ANY(events)
		`
		args = []interface{}{eventType}
	}
	
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var webhooks []*storage.Webhook
	for rows.Next() {
		webhook := &storage.Webhook{}
		err := rows.Scan(
			&webhook.ID, &webhook.TenantID, &webhook.Name, &webhook.Description, &webhook.URL, &webhook.Secret,
			&webhook.Events, &webhook.Headers, &webhook.IsActive, &webhook.RetryCount, &webhook.TimeoutSeconds,
			&webhook.CreatedBy, &webhook.CreatedAt, &webhook.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		webhooks = append(webhooks, webhook)
	}
	return webhooks, rows.Err()
}

func (s *PostgresStorage) UpdateWebhook(ctx context.Context, webhook *storage.Webhook) error {
	query := `
		UPDATE webhooks
		SET name = $2, description = $3, url = $4, events = $5, headers = $6, is_active = $7,
		    retry_count = $8, timeout_seconds = $9, updated_at = $10
		WHERE id = $1
	`
	webhook.UpdatedAt = time.Now()
	_, err := s.pool.Exec(ctx, query,
		webhook.ID, webhook.Name, webhook.Description, webhook.URL, webhook.Events, webhook.Headers,
		webhook.IsActive, webhook.RetryCount, webhook.TimeoutSeconds, webhook.UpdatedAt,
	)
	return err
}

func (s *PostgresStorage) DeleteWebhook(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM webhooks WHERE id = $1`
	_, err := s.pool.Exec(ctx, query, id)
	return err
}

func (s *PostgresStorage) CreateWebhookDelivery(ctx context.Context, delivery *storage.WebhookDelivery) error {
	query := `
		INSERT INTO webhook_deliveries (id, webhook_id, event_id, event_type, payload, response_status_code,
		                               response_time_ms, attempt_number, status, error_message, next_retry_at,
		                               created_at, completed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`
	_, err := s.pool.Exec(ctx, query,
		delivery.ID, delivery.WebhookID, delivery.EventID, delivery.EventType, delivery.Payload,
		delivery.ResponseStatusCode, delivery.ResponseTimeMs, delivery.AttemptNumber, delivery.Status,
		delivery.ErrorMessage, delivery.NextRetryAt, delivery.CreatedAt, delivery.CompletedAt,
	)
	return err
}

func (s *PostgresStorage) UpdateWebhookDelivery(ctx context.Context, delivery *storage.WebhookDelivery) error {
	query := `
		UPDATE webhook_deliveries
		SET response_status_code = $2, response_time_ms = $3, attempt_number = $4, status = $5,
		    error_message = $6, next_retry_at = $7, completed_at = $8
		WHERE id = $1
	`
	_, err := s.pool.Exec(ctx, query,
		delivery.ID, delivery.ResponseStatusCode, delivery.ResponseTimeMs, delivery.AttemptNumber,
		delivery.Status, delivery.ErrorMessage, delivery.NextRetryAt, delivery.CompletedAt,
	)
	return err
}

func (s *PostgresStorage) GetPendingDeliveries(ctx context.Context, limit int) ([]*storage.WebhookDelivery, error) {
	query := `
		SELECT id, webhook_id, event_id, event_type, payload, response_status_code, response_time_ms,
		       attempt_number, status, error_message, next_retry_at, created_at, completed_at
		FROM webhook_deliveries
		WHERE status IN ('pending', 'retrying') AND (next_retry_at IS NULL OR next_retry_at <= now())
		ORDER BY created_at ASC LIMIT $1
	`
	rows, err := s.pool.Query(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var deliveries []*storage.WebhookDelivery
	for rows.Next() {
		delivery := &storage.WebhookDelivery{}
		err := rows.Scan(
			&delivery.ID, &delivery.WebhookID, &delivery.EventID, &delivery.EventType, &delivery.Payload,
			&delivery.ResponseStatusCode, &delivery.ResponseTimeMs, &delivery.AttemptNumber, &delivery.Status,
			&delivery.ErrorMessage, &delivery.NextRetryAt, &delivery.CreatedAt, &delivery.CompletedAt,
		)
		if err != nil {
			return nil, err
		}
		deliveries = append(deliveries, delivery)
	}
	return deliveries, rows.Err()
}

func (s *PostgresStorage) GetWebhookDeliveries(ctx context.Context, webhookID uuid.UUID, limit, offset int) ([]*storage.WebhookDelivery, error) {
	query := `
		SELECT id, webhook_id, event_id, event_type, payload, response_status_code, response_time_ms,
		       attempt_number, status, error_message, next_retry_at, created_at, completed_at
		FROM webhook_deliveries WHERE webhook_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3
	`
	rows, err := s.pool.Query(ctx, query, webhookID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var deliveries []*storage.WebhookDelivery
	for rows.Next() {
		delivery := &storage.WebhookDelivery{}
		err := rows.Scan(
			&delivery.ID, &delivery.WebhookID, &delivery.EventID, &delivery.EventType, &delivery.Payload,
			&delivery.ResponseStatusCode, &delivery.ResponseTimeMs, &delivery.AttemptNumber, &delivery.Status,
			&delivery.ErrorMessage, &delivery.NextRetryAt, &delivery.CreatedAt, &delivery.CompletedAt,
		)
		if err != nil {
			return nil, err
		}
		deliveries = append(deliveries, delivery)
	}
	return deliveries, rows.Err()
}

// ============================================================================
// InvitationStorage methods
// ============================================================================

func (s *PostgresStorage) CreateInvitation(ctx context.Context, invitation *storage.UserInvitation) error {
	query := `
		INSERT INTO user_invitations (id, tenant_id, email, first_name, last_name, role_ids, group_ids,
		                              token_hash, invited_by, message, expires_at, accepted_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`
	_, err := s.pool.Exec(ctx, query,
		invitation.ID, invitation.TenantID, invitation.Email, invitation.FirstName, invitation.LastName,
		invitation.RoleIDs, invitation.GroupIDs, invitation.TokenHash, invitation.InvitedBy,
		invitation.Message, invitation.ExpiresAt, invitation.AcceptedAt, invitation.CreatedAt,
	)
	return err
}

func (s *PostgresStorage) GetInvitationByID(ctx context.Context, id uuid.UUID) (*storage.UserInvitation, error) {
	query := `
		SELECT id, tenant_id, email, first_name, last_name, role_ids, group_ids, token_hash, invited_by,
		       message, expires_at, accepted_at, created_at
		FROM user_invitations WHERE id = $1
	`
	invitation := &storage.UserInvitation{}
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&invitation.ID, &invitation.TenantID, &invitation.Email, &invitation.FirstName, &invitation.LastName,
		&invitation.RoleIDs, &invitation.GroupIDs, &invitation.TokenHash, &invitation.InvitedBy,
		&invitation.Message, &invitation.ExpiresAt, &invitation.AcceptedAt, &invitation.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return invitation, nil
}

func (s *PostgresStorage) GetInvitationByToken(ctx context.Context, tokenHash string) (*storage.UserInvitation, error) {
	query := `
		SELECT id, tenant_id, email, first_name, last_name, role_ids, group_ids, token_hash, invited_by,
		       message, expires_at, accepted_at, created_at
		FROM user_invitations WHERE token_hash = $1
	`
	invitation := &storage.UserInvitation{}
	err := s.pool.QueryRow(ctx, query, tokenHash).Scan(
		&invitation.ID, &invitation.TenantID, &invitation.Email, &invitation.FirstName, &invitation.LastName,
		&invitation.RoleIDs, &invitation.GroupIDs, &invitation.TokenHash, &invitation.InvitedBy,
		&invitation.Message, &invitation.ExpiresAt, &invitation.AcceptedAt, &invitation.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return invitation, nil
}

func (s *PostgresStorage) GetInvitationByEmail(ctx context.Context, tenantID *uuid.UUID, email string) (*storage.UserInvitation, error) {
	var query string
	var args []interface{}
	
	if tenantID != nil {
		query = `
			SELECT id, tenant_id, email, first_name, last_name, role_ids, group_ids, token_hash, invited_by,
			       message, expires_at, accepted_at, created_at
			FROM user_invitations WHERE tenant_id = $1 AND email = $2 AND accepted_at IS NULL
			ORDER BY created_at DESC LIMIT 1
		`
		args = []interface{}{*tenantID, email}
	} else {
		query = `
			SELECT id, tenant_id, email, first_name, last_name, role_ids, group_ids, token_hash, invited_by,
			       message, expires_at, accepted_at, created_at
			FROM user_invitations WHERE tenant_id IS NULL AND email = $1 AND accepted_at IS NULL
			ORDER BY created_at DESC LIMIT 1
		`
		args = []interface{}{email}
	}
	
	invitation := &storage.UserInvitation{}
	err := s.pool.QueryRow(ctx, query, args...).Scan(
		&invitation.ID, &invitation.TenantID, &invitation.Email, &invitation.FirstName, &invitation.LastName,
		&invitation.RoleIDs, &invitation.GroupIDs, &invitation.TokenHash, &invitation.InvitedBy,
		&invitation.Message, &invitation.ExpiresAt, &invitation.AcceptedAt, &invitation.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return invitation, nil
}

func (s *PostgresStorage) ListInvitations(ctx context.Context, tenantID *uuid.UUID, limit, offset int) ([]*storage.UserInvitation, error) {
	var query string
	var args []interface{}
	
	if tenantID != nil {
		query = `
			SELECT id, tenant_id, email, first_name, last_name, role_ids, group_ids, token_hash, invited_by,
			       message, expires_at, accepted_at, created_at
			FROM user_invitations WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3
		`
		args = []interface{}{*tenantID, limit, offset}
	} else {
		query = `
			SELECT id, tenant_id, email, first_name, last_name, role_ids, group_ids, token_hash, invited_by,
			       message, expires_at, accepted_at, created_at
			FROM user_invitations WHERE tenant_id IS NULL ORDER BY created_at DESC LIMIT $1 OFFSET $2
		`
		args = []interface{}{limit, offset}
	}
	
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var invitations []*storage.UserInvitation
	for rows.Next() {
		invitation := &storage.UserInvitation{}
		err := rows.Scan(
			&invitation.ID, &invitation.TenantID, &invitation.Email, &invitation.FirstName, &invitation.LastName,
			&invitation.RoleIDs, &invitation.GroupIDs, &invitation.TokenHash, &invitation.InvitedBy,
			&invitation.Message, &invitation.ExpiresAt, &invitation.AcceptedAt, &invitation.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		invitations = append(invitations, invitation)
	}
	return invitations, rows.Err()
}

func (s *PostgresStorage) AcceptInvitation(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE user_invitations SET accepted_at = now() WHERE id = $1`
	_, err := s.pool.Exec(ctx, query, id)
	return err
}

func (s *PostgresStorage) UpdateInvitation(ctx context.Context, invitation *storage.UserInvitation) error {
	query := `
		UPDATE user_invitations
		SET token_hash = $2, expires_at = $3, first_name = $4, last_name = $5, message = $6
		WHERE id = $1
	`
	_, err := s.pool.Exec(ctx, query,
		invitation.ID,
		invitation.TokenHash,
		invitation.ExpiresAt,
		invitation.FirstName,
		invitation.LastName,
		invitation.Message,
	)
	return err
}

func (s *PostgresStorage) DeleteInvitation(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM user_invitations WHERE id = $1`
	_, err := s.pool.Exec(ctx, query, id)
	return err
}

func (s *PostgresStorage) DeleteExpiredInvitations(ctx context.Context) error {
	query := `DELETE FROM user_invitations WHERE expires_at < now() AND accepted_at IS NULL`
	_, err := s.pool.Exec(ctx, query)
	return err
}

// ============================================================================
// SystemSettingsStorage methods
// ============================================================================

func (s *PostgresStorage) GetSetting(ctx context.Context, key string) (*storage.SystemSetting, error) {
	query := `
		SELECT key, value, category, is_secret, description, updated_at
		FROM system_settings WHERE key = $1
	`
	setting := &storage.SystemSetting{}
	err := s.pool.QueryRow(ctx, query, key).Scan(
		&setting.Key, &setting.Value, &setting.Category, &setting.IsSecret,
		&setting.Description, &setting.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return setting, nil
}

func (s *PostgresStorage) ListSettings(ctx context.Context, category string) ([]*storage.SystemSetting, error) {
	var query string
	var args []interface{}

	if category != "" {
		query = `
			SELECT key, value, category, is_secret, description, updated_at
			FROM system_settings WHERE category = $1 ORDER BY key
		`
		args = []interface{}{category}
	} else {
		query = `
			SELECT key, value, category, is_secret, description, updated_at
			FROM system_settings ORDER BY category, key
		`
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var settings []*storage.SystemSetting
	for rows.Next() {
		setting := &storage.SystemSetting{}
		err := rows.Scan(
			&setting.Key, &setting.Value, &setting.Category, &setting.IsSecret,
			&setting.Description, &setting.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		settings = append(settings, setting)
	}
	return settings, rows.Err()
}

func (s *PostgresStorage) UpdateSetting(ctx context.Context, key string, value interface{}) error {
	query := `
		UPDATE system_settings
		SET value = $2, updated_at = now()
		WHERE key = $1
	`
	_, err := s.pool.Exec(ctx, query, key, value)
	return err
}

// OAuthStateStorage implementation

// CreateOAuthState stores a new OAuth state for CSRF protection.
func (s *PostgresStorage) CreateOAuthState(ctx context.Context, state *storage.SocialLoginState) error {
	query := `
		INSERT INTO social_login_states (id, tenant_id, provider, state_hash, redirect_uri, code_verifier, metadata, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err := s.pool.Exec(ctx, query,
		state.ID,
		state.TenantID,
		state.Provider,
		state.StateHash,
		state.RedirectURI,
		state.CodeVerifier,
		state.Metadata,
		state.ExpiresAt,
		state.CreatedAt,
	)
	return err
}

// GetOAuthStateByHash retrieves an OAuth state by its hash.
func (s *PostgresStorage) GetOAuthStateByHash(ctx context.Context, stateHash string) (*storage.SocialLoginState, error) {
	query := `
		SELECT id, tenant_id, provider, state_hash, redirect_uri, code_verifier, metadata, expires_at, created_at
		FROM social_login_states
		WHERE state_hash = $1 AND expires_at > now()
	`
	state := &storage.SocialLoginState{}
	err := s.pool.QueryRow(ctx, query, stateHash).Scan(
		&state.ID,
		&state.TenantID,
		&state.Provider,
		&state.StateHash,
		&state.RedirectURI,
		&state.CodeVerifier,
		&state.Metadata,
		&state.ExpiresAt,
		&state.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return state, nil
}

// DeleteOAuthState deletes an OAuth state by ID.
func (s *PostgresStorage) DeleteOAuthState(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM social_login_states WHERE id = $1`
	_, err := s.pool.Exec(ctx, query, id)
	return err
}

// DeleteExpiredOAuthStates removes all expired OAuth states.
func (s *PostgresStorage) DeleteExpiredOAuthStates(ctx context.Context) error {
	query := `DELETE FROM social_login_states WHERE expires_at < now()`
	_, err := s.pool.Exec(ctx, query)
	return err
}

// ============================================================================
// Email Template Storage
// ============================================================================

// GetEmailTemplate retrieves an email template by tenant and type.
// Falls back to global template (tenant_id IS NULL) if tenant-specific not found.
func (s *PostgresStorage) GetEmailTemplate(ctx context.Context, tenantID *uuid.UUID, templateType string) (*storage.EmailTemplate, error) {
	query := `
		SELECT id, tenant_id, type, subject, html_body, text_body, is_active, created_at, updated_at
		FROM email_templates
		WHERE type = $1 AND (tenant_id = $2 OR (tenant_id IS NULL AND $2 IS NULL))
		ORDER BY tenant_id NULLS LAST
		LIMIT 1
	`
	template := &storage.EmailTemplate{}
	err := s.pool.QueryRow(ctx, query, templateType, tenantID).Scan(
		&template.ID,
		&template.TenantID,
		&template.Type,
		&template.Subject,
		&template.HTMLBody,
		&template.TextBody,
		&template.IsActive,
		&template.CreatedAt,
		&template.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return template, nil
}

// ListEmailTemplates lists all email templates for a tenant.
func (s *PostgresStorage) ListEmailTemplates(ctx context.Context, tenantID *uuid.UUID) ([]*storage.EmailTemplate, error) {
	query := `
		SELECT id, tenant_id, type, subject, html_body, text_body, is_active, created_at, updated_at
		FROM email_templates
		WHERE tenant_id = $1 OR (tenant_id IS NULL AND $1 IS NULL)
		ORDER BY type
	`
	rows, err := s.pool.Query(ctx, query, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var templates []*storage.EmailTemplate
	for rows.Next() {
		template := &storage.EmailTemplate{}
		if err := rows.Scan(
			&template.ID,
			&template.TenantID,
			&template.Type,
			&template.Subject,
			&template.HTMLBody,
			&template.TextBody,
			&template.IsActive,
			&template.CreatedAt,
			&template.UpdatedAt,
		); err != nil {
			return nil, err
		}
		templates = append(templates, template)
	}
	return templates, rows.Err()
}

// UpsertEmailTemplate creates or updates an email template.
func (s *PostgresStorage) UpsertEmailTemplate(ctx context.Context, template *storage.EmailTemplate) error {
	query := `
		INSERT INTO email_templates (id, tenant_id, type, subject, html_body, text_body, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (tenant_id, type) DO UPDATE SET
			subject = EXCLUDED.subject,
			html_body = EXCLUDED.html_body,
			text_body = EXCLUDED.text_body,
			is_active = EXCLUDED.is_active,
			updated_at = EXCLUDED.updated_at
	`
	if template.ID == uuid.Nil {
		template.ID = uuid.New()
	}
	now := time.Now()
	if template.CreatedAt.IsZero() {
		template.CreatedAt = now
	}
	template.UpdatedAt = now

	_, err := s.pool.Exec(ctx, query,
		template.ID,
		template.TenantID,
		template.Type,
		template.Subject,
		template.HTMLBody,
		template.TextBody,
		template.IsActive,
		template.CreatedAt,
		template.UpdatedAt,
	)
	return err
}

// DeleteEmailTemplate deletes an email template.
func (s *PostgresStorage) DeleteEmailTemplate(ctx context.Context, tenantID *uuid.UUID, templateType string) error {
	query := `
		DELETE FROM email_templates
		WHERE type = $1 AND (tenant_id = $2 OR (tenant_id IS NULL AND $2 IS NULL))
	`
	_, err := s.pool.Exec(ctx, query, templateType, tenantID)
	return err
}

// GetEmailBranding retrieves email branding for a tenant.
// Falls back to global branding (tenant_id IS NULL) if tenant-specific not found.
func (s *PostgresStorage) GetEmailBranding(ctx context.Context, tenantID *uuid.UUID) (*storage.EmailBranding, error) {
	query := `
		SELECT id, tenant_id, app_name, logo_url, primary_color, secondary_color, 
		       company_name, support_email, footer_text, created_at, updated_at
		FROM email_branding
		WHERE tenant_id = $1 OR tenant_id IS NULL
		ORDER BY tenant_id NULLS LAST
		LIMIT 1
	`
	branding := &storage.EmailBranding{}
	err := s.pool.QueryRow(ctx, query, tenantID).Scan(
		&branding.ID,
		&branding.TenantID,
		&branding.AppName,
		&branding.LogoURL,
		&branding.PrimaryColor,
		&branding.SecondaryColor,
		&branding.CompanyName,
		&branding.SupportEmail,
		&branding.FooterText,
		&branding.CreatedAt,
		&branding.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Return default branding
			return &storage.EmailBranding{
				AppName:        "ModernAuth",
				PrimaryColor:   "#667eea",
				SecondaryColor: "#764ba2",
			}, nil
		}
		return nil, err
	}
	return branding, nil
}

// UpsertEmailBranding creates or updates email branding.
func (s *PostgresStorage) UpsertEmailBranding(ctx context.Context, branding *storage.EmailBranding) error {
	query := `
		INSERT INTO email_branding (id, tenant_id, app_name, logo_url, primary_color, secondary_color, 
		                            company_name, support_email, footer_text, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (tenant_id) DO UPDATE SET
			app_name = EXCLUDED.app_name,
			logo_url = EXCLUDED.logo_url,
			primary_color = EXCLUDED.primary_color,
			secondary_color = EXCLUDED.secondary_color,
			company_name = EXCLUDED.company_name,
			support_email = EXCLUDED.support_email,
			footer_text = EXCLUDED.footer_text,
			updated_at = EXCLUDED.updated_at
	`
	if branding.ID == uuid.Nil {
		branding.ID = uuid.New()
	}
	now := time.Now()
	if branding.CreatedAt.IsZero() {
		branding.CreatedAt = now
	}
	branding.UpdatedAt = now

	_, err := s.pool.Exec(ctx, query,
		branding.ID,
		branding.TenantID,
		branding.AppName,
		branding.LogoURL,
		branding.PrimaryColor,
		branding.SecondaryColor,
		branding.CompanyName,
		branding.SupportEmail,
		branding.FooterText,
		branding.CreatedAt,
		branding.UpdatedAt,
	)
	return err
}

// ============================================================================
// Email Dead Letter Storage
// ============================================================================

// CreateEmailDeadLetter stores a failed email in the dead letter queue.
func (s *PostgresStorage) CreateEmailDeadLetter(ctx context.Context, dl *storage.EmailDeadLetter) error {
	query := `
		INSERT INTO email_dead_letters (id, tenant_id, job_type, recipient, subject, payload, error_message, attempts, created_at, failed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	if dl.ID == uuid.Nil {
		dl.ID = uuid.New()
	}
	now := time.Now()
	if dl.CreatedAt.IsZero() {
		dl.CreatedAt = now
	}
	if dl.FailedAt.IsZero() {
		dl.FailedAt = now
	}

	_, err := s.pool.Exec(ctx, query,
		dl.ID,
		dl.TenantID,
		dl.JobType,
		dl.Recipient,
		dl.Subject,
		dl.Payload,
		dl.ErrorMessage,
		dl.Attempts,
		dl.CreatedAt,
		dl.FailedAt,
	)
	return err
}

// ListEmailDeadLetters lists failed emails from the dead letter queue.
func (s *PostgresStorage) ListEmailDeadLetters(ctx context.Context, tenantID *uuid.UUID, resolved bool, limit, offset int) ([]*storage.EmailDeadLetter, error) {
	query := `
		SELECT id, tenant_id, job_type, recipient, subject, payload, error_message, attempts, created_at, failed_at, retried_at, resolved
		FROM email_dead_letters
		WHERE (tenant_id = $1 OR ($1 IS NULL AND tenant_id IS NULL)) AND resolved = $2
		ORDER BY failed_at DESC
		LIMIT $3 OFFSET $4
	`
	rows, err := s.pool.Query(ctx, query, tenantID, resolved, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var deadLetters []*storage.EmailDeadLetter
	for rows.Next() {
		dl := &storage.EmailDeadLetter{}
		if err := rows.Scan(
			&dl.ID,
			&dl.TenantID,
			&dl.JobType,
			&dl.Recipient,
			&dl.Subject,
			&dl.Payload,
			&dl.ErrorMessage,
			&dl.Attempts,
			&dl.CreatedAt,
			&dl.FailedAt,
			&dl.RetriedAt,
			&dl.Resolved,
		); err != nil {
			return nil, err
		}
		deadLetters = append(deadLetters, dl)
	}
	return deadLetters, rows.Err()
}

// MarkEmailDeadLetterResolved marks a dead letter as resolved.
func (s *PostgresStorage) MarkEmailDeadLetterResolved(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE email_dead_letters SET resolved = true, retried_at = $1 WHERE id = $2`
	_, err := s.pool.Exec(ctx, query, time.Now(), id)
	return err
}
