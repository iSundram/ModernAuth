// Package pg provides PostgreSQL implementation of the storage interfaces.
package pg

import (
	"context"
	"errors"
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
		INSERT INTO users (id, email, phone, username, hashed_password, is_email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := s.pool.Exec(ctx, query,
		user.ID,
		user.Email,
		user.Phone,
		user.Username,
		user.HashedPassword,
		user.IsEmailVerified,
		user.CreatedAt,
		user.UpdatedAt,
	)
	return err
}

// GetUserByID retrieves a user by their ID.
func (s *PostgresStorage) GetUserByID(ctx context.Context, id uuid.UUID) (*storage.User, error) {
	query := `
		SELECT id, email, phone, username, hashed_password, is_email_verified, created_at, updated_at
		FROM users
		WHERE id = $1
	`
	user := &storage.User{}
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.Email,
		&user.Phone,
		&user.Username,
		&user.HashedPassword,
		&user.IsEmailVerified,
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
		SELECT id, email, phone, username, hashed_password, is_email_verified, created_at, updated_at
		FROM users
		WHERE email = $1
	`
	user := &storage.User{}
	err := s.pool.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.Phone,
		&user.Username,
		&user.HashedPassword,
		&user.IsEmailVerified,
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

// ListUsers retrieves all users from the database.
func (s *PostgresStorage) ListUsers(ctx context.Context) ([]*storage.User, error) {
	query := `
		SELECT id, email, phone, username, hashed_password, is_email_verified, created_at, updated_at
		FROM users
		ORDER BY created_at DESC
	`
	rows, err := s.pool.Query(ctx, query)
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
			&user.HashedPassword,
			&user.IsEmailVerified,
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

// UpdateUser updates an existing user.
func (s *PostgresStorage) UpdateUser(ctx context.Context, user *storage.User) error {
	query := `
		UPDATE users
		SET email = $2, phone = $3, username = $4, hashed_password = $5, is_email_verified = $6, updated_at = $7
		WHERE id = $1
	`
	user.UpdatedAt = time.Now()
	_, err := s.pool.Exec(ctx, query,
		user.ID,
		user.Email,
		user.Phone,
		user.Username,
		user.HashedPassword,
		user.IsEmailVerified,
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
		INSERT INTO sessions (id, user_id, fingerprint, created_at, expires_at, revoked, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := s.pool.Exec(ctx, query,
		session.ID,
		session.UserID,
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
		SELECT id, user_id, fingerprint, created_at, expires_at, revoked, metadata
		FROM sessions
		WHERE id = $1
	`
	session := &storage.Session{}
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&session.ID,
		&session.UserID,
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

// GetAuditLogs retrieves audit logs with optional user filtering.
func (s *PostgresStorage) GetAuditLogs(ctx context.Context, userID *uuid.UUID, limit, offset int) ([]*storage.AuditLog, error) {
	var query string
	var rows pgx.Rows
	var err error

	if userID != nil {
		query = `
			SELECT id, user_id, actor_id, event_type, ip, user_agent, data, created_at
			FROM audit_logs
			WHERE user_id = $1
			ORDER BY created_at DESC
			LIMIT $2 OFFSET $3
		`
		rows, err = s.pool.Query(ctx, query, userID, limit, offset)
	} else {
		query = `
			SELECT id, user_id, actor_id, event_type, ip, user_agent, data, created_at
			FROM audit_logs
			ORDER BY created_at DESC
			LIMIT $1 OFFSET $2
		`
		rows, err = s.pool.Query(ctx, query, limit, offset)
	}

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []*storage.AuditLog
	for rows.Next() {
		log := &storage.AuditLog{}
		err := rows.Scan(
			&log.ID,
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
	query := `SELECT id, name, description, created_at FROM roles WHERE id = $1`
	role := &storage.Role{}
	err := s.pool.QueryRow(ctx, query, id).Scan(&role.ID, &role.Name, &role.Description, &role.CreatedAt)
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
	query := `SELECT id, name, description, created_at FROM roles WHERE name = $1`
	role := &storage.Role{}
	err := s.pool.QueryRow(ctx, query, name).Scan(&role.ID, &role.Name, &role.Description, &role.CreatedAt)
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
	query := `SELECT id, name, description, created_at FROM roles ORDER BY name`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []*storage.Role
	for rows.Next() {
		role := &storage.Role{}
		if err := rows.Scan(&role.ID, &role.Name, &role.Description, &role.CreatedAt); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

// GetUserRoles retrieves all roles assigned to a user.
func (s *PostgresStorage) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*storage.Role, error) {
	query := `
		SELECT r.id, r.name, r.description, r.created_at
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
		if err := rows.Scan(&role.ID, &role.Name, &role.Description, &role.CreatedAt); err != nil {
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
