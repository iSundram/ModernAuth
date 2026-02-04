package pg

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/iSundram/ModernAuth/internal/storage"
)

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

// GetRoleByIDAndTenant retrieves a role by its ID within a specific tenant context.
// Returns roles that belong to the tenant or are system roles (tenant_id IS NULL).
func (s *PostgresStorage) GetRoleByIDAndTenant(ctx context.Context, id uuid.UUID, tenantID *uuid.UUID) (*storage.Role, error) {
	var query string
	var args []interface{}

	if tenantID != nil {
		query = `SELECT id, tenant_id, name, description, is_system, created_at FROM roles WHERE id = $1 AND (tenant_id = $2 OR tenant_id IS NULL OR is_system = true)`
		args = []interface{}{id, *tenantID}
	} else {
		query = `SELECT id, tenant_id, name, description, is_system, created_at FROM roles WHERE id = $1 AND (tenant_id IS NULL OR is_system = true)`
		args = []interface{}{id}
	}

	role := &storage.Role{}
	err := s.pool.QueryRow(ctx, query, args...).Scan(&role.ID, &role.TenantID, &role.Name, &role.Description, &role.IsSystem, &role.CreatedAt)
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

// GetRoleByNameAndTenant retrieves a role by its name within a specific tenant context.
// Returns roles that belong to the tenant or are system roles.
func (s *PostgresStorage) GetRoleByNameAndTenant(ctx context.Context, name string, tenantID *uuid.UUID) (*storage.Role, error) {
	var query string
	var args []interface{}

	if tenantID != nil {
		query = `SELECT id, tenant_id, name, description, is_system, created_at FROM roles WHERE name = $1 AND (tenant_id = $2 OR tenant_id IS NULL OR is_system = true)`
		args = []interface{}{name, *tenantID}
	} else {
		query = `SELECT id, tenant_id, name, description, is_system, created_at FROM roles WHERE name = $1 AND (tenant_id IS NULL OR is_system = true)`
		args = []interface{}{name}
	}

	role := &storage.Role{}
	err := s.pool.QueryRow(ctx, query, args...).Scan(&role.ID, &role.TenantID, &role.Name, &role.Description, &role.IsSystem, &role.CreatedAt)
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

// ListRolesByTenant retrieves roles for a specific tenant plus system roles.
func (s *PostgresStorage) ListRolesByTenant(ctx context.Context, tenantID uuid.UUID) ([]*storage.Role, error) {
	query := `SELECT id, tenant_id, name, description, is_system, created_at FROM roles WHERE tenant_id = $1 OR tenant_id IS NULL OR is_system = true ORDER BY name`
	rows, err := s.pool.Query(ctx, query, tenantID)
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
