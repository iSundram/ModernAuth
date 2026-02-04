// Package auth provides authentication services for ModernAuth.
package auth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
)

var (
	// ErrRoleExists indicates a role with the given name already exists.
	ErrRoleExists = errors.New("role already exists")
	// ErrRoleNotFound indicates the role was not found.
	ErrRoleNotFound = errors.New("role not found")
	// ErrCannotModifySystemRole indicates an attempt to modify a system role.
	ErrCannotModifySystemRole = errors.New("cannot modify system role")
	// ErrPermissionNotFound indicates the permission was not found.
	ErrPermissionNotFound = errors.New("permission not found")
)

// CreateRoleRequest represents a request to create a role.
type CreateRoleRequest struct {
	TenantID    *uuid.UUID
	Name        string
	Description *string
}

// UpdateRoleRequest represents a request to update a role.
type UpdateRoleRequest struct {
	Name        *string
	Description *string
}

// GetAuditLogs retrieves audit logs with pagination and filtering.
func (s *AuthService) GetAuditLogs(ctx context.Context, userID *uuid.UUID, eventType *string, limit, offset int) ([]*storage.AuditLog, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	return s.storage.GetAuditLogs(ctx, userID, eventType, limit, offset)
}

// GetUserRoles retrieves all roles assigned to a user.
func (s *AuthService) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*storage.Role, error) {
	return s.storage.GetUserRoles(ctx, userID)
}

// AssignRole assigns a role to a user.
func (s *AuthService) AssignRole(ctx context.Context, userID, roleID uuid.UUID, assignedBy *uuid.UUID) error {
	if err := s.storage.AssignRoleToUser(ctx, userID, roleID, assignedBy); err != nil {
		return err
	}
	s.logAuditEvent(ctx, &userID, assignedBy, "role.assigned", nil, nil, map[string]interface{}{
		"role_id": roleID.String(),
	})
	return nil
}

// RemoveRole removes a role from a user.
func (s *AuthService) RemoveRole(ctx context.Context, userID, roleID uuid.UUID, actorID *uuid.UUID) error {
	if err := s.storage.RemoveRoleFromUser(ctx, userID, roleID); err != nil {
		return err
	}
	s.logAuditEvent(ctx, &userID, actorID, "role.removed", nil, nil, map[string]interface{}{
		"role_id": roleID.String(),
	})
	return nil
}

// UserHasRole checks if a user has a specific role.
func (s *AuthService) UserHasRole(ctx context.Context, userID uuid.UUID, roleName string) (bool, error) {
	return s.storage.UserHasRole(ctx, userID, roleName)
}

// UserHasPermission checks if a user has a specific permission.
func (s *AuthService) UserHasPermission(ctx context.Context, userID uuid.UUID, permissionName string) (bool, error) {
	return s.storage.UserHasPermission(ctx, userID, permissionName)
}

// GetRolePermissions retrieves all permissions for a role.
func (s *AuthService) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*storage.Permission, error) {
	return s.storage.GetRolePermissions(ctx, roleID)
}

// ListRoles retrieves all available roles.
func (s *AuthService) ListRoles(ctx context.Context) ([]*storage.Role, error) {
	return s.storage.ListRoles(ctx)
}

// CreateRole creates a new role.
func (s *AuthService) CreateRole(ctx context.Context, req *CreateRoleRequest) (*storage.Role, error) {
	// Check if role name already exists
	existing, err := s.storage.GetRoleByName(ctx, req.Name)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, ErrRoleExists
	}

	role := &storage.Role{
		ID:          uuid.New(),
		TenantID:    req.TenantID,
		Name:        req.Name,
		Description: req.Description,
		IsSystem:    false,
		CreatedAt:   time.Now(),
	}

	if err := s.storage.CreateRole(ctx, role); err != nil {
		return nil, err
	}

	s.logAuditEvent(ctx, nil, nil, "role.created", nil, nil, map[string]interface{}{
		"role_id":   role.ID.String(),
		"role_name": role.Name,
	})

	return role, nil
}

// UpdateRole updates an existing role.
func (s *AuthService) UpdateRole(ctx context.Context, roleID uuid.UUID, req *UpdateRoleRequest) (*storage.Role, error) {
	role, err := s.storage.GetRoleByID(ctx, roleID)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, ErrRoleNotFound
	}
	if role.IsSystem {
		return nil, ErrCannotModifySystemRole
	}

	// Check if new name conflicts with existing role
	if req.Name != nil && *req.Name != role.Name {
		existing, err := s.storage.GetRoleByName(ctx, *req.Name)
		if err != nil {
			return nil, err
		}
		if existing != nil && existing.ID != roleID {
			return nil, ErrRoleExists
		}
		role.Name = *req.Name
	}

	if req.Description != nil {
		role.Description = req.Description
	}

	if err := s.storage.UpdateRole(ctx, role); err != nil {
		return nil, err
	}

	s.logAuditEvent(ctx, nil, nil, "role.updated", nil, nil, map[string]interface{}{
		"role_id":   role.ID.String(),
		"role_name": role.Name,
	})

	return role, nil
}

// DeleteRole deletes a role.
func (s *AuthService) DeleteRole(ctx context.Context, roleID uuid.UUID) error {
	role, err := s.storage.GetRoleByID(ctx, roleID)
	if err != nil {
		return err
	}
	if role == nil {
		return ErrRoleNotFound
	}
	if role.IsSystem {
		return ErrCannotModifySystemRole
	}

	if err := s.storage.DeleteRole(ctx, roleID); err != nil {
		return err
	}

	s.logAuditEvent(ctx, nil, nil, "role.deleted", nil, nil, map[string]interface{}{
		"role_id":   roleID.String(),
		"role_name": role.Name,
	})

	return nil
}

// AssignPermissionToRole assigns a permission to a role.
func (s *AuthService) AssignPermissionToRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	role, err := s.storage.GetRoleByID(ctx, roleID)
	if err != nil {
		return err
	}
	if role == nil {
		return ErrRoleNotFound
	}

	perm, err := s.storage.GetPermissionByID(ctx, permissionID)
	if err != nil {
		return err
	}
	if perm == nil {
		return ErrPermissionNotFound
	}

	if err := s.storage.AssignPermissionToRole(ctx, roleID, permissionID); err != nil {
		return err
	}

	s.logAuditEvent(ctx, nil, nil, "role.permission.assigned", nil, nil, map[string]interface{}{
		"role_id":       roleID.String(),
		"permission_id": permissionID.String(),
	})

	return nil
}

// RemovePermissionFromRole removes a permission from a role.
func (s *AuthService) RemovePermissionFromRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	role, err := s.storage.GetRoleByID(ctx, roleID)
	if err != nil {
		return err
	}
	if role == nil {
		return ErrRoleNotFound
	}

	if err := s.storage.RemovePermissionFromRole(ctx, roleID, permissionID); err != nil {
		return err
	}

	s.logAuditEvent(ctx, nil, nil, "role.permission.removed", nil, nil, map[string]interface{}{
		"role_id":       roleID.String(),
		"permission_id": permissionID.String(),
	})

	return nil
}

// ListPermissions retrieves all available permissions.
func (s *AuthService) ListPermissions(ctx context.Context) ([]*storage.Permission, error) {
	return s.storage.ListPermissions(ctx)
}
