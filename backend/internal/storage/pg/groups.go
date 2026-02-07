package pg

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/iSundram/ModernAuth/internal/storage"
)

// ============================================================================
// UserGroupStorage methods
// ============================================================================

func (s *PostgresStorage) CreateGroup(ctx context.Context, group *storage.UserGroup) error {
	query := `
		INSERT INTO user_groups (id, tenant_id, name, description, metadata, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := s.pool.Exec(ctx, query,
		group.ID, group.TenantID, group.Name, group.Description,
		group.Metadata, group.CreatedAt, group.UpdatedAt,
	)
	return err
}

func (s *PostgresStorage) GetGroupByID(ctx context.Context, id uuid.UUID) (*storage.UserGroup, error) {
	query := `
		SELECT id, tenant_id, name, description, metadata, created_at, updated_at
		FROM user_groups WHERE id = $1
	`
	group := &storage.UserGroup{}
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&group.ID, &group.TenantID, &group.Name, &group.Description,
		&group.Metadata, &group.CreatedAt, &group.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return group, nil
}

func (s *PostgresStorage) ListGroups(ctx context.Context, tenantID *uuid.UUID, limit, offset int) ([]*storage.UserGroup, error) {
	var query string
	var args []interface{}

	if tenantID != nil {
		query = `
			SELECT id, tenant_id, name, description, metadata, created_at, updated_at
			FROM user_groups WHERE tenant_id = $1 ORDER BY name ASC LIMIT $2 OFFSET $3
		`
		args = []interface{}{*tenantID, limit, offset}
	} else {
		query = `
			SELECT id, tenant_id, name, description, metadata, created_at, updated_at
			FROM user_groups ORDER BY name ASC LIMIT $1 OFFSET $2
		`
		args = []interface{}{limit, offset}
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []*storage.UserGroup
	for rows.Next() {
		group := &storage.UserGroup{}
		err := rows.Scan(
			&group.ID, &group.TenantID, &group.Name, &group.Description,
			&group.Metadata, &group.CreatedAt, &group.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, rows.Err()
}

func (s *PostgresStorage) UpdateGroup(ctx context.Context, group *storage.UserGroup) error {
	query := `
		UPDATE user_groups
		SET name = $2, description = $3, metadata = $4, updated_at = $5
		WHERE id = $1
	`
	_, err := s.pool.Exec(ctx, query,
		group.ID, group.Name, group.Description, group.Metadata, group.UpdatedAt,
	)
	return err
}

func (s *PostgresStorage) DeleteGroup(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM user_groups WHERE id = $1`
	_, err := s.pool.Exec(ctx, query, id)
	return err
}

func (s *PostgresStorage) AddUserToGroup(ctx context.Context, userID, groupID uuid.UUID, role string) error {
	query := `
		INSERT INTO user_group_members (user_id, group_id, role, joined_at)
		VALUES ($1, $2, $3, now())
		ON CONFLICT (user_id, group_id) DO UPDATE SET role = $3
	`
	_, err := s.pool.Exec(ctx, query, userID, groupID, role)
	return err
}

func (s *PostgresStorage) RemoveUserFromGroup(ctx context.Context, userID, groupID uuid.UUID) error {
	query := `DELETE FROM user_group_members WHERE user_id = $1 AND group_id = $2`
	_, err := s.pool.Exec(ctx, query, userID, groupID)
	return err
}

func (s *PostgresStorage) GetGroupMembers(ctx context.Context, groupID uuid.UUID, limit, offset int) ([]*storage.UserGroupMember, error) {
	query := `
		SELECT user_id, group_id, role, joined_at
		FROM user_group_members WHERE group_id = $1
		ORDER BY joined_at ASC LIMIT $2 OFFSET $3
	`
	rows, err := s.pool.Query(ctx, query, groupID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []*storage.UserGroupMember
	for rows.Next() {
		member := &storage.UserGroupMember{}
		err := rows.Scan(&member.UserID, &member.GroupID, &member.Role, &member.JoinedAt)
		if err != nil {
			return nil, err
		}
		members = append(members, member)
	}
	return members, rows.Err()
}

func (s *PostgresStorage) GetUserGroups(ctx context.Context, userID uuid.UUID) ([]*storage.UserGroup, error) {
	query := `
		SELECT g.id, g.tenant_id, g.name, g.description, g.metadata, g.created_at, g.updated_at
		FROM user_groups g
		INNER JOIN user_group_members m ON g.id = m.group_id
		WHERE m.user_id = $1
		ORDER BY g.name ASC
	`
	rows, err := s.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []*storage.UserGroup
	for rows.Next() {
		group := &storage.UserGroup{}
		err := rows.Scan(
			&group.ID, &group.TenantID, &group.Name, &group.Description,
			&group.Metadata, &group.CreatedAt, &group.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, rows.Err()
}
