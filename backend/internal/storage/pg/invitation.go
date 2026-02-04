package pg

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/iSundram/ModernAuth/internal/storage"
)

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
