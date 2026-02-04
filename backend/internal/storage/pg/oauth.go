package pg

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/iSundram/ModernAuth/internal/storage"
)

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
