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

// OAuthProvider storage implementation

// GetUserByProviderID retrieves a user by their OAuth provider and provider user ID.
func (s *PostgresStorage) GetUserByProviderID(ctx context.Context, provider, providerUserID string) (*storage.User, error) {
	query := `
		SELECT u.id, u.email, u.phone, u.username, u.first_name, u.last_name, u.avatar_url, u.hashed_password,
		       u.is_email_verified, u.is_active, u.timezone, u.locale, u.metadata, u.last_login_at,
		       u.password_changed_at, u.created_at, u.updated_at, u.tenant_id
		FROM users u
		INNER JOIN user_providers up ON u.id = up.user_id
		WHERE up.provider = $1 AND up.provider_user_id = $2
		LIMIT 1
	`
	user := &storage.User{}
	err := s.pool.QueryRow(ctx, query, provider, providerUserID).Scan(
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

// LinkProvider links an OAuth provider to a user.
func (s *PostgresStorage) LinkProvider(ctx context.Context, userProvider *storage.UserProvider) error {
	query := `
		INSERT INTO user_providers (id, user_id, provider, provider_user_id, access_token_encrypted, refresh_token_encrypted, token_expires_at, profile_data, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (user_id, provider) DO UPDATE SET
			provider_user_id = EXCLUDED.provider_user_id,
			access_token_encrypted = EXCLUDED.access_token_encrypted,
			refresh_token_encrypted = EXCLUDED.refresh_token_encrypted,
			token_expires_at = EXCLUDED.token_expires_at,
			profile_data = EXCLUDED.profile_data,
			updated_at = EXCLUDED.updated_at
	`
	_, err := s.pool.Exec(ctx, query,
		userProvider.ID,
		userProvider.UserID,
		userProvider.Provider,
		userProvider.ProviderUserID,
		userProvider.AccessTokenEncrypted,
		userProvider.RefreshTokenEncrypted,
		userProvider.TokenExpiresAt,
		userProvider.ProfileData,
		userProvider.CreatedAt,
		userProvider.UpdatedAt,
	)
	return err
}

// UnlinkProvider removes an OAuth provider link from a user.
func (s *PostgresStorage) UnlinkProvider(ctx context.Context, userID uuid.UUID, provider string) error {
	query := `DELETE FROM user_providers WHERE user_id = $1 AND provider = $2`
	_, err := s.pool.Exec(ctx, query, userID, provider)
	return err
}

// GetUserProviders gets all linked providers for a user.
func (s *PostgresStorage) GetUserProviders(ctx context.Context, userID uuid.UUID) ([]*storage.UserProvider, error) {
	query := `
		SELECT id, user_id, provider, provider_user_id, access_token_encrypted, refresh_token_encrypted, token_expires_at, profile_data, created_at, updated_at
		FROM user_providers
		WHERE user_id = $1
		ORDER BY created_at ASC
	`
	rows, err := s.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var providers []*storage.UserProvider
	for rows.Next() {
		up := &storage.UserProvider{}
		err := rows.Scan(
			&up.ID,
			&up.UserID,
			&up.Provider,
			&up.ProviderUserID,
			&up.AccessTokenEncrypted,
			&up.RefreshTokenEncrypted,
			&up.TokenExpiresAt,
			&up.ProfileData,
			&up.CreatedAt,
			&up.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		providers = append(providers, up)
	}
	return providers, nil
}
