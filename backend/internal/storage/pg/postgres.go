// Package pg provides PostgreSQL implementation of the storage interfaces.
package pg

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStorage implements the Storage interface using PostgreSQL.
type PostgresStorage struct {
	pool *pgxpool.Pool
}

// NewPostgresStorage creates a new PostgreSQL storage instance.
func NewPostgresStorage(pool *pgxpool.Pool) *PostgresStorage {
	return &PostgresStorage{pool: pool}
}

// TxFunc is a function that executes within a transaction.
type TxFunc func(ctx context.Context, tx pgx.Tx) error

// WithTransaction executes a function within a database transaction.
// If the function returns an error, the transaction is rolled back.
// Otherwise, the transaction is committed.
func (s *PostgresStorage) WithTransaction(ctx context.Context, fn TxFunc) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	defer func() {
		if p := recover(); p != nil {
			// Rollback on panic
			_ = tx.Rollback(ctx)
			panic(p) // Re-throw panic after rollback
		}
	}()

	if err := fn(ctx, tx); err != nil {
		if rbErr := tx.Rollback(ctx); rbErr != nil {
			return fmt.Errorf("failed to rollback transaction: %v (original error: %w)", rbErr, err)
		}
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// Pool returns the underlying connection pool for advanced operations.
func (s *PostgresStorage) Pool() *pgxpool.Pool {
	return s.pool
}

// DeleteUserWithSessions atomically revokes all user sessions and deletes the user.
// This implements the storage.TransactionalStorage interface.
// Note: Some data is anonymized rather than deleted for compliance/audit purposes.
func (s *PostgresStorage) DeleteUserWithSessions(ctx context.Context, userID uuid.UUID) error {
	return s.WithTransaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		// Revoke all sessions for the user
		revokeQuery := `UPDATE sessions SET revoked = true WHERE user_id = $1`
		if _, err := tx.Exec(ctx, revokeQuery, userID); err != nil {
			return fmt.Errorf("failed to revoke user sessions: %w", err)
		}

		// Revoke all refresh tokens
		refreshQuery := `UPDATE refresh_tokens SET revoked = true, replaced_by = NULL WHERE user_id = $1`
		if _, err := tx.Exec(ctx, refreshQuery, userID); err != nil {
			return fmt.Errorf("failed to revoke refresh tokens: %w", err)
		}

		// Delete MFA settings
		mfaQuery := `DELETE FROM user_mfa_settings WHERE user_id = $1`
		if _, err := tx.Exec(ctx, mfaQuery, userID); err != nil {
			return fmt.Errorf("failed to delete MFA settings: %w", err)
		}

		// Delete MFA challenges
		challengeQuery := `DELETE FROM mfa_challenges WHERE user_id = $1`
		if _, err := tx.Exec(ctx, challengeQuery, userID); err != nil {
			return fmt.Errorf("failed to delete MFA challenges: %w", err)
		}

		// Delete user devices
		deviceQuery := `DELETE FROM user_devices WHERE user_id = $1`
		if _, err := tx.Exec(ctx, deviceQuery, userID); err != nil {
			return fmt.Errorf("failed to delete user devices: %w", err)
		}

		// Delete user roles
		roleQuery := `DELETE FROM user_roles WHERE user_id = $1`
		if _, err := tx.Exec(ctx, roleQuery, userID); err != nil {
			return fmt.Errorf("failed to delete user roles: %w", err)
		}

		// Delete API keys
		apiKeyQuery := `DELETE FROM api_keys WHERE user_id = $1`
		if _, err := tx.Exec(ctx, apiKeyQuery, userID); err != nil {
			return fmt.Errorf("failed to delete API keys: %w", err)
		}

		// Delete webhooks
		webhookQuery := `DELETE FROM webhooks WHERE user_id = $1`
		if _, err := tx.Exec(ctx, webhookQuery, userID); err != nil {
			return fmt.Errorf("failed to delete webhooks: %w", err)
		}

		// Delete invitations (where user is the invitee)
		invitationQuery := `DELETE FROM user_invitations WHERE email IN (SELECT email FROM users WHERE id = $1)`
		if _, err := tx.Exec(ctx, invitationQuery, userID); err != nil {
			return fmt.Errorf("failed to delete invitations: %w", err)
		}

		// Anonymize audit logs (keep for compliance but remove user reference)
		// Note: We don't delete audit logs as they may be needed for compliance
		// Instead, we update them to remove user references
		anonymizeAuditQuery := `
			UPDATE audit_logs 
			SET user_id = NULL, actor_id = NULL, data = jsonb_set(data, '{user_deleted}', 'true')
			WHERE user_id = $1 OR actor_id = $1
		`
		if _, err := tx.Exec(ctx, anonymizeAuditQuery, userID); err != nil {
			return fmt.Errorf("failed to anonymize audit logs: %w", err)
		}

		// Anonymize login history
		loginHistoryQuery := `
			UPDATE login_history 
			SET user_id = NULL, ip = NULL, user_agent = NULL, location_country = NULL, location_city = NULL
			WHERE user_id = $1
		`
		if _, err := tx.Exec(ctx, loginHistoryQuery, userID); err != nil {
			return fmt.Errorf("failed to anonymize login history: %w", err)
		}

		// Finally, delete the user
		deleteQuery := `DELETE FROM users WHERE id = $1`
		if _, err := tx.Exec(ctx, deleteQuery, userID); err != nil {
			return fmt.Errorf("failed to delete user: %w", err)
		}

		return nil
	})
}
