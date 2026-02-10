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
func (s *PostgresStorage) DeleteUserWithSessions(ctx context.Context, userID uuid.UUID) error {
	return s.WithTransaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		// First, revoke all sessions for the user
		revokeQuery := `UPDATE sessions SET revoked = true WHERE user_id = $1`
		if _, err := tx.Exec(ctx, revokeQuery, userID); err != nil {
			return fmt.Errorf("failed to revoke user sessions: %w", err)
		}

		// Then, delete the user
		deleteQuery := `DELETE FROM users WHERE id = $1`
		if _, err := tx.Exec(ctx, deleteQuery, userID); err != nil {
			return fmt.Errorf("failed to delete user: %w", err)
		}

		return nil
	})
}
