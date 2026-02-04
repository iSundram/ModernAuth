// Package pg provides PostgreSQL implementation of the storage interfaces.
package pg

import (
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
