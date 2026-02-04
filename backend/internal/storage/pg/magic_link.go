package pg

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/iSundram/ModernAuth/internal/storage"
)

// ========== Magic Link Storage ==========

// CreateMagicLink creates a new magic link.
func (s *PostgresStorage) CreateMagicLink(ctx context.Context, link *storage.MagicLink) error {
	query := `
		INSERT INTO magic_links (id, user_id, email, token_hash, expires_at, ip_address, user_agent, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := s.pool.Exec(ctx, query, link.ID, link.UserID, link.Email, link.TokenHash,
		link.ExpiresAt, link.IPAddress, link.UserAgent, link.CreatedAt)
	return err
}

// GetMagicLinkByHash retrieves a magic link by its token hash.
func (s *PostgresStorage) GetMagicLinkByHash(ctx context.Context, tokenHash string) (*storage.MagicLink, error) {
	query := `
		SELECT id, user_id, email, token_hash, expires_at, used_at, ip_address, user_agent, created_at
		FROM magic_links
		WHERE token_hash = $1`

	link := &storage.MagicLink{}
	err := s.pool.QueryRow(ctx, query, tokenHash).Scan(
		&link.ID, &link.UserID, &link.Email, &link.TokenHash, &link.ExpiresAt,
		&link.UsedAt, &link.IPAddress, &link.UserAgent, &link.CreatedAt)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, nil
		}
		return nil, err
	}
	return link, nil
}

// MarkMagicLinkUsed marks a magic link as used.
func (s *PostgresStorage) MarkMagicLinkUsed(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE magic_links SET used_at = $1 WHERE id = $2`
	_, err := s.pool.Exec(ctx, query, time.Now(), id)
	return err
}

// DeleteExpiredMagicLinks removes expired magic links.
func (s *PostgresStorage) DeleteExpiredMagicLinks(ctx context.Context) error {
	query := `DELETE FROM magic_links WHERE expires_at < $1 OR used_at IS NOT NULL`
	_, err := s.pool.Exec(ctx, query, time.Now())
	return err
}

// CountRecentMagicLinks counts magic links created for an email since a given time.
func (s *PostgresStorage) CountRecentMagicLinks(ctx context.Context, email string, since time.Time) (int, error) {
	query := `SELECT COUNT(*) FROM magic_links WHERE email = $1 AND created_at > $2`
	var count int
	err := s.pool.QueryRow(ctx, query, email, since).Scan(&count)
	return count, err
}
