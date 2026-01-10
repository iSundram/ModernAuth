// Package auth provides token blacklisting functionality.
package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	blacklistKeyPrefix = "token:blacklist:"
)

// TokenBlacklist provides JWT access token blacklisting using Redis.
type TokenBlacklist struct {
	rdb *redis.Client
}

// NewTokenBlacklist creates a new token blacklist.
func NewTokenBlacklist(rdb *redis.Client) *TokenBlacklist {
	return &TokenBlacklist{rdb: rdb}
}

// Blacklist adds a token JTI to the blacklist until it expires.
func (b *TokenBlacklist) Blacklist(ctx context.Context, jti string, expiry time.Time) error {
	ttl := time.Until(expiry)
	if ttl <= 0 {
		// Token already expired, no need to blacklist
		return nil
	}

	key := blacklistKeyPrefix + jti
	return b.rdb.Set(ctx, key, "1", ttl).Err()
}

// IsBlacklisted checks if a token JTI is blacklisted.
func (b *TokenBlacklist) IsBlacklisted(ctx context.Context, jti string) (bool, error) {
	key := blacklistKeyPrefix + jti
	result, err := b.rdb.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check blacklist: %w", err)
	}
	return result > 0, nil
}

// BlacklistSession blacklists all tokens for a session by storing session ID.
func (b *TokenBlacklist) BlacklistSession(ctx context.Context, sessionID string, ttl time.Duration) error {
	key := "session:blacklist:" + sessionID
	return b.rdb.Set(ctx, key, "1", ttl).Err()
}

// IsSessionBlacklisted checks if a session is blacklisted.
func (b *TokenBlacklist) IsSessionBlacklisted(ctx context.Context, sessionID string) (bool, error) {
	key := "session:blacklist:" + sessionID
	result, err := b.rdb.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check session blacklist: %w", err)
	}
	return result > 0, nil
}
