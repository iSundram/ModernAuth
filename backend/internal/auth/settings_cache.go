// Package auth provides authentication services for ModernAuth.
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	settingsCachePrefix = "settings:"
	settingsCacheTTL    = 30 * time.Second
)

// SettingsCache provides Redis-backed caching for system settings.
type SettingsCache struct {
	rdb *redis.Client
}

// NewSettingsCache creates a new settings cache.
func NewSettingsCache(rdb *redis.Client) *SettingsCache {
	return &SettingsCache{rdb: rdb}
}

// Get retrieves a cached setting value.
func (c *SettingsCache) Get(ctx context.Context, key string) (interface{}, bool) {
	if c.rdb == nil {
		return nil, false
	}

	cacheKey := settingsCachePrefix + key
	val, err := c.rdb.Get(ctx, cacheKey).Result()
	if err != nil {
		return nil, false
	}

	var result interface{}
	if err := json.Unmarshal([]byte(val), &result); err != nil {
		return nil, false
	}

	return result, true
}

// Set stores a setting value in cache.
func (c *SettingsCache) Set(ctx context.Context, key string, value interface{}) error {
	if c.rdb == nil {
		return nil
	}

	cacheKey := settingsCachePrefix + key
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal setting value: %w", err)
	}

	return c.rdb.Set(ctx, cacheKey, data, settingsCacheTTL).Err()
}

// Invalidate removes a setting from cache.
func (c *SettingsCache) Invalidate(ctx context.Context, key string) error {
	if c.rdb == nil {
		return nil
	}

	cacheKey := settingsCachePrefix + key
	return c.rdb.Del(ctx, cacheKey).Err()
}

// InvalidateAll removes all settings from cache.
func (c *SettingsCache) InvalidateAll(ctx context.Context) error {
	if c.rdb == nil {
		return nil
	}

	// Use SCAN to find and delete all settings keys
	iter := c.rdb.Scan(ctx, 0, settingsCachePrefix+"*", 100).Iterator()
	var keys []string
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}
	if err := iter.Err(); err != nil {
		return err
	}

	if len(keys) > 0 {
		return c.rdb.Del(ctx, keys...).Err()
	}
	return nil
}
