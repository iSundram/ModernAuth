package hibp

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// cacheKeyPrefix is the Redis key prefix for HIBP breach cache entries.
	cacheKeyPrefix = "hibp:range:"
)

// RedisBreachCache implements BreachCache using Redis for storage.
// Each SHA-1 prefix maps to a Redis hash where fields are hash suffixes
// and values are breach counts.
type RedisBreachCache struct {
	rdb *redis.Client
}

// NewRedisBreachCache creates a new Redis-backed breach cache.
func NewRedisBreachCache(rdb *redis.Client) *RedisBreachCache {
	return &RedisBreachCache{rdb: rdb}
}

// cacheKey returns the Redis key for a given hash prefix.
func cacheKey(hashPrefix string) string {
	return cacheKeyPrefix + hashPrefix
}

// GetBreachCount retrieves the cached suffix->count map for a hash prefix.
// Returns (map, true, nil) on cache hit, (nil, false, nil) on cache miss.
func (c *RedisBreachCache) GetBreachCount(ctx context.Context, hashPrefix string) (map[string]int, bool, error) {
	key := cacheKey(hashPrefix)

	// Use a single GET with the serialised format for efficiency.
	// We store the entire response as a single string value to minimise
	// Redis memory overhead (thousands of hash fields per prefix).
	val, err := c.rdb.Get(ctx, key).Result()
	if err == redis.Nil {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("redis get failed: %w", err)
	}

	suffixes, err := deserializeSuffixes(val)
	if err != nil {
		return nil, false, fmt.Errorf("failed to deserialize cached data: %w", err)
	}

	return suffixes, true, nil
}

// SetBreachCount stores the suffix->count map for a hash prefix with a TTL.
func (c *RedisBreachCache) SetBreachCount(ctx context.Context, hashPrefix string, suffixes map[string]int, ttl time.Duration) error {
	key := cacheKey(hashPrefix)

	data := serializeSuffixes(suffixes)

	err := c.rdb.Set(ctx, key, data, ttl).Err()
	if err != nil {
		return fmt.Errorf("redis set failed: %w", err)
	}

	return nil
}

// serializeSuffixes encodes the suffix map as a compact string:
//
//	SUFFIX:COUNT\nSUFFIX:COUNT\n...
//
// This mirrors the HIBP API response format for simplicity.
func serializeSuffixes(suffixes map[string]int) string {
	var b strings.Builder
	for suffix, count := range suffixes {
		b.WriteString(suffix)
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(count))
		b.WriteByte('\n')
	}
	return b.String()
}

// deserializeSuffixes decodes the compact string back into a suffix map.
func deserializeSuffixes(data string) (map[string]int, error) {
	suffixes := make(map[string]int)
	lines := strings.Split(strings.TrimSpace(data), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		count, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			continue
		}

		suffixes[strings.TrimSpace(parts[0])] = count
	}

	return suffixes, nil
}
