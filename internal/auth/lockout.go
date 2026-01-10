// Package auth provides account lockout functionality.
package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	lockoutKeyPrefix      = "lockout:"
	failedAttemptsPrefix  = "failed_attempts:"
	defaultMaxAttempts    = 5
	defaultLockoutWindow  = 15 * time.Minute
	defaultLockoutDuration = 30 * time.Minute
)

// AccountLockout provides account lockout functionality using Redis.
type AccountLockout struct {
	rdb             *redis.Client
	maxAttempts     int
	lockoutWindow   time.Duration
	lockoutDuration time.Duration
}

// LockoutConfig holds configuration for account lockout.
type LockoutConfig struct {
	MaxAttempts     int
	LockoutWindow   time.Duration
	LockoutDuration time.Duration
}

// DefaultLockoutConfig returns default lockout configuration.
func DefaultLockoutConfig() *LockoutConfig {
	return &LockoutConfig{
		MaxAttempts:     defaultMaxAttempts,
		LockoutWindow:   defaultLockoutWindow,
		LockoutDuration: defaultLockoutDuration,
	}
}

// NewAccountLockout creates a new account lockout manager.
func NewAccountLockout(rdb *redis.Client, config *LockoutConfig) *AccountLockout {
	if config == nil {
		config = DefaultLockoutConfig()
	}
	return &AccountLockout{
		rdb:             rdb,
		maxAttempts:     config.MaxAttempts,
		lockoutWindow:   config.LockoutWindow,
		lockoutDuration: config.LockoutDuration,
	}
}

// IsLocked checks if an account is currently locked.
func (l *AccountLockout) IsLocked(ctx context.Context, identifier string) (bool, time.Duration, error) {
	key := lockoutKeyPrefix + identifier
	ttl, err := l.rdb.TTL(ctx, key).Result()
	if err != nil {
		return false, 0, fmt.Errorf("failed to check lockout: %w", err)
	}
	
	// TTL returns -2 if key doesn't exist, -1 if no expiry
	if ttl < 0 {
		return false, 0, nil
	}
	
	return true, ttl, nil
}

// RecordFailedAttempt records a failed login attempt and returns whether the account is now locked.
func (l *AccountLockout) RecordFailedAttempt(ctx context.Context, identifier string) (bool, error) {
	key := failedAttemptsPrefix + identifier
	
	// Increment the counter
	count, err := l.rdb.Incr(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to record attempt: %w", err)
	}
	
	// Set expiry on first attempt
	if count == 1 {
		l.rdb.Expire(ctx, key, l.lockoutWindow)
	}
	
	// Check if we need to lock
	if count >= int64(l.maxAttempts) {
		lockKey := lockoutKeyPrefix + identifier
		if err := l.rdb.Set(ctx, lockKey, "1", l.lockoutDuration).Err(); err != nil {
			return false, fmt.Errorf("failed to set lockout: %w", err)
		}
		// Clear the failed attempts counter
		l.rdb.Del(ctx, key)
		return true, nil
	}
	
	return false, nil
}

// ClearFailedAttempts clears failed attempts after successful login.
func (l *AccountLockout) ClearFailedAttempts(ctx context.Context, identifier string) error {
	key := failedAttemptsPrefix + identifier
	return l.rdb.Del(ctx, key).Err()
}

// GetRemainingAttempts returns the number of remaining login attempts.
func (l *AccountLockout) GetRemainingAttempts(ctx context.Context, identifier string) (int, error) {
	key := failedAttemptsPrefix + identifier
	count, err := l.rdb.Get(ctx, key).Int()
	if err == redis.Nil {
		return l.maxAttempts, nil
	}
	if err != nil {
		return 0, fmt.Errorf("failed to get attempts: %w", err)
	}
	remaining := l.maxAttempts - count
	if remaining < 0 {
		remaining = 0
	}
	return remaining, nil
}

// Unlock manually unlocks an account.
func (l *AccountLockout) Unlock(ctx context.Context, identifier string) error {
	lockKey := lockoutKeyPrefix + identifier
	attemptsKey := failedAttemptsPrefix + identifier
	return l.rdb.Del(ctx, lockKey, attemptsKey).Err()
}
