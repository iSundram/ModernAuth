// Package email provides rate limiting for email sending.
package email

import (
	"context"
	"sync"
	"time"

	"github.com/iSundram/ModernAuth/internal/storage"
)

// RateLimitConfig holds rate limit configuration.
type RateLimitConfig struct {
	// VerificationLimit is the max verification emails per user per hour
	VerificationLimit int
	// PasswordResetLimit is the max password reset emails per user per hour
	PasswordResetLimit int
	// Window is the time window for rate limiting
	Window time.Duration
}

// DefaultRateLimitConfig returns sensible defaults.
func DefaultRateLimitConfig() *RateLimitConfig {
	return &RateLimitConfig{
		VerificationLimit:  3,
		PasswordResetLimit: 5,
		Window:             time.Hour,
	}
}

// rateLimitEntry tracks email sends for a user.
type rateLimitEntry struct {
	timestamps []time.Time
}

// RateLimitedService wraps an email service with rate limiting.
type RateLimitedService struct {
	inner  Service
	config *RateLimitConfig

	// In-memory rate limit tracking (can be replaced with Redis)
	verificationLimits  map[string]*rateLimitEntry
	passwordResetLimits map[string]*rateLimitEntry
	mu                  sync.RWMutex

	// Cleanup ticker
	cleanupTicker *time.Ticker
	stopCh        chan struct{}
}

// NewRateLimitedService creates a new rate-limited email service.
func NewRateLimitedService(inner Service, cfg *RateLimitConfig) *RateLimitedService {
	if cfg == nil {
		cfg = DefaultRateLimitConfig()
	}

	rls := &RateLimitedService{
		inner:               inner,
		config:              cfg,
		verificationLimits:  make(map[string]*rateLimitEntry),
		passwordResetLimits: make(map[string]*rateLimitEntry),
		cleanupTicker:       time.NewTicker(10 * time.Minute),
		stopCh:              make(chan struct{}),
	}

	// Start cleanup goroutine
	go rls.cleanupLoop()

	return rls
}

// Stop stops the rate limiter cleanup goroutine.
func (r *RateLimitedService) Stop() {
	close(r.stopCh)
	r.cleanupTicker.Stop()
}

// cleanupLoop periodically removes expired entries.
func (r *RateLimitedService) cleanupLoop() {
	for {
		select {
		case <-r.stopCh:
			return
		case <-r.cleanupTicker.C:
			r.cleanup()
		}
	}
}

// cleanup removes expired rate limit entries.
func (r *RateLimitedService) cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()

	cutoff := time.Now().Add(-r.config.Window)

	// Clean verification limits
	for key, entry := range r.verificationLimits {
		entry.timestamps = filterTimestamps(entry.timestamps, cutoff)
		if len(entry.timestamps) == 0 {
			delete(r.verificationLimits, key)
		}
	}

	// Clean password reset limits
	for key, entry := range r.passwordResetLimits {
		entry.timestamps = filterTimestamps(entry.timestamps, cutoff)
		if len(entry.timestamps) == 0 {
			delete(r.passwordResetLimits, key)
		}
	}
}

// filterTimestamps removes timestamps older than cutoff.
func filterTimestamps(timestamps []time.Time, cutoff time.Time) []time.Time {
	result := make([]time.Time, 0, len(timestamps))
	for _, ts := range timestamps {
		if ts.After(cutoff) {
			result = append(result, ts)
		}
	}
	return result
}

// checkRateLimit checks if an action is allowed and records it if so.
func (r *RateLimitedService) checkRateLimit(limits map[string]*rateLimitEntry, key string, maxCount int) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-r.config.Window)

	entry, exists := limits[key]
	if !exists {
		entry = &rateLimitEntry{timestamps: make([]time.Time, 0)}
		limits[key] = entry
	}

	// Filter out old timestamps
	entry.timestamps = filterTimestamps(entry.timestamps, cutoff)

	// Check if limit exceeded
	if len(entry.timestamps) >= maxCount {
		return ErrRateLimitExceeded
	}

	// Record this attempt
	entry.timestamps = append(entry.timestamps, now)
	return nil
}

// SendVerificationEmail sends a verification email with rate limiting.
func (r *RateLimitedService) SendVerificationEmail(ctx context.Context, user *storage.User, token string, verifyURL string) error {
	if err := r.checkRateLimit(r.verificationLimits, user.Email, r.config.VerificationLimit); err != nil {
		return err
	}
	return r.inner.SendVerificationEmail(ctx, user, token, verifyURL)
}

// SendPasswordResetEmail sends a password reset email with rate limiting.
func (r *RateLimitedService) SendPasswordResetEmail(ctx context.Context, user *storage.User, token string, resetURL string) error {
	if err := r.checkRateLimit(r.passwordResetLimits, user.Email, r.config.PasswordResetLimit); err != nil {
		return err
	}
	return r.inner.SendPasswordResetEmail(ctx, user, token, resetURL)
}

// SendWelcomeEmail sends a welcome email (no rate limiting - system triggered).
func (r *RateLimitedService) SendWelcomeEmail(ctx context.Context, user *storage.User) error {
	return r.inner.SendWelcomeEmail(ctx, user)
}

// SendLoginAlertEmail sends a login alert (no rate limiting - system triggered).
func (r *RateLimitedService) SendLoginAlertEmail(ctx context.Context, user *storage.User, device *DeviceInfo) error {
	return r.inner.SendLoginAlertEmail(ctx, user, device)
}

// SendInvitationEmail sends an invitation email (no rate limiting - admin action).
func (r *RateLimitedService) SendInvitationEmail(ctx context.Context, invitation *InvitationEmail) error {
	return r.inner.SendInvitationEmail(ctx, invitation)
}

// SendMFAEnabledEmail sends MFA enabled notification (no rate limiting - system triggered).
func (r *RateLimitedService) SendMFAEnabledEmail(ctx context.Context, user *storage.User) error {
	return r.inner.SendMFAEnabledEmail(ctx, user)
}

// SendPasswordChangedEmail sends password changed notification (no rate limiting - system triggered).
func (r *RateLimitedService) SendPasswordChangedEmail(ctx context.Context, user *storage.User) error {
	return r.inner.SendPasswordChangedEmail(ctx, user)
}

// SendSessionRevokedEmail sends session revoked notification (no rate limiting - system triggered).
func (r *RateLimitedService) SendSessionRevokedEmail(ctx context.Context, user *storage.User, reason string) error {
	return r.inner.SendSessionRevokedEmail(ctx, user, reason)
}

// Verify RateLimitedService implements Service interface
var _ Service = (*RateLimitedService)(nil)
