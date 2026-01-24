// Package email provides error definitions for email services.
package email

import "errors"

// Email service errors.
var (
	// ErrRateLimitExceeded is returned when email rate limit is exceeded.
	ErrRateLimitExceeded = errors.New("email rate limit exceeded, please try again later")

	// ErrQueueFull is returned when the email queue is full.
	ErrQueueFull = errors.New("email queue is full, please try again later")

	// ErrQueueStopped is returned when trying to enqueue after shutdown.
	ErrQueueStopped = errors.New("email queue has been stopped")
)
