// Package email provides a Redis Streams-based email queue with persistence.
package email

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/iSundram/ModernAuth/internal/storage"
)

const (
	// Stream and consumer group names
	emailStream        = "email:queue"
	emailConsumerGroup = "email:workers"
	deadLetterStream   = "email:dead_letters"

	// Consumer configuration
	defaultConsumerName = "worker"
	blockTimeout        = 5 * time.Second
	claimTimeout        = 30 * time.Second
	maxRetries          = 3
)

// RedisStreamQueue implements a persistent email queue using Redis Streams.
type RedisStreamQueue struct {
	rdb             *redis.Client
	inner           Service
	deadLetterStore storage.EmailTemplateStorage
	logger          *slog.Logger
	consumerName    string
	stopCh          chan struct{}
	wg              sync.WaitGroup
	mu              sync.RWMutex
	stopped         bool
}

// RedisQueueConfig holds Redis queue configuration.
type RedisQueueConfig struct {
	ConsumerName    string
	WorkerCount     int
	DeadLetterStore storage.EmailTemplateStorage
}

// DefaultRedisQueueConfig returns sensible defaults.
func DefaultRedisQueueConfig() *RedisQueueConfig {
	return &RedisQueueConfig{
		ConsumerName: defaultConsumerName,
		WorkerCount:  3,
	}
}

// NewRedisStreamQueue creates a new Redis Streams-based email queue.
func NewRedisStreamQueue(rdb *redis.Client, inner Service, cfg *RedisQueueConfig) (*RedisStreamQueue, error) {
	if cfg == nil {
		cfg = DefaultRedisQueueConfig()
	}

	q := &RedisStreamQueue{
		rdb:             rdb,
		inner:           inner,
		deadLetterStore: cfg.DeadLetterStore,
		logger:          slog.Default().With("component", "redis_email_queue"),
		consumerName:    cfg.ConsumerName,
		stopCh:          make(chan struct{}),
	}

	// Create consumer group if it doesn't exist
	ctx := context.Background()
	err := rdb.XGroupCreateMkStream(ctx, emailStream, emailConsumerGroup, "0").Err()
	if err != nil && err.Error() != "BUSYGROUP Consumer Group name already exists" {
		return nil, fmt.Errorf("failed to create consumer group: %w", err)
	}

	// Create dead letter stream
	err = rdb.XGroupCreateMkStream(ctx, deadLetterStream, emailConsumerGroup, "0").Err()
	if err != nil && err.Error() != "BUSYGROUP Consumer Group name already exists" {
		// Ignore error for dead letter stream
	}

	// Start workers
	for i := 0; i < cfg.WorkerCount; i++ {
		q.wg.Add(1)
		go q.worker(fmt.Sprintf("%s-%d", cfg.ConsumerName, i))
	}

	// Start pending message claimer
	q.wg.Add(1)
	go q.claimPendingMessages()

	q.logger.Info("Redis stream email queue started",
		"workers", cfg.WorkerCount,
		"stream", emailStream,
	)

	return q, nil
}

// Stop gracefully stops the queue workers.
func (q *RedisStreamQueue) Stop() {
	q.mu.Lock()
	if q.stopped {
		q.mu.Unlock()
		return
	}
	q.stopped = true
	q.mu.Unlock()

	close(q.stopCh)
	q.wg.Wait()
	q.logger.Info("Redis stream email queue stopped")
}

// worker processes messages from the Redis stream.
func (q *RedisStreamQueue) worker(consumerName string) {
	defer q.wg.Done()

	for {
		select {
		case <-q.stopCh:
			return
		default:
		}

		// Read from stream
		streams, err := q.rdb.XReadGroup(context.Background(), &redis.XReadGroupArgs{
			Group:    emailConsumerGroup,
			Consumer: consumerName,
			Streams:  []string{emailStream, ">"},
			Count:    10,
			Block:    blockTimeout,
		}).Result()

		if err != nil {
			if err != redis.Nil {
				q.logger.Error("Failed to read from stream", "error", err)
			}
			continue
		}

		for _, stream := range streams {
			for _, msg := range stream.Messages {
				q.processMessage(msg)
			}
		}
	}
}

// processMessage processes a single email job from the stream.
func (q *RedisStreamQueue) processMessage(msg redis.XMessage) {
	ctx := context.Background()

	// Parse the job
	jobType, _ := msg.Values["type"].(string)
	recipient, _ := msg.Values["recipient"].(string)
	payloadJSON, _ := msg.Values["payload"].(string)
	attemptsStr, _ := msg.Values["attempts"].(string)

	var attempts int
	fmt.Sscanf(attemptsStr, "%d", &attempts)

	var payload interface{}
	if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
		q.logger.Error("Failed to parse job payload", "id", msg.ID, "error", err)
		q.ackMessage(ctx, msg.ID)
		return
	}

	// Process the job
	err := q.processJob(ctx, jobType, recipient, payload)
	if err != nil {
		attempts++
		if attempts >= maxRetries {
			q.logger.Error("Email job failed permanently",
				"id", msg.ID,
				"type", jobType,
				"attempts", attempts,
				"error", err,
			)
			q.moveToDeadLetter(ctx, msg, err.Error())
		} else {
			q.logger.Warn("Email job failed, will retry",
				"id", msg.ID,
				"type", jobType,
				"attempt", attempts,
				"error", err,
			)
			// Re-add to stream with incremented attempts
			q.requeueWithRetry(ctx, msg, attempts)
		}
	} else {
		q.logger.Debug("Email job processed successfully", "id", msg.ID, "type", jobType)
	}

	// Acknowledge the message
	q.ackMessage(ctx, msg.ID)
}

// processJob executes the email job based on its type.
func (q *RedisStreamQueue) processJob(ctx context.Context, jobType, recipient string, payload interface{}) error {
	payloadMap, ok := payload.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid payload type")
	}

	switch jobType {
	case jobTypeVerification:
		return q.processVerificationEmail(ctx, payloadMap)
	case jobTypePasswordReset:
		return q.processPasswordResetEmail(ctx, payloadMap)
	case jobTypeWelcome:
		return q.processWelcomeEmail(ctx, payloadMap)
	case jobTypeLoginAlert:
		return q.processLoginAlertEmail(ctx, payloadMap)
	case jobTypeInvitation:
		return q.processInvitationEmail(ctx, payloadMap)
	case jobTypeMFAEnabled:
		return q.processMFAEnabledEmail(ctx, payloadMap)
	case jobTypeMFACode:
		return q.processMFACodeEmail(ctx, payloadMap)
	case jobTypeLowBackupCodes:
		return q.processLowBackupCodesEmail(ctx, payloadMap)
	case jobTypePasswordChanged:
		return q.processPasswordChangedEmail(ctx, payloadMap)
	case jobTypeSessionRevoked:
		return q.processSessionRevokedEmail(ctx, payloadMap)
	case jobTypeMagicLink:
		return q.processMagicLinkEmail(ctx, payloadMap)
	case jobTypeAccountDeactivated:
		return q.processAccountDeactivatedEmail(ctx, payloadMap)
	case jobTypeEmailChanged:
		return q.processEmailChangedEmail(ctx, payloadMap)
	case jobTypePasswordExpiry:
		return q.processPasswordExpiryEmail(ctx, payloadMap)
	case jobTypeSecurityAlert:
		return q.processSecurityAlertEmail(ctx, payloadMap)
	case jobTypeRateLimitWarning:
		return q.processRateLimitWarningEmail(ctx, payloadMap)
	default:
		q.logger.Warn("Unknown job type", "type", jobType)
		return nil
	}
}

// Helper methods for processing specific email types
func (q *RedisStreamQueue) processVerificationEmail(ctx context.Context, payload map[string]interface{}) error {
	user := q.extractUser(payload)
	token, _ := payload["token"].(string)
	verifyURL, _ := payload["verify_url"].(string)
	return q.inner.SendVerificationEmail(ctx, user, token, verifyURL)
}

func (q *RedisStreamQueue) processPasswordResetEmail(ctx context.Context, payload map[string]interface{}) error {
	user := q.extractUser(payload)
	token, _ := payload["token"].(string)
	resetURL, _ := payload["reset_url"].(string)
	return q.inner.SendPasswordResetEmail(ctx, user, token, resetURL)
}

func (q *RedisStreamQueue) processWelcomeEmail(ctx context.Context, payload map[string]interface{}) error {
	user := q.extractUser(payload)
	return q.inner.SendWelcomeEmail(ctx, user)
}

func (q *RedisStreamQueue) processLoginAlertEmail(ctx context.Context, payload map[string]interface{}) error {
	user := q.extractUser(payload)
	device := q.extractDeviceInfo(payload)
	return q.inner.SendLoginAlertEmail(ctx, user, device)
}

func (q *RedisStreamQueue) processInvitationEmail(ctx context.Context, payload map[string]interface{}) error {
	invitation := q.extractInvitation(payload)
	return q.inner.SendInvitationEmail(ctx, invitation)
}

func (q *RedisStreamQueue) processMFAEnabledEmail(ctx context.Context, payload map[string]interface{}) error {
	user := q.extractUser(payload)
	return q.inner.SendMFAEnabledEmail(ctx, user)
}

func (q *RedisStreamQueue) processMFACodeEmail(ctx context.Context, payload map[string]interface{}) error {
	email, _ := payload["email"].(string)
	code, _ := payload["code"].(string)
	return q.inner.SendMFACodeEmail(ctx, email, code)
}

func (q *RedisStreamQueue) processLowBackupCodesEmail(ctx context.Context, payload map[string]interface{}) error {
	user := q.extractUser(payload)
	remaining, _ := payload["remaining"].(float64)
	return q.inner.SendLowBackupCodesEmail(ctx, user, int(remaining))
}

func (q *RedisStreamQueue) processPasswordChangedEmail(ctx context.Context, payload map[string]interface{}) error {
	user := q.extractUser(payload)
	return q.inner.SendPasswordChangedEmail(ctx, user)
}

func (q *RedisStreamQueue) processSessionRevokedEmail(ctx context.Context, payload map[string]interface{}) error {
	user := q.extractUser(payload)
	reason, _ := payload["reason"].(string)
	return q.inner.SendSessionRevokedEmail(ctx, user, reason)
}

func (q *RedisStreamQueue) processMagicLinkEmail(ctx context.Context, payload map[string]interface{}) error {
	email, _ := payload["email"].(string)
	magicLinkURL, _ := payload["magic_link_url"].(string)
	return q.inner.SendMagicLink(ctx, email, magicLinkURL)
}

func (q *RedisStreamQueue) processAccountDeactivatedEmail(ctx context.Context, payload map[string]interface{}) error {
	user := q.extractUser(payload)
	reason, _ := payload["reason"].(string)
	reactivationURL, _ := payload["reactivation_url"].(string)
	return q.inner.SendAccountDeactivatedEmail(ctx, user, reason, reactivationURL)
}

func (q *RedisStreamQueue) processEmailChangedEmail(ctx context.Context, payload map[string]interface{}) error {
	user := q.extractUser(payload)
	oldEmail, _ := payload["old_email"].(string)
	newEmail, _ := payload["new_email"].(string)
	return q.inner.SendEmailChangedEmail(ctx, user, oldEmail, newEmail)
}

func (q *RedisStreamQueue) processPasswordExpiryEmail(ctx context.Context, payload map[string]interface{}) error {
	user := q.extractUser(payload)
	daysUntilExpiry, _ := payload["days_until_expiry"].(string)
	expiryDate, _ := payload["expiry_date"].(string)
	changePasswordURL, _ := payload["change_password_url"].(string)
	return q.inner.SendPasswordExpiryEmail(ctx, user, daysUntilExpiry, expiryDate, changePasswordURL)
}

func (q *RedisStreamQueue) processSecurityAlertEmail(ctx context.Context, payload map[string]interface{}) error {
	user := q.extractUser(payload)
	title, _ := payload["alert_title"].(string)
	message, _ := payload["alert_message"].(string)
	details, _ := payload["alert_details"].(string)
	actionURL, _ := payload["action_url"].(string)
	actionText, _ := payload["action_text"].(string)
	return q.inner.SendSecurityAlertEmail(ctx, user, title, message, details, actionURL, actionText)
}

func (q *RedisStreamQueue) processRateLimitWarningEmail(ctx context.Context, payload map[string]interface{}) error {
	user := q.extractUser(payload)
	actionType, _ := payload["action_type"].(string)
	currentCount, _ := payload["current_count"].(string)
	maxCount, _ := payload["max_count"].(string)
	timeWindow, _ := payload["time_window"].(string)
	upgradeURL, _ := payload["upgrade_url"].(string)
	return q.inner.SendRateLimitWarningEmail(ctx, user, actionType, currentCount, maxCount, timeWindow, upgradeURL)
}

// extractUser extracts user information from payload.
func (q *RedisStreamQueue) extractUser(payload map[string]interface{}) *storage.User {
	userMap, ok := payload["user"].(map[string]interface{})
	if !ok {
		return nil
	}
	user := &storage.User{}
	if email, ok := userMap["email"].(string); ok {
		user.Email = email
	}
	if firstName, ok := userMap["first_name"].(string); ok {
		user.FirstName = &firstName
	}
	if lastName, ok := userMap["last_name"].(string); ok {
		user.LastName = &lastName
	}
	return user
}

// extractDeviceInfo extracts device information from payload.
func (q *RedisStreamQueue) extractDeviceInfo(payload map[string]interface{}) *DeviceInfo {
	deviceMap, ok := payload["device"].(map[string]interface{})
	if !ok {
		return nil
	}
	device := &DeviceInfo{}
	if ip, ok := deviceMap["ip"].(string); ok {
		device.IPAddress = ip
	}
	if userAgent, ok := deviceMap["user_agent"].(string); ok {
		device.Browser = userAgent
	}
	if location, ok := deviceMap["location"].(string); ok {
		device.Location = location
	}
	return device
}

// extractInvitation extracts invitation information from payload.
func (q *RedisStreamQueue) extractInvitation(payload map[string]interface{}) *InvitationEmail {
	invMap, ok := payload["invitation"].(map[string]interface{})
	if !ok {
		return nil
	}
	inv := &InvitationEmail{}
	if email, ok := invMap["email"].(string); ok {
		inv.Email = email
	}
	if inviteURL, ok := invMap["invite_url"].(string); ok {
		inv.InviteURL = inviteURL
	}
	if inviterName, ok := invMap["inviter_name"].(string); ok {
		inv.InviterName = inviterName
	}
	return inv
}

// ackMessage acknowledges a processed message.
func (q *RedisStreamQueue) ackMessage(ctx context.Context, msgID string) {
	if err := q.rdb.XAck(ctx, emailStream, emailConsumerGroup, msgID).Err(); err != nil {
		q.logger.Error("Failed to acknowledge message", "id", msgID, "error", err)
	}
}

// requeueWithRetry re-adds a failed message to the stream with incremented retry count.
func (q *RedisStreamQueue) requeueWithRetry(ctx context.Context, msg redis.XMessage, attempts int) {
	values := make(map[string]interface{})
	for k, v := range msg.Values {
		values[k] = v
	}
	values["attempts"] = fmt.Sprintf("%d", attempts)

	if err := q.rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: emailStream,
		Values: values,
	}).Err(); err != nil {
		q.logger.Error("Failed to requeue message", "id", msg.ID, "error", err)
	}
}

// moveToDeadLetter moves a permanently failed message to the dead letter stream.
func (q *RedisStreamQueue) moveToDeadLetter(ctx context.Context, msg redis.XMessage, errorMsg string) {
	values := make(map[string]interface{})
	for k, v := range msg.Values {
		values[k] = v
	}
	values["error"] = errorMsg
	values["failed_at"] = time.Now().Format(time.RFC3339)

	if err := q.rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: deadLetterStream,
		Values: values,
	}).Err(); err != nil {
		q.logger.Error("Failed to move to dead letter", "id", msg.ID, "error", err)
	}

	// Also store in database if configured
	if q.deadLetterStore != nil {
		jobType, _ := msg.Values["type"].(string)
		recipient, _ := msg.Values["recipient"].(string)
		attemptsStr, _ := msg.Values["attempts"].(string)
		var attempts int
		fmt.Sscanf(attemptsStr, "%d", &attempts)

		dl := &storage.EmailDeadLetter{
			JobType:      jobType,
			Recipient:    recipient,
			ErrorMessage: errorMsg,
			Attempts:     attempts,
			CreatedAt:    time.Now(),
		}
		if err := q.deadLetterStore.CreateEmailDeadLetter(ctx, dl); err != nil {
			q.logger.Error("Failed to store dead letter in DB", "error", err)
		}
	}
}

// claimPendingMessages reclaims messages that other consumers failed to process.
func (q *RedisStreamQueue) claimPendingMessages() {
	defer q.wg.Done()

	ticker := time.NewTicker(claimTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-q.stopCh:
			return
		case <-ticker.C:
			q.claimOldPending()
		}
	}
}

// claimOldPending claims messages that have been pending too long.
func (q *RedisStreamQueue) claimOldPending() {
	ctx := context.Background()

	pending, err := q.rdb.XPendingExt(ctx, &redis.XPendingExtArgs{
		Stream: emailStream,
		Group:  emailConsumerGroup,
		Start:  "-",
		End:    "+",
		Count:  100,
	}).Result()

	if err != nil {
		if err != redis.Nil {
			q.logger.Error("Failed to get pending messages", "error", err)
		}
		return
	}

	for _, p := range pending {
		if p.Idle > claimTimeout {
			// Claim the message
			claimed, err := q.rdb.XClaim(ctx, &redis.XClaimArgs{
				Stream:   emailStream,
				Group:    emailConsumerGroup,
				Consumer: q.consumerName,
				MinIdle:  claimTimeout,
				Messages: []string{p.ID},
			}).Result()

			if err != nil {
				q.logger.Error("Failed to claim message", "id", p.ID, "error", err)
				continue
			}

			for _, msg := range claimed {
				q.logger.Info("Claimed pending message", "id", msg.ID)
				q.processMessage(msg)
			}
		}
	}
}

// Service interface implementations - enqueue via Redis Streams

func (q *RedisStreamQueue) enqueue(jobType, recipient string, payload interface{}) error {
	q.mu.RLock()
	if q.stopped {
		q.mu.RUnlock()
		return ErrQueueStopped
	}
	q.mu.RUnlock()

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	ctx := context.Background()
	err = q.rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: emailStream,
		Values: map[string]interface{}{
			"type":       jobType,
			"recipient":  recipient,
			"payload":    string(payloadJSON),
			"attempts":   "0",
			"created_at": time.Now().Format(time.RFC3339),
		},
	}).Err()

	if err != nil {
		q.logger.Error("Failed to enqueue email job", "type", jobType, "error", err)
		return err
	}

	q.logger.Debug("Email job enqueued to Redis stream", "type", jobType, "recipient", recipient)
	return nil
}

func (q *RedisStreamQueue) SendVerificationEmail(ctx context.Context, user *storage.User, token string, verifyURL string) error {
	return q.enqueue(jobTypeVerification, user.Email, map[string]interface{}{
		"user":       map[string]interface{}{"email": user.Email, "first_name": user.FirstName, "last_name": user.LastName},
		"token":      token,
		"verify_url": verifyURL,
	})
}

func (q *RedisStreamQueue) SendPasswordResetEmail(ctx context.Context, user *storage.User, token string, resetURL string) error {
	return q.enqueue(jobTypePasswordReset, user.Email, map[string]interface{}{
		"user":      map[string]interface{}{"email": user.Email, "first_name": user.FirstName, "last_name": user.LastName},
		"token":     token,
		"reset_url": resetURL,
	})
}

func (q *RedisStreamQueue) SendWelcomeEmail(ctx context.Context, user *storage.User) error {
	return q.enqueue(jobTypeWelcome, user.Email, map[string]interface{}{
		"user": map[string]interface{}{"email": user.Email, "first_name": user.FirstName, "last_name": user.LastName},
	})
}

func (q *RedisStreamQueue) SendLoginAlertEmail(ctx context.Context, user *storage.User, device *DeviceInfo) error {
	return q.enqueue(jobTypeLoginAlert, user.Email, map[string]interface{}{
		"user":   map[string]interface{}{"email": user.Email, "first_name": user.FirstName, "last_name": user.LastName},
		"device": map[string]interface{}{"ip": device.IPAddress, "user_agent": device.Browser, "location": device.Location},
	})
}

func (q *RedisStreamQueue) SendInvitationEmail(ctx context.Context, invitation *InvitationEmail) error {
	return q.enqueue(jobTypeInvitation, invitation.Email, map[string]interface{}{
		"invitation": map[string]interface{}{"email": invitation.Email, "invite_url": invitation.InviteURL, "inviter_name": invitation.InviterName},
	})
}

func (q *RedisStreamQueue) SendMFAEnabledEmail(ctx context.Context, user *storage.User) error {
	return q.enqueue(jobTypeMFAEnabled, user.Email, map[string]interface{}{
		"user": map[string]interface{}{"email": user.Email, "first_name": user.FirstName, "last_name": user.LastName},
	})
}

func (q *RedisStreamQueue) SendMFACodeEmail(ctx context.Context, email string, code string) error {
	return q.enqueue(jobTypeMFACode, email, map[string]interface{}{
		"email": email,
		"code":  code,
	})
}

func (q *RedisStreamQueue) SendLowBackupCodesEmail(ctx context.Context, user *storage.User, remaining int) error {
	return q.enqueue(jobTypeLowBackupCodes, user.Email, map[string]interface{}{
		"user":      map[string]interface{}{"email": user.Email, "first_name": user.FirstName, "last_name": user.LastName},
		"remaining": remaining,
	})
}

func (q *RedisStreamQueue) SendPasswordChangedEmail(ctx context.Context, user *storage.User) error {
	return q.enqueue(jobTypePasswordChanged, user.Email, map[string]interface{}{
		"user": map[string]interface{}{"email": user.Email, "first_name": user.FirstName, "last_name": user.LastName},
	})
}

func (q *RedisStreamQueue) SendSessionRevokedEmail(ctx context.Context, user *storage.User, reason string) error {
	return q.enqueue(jobTypeSessionRevoked, user.Email, map[string]interface{}{
		"user":   map[string]interface{}{"email": user.Email, "first_name": user.FirstName, "last_name": user.LastName},
		"reason": reason,
	})
}

func (q *RedisStreamQueue) SendMagicLink(ctx context.Context, email string, magicLinkURL string) error {
	return q.inner.SendMagicLink(ctx, email, magicLinkURL)
}

func (q *RedisStreamQueue) SendAccountDeactivatedEmail(ctx context.Context, user *storage.User, reason, reactivationURL string) error {
	return q.enqueue(jobTypeAccountDeactivated, user.Email, map[string]interface{}{
		"user":             map[string]interface{}{"email": user.Email, "first_name": user.FirstName, "last_name": user.LastName},
		"reason":           reason,
		"reactivation_url": reactivationURL,
	})
}

func (q *RedisStreamQueue) SendEmailChangedEmail(ctx context.Context, user *storage.User, oldEmail, newEmail string) error {
	return q.enqueue(jobTypeEmailChanged, oldEmail, map[string]interface{}{
		"user":      map[string]interface{}{"email": newEmail, "first_name": user.FirstName, "last_name": user.LastName},
		"old_email": oldEmail,
		"new_email": newEmail,
	})
}

func (q *RedisStreamQueue) SendPasswordExpiryEmail(ctx context.Context, user *storage.User, daysUntilExpiry, expiryDate, changePasswordURL string) error {
	return q.enqueue(jobTypePasswordExpiry, user.Email, map[string]interface{}{
		"user":                map[string]interface{}{"email": user.Email, "first_name": user.FirstName, "last_name": user.LastName},
		"days_until_expiry":   daysUntilExpiry,
		"expiry_date":         expiryDate,
		"change_password_url": changePasswordURL,
	})
}

func (q *RedisStreamQueue) SendSecurityAlertEmail(ctx context.Context, user *storage.User, title, message, details, actionURL, actionText string) error {
	return q.enqueue(jobTypeSecurityAlert, user.Email, map[string]interface{}{
		"user":          map[string]interface{}{"email": user.Email, "first_name": user.FirstName, "last_name": user.LastName},
		"alert_title":   title,
		"alert_message": message,
		"alert_details": details,
		"action_url":    actionURL,
		"action_text":   actionText,
	})
}

func (q *RedisStreamQueue) SendRateLimitWarningEmail(ctx context.Context, user *storage.User, actionType, currentCount, maxCount, timeWindow, upgradeURL string) error {
	return q.enqueue(jobTypeRateLimitWarning, user.Email, map[string]interface{}{
		"user":          map[string]interface{}{"email": user.Email, "first_name": user.FirstName, "last_name": user.LastName},
		"action_type":   actionType,
		"current_count": currentCount,
		"max_count":     maxCount,
		"time_window":   timeWindow,
		"upgrade_url":   upgradeURL,
	})
}

// GetQueueStats returns statistics about the email queue.
func (q *RedisStreamQueue) GetQueueStats(ctx context.Context) (*QueueStats, error) {
	info, err := q.rdb.XInfoStream(ctx, emailStream).Result()
	if err != nil {
		return nil, err
	}

	groups, err := q.rdb.XInfoGroups(ctx, emailStream).Result()
	if err != nil {
		return nil, err
	}

	var pending int64
	for _, g := range groups {
		pending += g.Pending
	}

	deadLetterLen, _ := q.rdb.XLen(ctx, deadLetterStream).Result()

	return &QueueStats{
		TotalMessages:   info.Length,
		PendingMessages: pending,
		DeadLetterCount: deadLetterLen,
		ConsumerGroups:  len(groups),
	}, nil
}

// QueueStats contains statistics about the email queue.
type QueueStats struct {
	TotalMessages   int64 `json:"total_messages"`
	PendingMessages int64 `json:"pending_messages"`
	DeadLetterCount int64 `json:"dead_letter_count"`
	ConsumerGroups  int   `json:"consumer_groups"`
}

// Verify RedisStreamQueue implements Service interface
var _ Service = (*RedisStreamQueue)(nil)
