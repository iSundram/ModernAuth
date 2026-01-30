// Package email provides an async email queue with retry logic.
package email

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/iSundram/ModernAuth/internal/storage"
)

// EmailJob represents an email job in the queue.
type EmailJob struct {
	ID        string
	Type      string
	Recipient string
	Subject   string
	Payload   interface{}
	Attempts  int
	MaxRetry  int
	NextRetry time.Time
	CreatedAt time.Time
}

// QueuedService wraps an email service with async queue and retry logic.
type QueuedService struct {
	inner           Service
	deadLetterStore storage.EmailTemplateStorage
	logger          *slog.Logger
	queue           chan *EmailJob
	wg              sync.WaitGroup
	stopCh          chan struct{}
	stopped         bool
	mu              sync.RWMutex
}

// QueueConfig holds queue configuration.
type QueueConfig struct {
	QueueSize        int                          // Buffer size for the job queue
	MaxRetries       int                          // Maximum retry attempts
	DeadLetterStore  storage.EmailTemplateStorage // Storage for dead letters (optional)
}

// DefaultQueueConfig returns sensible defaults.
func DefaultQueueConfig() *QueueConfig {
	return &QueueConfig{
		QueueSize:  1000,
		MaxRetries: 3,
	}
}

// NewQueuedService creates a new queued email service.
func NewQueuedService(inner Service, cfg *QueueConfig) *QueuedService {
	if cfg == nil {
		cfg = DefaultQueueConfig()
	}

	qs := &QueuedService{
		inner:           inner,
		deadLetterStore: cfg.DeadLetterStore,
		logger:          slog.Default().With("component", "email_queue"),
		queue:           make(chan *EmailJob, cfg.QueueSize),
		stopCh:          make(chan struct{}),
	}

	// Start worker
	qs.wg.Add(1)
	go qs.worker()

	return qs
}

// Stop gracefully stops the queue worker.
func (q *QueuedService) Stop() {
	q.mu.Lock()
	if q.stopped {
		q.mu.Unlock()
		return
	}
	q.stopped = true
	q.mu.Unlock()

	close(q.stopCh)
	q.wg.Wait()
	q.logger.Info("Email queue stopped")
}

// worker processes jobs from the queue.
func (q *QueuedService) worker() {
	defer q.wg.Done()

	// Retry queue for failed jobs
	retryQueue := make([]*EmailJob, 0)
	retryTicker := time.NewTicker(10 * time.Second)
	defer retryTicker.Stop()

	for {
		select {
		case <-q.stopCh:
			// Drain remaining jobs
			q.drainQueue()
			return

		case job := <-q.queue:
			if err := q.processJob(job); err != nil {
				if job.Attempts < job.MaxRetry {
					job.Attempts++
					job.NextRetry = q.calculateNextRetry(job.Attempts)
					retryQueue = append(retryQueue, job)
					q.logger.Warn("Email job failed, scheduled for retry",
						"job_id", job.ID,
						"type", job.Type,
						"attempt", job.Attempts,
						"next_retry", job.NextRetry,
						"error", err,
					)
				} else {
					q.logger.Error("Email job failed permanently",
						"job_id", job.ID,
						"type", job.Type,
						"attempts", job.Attempts,
						"error", err,
					)
					q.storeDeadLetter(job, err)
				}
			}

		case <-retryTicker.C:
			// Process retry queue
			now := time.Now()
			remaining := make([]*EmailJob, 0)
			for _, job := range retryQueue {
				if now.After(job.NextRetry) {
					if err := q.processJob(job); err != nil {
						if job.Attempts < job.MaxRetry {
							job.Attempts++
							job.NextRetry = q.calculateNextRetry(job.Attempts)
							remaining = append(remaining, job)
						} else {
							q.logger.Error("Email job failed permanently after retries",
								"job_id", job.ID,
								"type", job.Type,
								"attempts", job.Attempts,
								"error", err,
							)
							q.storeDeadLetter(job, err)
						}
					}
				} else {
					remaining = append(remaining, job)
				}
			}
			retryQueue = remaining
		}
	}
}

// calculateNextRetry returns the next retry time using exponential backoff.
func (q *QueuedService) calculateNextRetry(attempt int) time.Time {
	// Exponential backoff: 1min, 5min, 15min
	delays := []time.Duration{
		1 * time.Minute,
		5 * time.Minute,
		15 * time.Minute,
	}
	idx := attempt - 1
	if idx >= len(delays) {
		idx = len(delays) - 1
	}
	return time.Now().Add(delays[idx])
}

// storeDeadLetter stores a permanently failed job in the dead letter queue.
func (q *QueuedService) storeDeadLetter(job *EmailJob, err error) {
	if q.deadLetterStore == nil {
		return
	}

	// Convert payload to map for storage
	payloadMap := make(map[string]interface{})
	if payloadBytes, marshalErr := json.Marshal(job.Payload); marshalErr == nil {
		json.Unmarshal(payloadBytes, &payloadMap)
	}

	dl := &storage.EmailDeadLetter{
		JobType:      job.Type,
		Recipient:    job.Recipient,
		Payload:      payloadMap,
		ErrorMessage: err.Error(),
		Attempts:     job.Attempts,
		CreatedAt:    job.CreatedAt,
	}
	if job.Subject != "" {
		dl.Subject = &job.Subject
	}

	if storeErr := q.deadLetterStore.CreateEmailDeadLetter(context.Background(), dl); storeErr != nil {
		q.logger.Error("Failed to store dead letter", "job_id", job.ID, "error", storeErr)
	} else {
		q.logger.Info("Stored failed email in dead letter queue", "job_id", job.ID, "type", job.Type)
	}
}

// drainQueue processes remaining jobs before shutdown.
func (q *QueuedService) drainQueue() {
	for {
		select {
		case job := <-q.queue:
			if err := q.processJob(job); err != nil {
				q.logger.Warn("Failed to process job during drain", "job_id", job.ID, "error", err)
			}
		default:
			return
		}
	}
}

// Job type constants
const (
	jobTypeVerification    = "verification"
	jobTypePasswordReset   = "password_reset"
	jobTypeWelcome         = "welcome"
	jobTypeLoginAlert      = "login_alert"
	jobTypeInvitation      = "invitation"
	jobTypeMFAEnabled      = "mfa_enabled"
	jobTypePasswordChanged = "password_changed"
	jobTypeSessionRevoked  = "session_revoked"
)

// Payload types for jobs
type verificationPayload struct {
	User      *storage.User
	Token     string
	VerifyURL string
}

type passwordResetPayload struct {
	User     *storage.User
	Token    string
	ResetURL string
}

type welcomePayload struct {
	User *storage.User
}

type loginAlertPayload struct {
	User   *storage.User
	Device *DeviceInfo
}

type invitationPayload struct {
	Invitation *InvitationEmail
}

type mfaEnabledPayload struct {
	User *storage.User
}

type passwordChangedPayload struct {
	User *storage.User
}

type sessionRevokedPayload struct {
	User   *storage.User
	Reason string
}

// processJob executes the email job.
func (q *QueuedService) processJob(job *EmailJob) error {
	ctx := context.Background()

	switch job.Type {
	case jobTypeVerification:
		p := job.Payload.(*verificationPayload)
		return q.inner.SendVerificationEmail(ctx, p.User, p.Token, p.VerifyURL)
	case jobTypePasswordReset:
		p := job.Payload.(*passwordResetPayload)
		return q.inner.SendPasswordResetEmail(ctx, p.User, p.Token, p.ResetURL)
	case jobTypeWelcome:
		p := job.Payload.(*welcomePayload)
		return q.inner.SendWelcomeEmail(ctx, p.User)
	case jobTypeLoginAlert:
		p := job.Payload.(*loginAlertPayload)
		return q.inner.SendLoginAlertEmail(ctx, p.User, p.Device)
	case jobTypeInvitation:
		p := job.Payload.(*invitationPayload)
		return q.inner.SendInvitationEmail(ctx, p.Invitation)
	case jobTypeMFAEnabled:
		p := job.Payload.(*mfaEnabledPayload)
		return q.inner.SendMFAEnabledEmail(ctx, p.User)
	case jobTypePasswordChanged:
		p := job.Payload.(*passwordChangedPayload)
		return q.inner.SendPasswordChangedEmail(ctx, p.User)
	case jobTypeSessionRevoked:
		p := job.Payload.(*sessionRevokedPayload)
		return q.inner.SendSessionRevokedEmail(ctx, p.User, p.Reason)
	default:
		q.logger.Error("Unknown job type", "type", job.Type)
		return nil
	}
}

// enqueue adds a job to the queue.
func (q *QueuedService) enqueue(jobType string, recipient string, payload interface{}) error {
	q.mu.RLock()
	if q.stopped {
		q.mu.RUnlock()
		return ErrQueueStopped
	}
	q.mu.RUnlock()

	job := &EmailJob{
		ID:        generateJobID(),
		Type:      jobType,
		Recipient: recipient,
		Payload:   payload,
		Attempts:  0,
		MaxRetry:  3,
		CreatedAt: time.Now(),
	}

	select {
	case q.queue <- job:
		q.logger.Debug("Email job enqueued", "job_id", job.ID, "type", jobType)
		return nil
	default:
		q.logger.Error("Email queue full, dropping job", "type", jobType)
		return ErrQueueFull
	}
}

// generateJobID creates a unique job ID.
func generateJobID() string {
	return time.Now().Format("20060102150405.000000000")
}

// Service interface implementations - all async via queue

func (q *QueuedService) SendVerificationEmail(ctx context.Context, user *storage.User, token string, verifyURL string) error {
	return q.enqueue(jobTypeVerification, user.Email, &verificationPayload{User: user, Token: token, VerifyURL: verifyURL})
}

func (q *QueuedService) SendPasswordResetEmail(ctx context.Context, user *storage.User, token string, resetURL string) error {
	return q.enqueue(jobTypePasswordReset, user.Email, &passwordResetPayload{User: user, Token: token, ResetURL: resetURL})
}

func (q *QueuedService) SendWelcomeEmail(ctx context.Context, user *storage.User) error {
	return q.enqueue(jobTypeWelcome, user.Email, &welcomePayload{User: user})
}

func (q *QueuedService) SendLoginAlertEmail(ctx context.Context, user *storage.User, device *DeviceInfo) error {
	return q.enqueue(jobTypeLoginAlert, user.Email, &loginAlertPayload{User: user, Device: device})
}

func (q *QueuedService) SendInvitationEmail(ctx context.Context, invitation *InvitationEmail) error {
	return q.enqueue(jobTypeInvitation, invitation.Email, &invitationPayload{Invitation: invitation})
}

func (q *QueuedService) SendMFAEnabledEmail(ctx context.Context, user *storage.User) error {
	return q.enqueue(jobTypeMFAEnabled, user.Email, &mfaEnabledPayload{User: user})
}

func (q *QueuedService) SendPasswordChangedEmail(ctx context.Context, user *storage.User) error {
	return q.enqueue(jobTypePasswordChanged, user.Email, &passwordChangedPayload{User: user})
}

func (q *QueuedService) SendSessionRevokedEmail(ctx context.Context, user *storage.User, reason string) error {
	return q.enqueue(jobTypeSessionRevoked, user.Email, &sessionRevokedPayload{User: user, Reason: reason})
}

// SendMagicLink sends a magic link email (synchronously - no queue for time-sensitive emails).
func (q *QueuedService) SendMagicLink(email string, magicLinkURL string) error {
	// Magic links are time-sensitive, so we send them directly without queuing
	return q.inner.SendMagicLink(email, magicLinkURL)
}

// Verify QueuedService implements Service interface
var _ Service = (*QueuedService)(nil)
