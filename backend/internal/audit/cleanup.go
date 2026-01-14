// Package audit provides audit log cleanup functionality.
package audit

import (
	"context"
	"log/slog"
	"time"

	"github.com/iSundram/ModernAuth/internal/storage"
)

// CleanupService handles scheduled cleanup of old audit logs.
type CleanupService struct {
	storage        storage.Storage
	retentionPeriod time.Duration
	cleanupInterval time.Duration
	logger         *slog.Logger
	stopChan       chan struct{}
}

// NewCleanupService creates a new audit log cleanup service.
func NewCleanupService(storage storage.Storage, retentionPeriod, cleanupInterval time.Duration) *CleanupService {
	return &CleanupService{
		storage:         storage,
		retentionPeriod: retentionPeriod,
		cleanupInterval: cleanupInterval,
		logger:          slog.Default().With("component", "audit_cleanup"),
		stopChan:       make(chan struct{}),
	}
}

// Start begins the cleanup service in a goroutine.
func (s *CleanupService) Start(ctx context.Context) {
	go s.run(ctx)
}

// Stop stops the cleanup service.
func (s *CleanupService) Stop() {
	close(s.stopChan)
}

// run executes the cleanup loop.
func (s *CleanupService) run(ctx context.Context) {
	ticker := time.NewTicker(s.cleanupInterval)
	defer ticker.Stop()

	// Run cleanup immediately on start
	s.cleanup(ctx)

	for {
		select {
		case <-ticker.C:
			s.cleanup(ctx)
		case <-s.stopChan:
			s.logger.Info("Audit cleanup service stopped")
			return
		case <-ctx.Done():
			s.logger.Info("Audit cleanup service stopped due to context cancellation")
			return
		}
	}
}

// cleanup performs the actual cleanup of old audit logs.
func (s *CleanupService) cleanup(ctx context.Context) {
	cutoffTime := time.Now().Add(-s.retentionPeriod)
	
	s.logger.Info("Starting audit log cleanup", "cutoff_time", cutoffTime)
	
	deleted, err := s.storage.DeleteOldAuditLogs(ctx, cutoffTime)
	if err != nil {
		s.logger.Error("Failed to cleanup audit logs", "error", err)
		return
	}
	
	s.logger.Info("Audit log cleanup completed", "deleted_count", deleted, "cutoff_time", cutoffTime)
}
