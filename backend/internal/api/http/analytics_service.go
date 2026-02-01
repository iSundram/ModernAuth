// Package http provides the analytics service for ModernAuth.
package http

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
	"github.com/redis/go-redis/v9"
)

// AnalyticsService provides analytics data aggregation.
type AnalyticsService struct {
	storage storage.Storage
	rdb     *redis.Client
}

// NewAnalyticsService creates a new analytics service.
func NewAnalyticsService(store storage.Storage, rdb *redis.Client) *AnalyticsService {
	return &AnalyticsService{
		storage: store,
		rdb:     rdb,
	}
}

// GetOverview returns high-level analytics overview.
func (s *AnalyticsService) GetOverview(ctx context.Context) (*AnalyticsOverview, error) {
	totalUsers, err := s.storage.CountUsers(ctx)
	if err != nil {
		return nil, err
	}

	// Count users with recent activity (last 24h = DAU)
	dau, err := s.countActiveUsers(ctx, 24*time.Hour)
	if err != nil {
		dau = 0
	}

	// WAU - last 7 days
	wau, err := s.countActiveUsers(ctx, 7*24*time.Hour)
	if err != nil {
		wau = 0
	}

	// MAU - last 30 days
	mau, err := s.countActiveUsers(ctx, 30*24*time.Hour)
	if err != nil {
		mau = 0
	}

	// New users today
	newUsersToday, err := s.countNewUsers(ctx, 24*time.Hour)
	if err != nil {
		newUsersToday = 0
	}

	// New users this week
	newUsersThisWeek, err := s.countNewUsers(ctx, 7*24*time.Hour)
	if err != nil {
		newUsersThisWeek = 0
	}

	// MFA adoption rate
	usersWithMFA, err := s.countUsersWithMFA(ctx)
	if err != nil {
		usersWithMFA = 0
	}
	mfaAdoptionRate := 0.0
	if totalUsers > 0 {
		mfaAdoptionRate = float64(usersWithMFA) / float64(totalUsers) * 100
	}

	// Verified users rate
	verifiedUsers, err := s.countVerifiedUsers(ctx)
	if err != nil {
		verifiedUsers = 0
	}
	verifiedRate := 0.0
	if totalUsers > 0 {
		verifiedRate = float64(verifiedUsers) / float64(totalUsers) * 100
	}

	// Active users count (users with recent login)
	activeUsers, err := s.countActiveUsers(ctx, 30*24*time.Hour)
	if err != nil {
		activeUsers = 0
	}

	return &AnalyticsOverview{
		TotalUsers:        totalUsers,
		ActiveUsers:       activeUsers,
		NewUsersToday:     newUsersToday,
		NewUsersThisWeek:  newUsersThisWeek,
		DAU:               dau,
		WAU:               wau,
		MAU:               mau,
		MFAAdoptionRate:   mfaAdoptionRate,
		VerifiedUsersRate: verifiedRate,
	}, nil
}

// GetUserAnalytics returns detailed user analytics.
func (s *AnalyticsService) GetUserAnalytics(ctx context.Context) (*UserAnalytics, error) {
	totalUsers, _ := s.storage.CountUsers(ctx)
	verifiedUsers, _ := s.countVerifiedUsers(ctx)
	usersWithMFA, _ := s.countUsersWithMFA(ctx)
	activeUsers, _ := s.countActiveUsers(ctx, 30*24*time.Hour)

	// Get recent signups for the last 14 days
	recentSignups, err := s.getSignupTrend(ctx, 14)
	if err != nil {
		recentSignups = []SignupData{}
	}

	return &UserAnalytics{
		TotalUsers:      totalUsers,
		ActiveUsers:     activeUsers,
		VerifiedUsers:   verifiedUsers,
		UnverifiedUsers: totalUsers - verifiedUsers,
		UsersWithMFA:    usersWithMFA,
		RecentSignups:   recentSignups,
	}, nil
}

// GetAuthAnalytics returns authentication analytics for the specified period.
func (s *AnalyticsService) GetAuthAnalytics(ctx context.Context, days int) (*AuthAnalytics, error) {
	since := time.Now().AddDate(0, 0, -days)

	// Count login events
	successfulLogins, _ := s.countAuditEvents(ctx, "login.success", since)
	failedLogins, _ := s.countAuditEvents(ctx, "login.failure", since)
	totalLogins := successfulLogins + failedLogins

	successRate := 0.0
	if totalLogins > 0 {
		successRate = float64(successfulLogins) / float64(totalLogins) * 100
	}

	// Count other auth events
	passwordResets, _ := s.countAuditEvents(ctx, "password_reset.success", since)
	magicLinkLogins, _ := s.countAuditEvents(ctx, "magic_link.success", since)
	mfaChallenges, _ := s.countAuditEvents(ctx, "mfa.challenge", since)

	// Get active sessions count from Redis if available
	activeSessions := 0
	if s.rdb != nil {
		keys, _ := s.rdb.Keys(ctx, "session:*").Result()
		activeSessions = len(keys)
	}

	// Get login trend by day
	loginsByDay, err := s.getLoginTrend(ctx, days)
	if err != nil {
		loginsByDay = []DayData{}
	}

	return &AuthAnalytics{
		TotalLogins:      totalLogins,
		SuccessfulLogins: successfulLogins,
		FailedLogins:     failedLogins,
		SuccessRate:      successRate,
		PasswordResets:   passwordResets,
		MagicLinkLogins:  magicLinkLogins,
		MFAChallenges:    mfaChallenges,
		ActiveSessions:   activeSessions,
		LoginsByDay:      loginsByDay,
	}, nil
}

// GetSecurityAnalytics returns security-related analytics.
func (s *AnalyticsService) GetSecurityAnalytics(ctx context.Context) (*SecurityAnalytics, error) {
	since := time.Now().AddDate(0, 0, -7)

	// Count security events
	failedMFA, _ := s.countAuditEvents(ctx, "mfa.failure", since)
	revokedSessions, _ := s.countAuditEvents(ctx, "session.revoked", since)
	suspiciousLogins, _ := s.countAuditEvents(ctx, "login.suspicious", since)

	// Get blocked IPs from Redis if available
	blockedIPs := 0
	if s.rdb != nil {
		keys, _ := s.rdb.Keys(ctx, "lockout:*").Result()
		blockedIPs = len(keys)
	}

	// Get recent security events
	securityEvents, _ := s.getRecentSecurityEvents(ctx, 20)

	return &SecurityAnalytics{
		SuspiciousLogins:   suspiciousLogins,
		FailedMFAAttempts:  failedMFA,
		RevokedSessions:    revokedSessions,
		BlockedIPs:         blockedIPs,
		SecurityEvents:     securityEvents,
	}, nil
}

// GetTimeseriesData returns time-series data for the specified metric.
func (s *AnalyticsService) GetTimeseriesData(ctx context.Context, metric string, days int, interval string) ([]TimeseriesPoint, error) {
	var eventType string
	switch metric {
	case "logins":
		eventType = "login.success"
	case "signups":
		eventType = "user.created"
	case "failed_logins":
		eventType = "login.failure"
	case "mfa_challenges":
		eventType = "mfa.challenge"
	case "password_resets":
		eventType = "password_reset.success"
	default:
		eventType = "login.success"
	}

	return s.getTimeseriesForEvent(ctx, eventType, days, interval)
}

// Helper methods

func (s *AnalyticsService) countActiveUsers(ctx context.Context, period time.Duration) (int, error) {
	// This would ideally query users with last_login_at within the period
	// For now, approximate using audit logs
	since := time.Now().Add(-period)
	logs, err := s.storage.GetAuditLogs(ctx, nil, stringPtr("login.success"), 10000, 0)
	if err != nil {
		return 0, err
	}

	uniqueUsers := make(map[uuid.UUID]bool)
	for _, log := range logs {
		if log.CreatedAt.After(since) && log.UserID != nil {
			uniqueUsers[*log.UserID] = true
		}
	}
	return len(uniqueUsers), nil
}

func (s *AnalyticsService) countNewUsers(ctx context.Context, period time.Duration) (int, error) {
	since := time.Now().Add(-period)
	logs, err := s.storage.GetAuditLogs(ctx, nil, stringPtr("user.created"), 10000, 0)
	if err != nil {
		return 0, err
	}

	count := 0
	for _, log := range logs {
		if log.CreatedAt.After(since) {
			count++
		}
	}
	return count, nil
}

func (s *AnalyticsService) countUsersWithMFA(ctx context.Context) (int, error) {
	// Count from audit logs for MFA setup events
	logs, err := s.storage.GetAuditLogs(ctx, nil, stringPtr("mfa.enabled"), 10000, 0)
	if err != nil {
		return 0, err
	}

	uniqueUsers := make(map[uuid.UUID]bool)
	for _, log := range logs {
		if log.UserID != nil {
			uniqueUsers[*log.UserID] = true
		}
	}
	return len(uniqueUsers), nil
}

func (s *AnalyticsService) countVerifiedUsers(ctx context.Context) (int, error) {
	// Get all users and count verified
	users, err := s.storage.ListUsers(ctx, 10000, 0)
	if err != nil {
		return 0, err
	}

	count := 0
	for _, u := range users {
		if u.IsEmailVerified {
			count++
		}
	}
	return count, nil
}

func (s *AnalyticsService) countAuditEvents(ctx context.Context, eventType string, since time.Time) (int, error) {
	logs, err := s.storage.GetAuditLogs(ctx, nil, &eventType, 10000, 0)
	if err != nil {
		return 0, err
	}

	count := 0
	for _, log := range logs {
		if log.CreatedAt.After(since) {
			count++
		}
	}
	return count, nil
}

func (s *AnalyticsService) getSignupTrend(ctx context.Context, days int) ([]SignupData, error) {
	data := make([]SignupData, days)
	now := time.Now()

	for i := 0; i < days; i++ {
		date := now.AddDate(0, 0, -(days - 1 - i))
		data[i] = SignupData{
			Date:  date.Format("2006-01-02"),
			Count: 0,
		}
	}

	logs, err := s.storage.GetAuditLogs(ctx, nil, stringPtr("user.created"), 10000, 0)
	if err != nil {
		return data, nil
	}

	since := now.AddDate(0, 0, -days)
	for _, log := range logs {
		if log.CreatedAt.After(since) {
			dateStr := log.CreatedAt.Format("2006-01-02")
			for i := range data {
				if data[i].Date == dateStr {
					data[i].Count++
					break
				}
			}
		}
	}

	return data, nil
}

func (s *AnalyticsService) getLoginTrend(ctx context.Context, days int) ([]DayData, error) {
	data := make([]DayData, days)
	now := time.Now()

	for i := 0; i < days; i++ {
		date := now.AddDate(0, 0, -(days - 1 - i))
		data[i] = DayData{
			Date:  date.Format("2006-01-02"),
			Value: 0,
		}
	}

	logs, err := s.storage.GetAuditLogs(ctx, nil, stringPtr("login.success"), 10000, 0)
	if err != nil {
		return data, nil
	}

	since := now.AddDate(0, 0, -days)
	for _, log := range logs {
		if log.CreatedAt.After(since) {
			dateStr := log.CreatedAt.Format("2006-01-02")
			for i := range data {
				if data[i].Date == dateStr {
					data[i].Value++
					break
				}
			}
		}
	}

	return data, nil
}

func (s *AnalyticsService) getRecentSecurityEvents(ctx context.Context, limit int) ([]SecurityEvent, error) {
	// Get security-related events
	eventTypes := []string{"login.failure", "mfa.failure", "session.revoked", "login.suspicious", "account.locked"}

	logs, err := s.storage.ListAuditLogsByEventTypes(ctx, eventTypes, limit, 0)
	if err != nil {
		return nil, err
	}

	events := make([]SecurityEvent, 0, len(logs))
	for _, log := range logs {
		var userID *string
		if log.UserID != nil {
			id := log.UserID.String()
			userID = &id
		}

		ip := ""
		if log.IP != nil {
			ip = *log.IP
		}

		events = append(events, SecurityEvent{
			ID:        log.ID.String(),
			Type:      log.EventType,
			UserID:    userID,
			IP:        ip,
			CreatedAt: log.CreatedAt,
		})
	}

	return events, nil
}

func (s *AnalyticsService) getTimeseriesForEvent(ctx context.Context, eventType string, days int, interval string) ([]TimeseriesPoint, error) {
	now := time.Now()
	since := now.AddDate(0, 0, -days)

	logs, err := s.storage.GetAuditLogs(ctx, nil, &eventType, 100000, 0)
	if err != nil {
		return nil, err
	}

	// Group by interval
	points := make(map[string]int)
	for _, log := range logs {
		if log.CreatedAt.After(since) {
			var key string
			switch interval {
			case "hour":
				key = log.CreatedAt.Format("2006-01-02T15:00:00Z")
			case "day":
				key = log.CreatedAt.Format("2006-01-02")
			case "week":
				year, week := log.CreatedAt.ISOWeek()
				key = time.Date(year, 1, (week-1)*7+1, 0, 0, 0, 0, time.UTC).Format("2006-01-02")
			default:
				key = log.CreatedAt.Format("2006-01-02")
			}
			points[key]++
		}
	}

	// Convert to sorted slice
	result := make([]TimeseriesPoint, 0, len(points))
	for i := 0; i < days; i++ {
		date := now.AddDate(0, 0, -(days - 1 - i))
		key := date.Format("2006-01-02")
		result = append(result, TimeseriesPoint{
			Timestamp: date,
			Value:     points[key],
			Label:     key,
		})
	}

	return result, nil
}

func stringPtr(s string) *string {
	return &s
}
