// Package http provides analytics HTTP handlers for ModernAuth API.
package http

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
)

// AnalyticsHandler provides HTTP handlers for analytics.
type AnalyticsHandler struct {
	analyticsService *AnalyticsService
}

// NewAnalyticsHandler creates a new analytics handler.
func NewAnalyticsHandler(service *AnalyticsService) *AnalyticsHandler {
	return &AnalyticsHandler{analyticsService: service}
}

// AnalyticsRoutes returns chi routes for analytics endpoints.
func (h *AnalyticsHandler) AnalyticsRoutes() chi.Router {
	r := chi.NewRouter()

	r.Get("/overview", h.GetOverview)
	r.Get("/users", h.GetUserAnalytics)
	r.Get("/auth", h.GetAuthAnalytics)
	r.Get("/security", h.GetSecurityAnalytics)
	r.Get("/timeseries", h.GetTimeseriesData)

	return r
}

// GetOverview returns high-level analytics overview.
func (h *AnalyticsHandler) GetOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	overview, err := h.analyticsService.GetOverview(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get analytics overview", err)
		return
	}

	writeJSON(w, http.StatusOK, overview)
}

// GetUserAnalytics returns user-related analytics.
func (h *AnalyticsHandler) GetUserAnalytics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	analytics, err := h.analyticsService.GetUserAnalytics(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get user analytics", err)
		return
	}

	writeJSON(w, http.StatusOK, analytics)
}

// GetAuthAnalytics returns authentication-related analytics.
func (h *AnalyticsHandler) GetAuthAnalytics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse optional time range
	days := 7
	if d := r.URL.Query().Get("days"); d != "" {
		if parsed, err := strconv.Atoi(d); err == nil && parsed > 0 && parsed <= 90 {
			days = parsed
		}
	}

	analytics, err := h.analyticsService.GetAuthAnalytics(ctx, days)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get auth analytics", err)
		return
	}

	writeJSON(w, http.StatusOK, analytics)
}

// GetSecurityAnalytics returns security-related analytics.
func (h *AnalyticsHandler) GetSecurityAnalytics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	analytics, err := h.analyticsService.GetSecurityAnalytics(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get security analytics", err)
		return
	}

	writeJSON(w, http.StatusOK, analytics)
}

// GetTimeseriesData returns time-series data for charts.
func (h *AnalyticsHandler) GetTimeseriesData(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	metric := r.URL.Query().Get("metric")
	if metric == "" {
		metric = "logins"
	}

	days := 30
	if d := r.URL.Query().Get("days"); d != "" {
		if parsed, err := strconv.Atoi(d); err == nil && parsed > 0 && parsed <= 365 {
			days = parsed
		}
	}

	interval := r.URL.Query().Get("interval")
	if interval == "" {
		interval = "day"
	}

	data, err := h.analyticsService.GetTimeseriesData(ctx, metric, days, interval)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get timeseries data", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"metric":   metric,
		"interval": interval,
		"days":     days,
		"data":     data,
	})
}

// AnalyticsOverview represents the analytics overview response.
type AnalyticsOverview struct {
	TotalUsers       int     `json:"total_users"`
	ActiveUsers      int     `json:"active_users"`
	NewUsersToday    int     `json:"new_users_today"`
	NewUsersThisWeek int     `json:"new_users_this_week"`
	DAU              int     `json:"dau"`
	WAU              int     `json:"wau"`
	MAU              int     `json:"mau"`
	AvgSessionsPerUser float64 `json:"avg_sessions_per_user"`
	MFAAdoptionRate  float64 `json:"mfa_adoption_rate"`
	VerifiedUsersRate float64 `json:"verified_users_rate"`
}

// UserAnalytics represents user-related analytics.
type UserAnalytics struct {
	TotalUsers        int            `json:"total_users"`
	ActiveUsers       int            `json:"active_users"`
	VerifiedUsers     int            `json:"verified_users"`
	UnverifiedUsers   int            `json:"unverified_users"`
	UsersWithMFA      int            `json:"users_with_mfa"`
	UsersByPlan       map[string]int `json:"users_by_plan,omitempty"`
	UsersByTenant     map[string]int `json:"users_by_tenant,omitempty"`
	RecentSignups     []SignupData   `json:"recent_signups"`
}

// SignupData represents signup trend data.
type SignupData struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

// AuthAnalytics represents authentication-related analytics.
type AuthAnalytics struct {
	TotalLogins      int     `json:"total_logins"`
	SuccessfulLogins int     `json:"successful_logins"`
	FailedLogins     int     `json:"failed_logins"`
	SuccessRate      float64 `json:"success_rate"`
	PasswordResets   int     `json:"password_resets"`
	MagicLinkLogins  int     `json:"magic_link_logins"`
	OAuthLogins      int     `json:"oauth_logins"`
	MFAChallenges    int     `json:"mfa_challenges"`
	ActiveSessions   int     `json:"active_sessions"`
	LoginsByMethod   map[string]int `json:"logins_by_method"`
	LoginsByDay      []DayData      `json:"logins_by_day"`
}

// DayData represents data for a single day.
type DayData struct {
	Date  string `json:"date"`
	Value int    `json:"value"`
}

// SecurityAnalytics represents security-related analytics.
type SecurityAnalytics struct {
	LockedAccounts      int            `json:"locked_accounts"`
	SuspiciousLogins    int            `json:"suspicious_logins"`
	FailedMFAAttempts   int            `json:"failed_mfa_attempts"`
	RevokedSessions     int            `json:"revoked_sessions"`
	BlockedIPs          int            `json:"blocked_ips"`
	SecurityEvents      []SecurityEvent `json:"security_events"`
	RiskDistribution    map[string]int `json:"risk_distribution"`
}

// SecurityEvent represents a security event.
type SecurityEvent struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	UserID    *string   `json:"user_id,omitempty"`
	IP        string    `json:"ip"`
	Details   string    `json:"details"`
	CreatedAt time.Time `json:"created_at"`
}

// TimeseriesPoint represents a single point in time-series data.
type TimeseriesPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     int       `json:"value"`
	Label     string    `json:"label"`
}
