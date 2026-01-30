// Package auth provides authentication services for ModernAuth.
// This file contains risk-based authentication functionality.
package auth

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
)

// RiskLevel represents the risk level of an authentication attempt.
type RiskLevel string

const (
	RiskLevelLow    RiskLevel = "low"
	RiskLevelMedium RiskLevel = "medium"
	RiskLevelHigh   RiskLevel = "high"
)

// RiskAction represents the action taken based on risk assessment.
type RiskAction string

const (
	RiskActionAllowed     RiskAction = "allowed"
	RiskActionMFARequired RiskAction = "mfa_required"
	RiskActionBlocked     RiskAction = "blocked"
	RiskActionWarned      RiskAction = "warned"
)

// RiskFactor represents a factor contributing to risk score.
type RiskFactor struct {
	Name        string `json:"name"`
	Score       int    `json:"score"`
	Description string `json:"description"`
}

// RiskAssessmentResult represents the result of a risk assessment.
type RiskAssessmentResult struct {
	RiskScore   int          `json:"risk_score"`
	RiskLevel   RiskLevel    `json:"risk_level"`
	Factors     []RiskFactor `json:"factors"`
	Action      RiskAction   `json:"action"`
	RequiresMFA bool         `json:"requires_mfa"`
}

// RiskAssessmentRequest contains information for risk assessment.
type RiskAssessmentRequest struct {
	UserID          uuid.UUID
	IPAddress       string
	UserAgent       string
	DeviceID        *uuid.UUID
	LocationCountry string
	LocationCity    string
}

// RiskAssessmentStorage interface for risk assessment operations.
type RiskAssessmentStorage interface {
	CreateRiskAssessment(ctx context.Context, assessment *storage.RiskAssessment) error
	GetRecentRiskAssessments(ctx context.Context, userID uuid.UUID, limit int) ([]*storage.RiskAssessment, error)
}

// AssessLoginRisk performs risk-based authentication assessment.
func (s *AuthService) AssessLoginRisk(ctx context.Context, req *RiskAssessmentRequest, highThreshold, mediumThreshold int) (*RiskAssessmentResult, error) {
	factors := []RiskFactor{}
	totalScore := 0

	// Factor 1: Check for new device
	if req.DeviceID == nil {
		factor := RiskFactor{
			Name:        "new_device",
			Score:       20,
			Description: "Login from new device",
		}
		factors = append(factors, factor)
		totalScore += factor.Score
	}

	// Factor 2: Check login history for unusual patterns
	recentLogins, err := s.getRecentLogins(ctx, req.UserID)
	if err == nil {
		// Check for unusual IP
		if isUnusualIP(req.IPAddress, recentLogins) {
			factor := RiskFactor{
				Name:        "unusual_ip",
				Score:       15,
				Description: "Login from unusual IP address",
			}
			factors = append(factors, factor)
			totalScore += factor.Score
		}

		// Check for unusual location
		if isUnusualLocation(req.LocationCountry, recentLogins) {
			factor := RiskFactor{
				Name:        "unusual_location",
				Score:       25,
				Description: "Login from unusual location",
			}
			factors = append(factors, factor)
			totalScore += factor.Score
		}

		// Check for high velocity (too many logins in short time)
		if isHighVelocity(recentLogins) {
			factor := RiskFactor{
				Name:        "high_velocity",
				Score:       30,
				Description: "Unusually high login frequency",
			}
			factors = append(factors, factor)
			totalScore += factor.Score
		}
	}

	// Factor 3: Check user agent for suspicious patterns
	if isSuspiciousUserAgent(req.UserAgent) {
		factor := RiskFactor{
			Name:        "suspicious_user_agent",
			Score:       20,
			Description: "Suspicious user agent detected",
		}
		factors = append(factors, factor)
		totalScore += factor.Score
	}

	// Factor 4: Check for unusual time of login
	if isUnusualTime() {
		factor := RiskFactor{
			Name:        "unusual_time",
			Score:       10,
			Description: "Login at unusual time",
		}
		factors = append(factors, factor)
		totalScore += factor.Score
	}

	// Cap score at 100
	if totalScore > 100 {
		totalScore = 100
	}

	// Determine risk level and action
	var riskLevel RiskLevel
	var action RiskAction
	var requiresMFA bool

	switch {
	case totalScore >= highThreshold:
		riskLevel = RiskLevelHigh
		action = RiskActionBlocked
		requiresMFA = true
	case totalScore >= mediumThreshold:
		riskLevel = RiskLevelMedium
		action = RiskActionMFARequired
		requiresMFA = true
	default:
		riskLevel = RiskLevelLow
		action = RiskActionAllowed
		requiresMFA = false
	}

	result := &RiskAssessmentResult{
		RiskScore:   totalScore,
		RiskLevel:   riskLevel,
		Factors:     factors,
		Action:      action,
		RequiresMFA: requiresMFA,
	}

	// Store risk assessment
	if riskStorage, ok := s.storage.(RiskAssessmentStorage); ok {
		factorsMap := make(map[string]interface{})
		for _, f := range factors {
			factorsMap[f.Name] = map[string]interface{}{
				"score":       f.Score,
				"description": f.Description,
			}
		}

		assessment := &storage.RiskAssessment{
			ID:              uuid.New(),
			UserID:          req.UserID,
			RiskScore:       totalScore,
			RiskLevel:       string(riskLevel),
			Factors:         factorsMap,
			ActionTaken:     string(action),
			CreatedAt:       time.Now(),
		}
		if req.IPAddress != "" {
			assessment.IPAddress = &req.IPAddress
		}
		if req.UserAgent != "" {
			assessment.UserAgent = &req.UserAgent
		}
		if req.LocationCountry != "" {
			assessment.LocationCountry = &req.LocationCountry
		}
		if req.LocationCity != "" {
			assessment.LocationCity = &req.LocationCity
		}

		if err := riskStorage.CreateRiskAssessment(ctx, assessment); err != nil {
			s.logger.Warn("Failed to store risk assessment", "error", err)
		}
	}

	s.logger.Info("Risk assessment completed",
		"user_id", req.UserID,
		"score", totalScore,
		"level", riskLevel,
		"action", action)

	return result, nil
}

// getRecentLogins retrieves recent login history for risk analysis.
func (s *AuthService) getRecentLogins(ctx context.Context, userID uuid.UUID) ([]*storage.LoginHistory, error) {
	if deviceStorage, ok := s.storage.(storage.DeviceStorage); ok {
		return deviceStorage.GetLoginHistory(ctx, userID, 20, 0)
	}
	return nil, nil
}

// isUnusualIP checks if the IP is unusual compared to recent logins.
func isUnusualIP(ip string, history []*storage.LoginHistory) bool {
	if len(history) < 3 {
		return false // Not enough history
	}

	// Check if IP was seen in last 5 logins
	for i, h := range history {
		if i >= 5 {
			break
		}
		if h.IPAddress != nil && *h.IPAddress == ip {
			return false
		}
	}
	return true
}

// isUnusualLocation checks if the location is unusual compared to recent logins.
func isUnusualLocation(country string, history []*storage.LoginHistory) bool {
	if country == "" || len(history) < 3 {
		return false
	}

	// Check if country was seen in last 10 logins
	for i, h := range history {
		if i >= 10 {
			break
		}
		if h.LocationCountry != nil && *h.LocationCountry == country {
			return false
		}
	}
	return true
}

// isHighVelocity checks for unusually high login frequency.
func isHighVelocity(history []*storage.LoginHistory) bool {
	if len(history) < 5 {
		return false
	}

	// Check for more than 5 logins in last hour
	oneHourAgo := time.Now().Add(-time.Hour)
	count := 0
	for _, h := range history {
		if h.CreatedAt.After(oneHourAgo) {
			count++
		}
	}
	return count >= 5
}

// isSuspiciousUserAgent checks for suspicious user agent patterns.
func isSuspiciousUserAgent(userAgent string) bool {
	if userAgent == "" {
		return true // No user agent is suspicious
	}

	ua := strings.ToLower(userAgent)

	// Check for automated tools
	suspiciousPatterns := []string{
		"curl",
		"wget",
		"python-requests",
		"scrapy",
		"bot",
		"spider",
		"crawler",
		"headless",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(ua, pattern) {
			return true
		}
	}

	return false
}

// isUnusualTime checks if the current time is unusual for logins.
func isUnusualTime() bool {
	hour := time.Now().UTC().Hour()
	// Consider 2 AM - 5 AM UTC as unusual
	return hour >= 2 && hour <= 5
}
