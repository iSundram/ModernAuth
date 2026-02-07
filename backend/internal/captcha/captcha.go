package captcha

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Provider identifies which CAPTCHA backend is in use.
type Provider string

const (
	ProviderNone        Provider = "none"
	ProviderRecaptchaV2 Provider = "recaptcha_v2"
	ProviderRecaptchaV3 Provider = "recaptcha_v3"
	ProviderTurnstile   Provider = "turnstile"
)

// Config holds CAPTCHA configuration.
type Config struct {
	Provider  Provider
	SiteKey   string
	SecretKey string
	MinScore  float64 // For reCAPTCHA v3, minimum score (0.0-1.0, default 0.5)
}

// VerifyResult contains the outcome of a CAPTCHA verification request.
type VerifyResult struct {
	Success    bool
	Score      float64 // reCAPTCHA v3 score
	Action     string
	Hostname   string
	ErrorCodes []string
}

// Service is the interface for CAPTCHA verification.
type Service interface {
	Verify(ctx context.Context, token string, remoteIP string) (*VerifyResult, error)
	IsEnabled() bool
	GetProvider() Provider
	GetSiteKey() string
}

// ---- reCAPTCHA response (shared by v2 and v3) ----

type recaptchaResponse struct {
	Success     bool     `json:"success"`
	Score       float64  `json:"score"`  // v3 only
	Action      string   `json:"action"` // v3 only
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	ErrorCodes  []string `json:"error-codes"`
}

// ---- Turnstile response ----

type turnstileResponse struct {
	Success     bool     `json:"success"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	ErrorCodes  []string `json:"error-codes"`
	Action      string   `json:"action"`
	CData       string   `json:"cdata"`
}

// ---- Verification endpoints ----

const (
	recaptchaVerifyURL = "https://www.google.com/recaptcha/api/siteverify"
	turnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
)

// ---- HTTP client shared by all implementations ----

var httpClient = &http.Client{
	Timeout: 10 * time.Second,
}

// ============================================================================
// NoopService – always succeeds (captcha disabled)
// ============================================================================

type noopService struct{}

func (n *noopService) Verify(_ context.Context, _ string, _ string) (*VerifyResult, error) {
	return &VerifyResult{Success: true}, nil
}

func (n *noopService) IsEnabled() bool       { return false }
func (n *noopService) GetProvider() Provider { return ProviderNone }
func (n *noopService) GetSiteKey() string    { return "" }

// ============================================================================
// recaptchaV2Service
// ============================================================================

type recaptchaV2Service struct {
	siteKey   string
	secretKey string
	logger    *slog.Logger
}

func (s *recaptchaV2Service) Verify(ctx context.Context, token string, remoteIP string) (*VerifyResult, error) {
	if token == "" {
		return &VerifyResult{Success: false, ErrorCodes: []string{"missing-input-response"}}, nil
	}

	form := url.Values{
		"secret":   {s.secretKey},
		"response": {token},
	}
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, recaptchaVerifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("captcha: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("captcha: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("captcha: failed to read response: %w", err)
	}

	var rr recaptchaResponse
	if err := json.Unmarshal(body, &rr); err != nil {
		return nil, fmt.Errorf("captcha: failed to parse response: %w", err)
	}

	s.logger.Debug("reCAPTCHA v2 verification", "success", rr.Success, "hostname", rr.Hostname, "errors", rr.ErrorCodes)

	return &VerifyResult{
		Success:    rr.Success,
		Hostname:   rr.Hostname,
		ErrorCodes: rr.ErrorCodes,
	}, nil
}

func (s *recaptchaV2Service) IsEnabled() bool       { return true }
func (s *recaptchaV2Service) GetProvider() Provider { return ProviderRecaptchaV2 }
func (s *recaptchaV2Service) GetSiteKey() string    { return s.siteKey }

// ============================================================================
// recaptchaV3Service
// ============================================================================

type recaptchaV3Service struct {
	siteKey   string
	secretKey string
	minScore  float64
	logger    *slog.Logger
}

func (s *recaptchaV3Service) Verify(ctx context.Context, token string, remoteIP string) (*VerifyResult, error) {
	if token == "" {
		return &VerifyResult{Success: false, ErrorCodes: []string{"missing-input-response"}}, nil
	}

	form := url.Values{
		"secret":   {s.secretKey},
		"response": {token},
	}
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, recaptchaVerifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("captcha: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("captcha: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("captcha: failed to read response: %w", err)
	}

	var rr recaptchaResponse
	if err := json.Unmarshal(body, &rr); err != nil {
		return nil, fmt.Errorf("captcha: failed to parse response: %w", err)
	}

	s.logger.Debug("reCAPTCHA v3 verification",
		"success", rr.Success,
		"score", rr.Score,
		"action", rr.Action,
		"hostname", rr.Hostname,
		"errors", rr.ErrorCodes,
	)

	// For v3, success must be true AND the score must meet the threshold.
	passed := rr.Success && rr.Score >= s.minScore

	result := &VerifyResult{
		Success:    passed,
		Score:      rr.Score,
		Action:     rr.Action,
		Hostname:   rr.Hostname,
		ErrorCodes: rr.ErrorCodes,
	}

	if rr.Success && !passed {
		result.ErrorCodes = append(result.ErrorCodes, fmt.Sprintf("score-too-low: %.2f < %.2f", rr.Score, s.minScore))
	}

	return result, nil
}

func (s *recaptchaV3Service) IsEnabled() bool       { return true }
func (s *recaptchaV3Service) GetProvider() Provider { return ProviderRecaptchaV3 }
func (s *recaptchaV3Service) GetSiteKey() string    { return s.siteKey }

// ============================================================================
// turnstileService
// ============================================================================

type turnstileService struct {
	siteKey   string
	secretKey string
	logger    *slog.Logger
}

func (s *turnstileService) Verify(ctx context.Context, token string, remoteIP string) (*VerifyResult, error) {
	if token == "" {
		return &VerifyResult{Success: false, ErrorCodes: []string{"missing-input-response"}}, nil
	}

	form := url.Values{
		"secret":   {s.secretKey},
		"response": {token},
	}
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, turnstileVerifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("captcha: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("captcha: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("captcha: failed to read response: %w", err)
	}

	var tr turnstileResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("captcha: failed to parse response: %w", err)
	}

	s.logger.Debug("Turnstile verification", "success", tr.Success, "hostname", tr.Hostname, "errors", tr.ErrorCodes)

	return &VerifyResult{
		Success:    tr.Success,
		Action:     tr.Action,
		Hostname:   tr.Hostname,
		ErrorCodes: tr.ErrorCodes,
	}, nil
}

func (s *turnstileService) IsEnabled() bool       { return true }
func (s *turnstileService) GetProvider() Provider { return ProviderTurnstile }
func (s *turnstileService) GetSiteKey() string    { return s.siteKey }

// ============================================================================
// NewService – factory
// ============================================================================

// NewService creates the appropriate captcha Service based on Config.
func NewService(cfg *Config) Service {
	logger := slog.Default().With("component", "captcha")

	if cfg == nil || cfg.Provider == ProviderNone || cfg.Provider == "" {
		logger.Info("CAPTCHA disabled")
		return &noopService{}
	}

	switch cfg.Provider {
	case ProviderRecaptchaV2:
		logger.Info("CAPTCHA enabled", "provider", "recaptcha_v2")
		return &recaptchaV2Service{
			siteKey:   cfg.SiteKey,
			secretKey: cfg.SecretKey,
			logger:    logger,
		}

	case ProviderRecaptchaV3:
		minScore := cfg.MinScore
		if minScore <= 0 || minScore > 1.0 {
			minScore = 0.5
		}
		logger.Info("CAPTCHA enabled", "provider", "recaptcha_v3", "min_score", minScore)
		return &recaptchaV3Service{
			siteKey:   cfg.SiteKey,
			secretKey: cfg.SecretKey,
			minScore:  minScore,
			logger:    logger,
		}

	case ProviderTurnstile:
		logger.Info("CAPTCHA enabled", "provider", "turnstile")
		return &turnstileService{
			siteKey:   cfg.SiteKey,
			secretKey: cfg.SecretKey,
			logger:    logger,
		}

	default:
		logger.Warn("Unknown CAPTCHA provider, disabling", "provider", cfg.Provider)
		return &noopService{}
	}
}
