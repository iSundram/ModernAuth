// Package hibp provides breached password detection using the HaveIBeenPwned
// Passwords API with k-Anonymity to protect user privacy.
package hibp

import (
	"context"
	"crypto/sha1"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Config holds the configuration for the HIBP service.
type Config struct {
	Enabled   bool
	APIKey    string // Optional, for higher rate limits
	UserAgent string
	CacheTTL  time.Duration
}

// BreachCache provides caching for HIBP API responses keyed by SHA-1 prefix.
type BreachCache interface {
	// GetBreachCount retrieves cached suffix->count mappings for a hash prefix.
	// Returns the map, whether the cache entry exists, and any error.
	GetBreachCount(ctx context.Context, hashPrefix string) (map[string]int, bool, error)
	// SetBreachCount stores suffix->count mappings for a hash prefix with a TTL.
	SetBreachCount(ctx context.Context, hashPrefix string, suffixes map[string]int, ttl time.Duration) error
}

// CheckResult contains the result of a breached password check.
type CheckResult struct {
	IsBreached bool
	Count      int // Number of times seen in breaches
}

// Service provides breached password detection via the HIBP API.
type Service struct {
	config     *Config
	httpClient *http.Client
	cache      BreachCache
	logger     *slog.Logger
}

// NewService creates a new HIBP service instance.
func NewService(config *Config, cache BreachCache) *Service {
	if config.CacheTTL == 0 {
		config.CacheTTL = 24 * time.Hour
	}
	if config.UserAgent == "" {
		config.UserAgent = "ModernAuth"
	}

	return &Service{
		config: config,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		cache:  cache,
		logger: slog.Default().With("component", "hibp_service"),
	}
}

// CheckPassword checks whether a password has appeared in known data breaches
// using the HIBP k-Anonymity model:
//  1. SHA-1 hash the password
//  2. Send only the first 5 characters (prefix) to the API
//  3. Compare the remaining suffix against the returned list
//
// This ensures the full password hash is never sent over the network.
func (s *Service) CheckPassword(ctx context.Context, password string) (*CheckResult, error) {
	if !s.config.Enabled {
		return &CheckResult{IsBreached: false, Count: 0}, nil
	}

	// SHA-1 hash the password and split into prefix/suffix
	hash := fmt.Sprintf("%X", sha1.Sum([]byte(password)))
	prefix := hash[:5]
	suffix := hash[5:]

	// Check cache first
	if s.cache != nil {
		suffixes, found, err := s.cache.GetBreachCount(ctx, prefix)
		if err != nil {
			s.logger.Warn("Failed to read HIBP cache", "error", err, "prefix", prefix)
			// Fall through to API call
		} else if found {
			count, exists := suffixes[suffix]
			return &CheckResult{
				IsBreached: exists && count > 0,
				Count:      count,
			}, nil
		}
	}

	// Query the HIBP API
	suffixes, err := s.queryAPI(ctx, prefix)
	if err != nil {
		return nil, fmt.Errorf("HIBP API query failed: %w", err)
	}

	// Cache the results
	if s.cache != nil {
		if cacheErr := s.cache.SetBreachCount(ctx, prefix, suffixes, s.config.CacheTTL); cacheErr != nil {
			s.logger.Warn("Failed to write HIBP cache", "error", cacheErr, "prefix", prefix)
		}
	}

	count, exists := suffixes[suffix]
	return &CheckResult{
		IsBreached: exists && count > 0,
		Count:      count,
	}, nil
}

// queryAPI performs a GET request to the HIBP Passwords range endpoint and
// parses the response into a map of suffix -> breach count.
func (s *Service) queryAPI(ctx context.Context, prefix string) (map[string]int, error) {
	url := fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", prefix)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", s.config.UserAgent)
	req.Header.Set("Add-Padding", "true")

	if s.config.APIKey != "" {
		req.Header.Set("hibp-api-key", s.config.APIKey)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query HIBP API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HIBP API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read HIBP API response: %w", err)
	}

	return parseResponse(string(body))
}

// parseResponse parses the HIBP range API response format:
//
//	SUFFIX:COUNT\r\n
//
// Each line contains a hash suffix and how many times that password appeared
// in known breaches. Padded entries (count 0) are included when Add-Padding
// is set.
func parseResponse(body string) (map[string]int, error) {
	suffixes := make(map[string]int)
	lines := strings.Split(strings.TrimSpace(body), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		hashSuffix := strings.TrimSpace(parts[0])
		countStr := strings.TrimSpace(parts[1])

		count, err := strconv.Atoi(countStr)
		if err != nil {
			continue // Skip malformed lines
		}

		suffixes[hashSuffix] = count
	}

	return suffixes, nil
}
