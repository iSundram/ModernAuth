// Package oauth provides OAuth2 social login support for ModernAuth.
package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
	"github.com/iSundram/ModernAuth/internal/utils"
)

var (
	// ErrProviderNotFound indicates the OAuth provider was not found.
	ErrProviderNotFound = errors.New("oauth provider not found")
	// ErrProviderNotConfigured indicates the OAuth provider is not configured.
	ErrProviderNotConfigured = errors.New("oauth provider not configured")
	// ErrInvalidState indicates the OAuth state parameter is invalid.
	ErrInvalidState = errors.New("invalid oauth state")
	// ErrInvalidCode indicates the OAuth authorization code is invalid.
	ErrInvalidCode = errors.New("invalid authorization code")
	// ErrUserInfoFailed indicates fetching user info failed.
	ErrUserInfoFailed = errors.New("failed to fetch user info")
	// ErrEmailNotVerified indicates the email from the provider is not verified.
	ErrEmailNotVerified = errors.New("email not verified by provider")
	// ErrInvalidRedirectURL indicates the redirect URL is not allowed.
	ErrInvalidRedirectURL = errors.New("redirect URL not in allowed list")
	// ErrInvalidPKCE indicates the PKCE code verifier is invalid.
	ErrInvalidPKCE = errors.New("invalid PKCE code verifier")
)

// Provider represents an OAuth2 provider.
type Provider string

const (
	ProviderGoogle    Provider = "google"
	ProviderGitHub    Provider = "github"
	ProviderMicrosoft Provider = "microsoft"
)

// ProviderConfig contains OAuth2 provider configuration.
type ProviderConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

// Config contains OAuth2 service configuration.
type Config struct {
	Google              *ProviderConfig
	GitHub              *ProviderConfig
	Microsoft           *ProviderConfig
	StateSecret         string   // Secret for signing state tokens
	AllowedRedirectURLs []string // Allowed redirect URLs for OAuth callbacks
}

// UserInfo contains user information from OAuth provider.
type UserInfo struct {
	Provider       Provider
	ProviderUserID string
	Email          string
	EmailVerified  bool
	Name           string
	FirstName      string
	LastName       string
	AvatarURL      string
	ProfileData    map[string]interface{}
}

// Service provides OAuth2 authentication operations.
type Service struct {
	config       *Config
	storage      OAuthStorage
	stateStorage OAuthStateStorage
	logger       *slog.Logger
	httpClient   *http.Client
}

// OAuthStorage defines OAuth-specific storage operations.
type OAuthStorage interface {
	storage.UserStorage
	
	// GetUserByProviderID retrieves a user by their provider ID.
	GetUserByProviderID(ctx context.Context, provider, providerUserID string) (*storage.User, error)
	
	// LinkProvider links an OAuth provider to a user.
	LinkProvider(ctx context.Context, userProvider *storage.UserProvider) error
	
	// UnlinkProvider removes an OAuth provider link from a user.
	UnlinkProvider(ctx context.Context, userID uuid.UUID, provider string) error
	
	// GetUserProviders gets all linked providers for a user.
	GetUserProviders(ctx context.Context, userID uuid.UUID) ([]*storage.UserProvider, error)
}

// OAuthStateStorage defines OAuth state storage for CSRF protection.
type OAuthStateStorage interface {
	CreateOAuthState(ctx context.Context, state *storage.SocialLoginState) error
	GetOAuthStateByHash(ctx context.Context, stateHash string) (*storage.SocialLoginState, error)
	DeleteOAuthState(ctx context.Context, id uuid.UUID) error
	DeleteExpiredOAuthStates(ctx context.Context) error
}

// NewService creates a new OAuth service.
func NewService(config *Config, store OAuthStorage) *Service {
	return &Service{
		config:  config,
		storage: store,
		logger:  slog.Default().With("component", "oauth_service"),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// NewServiceWithStateStorage creates a new OAuth service with state storage for CSRF protection.
func NewServiceWithStateStorage(config *Config, store OAuthStorage, stateStore OAuthStateStorage) *Service {
	return &Service{
		config:       config,
		storage:      store,
		stateStorage: stateStore,
		logger:       slog.Default().With("component", "oauth_service"),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GetAuthorizationURL generates the OAuth authorization URL for a provider.
func (s *Service) GetAuthorizationURL(provider Provider, redirectURL string) (string, string, error) {
	cfg := s.getProviderConfig(provider)
	if cfg == nil {
		return "", "", ErrProviderNotConfigured
	}

	// Generate state token
	state, err := s.generateState()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate state: %w", err)
	}

	var authURL string
	switch provider {
	case ProviderGoogle:
		authURL = s.buildGoogleAuthURL(cfg, state, redirectURL)
	case ProviderGitHub:
		authURL = s.buildGitHubAuthURL(cfg, state, redirectURL)
	case ProviderMicrosoft:
		authURL = s.buildMicrosoftAuthURL(cfg, state, redirectURL)
	default:
		return "", "", ErrProviderNotFound
	}

	return authURL, state, nil
}

// GetAuthorizationURLWithStoredState generates the OAuth authorization URL and stores the state for CSRF protection.
// This is the recommended method for production use.
func (s *Service) GetAuthorizationURLWithStoredState(ctx context.Context, provider Provider, redirectURL string) (string, string, error) {
	cfg := s.getProviderConfig(provider)
	if cfg == nil {
		return "", "", ErrProviderNotConfigured
	}

	// Store state with the redirect URL for validation during callback
	state, err := s.StoreState(ctx, provider, redirectURL, "")
	if err != nil {
		return "", "", fmt.Errorf("failed to store state: %w", err)
	}

	var authURL string
	switch provider {
	case ProviderGoogle:
		authURL = s.buildGoogleAuthURL(cfg, state, redirectURL)
	case ProviderGitHub:
		authURL = s.buildGitHubAuthURL(cfg, state, redirectURL)
	case ProviderMicrosoft:
		authURL = s.buildMicrosoftAuthURL(cfg, state, redirectURL)
	default:
		return "", "", ErrProviderNotFound
	}

	return authURL, state, nil
}

// GetAuthorizationURLWithPKCE generates the OAuth authorization URL with PKCE support.
// Returns the authorization URL, state, and PKCE struct (containing code_verifier).
// The code_verifier must be stored and sent during token exchange.
func (s *Service) GetAuthorizationURLWithPKCE(provider Provider, redirectURL string) (string, string, *PKCE, error) {
	cfg := s.getProviderConfig(provider)
	if cfg == nil {
		return "", "", nil, ErrProviderNotConfigured
	}

	// Validate redirect URL
	if err := s.ValidateRedirectURL(redirectURL); err != nil {
		return "", "", nil, err
	}

	// Generate state token
	state, err := s.generateState()
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to generate state: %w", err)
	}

	// Generate PKCE challenge
	pkce, err := GeneratePKCE()
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to generate PKCE: %w", err)
	}

	var authURL string
	switch provider {
	case ProviderGoogle:
		authURL = s.buildGoogleAuthURLWithPKCE(cfg, state, redirectURL, pkce)
	case ProviderGitHub:
		// GitHub doesn't support PKCE, use regular URL
		authURL = s.buildGitHubAuthURL(cfg, state, redirectURL)
	case ProviderMicrosoft:
		authURL = s.buildMicrosoftAuthURLWithPKCE(cfg, state, redirectURL, pkce)
	default:
		return "", "", nil, ErrProviderNotFound
	}

	return authURL, state, pkce, nil
}

// ExchangeCode exchanges an authorization code for user info.
func (s *Service) ExchangeCode(ctx context.Context, provider Provider, code, redirectURL string) (*UserInfo, error) {
	cfg := s.getProviderConfig(provider)
	if cfg == nil {
		return nil, ErrProviderNotConfigured
	}

	switch provider {
	case ProviderGoogle:
		return s.exchangeGoogleCode(ctx, cfg, code, redirectURL)
	case ProviderGitHub:
		return s.exchangeGitHubCode(ctx, cfg, code, redirectURL)
	case ProviderMicrosoft:
		return s.exchangeMicrosoftCode(ctx, cfg, code, redirectURL)
	default:
		return nil, ErrProviderNotFound
	}
}

// FindOrCreateUser finds an existing user or creates a new one from OAuth info.
func (s *Service) FindOrCreateUser(ctx context.Context, info *UserInfo) (*storage.User, bool, error) {
	// First, try to find user by provider ID
	user, err := s.storage.GetUserByProviderID(ctx, string(info.Provider), info.ProviderUserID)
	if err != nil {
		return nil, false, err
	}
	if user != nil {
		return user, false, nil
	}

	// Try to find user by email
	user, err = s.storage.GetUserByEmail(ctx, info.Email)
	if err != nil {
		return nil, false, err
	}

	if user != nil {
		// Link the provider to existing user
		if err := s.linkProviderToUser(ctx, user.ID, info); err != nil {
			s.logger.Error("Failed to link provider to existing user", "error", err, "user_id", user.ID)
		}
		return user, false, nil
	}

	// Create new user
	now := time.Now()
	user = &storage.User{
		ID:              uuid.New(),
		Email:           info.Email,
		IsEmailVerified: info.EmailVerified,
		IsActive:        true,
		Timezone:        "UTC",
		Locale:          "en",
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	if info.FirstName != "" {
		user.FirstName = &info.FirstName
	}
	if info.LastName != "" {
		user.LastName = &info.LastName
	}
	if info.AvatarURL != "" {
		user.AvatarURL = &info.AvatarURL
	}

	if err := s.storage.CreateUser(ctx, user); err != nil {
		return nil, false, err
	}

	// Link provider to new user
	if err := s.linkProviderToUser(ctx, user.ID, info); err != nil {
		s.logger.Error("Failed to link provider to new user", "error", err, "user_id", user.ID)
	}

	s.logger.Info("Created user from OAuth", "user_id", user.ID, "provider", info.Provider)
	return user, true, nil
}

// LinkProvider links an OAuth provider to an existing user.
func (s *Service) LinkProvider(ctx context.Context, userID uuid.UUID, info *UserInfo) error {
	return s.linkProviderToUser(ctx, userID, info)
}

// UnlinkProvider unlinks an OAuth provider from a user.
func (s *Service) UnlinkProvider(ctx context.Context, userID uuid.UUID, provider Provider) error {
	return s.storage.UnlinkProvider(ctx, userID, string(provider))
}

// GetUserProviders returns all linked OAuth providers for a user.
func (s *Service) GetUserProviders(ctx context.Context, userID uuid.UUID) ([]*storage.UserProvider, error) {
	return s.storage.GetUserProviders(ctx, userID)
}

// IsProviderConfigured checks if a provider is configured.
func (s *Service) IsProviderConfigured(provider Provider) bool {
	return s.getProviderConfig(provider) != nil
}

// GetConfiguredProviders returns a list of configured providers.
func (s *Service) GetConfiguredProviders() []Provider {
	var providers []Provider
	if s.config.Google != nil && s.config.Google.ClientID != "" {
		providers = append(providers, ProviderGoogle)
	}
	if s.config.GitHub != nil && s.config.GitHub.ClientID != "" {
		providers = append(providers, ProviderGitHub)
	}
	if s.config.Microsoft != nil && s.config.Microsoft.ClientID != "" {
		providers = append(providers, ProviderMicrosoft)
	}
	return providers
}

// Helper methods

func (s *Service) getProviderConfig(provider Provider) *ProviderConfig {
	switch provider {
	case ProviderGoogle:
		if s.config.Google != nil && s.config.Google.ClientID != "" {
			return s.config.Google
		}
	case ProviderGitHub:
		if s.config.GitHub != nil && s.config.GitHub.ClientID != "" {
			return s.config.GitHub
		}
	case ProviderMicrosoft:
		if s.config.Microsoft != nil && s.config.Microsoft.ClientID != "" {
			return s.config.Microsoft
		}
	}
	return nil
}

func (s *Service) generateState() (string, error) {
	return utils.GenerateRandomString(32)
}

// StoreState stores an OAuth state for CSRF protection.
// Returns the raw state token to be included in the authorization URL.
func (s *Service) StoreState(ctx context.Context, provider Provider, redirectURI, codeVerifier string) (string, error) {
	if s.stateStorage == nil {
		// Fallback: just generate state without storage (less secure)
		return s.generateState()
	}

	state, err := s.generateState()
	if err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}

	stateRecord := &storage.SocialLoginState{
		ID:           uuid.New(),
		Provider:     string(provider),
		StateHash:    utils.HashToken(state),
		RedirectURI:  redirectURI,
		CodeVerifier: codeVerifier,
		ExpiresAt:    time.Now().Add(10 * time.Minute), // State expires in 10 minutes
		CreatedAt:    time.Now(),
	}

	if err := s.stateStorage.CreateOAuthState(ctx, stateRecord); err != nil {
		return "", fmt.Errorf("failed to store state: %w", err)
	}

	return state, nil
}

// ValidateAndConsumeState validates an OAuth state and removes it (single use).
// Returns the stored state record if valid, nil if invalid or expired.
func (s *Service) ValidateAndConsumeState(ctx context.Context, provider Provider, state string) (*storage.SocialLoginState, error) {
	if s.stateStorage == nil {
		// No state storage configured - skip validation (less secure)
		s.logger.Warn("OAuth state validation skipped: no state storage configured")
		return nil, nil
	}

	if state == "" {
		return nil, ErrInvalidState
	}

	stateHash := utils.HashToken(state)
	stateRecord, err := s.stateStorage.GetOAuthStateByHash(ctx, stateHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get state: %w", err)
	}

	if stateRecord == nil {
		return nil, ErrInvalidState
	}

	// Verify provider matches
	if stateRecord.Provider != string(provider) {
		s.logger.Warn("OAuth state provider mismatch",
			"expected", stateRecord.Provider,
			"got", string(provider),
		)
		return nil, ErrInvalidState
	}

	// Delete the state (single use)
	if err := s.stateStorage.DeleteOAuthState(ctx, stateRecord.ID); err != nil {
		s.logger.Error("Failed to delete OAuth state", "error", err, "state_id", stateRecord.ID)
		// Continue - state is still valid
	}

	return stateRecord, nil
}

func (s *Service) linkProviderToUser(ctx context.Context, userID uuid.UUID, info *UserInfo) error {
	now := time.Now()
	profileData, _ := json.Marshal(info.ProfileData)
	var profileDataMap map[string]interface{}
	json.Unmarshal(profileData, &profileDataMap)

	userProvider := &storage.UserProvider{
		ID:             uuid.New(),
		UserID:         userID,
		Provider:       string(info.Provider),
		ProviderUserID: info.ProviderUserID,
		ProfileData:    profileDataMap,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	return s.storage.LinkProvider(ctx, userProvider)
}

// Google OAuth implementation

func (s *Service) buildGoogleAuthURL(cfg *ProviderConfig, state, redirectURL string) string {
	params := url.Values{}
	params.Set("client_id", cfg.ClientID)
	params.Set("redirect_uri", redirectURL)
	params.Set("response_type", "code")
	params.Set("scope", strings.Join(cfg.Scopes, " "))
	params.Set("state", state)
	params.Set("access_type", "offline")
	params.Set("prompt", "consent")

	return "https://accounts.google.com/o/oauth2/v2/auth?" + params.Encode()
}

func (s *Service) buildGoogleAuthURLWithPKCE(cfg *ProviderConfig, state, redirectURL string, pkce *PKCE) string {
	params := url.Values{}
	params.Set("client_id", cfg.ClientID)
	params.Set("redirect_uri", redirectURL)
	params.Set("response_type", "code")
	params.Set("scope", strings.Join(cfg.Scopes, " "))
	params.Set("state", state)
	params.Set("access_type", "offline")
	params.Set("prompt", "consent")
	params.Set("code_challenge", pkce.CodeChallenge)
	params.Set("code_challenge_method", pkce.Method)

	return "https://accounts.google.com/o/oauth2/v2/auth?" + params.Encode()
}

func (s *Service) exchangeGoogleCode(ctx context.Context, cfg *ProviderConfig, code, redirectURL string) (*UserInfo, error) {
	// Exchange code for tokens
	tokenURL := "https://oauth2.googleapis.com/token"
	data := url.Values{}
	data.Set("client_id", cfg.ClientID)
	data.Set("client_secret", cfg.ClientSecret)
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", redirectURL)

	resp, err := s.httpClient.Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed: %s", string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	// Get user info
	userInfoURL := "https://www.googleapis.com/oauth2/v2/userinfo"
	req, _ := http.NewRequestWithContext(ctx, "GET", userInfoURL, nil)
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)

	resp, err = s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	var googleUser struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		VerifiedEmail bool   `json:"verified_email"`
		Name          string `json:"name"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Picture       string `json:"picture"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&googleUser); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	return &UserInfo{
		Provider:       ProviderGoogle,
		ProviderUserID: googleUser.ID,
		Email:          googleUser.Email,
		EmailVerified:  googleUser.VerifiedEmail,
		Name:           googleUser.Name,
		FirstName:      googleUser.GivenName,
		LastName:       googleUser.FamilyName,
		AvatarURL:      googleUser.Picture,
		ProfileData: map[string]interface{}{
			"id":    googleUser.ID,
			"email": googleUser.Email,
			"name":  googleUser.Name,
		},
	}, nil
}

// GitHub OAuth implementation

func (s *Service) buildGitHubAuthURL(cfg *ProviderConfig, state, redirectURL string) string {
	params := url.Values{}
	params.Set("client_id", cfg.ClientID)
	params.Set("redirect_uri", redirectURL)
	params.Set("scope", strings.Join(cfg.Scopes, " "))
	params.Set("state", state)

	return "https://github.com/login/oauth/authorize?" + params.Encode()
}

func (s *Service) exchangeGitHubCode(ctx context.Context, cfg *ProviderConfig, code, redirectURL string) (*UserInfo, error) {
	// Exchange code for tokens
	tokenURL := "https://github.com/login/oauth/access_token"
	data := url.Values{}
	data.Set("client_id", cfg.ClientID)
	data.Set("client_secret", cfg.ClientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURL)

	req, _ := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return nil, ErrInvalidCode
	}

	// Get user info
	userInfoURL := "https://api.github.com/user"
	req, _ = http.NewRequestWithContext(ctx, "GET", userInfoURL, nil)
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err = s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	var githubUser struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&githubUser); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	// Get email if not returned in user info
	email := githubUser.Email
	emailVerified := false
	if email == "" {
		email, emailVerified = s.getGitHubEmail(ctx, tokenResp.AccessToken)
	} else {
		emailVerified = true
	}

	// Parse name into first and last
	firstName, lastName := parseName(githubUser.Name)

	return &UserInfo{
		Provider:       ProviderGitHub,
		ProviderUserID: fmt.Sprintf("%d", githubUser.ID),
		Email:          email,
		EmailVerified:  emailVerified,
		Name:           githubUser.Name,
		FirstName:      firstName,
		LastName:       lastName,
		AvatarURL:      githubUser.AvatarURL,
		ProfileData: map[string]interface{}{
			"id":    githubUser.ID,
			"login": githubUser.Login,
			"email": email,
		},
	}, nil
}

func (s *Service) getGitHubEmail(ctx context.Context, accessToken string) (string, bool) {
	emailsURL := "https://api.github.com/user/emails"
	req, _ := http.NewRequestWithContext(ctx, "GET", emailsURL, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", false
	}

	// Find primary verified email
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, true
		}
	}
	// Fallback to any verified email
	for _, e := range emails {
		if e.Verified {
			return e.Email, true
		}
	}
	// Fallback to primary email
	for _, e := range emails {
		if e.Primary {
			return e.Email, false
		}
	}

	return "", false
}

// Microsoft OAuth implementation

func (s *Service) buildMicrosoftAuthURL(cfg *ProviderConfig, state, redirectURL string) string {
	params := url.Values{}
	params.Set("client_id", cfg.ClientID)
	params.Set("redirect_uri", redirectURL)
	params.Set("response_type", "code")
	params.Set("scope", strings.Join(cfg.Scopes, " "))
	params.Set("state", state)
	params.Set("response_mode", "query")

	return "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?" + params.Encode()
}

func (s *Service) buildMicrosoftAuthURLWithPKCE(cfg *ProviderConfig, state, redirectURL string, pkce *PKCE) string {
	params := url.Values{}
	params.Set("client_id", cfg.ClientID)
	params.Set("redirect_uri", redirectURL)
	params.Set("response_type", "code")
	params.Set("scope", strings.Join(cfg.Scopes, " "))
	params.Set("state", state)
	params.Set("response_mode", "query")
	params.Set("code_challenge", pkce.CodeChallenge)
	params.Set("code_challenge_method", pkce.Method)

	return "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?" + params.Encode()
}

func (s *Service) exchangeMicrosoftCode(ctx context.Context, cfg *ProviderConfig, code, redirectURL string) (*UserInfo, error) {
	// Exchange code for tokens
	tokenURL := "https://login.microsoftonline.com/common/oauth2/v2.0/token"
	data := url.Values{}
	data.Set("client_id", cfg.ClientID)
	data.Set("client_secret", cfg.ClientSecret)
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", redirectURL)

	resp, err := s.httpClient.Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed: %s", string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	// Get user info from Microsoft Graph
	userInfoURL := "https://graph.microsoft.com/v1.0/me"
	req, _ := http.NewRequestWithContext(ctx, "GET", userInfoURL, nil)
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)

	resp, err = s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	var msUser struct {
		ID                string `json:"id"`
		DisplayName       string `json:"displayName"`
		GivenName         string `json:"givenName"`
		Surname           string `json:"surname"`
		Mail              string `json:"mail"`
		UserPrincipalName string `json:"userPrincipalName"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&msUser); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	email := msUser.Mail
	if email == "" {
		email = msUser.UserPrincipalName
	}

	return &UserInfo{
		Provider:       ProviderMicrosoft,
		ProviderUserID: msUser.ID,
		Email:          email,
		EmailVerified:  true, // Microsoft accounts have verified emails
		Name:           msUser.DisplayName,
		FirstName:      msUser.GivenName,
		LastName:       msUser.Surname,
		AvatarURL:      "", // Would need additional API call for photo
		ProfileData: map[string]interface{}{
			"id":          msUser.ID,
			"displayName": msUser.DisplayName,
			"email":       email,
		},
	}, nil
}

// parseName splits a full name into first and last name.
func parseName(fullName string) (string, string) {
	parts := strings.SplitN(strings.TrimSpace(fullName), " ", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	if len(parts) == 1 {
		return parts[0], ""
	}
	return "", ""
}

// PKCE represents a PKCE (Proof Key for Code Exchange) challenge.
type PKCE struct {
	CodeVerifier  string `json:"code_verifier"`
	CodeChallenge string `json:"code_challenge"`
	Method        string `json:"method"` // Always "S256"
}

// GeneratePKCE generates a new PKCE code verifier and challenge.
// Uses S256 method (SHA-256 hash, base64url encoded).
func GeneratePKCE() (*PKCE, error) {
	// Generate a random 32-byte code verifier
	verifier, err := utils.GenerateRandomString(43) // 43 chars is standard for PKCE
	if err != nil {
		return nil, fmt.Errorf("failed to generate code verifier: %w", err)
	}

	// Create S256 challenge: base64url(sha256(verifier))
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	return &PKCE{
		CodeVerifier:  verifier,
		CodeChallenge: challenge,
		Method:        "S256",
	}, nil
}

// ValidatePKCE validates that a code verifier matches a code challenge.
func ValidatePKCE(codeVerifier, codeChallenge string) bool {
	hash := sha256.Sum256([]byte(codeVerifier))
	expected := base64.RawURLEncoding.EncodeToString(hash[:])
	return expected == codeChallenge
}

// ValidateRedirectURL checks if a redirect URL is in the allowed list.
func (s *Service) ValidateRedirectURL(redirectURL string) error {
	if len(s.config.AllowedRedirectURLs) == 0 {
		// If no allowed URLs configured, allow any (development mode)
		s.logger.Warn("No allowed redirect URLs configured, allowing any redirect URL")
		return nil
	}

	// Parse the provided URL
	parsed, err := url.Parse(redirectURL)
	if err != nil {
		return ErrInvalidRedirectURL
	}

	// Check against allowed list
	for _, allowed := range s.config.AllowedRedirectURLs {
		allowedParsed, err := url.Parse(allowed)
		if err != nil {
			continue
		}

		// Match scheme and host (port included in host)
		if parsed.Scheme == allowedParsed.Scheme && parsed.Host == allowedParsed.Host {
			// If allowed URL has a path, it must be a prefix match
			if allowedParsed.Path == "" || strings.HasPrefix(parsed.Path, allowedParsed.Path) {
				return nil
			}
		}
	}

	s.logger.Warn("Redirect URL not in allowed list",
		"redirect_url", redirectURL,
		"allowed_urls", s.config.AllowedRedirectURLs,
	)
	return ErrInvalidRedirectURL
}
