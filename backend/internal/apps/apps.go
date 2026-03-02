// Package apps provides OAuth2 application management for ModernAuth.
package apps

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
	"github.com/iSundram/ModernAuth/internal/utils"
)

// Common errors
var (
	ErrAppNotFound        = errors.New("application not found")
	ErrAppSuspended       = errors.New("application is suspended")
	ErrAppDeleted         = errors.New("application has been deleted")
	ErrSecretNotFound     = errors.New("secret not found")
	ErrSecretRevoked      = errors.New("secret has been revoked")
	ErrSecretExpired      = errors.New("secret has expired")
	ErrInvalidRedirectURI = errors.New("invalid redirect URI")
	ErrInvalidScope       = errors.New("invalid scope")
	ErrConsentRequired    = errors.New("user consent required")
	ErrCodeExpired        = errors.New("authorization code expired")
	ErrCodeUsed           = errors.New("authorization code already used")
	ErrTokenExpired       = errors.New("token has expired")
	ErrTokenRevoked       = errors.New("token has been revoked")
	ErrPKCERequired       = errors.New("PKCE is required for this application")
	ErrInvalidGrantType   = errors.New("invalid grant type")
	ErrClientCredentials  = errors.New("client credentials invalid")
)

// Service provides OAuth2 application management operations.
type Service struct {
	storage storage.AppStorage
	logger  *slog.Logger
}

// NewService creates a new apps service.
func NewService(store storage.AppStorage) *Service {
	return &Service{
		storage: store,
		logger:  slog.Default().With("component", "apps_service"),
	}
}

// ============================================================================
// App Management
// ============================================================================

// CreateAppRequest represents a request to create an OAuth2 application.
type CreateAppRequest struct {
	TenantID                *uuid.UUID       `json:"tenant_id,omitempty"`
	Name                    string           `json:"name"`
	Description             *string          `json:"description,omitempty"`
	AppType                 storage.AppType  `json:"app_type"`
	RedirectURIs            []string         `json:"redirect_uris"`
	AllowedScopes           []string         `json:"allowed_scopes"`
	DefaultScopes           []string         `json:"default_scopes"`
	ConsentRequired         *bool            `json:"consent_required,omitempty"`
	PKCERequired            *bool            `json:"pkce_required,omitempty"`
	RefreshTokenTTLSeconds  *int             `json:"refresh_token_ttl_seconds,omitempty"`
	AccessTokenTTLSeconds   *int             `json:"access_token_ttl_seconds,omitempty"`
	AllowedGrantTypes       []storage.GrantType `json:"allowed_grant_types"`
	RateLimitPerMinute      *int             `json:"rate_limit_per_minute,omitempty"`
	LogoURL                 *string          `json:"logo_url,omitempty"`
	PrivacyPolicyURL        *string          `json:"privacy_policy_url,omitempty"`
	TermsOfServiceURL       *string          `json:"terms_of_service_url,omitempty"`
	WebsiteURL              *string          `json:"website_url,omitempty"`
	Metadata                map[string]interface{} `json:"metadata,omitempty"`
	CreatedBy               *uuid.UUID       `json:"created_by,omitempty"`
}

// CreateAppResult contains the created app and the initial client secret.
type CreateAppResult struct {
	App           *storage.App `json:"app"`
	ClientID      string       `json:"client_id"`
	ClientSecret  string       `json:"client_secret,omitempty"` // Only for confidential clients
}

// CreateApp creates a new OAuth2 application.
func (s *Service) CreateApp(ctx context.Context, req *CreateAppRequest) (*CreateAppResult, error) {
	now := time.Now()

	// Generate client ID
	clientID, err := generateClientID()
	if err != nil {
		return nil, err
	}

	// Set defaults
	consentRequired := true
	if req.ConsentRequired != nil {
		consentRequired = *req.ConsentRequired
	}
	pkceRequired := false
	if req.PKCERequired != nil {
		pkceRequired = *req.PKCERequired
	}
	refreshTokenTTL := 2592000 // 30 days
	if req.RefreshTokenTTLSeconds != nil {
		refreshTokenTTL = *req.RefreshTokenTTLSeconds
	}
	accessTokenTTL := 3600 // 1 hour
	if req.AccessTokenTTLSeconds != nil {
		accessTokenTTL = *req.AccessTokenTTLSeconds
	}
	rateLimit := 60
	if req.RateLimitPerMinute != nil {
		rateLimit = *req.RateLimitPerMinute
	}

	// Default grant types based on app type
	grantTypes := req.AllowedGrantTypes
	if len(grantTypes) == 0 {
		grantTypes = getDefaultGrantTypes(req.AppType)
	}

	app := &storage.App{
		ID:                    uuid.New(),
		TenantID:              req.TenantID,
		Name:                  req.Name,
		Description:           req.Description,
		ClientID:              clientID,
		AppType:               req.AppType,
		Status:                storage.AppStatusActive,
		RedirectURIs:          req.RedirectURIs,
		AllowedScopes:         req.AllowedScopes,
		DefaultScopes:         req.DefaultScopes,
		ConsentRequired:       consentRequired,
		PKCERequired:          pkceRequired,
		RefreshTokenTTLSeconds: refreshTokenTTL,
		AccessTokenTTLSeconds:  accessTokenTTL,
		AllowedGrantTypes:     grantTypes,
		RateLimitPerMinute:    rateLimit,
		LogoURL:               req.LogoURL,
		PrivacyPolicyURL:      req.PrivacyPolicyURL,
		TermsOfServiceURL:     req.TermsOfServiceURL,
		WebsiteURL:            req.WebsiteURL,
		Metadata:              req.Metadata,
		CreatedAt:             now,
		UpdatedAt:             now,
		CreatedBy:             req.CreatedBy,
	}

	if err := s.storage.CreateApp(ctx, app); err != nil {
		return nil, err
	}

	result := &CreateAppResult{
		App:      app,
		ClientID: clientID,
	}

	// Generate client secret for confidential clients (web, machine)
	if req.AppType == storage.AppTypeWeb || req.AppType == storage.AppTypeMachine {
		secret, err := s.CreateSecret(ctx, app.ID, "Default", nil, req.CreatedBy)
		if err != nil {
			s.logger.Error("Failed to create initial secret", "error", err, "app_id", app.ID)
		} else {
			result.ClientSecret = secret.RawSecret
		}
	}

	s.logger.Info("App created", "app_id", app.ID, "name", app.Name, "type", app.AppType)
	return result, nil
}

// GetApp retrieves an app by ID.
func (s *Service) GetApp(ctx context.Context, id uuid.UUID) (*storage.App, error) {
	app, err := s.storage.GetAppByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, ErrAppNotFound
	}
	return app, nil
}

// GetAppByClientID retrieves an app by client ID.
func (s *Service) GetAppByClientID(ctx context.Context, clientID string) (*storage.App, error) {
	app, err := s.storage.GetAppByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, ErrAppNotFound
	}
	return app, nil
}

// ListAppsRequest represents options for listing apps.
type ListAppsRequest struct {
	TenantID *uuid.UUID      `json:"tenant_id,omitempty"`
	Status   *storage.AppStatus `json:"status,omitempty"`
	AppType  *storage.AppType  `json:"app_type,omitempty"`
	Search   string          `json:"search,omitempty"`
	Limit    int             `json:"limit"`
	Offset   int             `json:"offset"`
}

// ListAppsResult contains a list of apps and total count.
type ListAppsResult struct {
	Apps  []*storage.App `json:"apps"`
	Total int            `json:"total"`
}

// ListApps lists apps with filtering and pagination.
func (s *Service) ListApps(ctx context.Context, req *ListAppsRequest) (*ListAppsResult, error) {
	if req.Limit <= 0 {
		req.Limit = 50
	}
	if req.Limit > 100 {
		req.Limit = 100
	}

	opts := &storage.AppListOptions{
		TenantID: req.TenantID,
		Status:   req.Status,
		AppType:  req.AppType,
		Search:   req.Search,
		Limit:    req.Limit,
		Offset:   req.Offset,
	}

	apps, total, err := s.storage.ListApps(ctx, opts)
	if err != nil {
		return nil, err
	}

	return &ListAppsResult{
		Apps:  apps,
		Total: total,
	}, nil
}

// UpdateAppRequest represents a request to update an app.
type UpdateAppRequest struct {
	Name                    *string           `json:"name,omitempty"`
	Description             *string           `json:"description,omitempty"`
	RedirectURIs            []string          `json:"redirect_uris,omitempty"`
	AllowedScopes           []string          `json:"allowed_scopes,omitempty"`
	DefaultScopes           []string          `json:"default_scopes,omitempty"`
	ConsentRequired         *bool             `json:"consent_required,omitempty"`
	PKCERequired            *bool             `json:"pkce_required,omitempty"`
	RefreshTokenTTLSeconds  *int              `json:"refresh_token_ttl_seconds,omitempty"`
	AccessTokenTTLSeconds   *int              `json:"access_token_ttl_seconds,omitempty"`
	AllowedGrantTypes       []storage.GrantType `json:"allowed_grant_types,omitempty"`
	RateLimitPerMinute      *int              `json:"rate_limit_per_minute,omitempty"`
	LogoURL                 *string           `json:"logo_url,omitempty"`
	PrivacyPolicyURL        *string           `json:"privacy_policy_url,omitempty"`
	TermsOfServiceURL       *string           `json:"terms_of_service_url,omitempty"`
	WebsiteURL              *string           `json:"website_url,omitempty"`
	Metadata                map[string]interface{} `json:"metadata,omitempty"`
}

// UpdateApp updates an application.
func (s *Service) UpdateApp(ctx context.Context, id uuid.UUID, req *UpdateAppRequest) (*storage.App, error) {
	app, err := s.storage.GetAppByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, ErrAppNotFound
	}

	// Update fields
	if req.Name != nil {
		app.Name = *req.Name
	}
	if req.Description != nil {
		app.Description = req.Description
	}
	if req.RedirectURIs != nil {
		app.RedirectURIs = req.RedirectURIs
	}
	if req.AllowedScopes != nil {
		app.AllowedScopes = req.AllowedScopes
	}
	if req.DefaultScopes != nil {
		app.DefaultScopes = req.DefaultScopes
	}
	if req.ConsentRequired != nil {
		app.ConsentRequired = *req.ConsentRequired
	}
	if req.PKCERequired != nil {
		app.PKCERequired = *req.PKCERequired
	}
	if req.RefreshTokenTTLSeconds != nil {
		app.RefreshTokenTTLSeconds = *req.RefreshTokenTTLSeconds
	}
	if req.AccessTokenTTLSeconds != nil {
		app.AccessTokenTTLSeconds = *req.AccessTokenTTLSeconds
	}
	if req.AllowedGrantTypes != nil {
		app.AllowedGrantTypes = req.AllowedGrantTypes
	}
	if req.RateLimitPerMinute != nil {
		app.RateLimitPerMinute = *req.RateLimitPerMinute
	}
	if req.LogoURL != nil {
		app.LogoURL = req.LogoURL
	}
	if req.PrivacyPolicyURL != nil {
		app.PrivacyPolicyURL = req.PrivacyPolicyURL
	}
	if req.TermsOfServiceURL != nil {
		app.TermsOfServiceURL = req.TermsOfServiceURL
	}
	if req.WebsiteURL != nil {
		app.WebsiteURL = req.WebsiteURL
	}
	if req.Metadata != nil {
		app.Metadata = req.Metadata
	}

	app.UpdatedAt = time.Now()

	if err := s.storage.UpdateApp(ctx, app); err != nil {
		return nil, err
	}

	s.logger.Info("App updated", "app_id", id)
	return app, nil
}

// DeleteApp deletes an application.
func (s *Service) DeleteApp(ctx context.Context, id uuid.UUID) error {
	app, err := s.storage.GetAppByID(ctx, id)
	if err != nil {
		return err
	}
	if app == nil {
		return ErrAppNotFound
	}

	if err := s.storage.DeleteApp(ctx, id); err != nil {
		return err
	}

	s.logger.Info("App deleted", "app_id", id)
	return nil
}

// SuspendApp suspends an application.
func (s *Service) SuspendApp(ctx context.Context, id uuid.UUID) error {
	if err := s.storage.SuspendApp(ctx, id); err != nil {
		return err
	}
	s.logger.Info("App suspended", "app_id", id)
	return nil
}

// ActivateApp activates a suspended application.
func (s *Service) ActivateApp(ctx context.Context, id uuid.UUID) error {
	if err := s.storage.ActivateApp(ctx, id); err != nil {
		return err
	}
	s.logger.Info("App activated", "app_id", id)
	return nil
}

// ============================================================================
// Secret Management
// ============================================================================

// CreateSecretResult contains the created secret and the raw secret value.
type CreateSecretResult struct {
	Secret     *storage.AppSecret `json:"secret"`
	RawSecret  string             `json:"raw_secret"` // Only shown once
}

// CreateSecret creates a new client secret for an app.
func (s *Service) CreateSecret(ctx context.Context, appID uuid.UUID, name string, description *string, createdBy *uuid.UUID) (*CreateSecretResult, error) {
	// Generate secret
	rawSecret, err := generateClientSecret()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	secret := &storage.AppSecret{
		ID:           uuid.New(),
		AppID:        appID,
		Name:         name,
		SecretHash:   utils.HashToken(rawSecret),
		SecretPrefix: rawSecret[:8],
		Description:  description,
		IsActive:     true,
		CreatedAt:    now,
		CreatedBy:    createdBy,
	}

	if err := s.storage.CreateAppSecret(ctx, secret); err != nil {
		return nil, err
	}

	s.logger.Info("App secret created", "secret_id", secret.ID, "app_id", appID)
	return &CreateSecretResult{
		Secret:    secret,
		RawSecret: rawSecret,
	}, nil
}

// ListSecrets lists all secrets for an app.
func (s *Service) ListSecrets(ctx context.Context, appID uuid.UUID) ([]*storage.AppSecret, error) {
	return s.storage.ListAppSecrets(ctx, appID)
}

// RevokeSecret revokes a client secret.
func (s *Service) RevokeSecret(ctx context.Context, secretID uuid.UUID, revokedBy *uuid.UUID) error {
	secret, err := s.storage.GetAppSecretByID(ctx, secretID)
	if err != nil {
		return err
	}
	if secret == nil {
		return ErrSecretNotFound
	}

	if err := s.storage.RevokeAppSecret(ctx, secretID, revokedBy); err != nil {
		return err
	}

	s.logger.Info("App secret revoked", "secret_id", secretID)
	return nil
}

// ValidateClientCredentials validates client ID and secret.
func (s *Service) ValidateClientCredentials(ctx context.Context, clientID, clientSecret string) (*storage.App, error) {
	app, err := s.storage.GetAppByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, ErrAppNotFound
	}

	// Check app status
	if app.Status == storage.AppStatusSuspended {
		return nil, ErrAppSuspended
	}
	if app.Status == storage.AppStatusDeleted {
		return nil, ErrAppDeleted
	}

	// Validate secret
	secret, err := s.storage.GetAppSecretByPrefix(ctx, app.ID, clientSecret[:8])
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, ErrClientCredentials
	}

	// Check secret hash
	if secret.SecretHash != utils.HashToken(clientSecret) {
		return nil, ErrClientCredentials
	}

	// Check if secret is active
	if !secret.IsActive || secret.RevokedAt != nil {
		return nil, ErrSecretRevoked
	}

	// Check expiration
	if secret.ExpiresAt != nil && time.Now().After(*secret.ExpiresAt) {
		return nil, ErrSecretExpired
	}

	return app, nil
}

// ============================================================================
// OAuth2 Flow
// ============================================================================

// AuthorizationRequest represents an OAuth2 authorization request.
type AuthorizationRequest struct {
	AppID              uuid.UUID  `json:"app_id"`
	UserID             uuid.UUID  `json:"user_id"`
	TenantID           *uuid.UUID `json:"tenant_id,omitempty"`
	RedirectURI        string     `json:"redirect_uri"`
	Scopes             []string   `json:"scopes"`
	State              string     `json:"state,omitempty"`
	CodeChallenge      *string    `json:"code_challenge,omitempty"`
	CodeChallengeMethod *string   `json:"code_challenge_method,omitempty"`
	Nonce              *string    `json:"nonce,omitempty"`
	ClientIP           string     `json:"client_ip,omitempty"`
}

// AuthorizationResult contains the authorization code.
type AuthorizationResult struct {
	Code string `json:"code"`
}

// CreateAuthorizationCode creates an authorization code for the OAuth2 flow.
func (s *Service) CreateAuthorizationCode(ctx context.Context, req *AuthorizationRequest) (*AuthorizationResult, error) {
	app, err := s.storage.GetAppByID(ctx, req.AppID)
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, ErrAppNotFound
	}

	// Validate redirect URI
	if !isValidRedirectURI(req.RedirectURI, app.RedirectURIs) {
		return nil, ErrInvalidRedirectURI
	}

	// Validate scopes
	for _, scope := range req.Scopes {
		if !isScopeAllowed(scope, app.AllowedScopes) {
			return nil, ErrInvalidScope
		}
	}

	// Check PKCE requirement
	if app.PKCERequired && req.CodeChallenge == nil {
		return nil, ErrPKCERequired
	}

	// Generate authorization code
	rawCode, codeHash, err := generateAuthorizationCode()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	expiresAt := now.Add(10 * time.Minute) // Authorization codes are short-lived

	code := &storage.AuthorizationCode{
		ID:                  uuid.New(),
		CodeHash:            codeHash,
		AppID:               req.AppID,
		UserID:              req.UserID,
		TenantID:            req.TenantID,
		RedirectURI:         req.RedirectURI,
		Scopes:              req.Scopes,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		ExpiresAt:           expiresAt,
		State:               req.State,
		Nonce:               req.Nonce,
		CreatedAt:           now,
		CreatedIP:           &req.ClientIP,
	}

	if err := s.storage.CreateAuthorizationCode(ctx, code); err != nil {
		return nil, err
	}

	return &AuthorizationResult{Code: rawCode}, nil
}

// TokenRequest represents an OAuth2 token request.
type TokenRequest struct {
	GrantType    storage.GrantType `json:"grant_type"`
	Code         *string           `json:"code,omitempty"`
	RedirectURI  *string           `json:"redirect_uri,omitempty"`
	CodeVerifier *string           `json:"code_verifier,omitempty"`
	RefreshToken *string           `json:"refresh_token,omitempty"`
	Scopes       []string          `json:"scopes,omitempty"`
	ClientID     string            `json:"client_id"`
	ClientSecret *string           `json:"client_secret,omitempty"`
	ClientIP     string            `json:"client_ip,omitempty"`
}

// TokenResponse represents an OAuth2 token response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
}

// ExchangeToken exchanges an authorization code or refresh token for access tokens.
func (s *Service) ExchangeToken(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	app, err := s.storage.GetAppByClientID(ctx, req.ClientID)
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, ErrAppNotFound
	}

	// Validate app status
	if app.Status == storage.AppStatusSuspended {
		return nil, ErrAppSuspended
	}

	// Validate grant type is allowed
	if !isGrantTypeAllowed(req.GrantType, app.AllowedGrantTypes) {
		return nil, ErrInvalidGrantType
	}

	switch req.GrantType {
	case storage.GrantTypeAuthorizationCode:
		return s.exchangeAuthorizationCode(ctx, app, req)
	case storage.GrantTypeRefreshToken:
		return s.exchangeRefreshToken(ctx, app, req)
	case storage.GrantTypeClientCredentials:
		return s.exchangeClientCredentials(ctx, app, req)
	default:
		return nil, ErrInvalidGrantType
	}
}

func (s *Service) exchangeAuthorizationCode(ctx context.Context, app *storage.App, req *TokenRequest) (*TokenResponse, error) {
	// Validate client secret for confidential clients
	if app.AppType == storage.AppTypeWeb || app.AppType == storage.AppTypeMachine {
		if req.ClientSecret == nil {
			return nil, ErrClientCredentials
		}
		if _, err := s.ValidateClientCredentials(ctx, req.ClientID, *req.ClientSecret); err != nil {
			return nil, err
		}
	}

	// Get and validate authorization code
	codeHash := utils.HashToken(*req.Code)
	authCode, err := s.storage.GetAuthorizationCodeByHash(ctx, codeHash)
	if err != nil {
		return nil, err
	}
	if authCode == nil {
		return nil, ErrCodeExpired
	}

	// Check if code is already used
	if authCode.UsedAt != nil {
		return nil, ErrCodeUsed
	}

	// Check expiration
	if time.Now().After(authCode.ExpiresAt) {
		return nil, ErrCodeExpired
	}

	// Verify the code belongs to this app
	if authCode.AppID != app.ID {
		return nil, ErrCodeExpired
	}

	// Verify redirect URI matches
	if req.RedirectURI != nil && *req.RedirectURI != authCode.RedirectURI {
		return nil, ErrInvalidRedirectURI
	}

	// Verify PKCE if applicable
	if authCode.CodeChallenge != nil {
		if req.CodeVerifier == nil {
			return nil, ErrPKCERequired
		}
		if !verifyPKCE(authCode.CodeChallenge, req.CodeVerifier, authCode.CodeChallengeMethod) {
			return nil, ErrInvalidGrantType
		}
	}

	// Mark code as used
	if err := s.storage.MarkAuthorizationCodeUsed(ctx, authCode.ID); err != nil {
		return nil, err
	}

	// Generate tokens
	return s.generateTokens(ctx, app, authCode.UserID, authCode.TenantID, authCode.Scopes, req.ClientIP)
}

func (s *Service) exchangeRefreshToken(ctx context.Context, app *storage.App, req *TokenRequest) (*TokenResponse, error) {
	// Validate client secret for confidential clients
	if app.AppType == storage.AppTypeWeb || app.AppType == storage.AppTypeMachine {
		if req.ClientSecret == nil {
			return nil, ErrClientCredentials
		}
		if _, err := s.ValidateClientCredentials(ctx, req.ClientID, *req.ClientSecret); err != nil {
			return nil, err
		}
	}

	// Get and validate refresh token
	tokenHash := utils.HashToken(*req.RefreshToken)
	refreshToken, err := s.storage.GetAppRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		return nil, err
	}
	if refreshToken == nil {
		return nil, ErrTokenRevoked
	}

	// Check if revoked
	if refreshToken.RevokedAt != nil {
		return nil, ErrTokenRevoked
	}

	// Check expiration
	if time.Now().After(refreshToken.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	// Verify the token belongs to this app
	if refreshToken.AppID != app.ID {
		return nil, ErrTokenRevoked
	}

	// Revoke old refresh token
	if err := s.storage.RevokeAppRefreshToken(ctx, refreshToken.ID, nil); err != nil {
		s.logger.Error("Failed to revoke old refresh token", "error", err)
	}

	// Determine scopes (use requested scopes or original scopes)
	scopes := refreshToken.Scopes
	if len(req.Scopes) > 0 {
		// Validate requested scopes are subset of original scopes
		for _, scope := range req.Scopes {
			if !containsString(refreshToken.Scopes, scope) {
				return nil, ErrInvalidScope
			}
		}
		scopes = req.Scopes
	}

	// Generate new tokens
	return s.generateTokens(ctx, app, refreshToken.UserID, refreshToken.TenantID, scopes, req.ClientIP)
}

func (s *Service) exchangeClientCredentials(ctx context.Context, app *storage.App, req *TokenRequest) (*TokenResponse, error) {
	// Client credentials flow requires client secret
	if req.ClientSecret == nil {
		return nil, ErrClientCredentials
	}
	if _, err := s.ValidateClientCredentials(ctx, req.ClientID, *req.ClientSecret); err != nil {
		return nil, err
	}

	// Determine scopes
	scopes := app.DefaultScopes
	if len(req.Scopes) > 0 {
		for _, scope := range req.Scopes {
			if !isScopeAllowed(scope, app.AllowedScopes) {
				return nil, ErrInvalidScope
			}
		}
		scopes = req.Scopes
	}

	// Generate access token (no refresh token for client credentials)
	return s.generateAccessToken(ctx, app, nil, app.TenantID, scopes, req.ClientIP)
}

func (s *Service) generateTokens(ctx context.Context, app *storage.App, userID uuid.UUID, tenantID *uuid.UUID, scopes []string, clientIP string) (*TokenResponse, error) {
	now := time.Now()

	// Generate access token
	accessToken, accessTokenHash, err := generateAccessToken()
	if err != nil {
		return nil, err
	}

	accessTokenTTL := time.Duration(app.AccessTokenTTLSeconds) * time.Second
	accessExpiresAt := now.Add(accessTokenTTL)

	accessTokenRecord := &storage.AppAccessToken{
		ID:         uuid.New(),
		TokenHash:  accessTokenHash,
		AppID:      app.ID,
		UserID:     &userID,
		TenantID:   tenantID,
		Scopes:     scopes,
		ExpiresAt:  accessExpiresAt,
		CreatedAt:  now,
		CreatedIP:  &clientIP,
	}

	if err := s.storage.CreateAppAccessToken(ctx, accessTokenRecord); err != nil {
		return nil, err
	}

	// Generate refresh token
	refreshToken, refreshTokenHash, err := generateRefreshToken()
	if err != nil {
		return nil, err
	}

	refreshTokenTTL := time.Duration(app.RefreshTokenTTLSeconds) * time.Second
	refreshExpiresAt := now.Add(refreshTokenTTL)

	refreshTokenRecord := &storage.AppRefreshToken{
		ID:            uuid.New(),
		TokenHash:     refreshTokenHash,
		AppID:         app.ID,
		UserID:        userID,
		TenantID:      tenantID,
		AccessTokenID: &accessTokenRecord.ID,
		Scopes:        scopes,
		ExpiresAt:     refreshExpiresAt,
		CreatedAt:     now,
		CreatedIP:     &clientIP,
	}

	if err := s.storage.CreateAppRefreshToken(ctx, refreshTokenRecord); err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(accessTokenTTL.Seconds()),
		Scope:        joinScopes(scopes),
	}, nil
}

func (s *Service) generateAccessToken(ctx context.Context, app *storage.App, userID *uuid.UUID, tenantID *uuid.UUID, scopes []string, clientIP string) (*TokenResponse, error) {
	now := time.Now()

	accessToken, accessTokenHash, err := generateAccessToken()
	if err != nil {
		return nil, err
	}

	accessTokenTTL := time.Duration(app.AccessTokenTTLSeconds) * time.Second
	accessExpiresAt := now.Add(accessTokenTTL)

	accessTokenRecord := &storage.AppAccessToken{
		ID:         uuid.New(),
		TokenHash:  accessTokenHash,
		AppID:      app.ID,
		UserID:     userID,
		TenantID:   tenantID,
		Scopes:     scopes,
		ExpiresAt:  accessExpiresAt,
		CreatedAt:  now,
		CreatedIP:  &clientIP,
	}

	if err := s.storage.CreateAppAccessToken(ctx, accessTokenRecord); err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(accessTokenTTL.Seconds()),
		Scope:       joinScopes(scopes),
	}, nil
}

// ValidateAccessToken validates an access token and returns the token info.
func (s *Service) ValidateAccessToken(ctx context.Context, token string) (*storage.AppAccessToken, *storage.App, error) {
	tokenHash := utils.HashToken(token)

	accessToken, err := s.storage.GetAppAccessTokenByHash(ctx, tokenHash)
	if err != nil {
		return nil, nil, err
	}
	if accessToken == nil {
		return nil, nil, ErrTokenRevoked
	}

	// Check if revoked
	if accessToken.RevokedAt != nil {
		return nil, nil, ErrTokenRevoked
	}

	// Check expiration
	if time.Now().After(accessToken.ExpiresAt) {
		return nil, nil, ErrTokenExpired
	}

	// Get app
	app, err := s.storage.GetAppByID(ctx, accessToken.AppID)
	if err != nil {
		return nil, nil, err
	}
	if app == nil {
		return nil, nil, ErrAppNotFound
	}

	// Check app status
	if app.Status != storage.AppStatusActive {
		return nil, nil, ErrAppSuspended
	}

	// Update last used (async)
	go func() {
		if err := s.storage.UpdateAppAccessTokenLastUsed(context.Background(), accessToken.ID); err != nil {
			s.logger.Error("Failed to update access token last used", "error", err)
		}
	}()

	return accessToken, app, nil
}

// ============================================================================
// User Consent
// ============================================================================

// CreateConsentRequest represents a request to create user consent.
type CreateConsentRequest struct {
	UserID    uuid.UUID  `json:"user_id"`
	AppID     uuid.UUID  `json:"app_id"`
	Scopes    []string   `json:"scopes"`
	ExpiresIn *int       `json:"expires_in,omitempty"` // seconds
}

// CreateUserConsent creates or updates user consent for an app.
func (s *Service) CreateUserConsent(ctx context.Context, req *CreateConsentRequest) error {
	now := time.Now()
	var expiresAt *time.Time
	if req.ExpiresIn != nil && *req.ExpiresIn > 0 {
		exp := now.Add(time.Duration(*req.ExpiresIn) * time.Second)
		expiresAt = &exp
	}

	consent := &storage.UserConsent{
		ID:        uuid.New(),
		UserID:    req.UserID,
		AppID:     req.AppID,
		Scopes:    req.Scopes,
		GrantedAt: now,
		ExpiresAt: expiresAt,
	}

	return s.storage.CreateUserConsent(ctx, consent)
}

// GetUserConsent retrieves user consent for an app.
func (s *Service) GetUserConsent(ctx context.Context, userID, appID uuid.UUID) (*storage.UserConsent, error) {
	return s.storage.GetUserConsent(ctx, userID, appID)
}

// RevokeUserConsent revokes user consent for an app.
func (s *Service) RevokeUserConsent(ctx context.Context, userID, appID uuid.UUID) error {
	return s.storage.RevokeUserConsent(ctx, userID, appID)
}

// ListUserConsents lists all consents for a user.
func (s *Service) ListUserConsents(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*storage.UserConsent, error) {
	if limit <= 0 {
		limit = 50
	}
	return s.storage.ListUserConsents(ctx, userID, limit, offset)
}

// ListScopes lists all scopes for an app.
func (s *Service) ListScopes(ctx context.Context, appID uuid.UUID) ([]*storage.AppScope, error) {
	return s.storage.ListAppScopes(ctx, appID)
}

// CreateScope creates a new custom scope for an app.
func (s *Service) CreateScope(ctx context.Context, appID uuid.UUID, name, description string, isDefault bool) (*storage.AppScope, error) {
	// Verify app exists
	_, err := s.GetApp(ctx, appID)
	if err != nil {
		return nil, err
	}

	scope := &storage.AppScope{
		ID:        uuid.New(),
		AppID:     appID,
		Name:      name,
		IsDefault: isDefault,
		CreatedAt: time.Now(),
	}
	if description != "" {
		scope.Description = &description
	}

	if err := s.storage.CreateAppScope(ctx, scope); err != nil {
		return nil, err
	}
	return scope, nil
}

// DeleteScope deletes a custom scope.
func (s *Service) DeleteScope(ctx context.Context, scopeID uuid.UUID) error {
	return s.storage.DeleteAppScope(ctx, scopeID)
}

// RevokeAccessToken revokes an access token by its raw token value.
func (s *Service) RevokeAccessToken(ctx context.Context, token string) error {
	hash := utils.HashToken(token)
	accessToken, err := s.storage.GetAppAccessTokenByHash(ctx, hash)
	if err != nil {
		return err
	}
	if accessToken == nil {
		return nil // Token not found, consider it revoked
	}
	return s.storage.RevokeAppAccessToken(ctx, accessToken.ID, nil)
}

// RevokeRefreshToken revokes a refresh token by its raw token value.
func (s *Service) RevokeRefreshToken(ctx context.Context, token string) error {
	hash := utils.HashToken(token)
	refreshToken, err := s.storage.GetAppRefreshTokenByHash(ctx, hash)
	if err != nil {
		return err
	}
	if refreshToken == nil {
		return nil // Token not found, consider it revoked
	}
	return s.storage.RevokeAppRefreshToken(ctx, refreshToken.ID, nil)
}

// ListAppConsents lists all consents for an app.
func (s *Service) ListAppConsents(ctx context.Context, appID uuid.UUID, limit, offset int) ([]*storage.UserConsent, error) {
	if limit <= 0 {
		limit = 50
	}
	return s.storage.ListAppConsents(ctx, appID, limit, offset)
}

// ============================================================================
// Helper Functions
// ============================================================================

func generateClientID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "app_" + base64.URLEncoding.EncodeToString(bytes), nil
}

func generateClientSecret() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "secret_" + base64.URLEncoding.EncodeToString(bytes), nil
}

func generateAuthorizationCode() (string, string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", "", err
	}
	code := base64.URLEncoding.EncodeToString(bytes)
	return code, utils.HashToken(code), nil
}

func generateAccessToken() (string, string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", "", err
	}
	token := base64.URLEncoding.EncodeToString(bytes)
	return token, utils.HashToken(token), nil
}

func generateRefreshToken() (string, string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", "", err
	}
	token := base64.URLEncoding.EncodeToString(bytes)
	return token, utils.HashToken(token), nil
}

func isValidRedirectURI(uri string, allowedURIs []string) bool {
	for _, allowed := range allowedURIs {
		if uri == allowed {
			return true
		}
	}
	return false
}

func isScopeAllowed(scope string, allowedScopes []string) bool {
	for _, allowed := range allowedScopes {
		if scope == allowed || allowed == "*" {
			return true
		}
	}
	return false
}

func isGrantTypeAllowed(grantType storage.GrantType, allowedTypes []storage.GrantType) bool {
	for _, allowed := range allowedTypes {
		if grantType == allowed {
			return true
		}
	}
	return false
}

func getDefaultGrantTypes(appType storage.AppType) []storage.GrantType {
	switch appType {
	case storage.AppTypeWeb:
		return []storage.GrantType{storage.GrantTypeAuthorizationCode, storage.GrantTypeRefreshToken}
	case storage.AppTypeSPA:
		return []storage.GrantType{storage.GrantTypeAuthorizationCode, storage.GrantTypeRefreshToken}
	case storage.AppTypeNative:
		return []storage.GrantType{storage.GrantTypeAuthorizationCode, storage.GrantTypeRefreshToken}
	case storage.AppTypeMachine:
		return []storage.GrantType{storage.GrantTypeClientCredentials}
	default:
		return []storage.GrantType{storage.GrantTypeAuthorizationCode}
	}
}

func verifyPKCE(codeChallenge, codeVerifier, method *string) bool {
	if method == nil || *method == "plain" {
		return codeChallenge != nil && *codeChallenge == *codeVerifier
	}
	if *method == "S256" {
		hash := sha256.Sum256([]byte(*codeVerifier))
		expected := base64.URLEncoding.EncodeToString(hash[:])
		return *codeChallenge == expected
	}
	return false
}

func joinScopes(scopes []string) string {
	result := ""
	for i, scope := range scopes {
		if i > 0 {
			result += " "
		}
		result += scope
	}
	return result
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// Helper to marshal scopes to JSON
func marshalScopes(scopes []string) string {
	b, _ := json.Marshal(scopes)
	return string(b)
}
