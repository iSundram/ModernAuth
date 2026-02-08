package config

import (
	"fmt"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	App      AppConfig      `yaml:"app"`
	Database DatabaseConfig `yaml:"database"`
	Redis    RedisConfig    `yaml:"redis"`
	Auth     AuthConfig     `yaml:"auth"`
	Lockout  LockoutConfig  `yaml:"lockout"`
	Email    EmailConfig    `yaml:"email"`
	OAuth    OAuthConfig    `yaml:"oauth"`
	Audit    AuditConfig    `yaml:"audit"`
	Captcha  CaptchaConfig  `yaml:"captcha"`
	HIBP     HIBPConfig     `yaml:"hibp"`
	SMS      SMSConfig      `yaml:"sms"`
}

type AppConfig struct {
	Name        string   `yaml:"name" env:"APP_NAME" env-default:"ModernAuth"`
	Port        string   `yaml:"port" env:"PORT" env-default:"8080"`
	Env         string   `yaml:"env" env:"APP_ENV" env-default:"development"`
	CORSOrigins []string `yaml:"cors_origins" env:"CORS_ORIGINS" env-default:"*" env-separator:","`
	BaseURL     string   `yaml:"base_url" env:"APP_BASE_URL" env-default:""`
}

type DatabaseConfig struct {
	URL string `yaml:"url" env:"DATABASE_URL" env-required:"true"`
}

type RedisConfig struct {
	URL string `yaml:"url" env:"REDIS_URL" env-default:"redis://localhost:6379"`
}

type AuthConfig struct {
	JWTSecret       string        `yaml:"jwt_secret" env:"JWT_SECRET" env-required:"true"`
	AccessTokenTTL  time.Duration `yaml:"access_token_ttl" env:"ACCESS_TOKEN_TTL" env-default:"15m"`
	RefreshTokenTTL time.Duration `yaml:"refresh_token_ttl" env:"REFRESH_TOKEN_TTL" env-default:"168h"`
	SessionTTL      time.Duration `yaml:"session_ttl" env:"SESSION_TTL" env-default:"168h"`
	Issuer          string        `yaml:"issuer" env:"JWT_ISSUER" env-default:"modernauth"`
}

// LockoutConfig holds account lockout configuration.
type LockoutConfig struct {
	MaxAttempts     int           `yaml:"max_attempts" env:"LOCKOUT_MAX_ATTEMPTS" env-default:"5"`
	LockoutWindow   time.Duration `yaml:"lockout_window" env:"LOCKOUT_WINDOW" env-default:"15m"`
	LockoutDuration time.Duration `yaml:"lockout_duration" env:"LOCKOUT_DURATION" env-default:"30m"`
}

// EmailConfig holds email service configuration.
// Provider can be:
//   - "console":  log emails to stdout (safe default for development)
//   - "smtp":     send real emails via SMTP using the settings below
//   - "sendgrid": send real emails via SendGrid API
type EmailConfig struct {
	Provider     string `yaml:"provider" env:"EMAIL_PROVIDER" env-default:"console"`
	SMTPHost     string `yaml:"smtp_host" env:"SMTP_HOST" env-default:""`
	SMTPPort     int    `yaml:"smtp_port" env:"SMTP_PORT" env-default:"587"`
	SMTPUsername string `yaml:"smtp_username" env:"SMTP_USERNAME" env-default:""`
	SMTPPassword string `yaml:"smtp_password" env:"SMTP_PASSWORD" env-default:""`
	FromEmail    string `yaml:"from_email" env:"EMAIL_FROM" env-default:"noreply@modernauth.local"`
	FromName     string `yaml:"from_name" env:"EMAIL_FROM_NAME" env-default:"ModernAuth"`

	// SendGrid configuration
	SendGridAPIKey string `yaml:"sendgrid_api_key" env:"SENDGRID_API_KEY" env-default:""`

	// Queue configuration
	QueueEnabled bool `yaml:"queue_enabled" env:"EMAIL_QUEUE_ENABLED" env-default:"true"`
	QueueSize    int  `yaml:"queue_size" env:"EMAIL_QUEUE_SIZE" env-default:"1000"`

	// Rate limiting configuration
	RateLimitEnabled       bool `yaml:"rate_limit_enabled" env:"EMAIL_RATE_LIMIT_ENABLED" env-default:"true"`
	VerificationRateLimit  int  `yaml:"verification_rate_limit" env:"EMAIL_VERIFICATION_RATE_LIMIT" env-default:"3"`
	PasswordResetRateLimit int  `yaml:"password_reset_rate_limit" env:"EMAIL_PASSWORD_RESET_RATE_LIMIT" env-default:"5"`
	MFACodeRateLimit       int  `yaml:"mfa_code_rate_limit" env:"EMAIL_MFA_CODE_RATE_LIMIT" env-default:"10"`
	LoginAlertRateLimit    int  `yaml:"login_alert_rate_limit" env:"EMAIL_LOGIN_ALERT_RATE_LIMIT" env-default:"10"`
}

// OAuthConfig holds OAuth2 provider configurations.
type OAuthConfig struct {
	// Google OAuth
	GoogleClientID     string `yaml:"google_client_id" env:"OAUTH_GOOGLE_CLIENT_ID" env-default:""`
	GoogleClientSecret string `yaml:"google_client_secret" env:"OAUTH_GOOGLE_CLIENT_SECRET" env-default:""`

	// GitHub OAuth
	GitHubClientID     string `yaml:"github_client_id" env:"OAUTH_GITHUB_CLIENT_ID" env-default:""`
	GitHubClientSecret string `yaml:"github_client_secret" env:"OAUTH_GITHUB_CLIENT_SECRET" env-default:""`

	// Microsoft OAuth
	MicrosoftClientID     string `yaml:"microsoft_client_id" env:"OAUTH_MICROSOFT_CLIENT_ID" env-default:""`
	MicrosoftClientSecret string `yaml:"microsoft_client_secret" env:"OAUTH_MICROSOFT_CLIENT_SECRET" env-default:""`

	// Apple OAuth
	AppleClientID     string `yaml:"apple_client_id" env:"OAUTH_APPLE_CLIENT_ID" env-default:""`
	AppleClientSecret string `yaml:"apple_client_secret" env:"OAUTH_APPLE_CLIENT_SECRET" env-default:""`
	AppleTeamID       string `yaml:"apple_team_id" env:"OAUTH_APPLE_TEAM_ID" env-default:""`
	AppleKeyID        string `yaml:"apple_key_id" env:"OAUTH_APPLE_KEY_ID" env-default:""`

	// Facebook OAuth
	FacebookClientID     string `yaml:"facebook_client_id" env:"OAUTH_FACEBOOK_CLIENT_ID" env-default:""`
	FacebookClientSecret string `yaml:"facebook_client_secret" env:"OAUTH_FACEBOOK_CLIENT_SECRET" env-default:""`

	// LinkedIn OAuth
	LinkedInClientID     string `yaml:"linkedin_client_id" env:"OAUTH_LINKEDIN_CLIENT_ID" env-default:""`
	LinkedInClientSecret string `yaml:"linkedin_client_secret" env:"OAUTH_LINKEDIN_CLIENT_SECRET" env-default:""`

	// Discord OAuth
	DiscordClientID     string `yaml:"discord_client_id" env:"OAUTH_DISCORD_CLIENT_ID" env-default:""`
	DiscordClientSecret string `yaml:"discord_client_secret" env:"OAUTH_DISCORD_CLIENT_SECRET" env-default:""`

	// Twitter OAuth
	TwitterClientID     string `yaml:"twitter_client_id" env:"OAUTH_TWITTER_CLIENT_ID" env-default:""`
	TwitterClientSecret string `yaml:"twitter_client_secret" env:"OAUTH_TWITTER_CLIENT_SECRET" env-default:""`

	// GitLab OAuth
	GitLabClientID     string `yaml:"gitlab_client_id" env:"OAUTH_GITLAB_CLIENT_ID" env-default:""`
	GitLabClientSecret string `yaml:"gitlab_client_secret" env:"OAUTH_GITLAB_CLIENT_SECRET" env-default:""`

	// Slack OAuth
	SlackClientID     string `yaml:"slack_client_id" env:"OAUTH_SLACK_CLIENT_ID" env-default:""`
	SlackClientSecret string `yaml:"slack_client_secret" env:"OAUTH_SLACK_CLIENT_SECRET" env-default:""`

	// Spotify OAuth
	SpotifyClientID     string `yaml:"spotify_client_id" env:"OAUTH_SPOTIFY_CLIENT_ID" env-default:""`
	SpotifyClientSecret string `yaml:"spotify_client_secret" env:"OAUTH_SPOTIFY_CLIENT_SECRET" env-default:""`

	// Redirect URLs
	RedirectBaseURL     string   `yaml:"redirect_base_url" env:"OAUTH_REDIRECT_BASE_URL" env-default:""`
	AllowedRedirectURLs []string `yaml:"allowed_redirect_urls" env:"OAUTH_ALLOWED_REDIRECT_URLS" env-default:"" env-separator:","`
}

// AuditConfig holds audit log configuration.
type AuditConfig struct {
	RetentionPeriod time.Duration `yaml:"retention_period" env:"AUDIT_RETENTION_PERIOD" env-default:"8760h"` // Default: 1 year
	CleanupInterval time.Duration `yaml:"cleanup_interval" env:"AUDIT_CLEANUP_INTERVAL" env-default:"24h"`   // Default: daily
}

// CaptchaConfig holds CAPTCHA / bot-detection configuration.
type CaptchaConfig struct {
	Provider  string  `yaml:"provider" env:"CAPTCHA_PROVIDER" env-default:"none"`
	SiteKey   string  `yaml:"site_key" env:"CAPTCHA_SITE_KEY" env-default:""`
	SecretKey string  `yaml:"secret_key" env:"CAPTCHA_SECRET_KEY" env-default:""`
	MinScore  float64 `yaml:"min_score" env:"CAPTCHA_MIN_SCORE" env-default:"0.5"`
}

// HIBPConfig holds HaveIBeenPwned breached password detection configuration.
type HIBPConfig struct {
	Enabled  bool          `yaml:"enabled" env:"HIBP_ENABLED" env-default:"false"`
	APIKey   string        `yaml:"api_key" env:"HIBP_API_KEY" env-default:""`
	CacheTTL time.Duration `yaml:"cache_ttl" env:"HIBP_CACHE_TTL" env-default:"24h"`
}

// SMSConfig holds SMS service configuration.
type SMSConfig struct {
	Provider          string `yaml:"provider" env:"SMS_PROVIDER" env-default:"console"`
	TwilioAccountSID  string `yaml:"twilio_account_sid" env:"TWILIO_ACCOUNT_SID" env-default:""`
	TwilioAuthToken   string `yaml:"twilio_auth_token" env:"TWILIO_AUTH_TOKEN" env-default:""`
	TwilioPhoneNumber string `yaml:"twilio_phone_number" env:"TWILIO_PHONE_NUMBER" env-default:""`
}

// IsTwilioConfigured returns true if Twilio SMS is configured.
func (c *SMSConfig) IsTwilioConfigured() bool {
	return c.Provider == "twilio" && c.TwilioAccountSID != "" && c.TwilioAuthToken != "" && c.TwilioPhoneNumber != ""
}

// IsGoogleConfigured returns true if Google OAuth is configured.
func (c *OAuthConfig) IsGoogleConfigured() bool {
	return c.GoogleClientID != "" && c.GoogleClientSecret != ""
}

// IsGitHubConfigured returns true if GitHub OAuth is configured.
func (c *OAuthConfig) IsGitHubConfigured() bool {
	return c.GitHubClientID != "" && c.GitHubClientSecret != ""
}

// IsMicrosoftConfigured returns true if Microsoft OAuth is configured.
func (c *OAuthConfig) IsMicrosoftConfigured() bool {
	return c.MicrosoftClientID != "" && c.MicrosoftClientSecret != ""
}

// IsAppleConfigured returns true if Apple OAuth is configured.
func (c *OAuthConfig) IsAppleConfigured() bool {
	return c.AppleClientID != "" && c.AppleClientSecret != ""
}

// IsFacebookConfigured returns true if Facebook OAuth is configured.
func (c *OAuthConfig) IsFacebookConfigured() bool {
	return c.FacebookClientID != "" && c.FacebookClientSecret != ""
}

// IsLinkedInConfigured returns true if LinkedIn OAuth is configured.
func (c *OAuthConfig) IsLinkedInConfigured() bool {
	return c.LinkedInClientID != "" && c.LinkedInClientSecret != ""
}

// IsDiscordConfigured returns true if Discord OAuth is configured.
func (c *OAuthConfig) IsDiscordConfigured() bool {
	return c.DiscordClientID != "" && c.DiscordClientSecret != ""
}

// IsTwitterConfigured returns true if Twitter OAuth is configured.
func (c *OAuthConfig) IsTwitterConfigured() bool {
	return c.TwitterClientID != "" && c.TwitterClientSecret != ""
}

// IsGitLabConfigured returns true if GitLab OAuth is configured.
func (c *OAuthConfig) IsGitLabConfigured() bool {
	return c.GitLabClientID != "" && c.GitLabClientSecret != ""
}

// IsSlackConfigured returns true if Slack OAuth is configured.
func (c *OAuthConfig) IsSlackConfigured() bool {
	return c.SlackClientID != "" && c.SlackClientSecret != ""
}

// IsSpotifyConfigured returns true if Spotify OAuth is configured.
func (c *OAuthConfig) IsSpotifyConfigured() bool {
	return c.SpotifyClientID != "" && c.SpotifyClientSecret != ""
}

// IsSMTPConfigured returns true if SMTP email is configured with the
// minimum required fields for sending real emails.
func (c *EmailConfig) IsSMTPConfigured() bool {
	// Require:
	//   - Provider explicitly set to "smtp"
	//   - SMTPHost non-empty
	//   - FromEmail non-empty (address used as SMTP MAIL FROM)
	return c.Provider == "smtp" && c.SMTPHost != "" && c.FromEmail != ""
}

// IsSendGridConfigured returns true if SendGrid is configured.
func (c *EmailConfig) IsSendGridConfigured() bool {
	return c.Provider == "sendgrid" && c.SendGridAPIKey != "" && c.FromEmail != ""
}

func Load() (*Config, error) {
	cfg := &Config{}

	// Try loading from .env file first, but don't fail if it doesn't exist
	// cleanenv.ReadConfig will read from environment variables if file not found or if env vars are set
	if err := cleanenv.ReadConfig(".env", cfg); err != nil {
		// If .env doesn't exist, try reading purely from environment variables
		if err := cleanenv.ReadEnv(cfg); err != nil {
			return nil, fmt.Errorf("config error: %w", err)
		}
	}

	// Validate JWT secret minimum length (32 bytes for HS256)
	if len(cfg.Auth.JWTSecret) < 32 {
		return nil, fmt.Errorf("JWT_SECRET must be at least 32 characters for security, got %d", len(cfg.Auth.JWTSecret))
	}

	return cfg, nil
}
