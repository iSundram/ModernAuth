// Package main provides the entry point for the ModernAuth server.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	httpapi "github.com/iSundram/ModernAuth/internal/api/http"
	"github.com/iSundram/ModernAuth/internal/apikey"
	"github.com/iSundram/ModernAuth/internal/audit"
	"github.com/iSundram/ModernAuth/internal/auth"
	"github.com/iSundram/ModernAuth/internal/captcha"
	"github.com/iSundram/ModernAuth/internal/config"
	"github.com/iSundram/ModernAuth/internal/device"
	"github.com/iSundram/ModernAuth/internal/email"
	"github.com/iSundram/ModernAuth/internal/groups"
	"github.com/iSundram/ModernAuth/internal/hibp"
	"github.com/iSundram/ModernAuth/internal/invitation"
	"github.com/iSundram/ModernAuth/internal/oauth"
	"github.com/iSundram/ModernAuth/internal/sms"
	"github.com/iSundram/ModernAuth/internal/storage/pg"
	"github.com/iSundram/ModernAuth/internal/tenant"
	"github.com/iSundram/ModernAuth/internal/webhook"
)

func main() {
	// Initialize structured logging
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		slog.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Create database connection pool
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.Database.URL)
	if err != nil {
		slog.Error("Failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	// Verify database connection
	if err := pool.Ping(ctx); err != nil {
		slog.Error("Failed to ping database", "error", err)
		os.Exit(1)
	}
	slog.Info("Connected to database")

	// Initialize Redis client
	opts, err := redis.ParseURL(cfg.Redis.URL)
	if err != nil {
		slog.Error("Failed to parse REDIS_URL", "error", err)
		os.Exit(1)
	}
	rdb := redis.NewClient(opts)
	if err := rdb.Ping(ctx).Err(); err != nil {
		slog.Error("Failed to connect to Redis", "error", err)
		os.Exit(1)
	}
	defer rdb.Close()
	slog.Info("Connected to Redis")

	// Initialize storage
	storage := pg.NewPostgresStorage(pool)

	// Initialize token service
	tokenConfig := &auth.TokenConfig{
		Issuer:          cfg.Auth.Issuer,
		AccessTokenTTL:  cfg.Auth.AccessTokenTTL,
		RefreshTokenTTL: cfg.Auth.RefreshTokenTTL,
		SigningKey:      []byte(cfg.Auth.JWTSecret),
		SigningMethod:   auth.DefaultTokenConfig().SigningMethod,
	}
	tokenService := auth.NewTokenService(tokenConfig)

	// Initialize account lockout
	lockoutConfig := &auth.LockoutConfig{
		MaxAttempts:     cfg.Lockout.MaxAttempts,
		LockoutWindow:   cfg.Lockout.LockoutWindow,
		LockoutDuration: cfg.Lockout.LockoutDuration,
	}
	accountLockout := auth.NewAccountLockout(rdb, lockoutConfig)

	// Initialize MFA lockout with stricter settings (5 attempts, 5 min lockout)
	mfaLockoutConfig := &auth.LockoutConfig{
		MaxAttempts:     5,
		LockoutWindow:   5 * time.Minute,
		LockoutDuration: 5 * time.Minute,
	}
	mfaLockout := auth.NewAccountLockout(rdb, mfaLockoutConfig)

	// Initialize token blacklist
	tokenBlacklist := auth.NewTokenBlacklist(rdb)

	// Initialize email service
	var emailService email.Service
	var queuedEmailService *email.QueuedService           // Track for graceful shutdown
	var rateLimitedEmailService *email.RateLimitedService // Track for cleanup

	// Validate provider configuration
	switch cfg.Email.Provider {
	case "smtp":
		if !cfg.Email.IsSMTPConfigured() {
			slog.Error("SMTP email provider selected but configuration is incomplete",
				"provider", cfg.Email.Provider,
				"smtp_host_set", cfg.Email.SMTPHost != "",
				"from_email_set", cfg.Email.FromEmail != "",
			)
			os.Exit(1)
		}
	case "sendgrid":
		if !cfg.Email.IsSendGridConfigured() {
			slog.Error("SendGrid email provider selected but configuration is incomplete",
				"provider", cfg.Email.Provider,
				"api_key_set", cfg.Email.SendGridAPIKey != "",
				"from_email_set", cfg.Email.FromEmail != "",
			)
			os.Exit(1)
		}
	}

	// Create base email sender based on provider
	var emailSender email.EmailSender
	switch cfg.Email.Provider {
	case "smtp":
		emailConfig := &email.Config{
			SMTPHost:     cfg.Email.SMTPHost,
			SMTPPort:     cfg.Email.SMTPPort,
			SMTPUsername: cfg.Email.SMTPUsername,
			SMTPPassword: cfg.Email.SMTPPassword,
			FromEmail:    cfg.Email.FromEmail,
			FromName:     cfg.Email.FromName,
			BaseURL:      cfg.App.BaseURL,
		}
		emailSender = email.NewSMTPService(emailConfig)
		slog.Info("Using SMTP email service", "host", cfg.Email.SMTPHost, "port", cfg.Email.SMTPPort)

	case "sendgrid":
		sendgridConfig := &email.SendGridConfig{
			APIKey:    cfg.Email.SendGridAPIKey,
			FromEmail: cfg.Email.FromEmail,
			FromName:  cfg.Email.FromName,
			BaseURL:   cfg.App.BaseURL,
		}
		emailSender = email.NewSendGridService(sendgridConfig)
		slog.Info("Using SendGrid email service")

	default:
		emailSender = email.NewConsoleService()
		slog.Info("Using console email service (development mode)",
			"provider", cfg.Email.Provider,
		)
	}

	// Initialize email template service
	templateService := email.NewTemplateService(storage)

	// Create template-aware email service (uses DB templates with rich variables)
	emailService = email.NewTemplateAwareService(&email.TemplateAwareConfig{
		Sender:          emailSender,
		TemplateService: templateService,
		Storage:         storage,
	})
	slog.Info("Email template service enabled")

	// Wrap with rate limiting if enabled
	if cfg.Email.RateLimitEnabled {
		rateLimitConfig := &email.RateLimitConfig{
			VerificationLimit:  cfg.Email.VerificationRateLimit,
			PasswordResetLimit: cfg.Email.PasswordResetRateLimit,
			MFACodeLimit:       cfg.Email.MFACodeRateLimit,
			LoginAlertLimit:    cfg.Email.LoginAlertRateLimit,
			Window:             time.Hour,
		}
		rateLimitedEmailService = email.NewRateLimitedService(emailService, rateLimitConfig)
		emailService = rateLimitedEmailService
		slog.Info("Email rate limiting enabled",
			"verification_limit", cfg.Email.VerificationRateLimit,
			"password_reset_limit", cfg.Email.PasswordResetRateLimit,
			"mfa_code_limit", cfg.Email.MFACodeRateLimit,
			"login_alert_limit", cfg.Email.LoginAlertRateLimit,
		)
	}

	// Wrap with queue if enabled
	if cfg.Email.QueueEnabled {
		queueConfig := &email.QueueConfig{
			QueueSize:       cfg.Email.QueueSize,
			MaxRetries:      3,
			DeadLetterStore: storage,
		}
		queuedEmailService = email.NewQueuedService(emailService, queueConfig)
		emailService = queuedEmailService
		slog.Info("Email queue enabled", "queue_size", cfg.Email.QueueSize)
	}

	// Initialize auth service (now after email service is created)
	authService := auth.NewAuthService(storage, tokenService, emailService, cfg.Auth.SessionTTL)

	// Initialize HIBP breached password detection
	if cfg.HIBP.Enabled {
		hibpCache := hibp.NewRedisBreachCache(rdb)
		hibpService := hibp.NewService(&hibp.Config{
			Enabled:   true,
			APIKey:    cfg.HIBP.APIKey,
			CacheTTL:  cfg.HIBP.CacheTTL,
			UserAgent: "ModernAuth",
		}, hibpCache)
		authService.SetHIBPService(hibpService)
		slog.Info("HIBP breached password detection enabled", "cache_ttl", cfg.HIBP.CacheTTL)
	}

	// Initialize SMS service
	smsService := sms.NewService(&sms.Config{
		Provider:          cfg.SMS.Provider,
		TwilioAccountSID:  cfg.SMS.TwilioAccountSID,
		TwilioAuthToken:   cfg.SMS.TwilioAuthToken,
		TwilioPhoneNumber: cfg.SMS.TwilioPhoneNumber,
	})
	authService.SetSMSService(smsService)
	if cfg.SMS.IsTwilioConfigured() {
		slog.Info("SMS service initialized with Twilio")
	} else {
		slog.Info("SMS service initialized in console mode (development)")
	}

	// Initialize tenant service
	tenantService := tenant.NewService(storage)

	// Initialize device service
	deviceService := device.NewService(storage, storage, emailService)

	// Initialize API key service
	apiKeyService := apikey.NewService(storage)

	// Initialize webhook service
	webhookService := webhook.NewService(storage)

	// Initialize invitation service
	invitationService := invitation.NewService(storage, storage, emailService, &invitation.Config{
		BaseURL: cfg.App.BaseURL, // Use config value, defaults handled in service
	})

	// Initialize groups service
	groupsService := groups.NewService(storage)

	// Initialize audit cleanup service
	auditCleanupService := audit.NewCleanupService(storage, cfg.Audit.RetentionPeriod, cfg.Audit.CleanupInterval)
	auditCleanupService.Start(ctx)
	defer auditCleanupService.Stop()
	slog.Info("Audit cleanup service started",
		"retention_period", cfg.Audit.RetentionPeriod,
		"cleanup_interval", cfg.Audit.CleanupInterval)

	// Initialize HTTP handler
	handler := httpapi.NewHandler(authService, tokenService, storage, rdb, accountLockout, tokenBlacklist, emailService)

	// Set database pool for health checks
	handler.SetDBPool(pool)

	// Configure CORS
	if len(cfg.App.CORSOrigins) > 0 {
		handler.SetCORSOrigins(cfg.App.CORSOrigins)
	}

	// Set MFA lockout
	handler.SetMFALockout(mfaLockout)

	// Initialize CAPTCHA service
	captchaService := captcha.NewService(&captcha.Config{
		Provider:  captcha.Provider(cfg.Captcha.Provider),
		SiteKey:   cfg.Captcha.SiteKey,
		SecretKey: cfg.Captcha.SecretKey,
		MinScore:  cfg.Captcha.MinScore,
	})
	handler.SetCaptchaService(captchaService)

	// Initialize specialized handlers
	tenantHandler := httpapi.NewTenantHandler(tenantService, authService)
	deviceHandler := httpapi.NewDeviceHandler(deviceService)
	apiKeyHandler := httpapi.NewAPIKeyHandler(apiKeyService)
	webhookHandler := httpapi.NewWebhookHandler(webhookService)
	invitationHandler := httpapi.NewInvitationHandler(invitationService)
	emailTemplateHandler := httpapi.NewEmailTemplateHandler(storage, templateService)
	groupHandler := httpapi.NewGroupHandler(groupsService)

	// Set handlers on main handler
	handler.SetTenantHandler(tenantHandler)
	handler.SetDeviceHandler(deviceHandler)
	handler.SetAPIKeyHandler(apiKeyHandler)
	handler.SetWebhookHandler(webhookHandler)
	handler.SetInvitationHandler(invitationHandler)
	handler.SetEmailTemplateHandler(emailTemplateHandler)
	handler.SetGroupHandler(groupHandler)

	// Initialize OAuth service
	oauthBaseURL := cfg.OAuth.RedirectBaseURL
	if oauthBaseURL == "" {
		oauthBaseURL = cfg.App.BaseURL
	}
	oauthConfig := &oauth.Config{
		AllowedRedirectURLs: cfg.OAuth.AllowedRedirectURLs,
	}
	if cfg.OAuth.IsGoogleConfigured() {
		oauthConfig.Google = &oauth.ProviderConfig{
			ClientID:     cfg.OAuth.GoogleClientID,
			ClientSecret: cfg.OAuth.GoogleClientSecret,
			RedirectURL:  oauthBaseURL + "/v1/oauth/google/callback",
			Scopes:       []string{"openid", "email", "profile"},
		}
	}
	if cfg.OAuth.IsGitHubConfigured() {
		oauthConfig.GitHub = &oauth.ProviderConfig{
			ClientID:     cfg.OAuth.GitHubClientID,
			ClientSecret: cfg.OAuth.GitHubClientSecret,
			RedirectURL:  oauthBaseURL + "/v1/oauth/github/callback",
			Scopes:       []string{"user:email", "read:user"},
		}
	}
	if cfg.OAuth.IsMicrosoftConfigured() {
		oauthConfig.Microsoft = &oauth.ProviderConfig{
			ClientID:     cfg.OAuth.MicrosoftClientID,
			ClientSecret: cfg.OAuth.MicrosoftClientSecret,
			RedirectURL:  oauthBaseURL + "/v1/oauth/microsoft/callback",
			Scopes:       []string{"openid", "email", "profile", "User.Read"},
		}
	}
	if cfg.OAuth.IsAppleConfigured() {
		oauthConfig.Apple = &oauth.ProviderConfig{
			ClientID:     cfg.OAuth.AppleClientID,
			ClientSecret: cfg.OAuth.AppleClientSecret,
			RedirectURL:  oauthBaseURL + "/v1/oauth/apple/callback",
			Scopes:       []string{"name", "email"},
		}
	}
	if cfg.OAuth.IsFacebookConfigured() {
		oauthConfig.Facebook = &oauth.ProviderConfig{
			ClientID:     cfg.OAuth.FacebookClientID,
			ClientSecret: cfg.OAuth.FacebookClientSecret,
			RedirectURL:  oauthBaseURL + "/v1/oauth/facebook/callback",
			Scopes:       []string{"email", "public_profile"},
		}
	}
	if cfg.OAuth.IsLinkedInConfigured() {
		oauthConfig.LinkedIn = &oauth.ProviderConfig{
			ClientID:     cfg.OAuth.LinkedInClientID,
			ClientSecret: cfg.OAuth.LinkedInClientSecret,
			RedirectURL:  oauthBaseURL + "/v1/oauth/linkedin/callback",
			Scopes:       []string{"openid", "profile", "email"},
		}
	}
	if cfg.OAuth.IsDiscordConfigured() {
		oauthConfig.Discord = &oauth.ProviderConfig{
			ClientID:     cfg.OAuth.DiscordClientID,
			ClientSecret: cfg.OAuth.DiscordClientSecret,
			RedirectURL:  oauthBaseURL + "/v1/oauth/discord/callback",
			Scopes:       []string{"identify", "email"},
		}
	}
	if cfg.OAuth.IsTwitterConfigured() {
		oauthConfig.Twitter = &oauth.ProviderConfig{
			ClientID:     cfg.OAuth.TwitterClientID,
			ClientSecret: cfg.OAuth.TwitterClientSecret,
			RedirectURL:  oauthBaseURL + "/v1/oauth/twitter/callback",
			Scopes:       []string{"users.read", "tweet.read", "offline.access"},
		}
	}
	if cfg.OAuth.IsGitLabConfigured() {
		oauthConfig.GitLab = &oauth.ProviderConfig{
			ClientID:     cfg.OAuth.GitLabClientID,
			ClientSecret: cfg.OAuth.GitLabClientSecret,
			RedirectURL:  oauthBaseURL + "/v1/oauth/gitlab/callback",
			Scopes:       []string{"read_user"},
		}
	}
	if cfg.OAuth.IsSlackConfigured() {
		oauthConfig.Slack = &oauth.ProviderConfig{
			ClientID:     cfg.OAuth.SlackClientID,
			ClientSecret: cfg.OAuth.SlackClientSecret,
			RedirectURL:  oauthBaseURL + "/v1/oauth/slack/callback",
			Scopes:       []string{"openid", "profile", "email"},
		}
	}
	if cfg.OAuth.IsSpotifyConfigured() {
		oauthConfig.Spotify = &oauth.ProviderConfig{
			ClientID:     cfg.OAuth.SpotifyClientID,
			ClientSecret: cfg.OAuth.SpotifyClientSecret,
			RedirectURL:  oauthBaseURL + "/v1/oauth/spotify/callback",
			Scopes:       []string{"user-read-email", "user-read-private"},
		}
	}
	oauthService := oauth.NewServiceWithStateStorage(oauthConfig, storage, storage)
	oauthHandler := httpapi.NewOAuthHandler(oauthService, oauthBaseURL)
	handler.SetOAuthHandler(oauthHandler)
	slog.Info("OAuth service initialized", "providers", oauthService.GetConfiguredProviders())

	// Initialize analytics service and handler
	analyticsService := httpapi.NewAnalyticsService(storage, rdb)
	analyticsHandler := httpapi.NewAnalyticsHandler(analyticsService)
	handler.SetAnalyticsHandler(analyticsHandler)

	router := handler.Router()

	// Create HTTP server
	server := &http.Server{
		Addr:           ":" + cfg.App.Port,
		Handler:        router,
		ReadTimeout:    15 * time.Second,
		WriteTimeout:   15 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	// Start server in a goroutine
	go func() {
		slog.Info("Starting server", "port", cfg.App.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Server failed", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("Shutting down server...")

	// Stop email services gracefully
	if queuedEmailService != nil {
		slog.Info("Stopping email queue...")
		queuedEmailService.Stop()
	}
	if rateLimitedEmailService != nil {
		rateLimitedEmailService.Stop()
	}

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		slog.Error("Server forced to shutdown", "error", err)
		os.Exit(1)
	}

	slog.Info("Server stopped")
}
