// Package http provides HTTP routing for ModernAuth API.
package http

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/iSundram/ModernAuth/internal/captcha"
)

// Router returns the configured chi router with all routes.
func (h *Handler) Router() *chi.Mux {
	r := chi.NewRouter()

	// Global middleware - CORS
	corsOptions := cors.Options{
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-Tenant-ID", "X-Captcha-Token"},
		ExposedHeaders:   []string{"Link", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset", "Retry-After"},
		AllowCredentials: true,
		MaxAge:           300,
	}

	// Set allowed origins - if "*" is in the list, allow all (development mode)
	// Otherwise, use specific origins (production mode)
	if len(h.corsOrigins) > 0 && h.corsOrigins[0] == "*" {
		corsOptions.AllowedOrigins = []string{"*"}
	} else {
		corsOptions.AllowedOrigins = h.corsOrigins
	}

	r.Use(cors.Handler(corsOptions))
	r.Use(h.SecurityHeaders)
	r.Use(h.MaxBodySize(1 << 20)) // 1MB max request body
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(h.Metrics)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.SetHeader("Content-Type", "application/json"))

	// Health check
	r.Get("/health", h.HealthCheck)

	// Metrics
	r.Handle("/metrics", promhttp.Handler())

	// API v1 routes
	r.Route("/v1", func(r chi.Router) {
		// Auth routes (login, register, logout, refresh, MFA, sessions)
		r.Route("/auth", func(r chi.Router) {
			// Build a captcha middleware (no-op when captcha is disabled).
			var captchaMW func(http.Handler) http.Handler
			if h.captchaService != nil {
				captchaMW = captcha.Middleware(h.captchaService)
			} else {
				captchaMW = func(next http.Handler) http.Handler { return next }
			}

			r.With(captchaMW, h.RateLimit(5, time.Hour)).Post("/register", h.Register)
			r.With(captchaMW, h.RateLimit(10, 15*time.Minute)).Post("/login", h.Login)
			r.With(h.RateLimit(10, 15*time.Minute)).Post("/login/mfa", h.LoginMFA)
			r.With(h.RateLimit(10, 15*time.Minute)).Post("/google/one-tap", h.GoogleOneTapLogin)
			r.With(h.RateLimit(100, 15*time.Minute)).Post("/refresh", h.Refresh)
			r.With(h.Auth).Post("/logout", h.Logout)
			r.With(h.Auth).Get("/me", h.Me)
			r.Get("/settings", h.GetPublicSettings)
			r.Get("/captcha/config", h.GetCaptchaConfig)

			// Email Verification
			r.With(h.RateLimit(5, time.Hour)).Post("/verify-email", h.VerifyEmail)
			r.With(h.Auth).Post("/send-verification", h.SendVerificationEmail)

			// Password Reset
			r.With(h.RateLimit(5, time.Hour)).Post("/forgot-password", h.ForgotPassword)
			r.With(h.RateLimit(5, time.Hour)).Post("/reset-password", h.ResetPassword)

			// Magic Link Authentication (Passwordless)
			r.With(h.RateLimit(3, time.Hour)).Post("/magic-link/send", h.SendMagicLink)
			r.With(h.RateLimit(10, 15*time.Minute)).Post("/magic-link/verify", h.VerifyMagicLink)

			// Session Management (Protected)
			r.With(h.Auth).Post("/revoke-all-sessions", h.RevokeAllSessions)

			// Impersonation (Protected)
			r.Group(func(r chi.Router) {
				r.Use(h.Auth)
				r.Get("/impersonation/status", h.GetImpersonationStatus)
				r.Post("/impersonation/end", h.EndImpersonation)
			})

			// MFA Management (Protected)
			r.Group(func(r chi.Router) {
				r.Use(h.Auth)
				r.Get("/mfa/status", h.GetMFAStatus)
				r.Post("/mfa/setup", h.SetupMFA)
				r.Post("/mfa/enable", h.EnableMFA)
				r.Post("/mfa/disable", h.DisableMFA)
				r.Post("/mfa/backup-codes", h.GenerateBackupCodes)
				r.Get("/mfa/backup-codes/count", h.GetBackupCodeCount)
				r.Post("/mfa/preferred", h.SetPreferredMFA)

				// Email MFA
				r.Post("/mfa/email/enable", h.EnableEmailMFA)
				r.Post("/mfa/email/disable", h.DisableEmailMFA)

				// SMS MFA
				r.Post("/mfa/sms/enable", h.EnableSMSMFA)
				r.Post("/mfa/sms/disable", h.DisableSMSMFA)

				// Device MFA Trust
				r.Post("/mfa/trust-device", h.TrustDeviceForMFA)
				r.Post("/mfa/revoke-trust", h.RevokeMFATrust)

				// WebAuthn/Passkeys (Protected - registration)
				r.Post("/mfa/webauthn/register/begin", h.BeginWebAuthnRegistration)
				r.Post("/mfa/webauthn/register/finish", h.FinishWebAuthnRegistration)
				r.Get("/mfa/webauthn/credentials", h.ListWebAuthnCredentials)
				r.Delete("/mfa/webauthn/credentials", h.DeleteWebAuthnCredential)
			})

			// MFA Login with Backup Code (no auth required)
			r.With(h.RateLimit(10, 15*time.Minute)).Post("/login/mfa/backup", h.LoginMFABackup)

			// Email MFA (no auth required - during login flow)
			r.With(h.RateLimit(5, 15*time.Minute)).Post("/login/mfa/email/send", h.SendEmailMFA)
			r.With(h.RateLimit(10, 15*time.Minute)).Post("/login/mfa/email", h.LoginEmailMFA)

			// SMS MFA (no auth required - during login flow)
			r.With(h.RateLimit(5, 15*time.Minute)).Post("/login/mfa/sms/send", h.SendSMSMFA)
			r.With(h.RateLimit(10, 15*time.Minute)).Post("/login/mfa/sms", h.LoginSMSMFA)

			// WebAuthn Login (no auth required - during login flow)
			r.With(h.RateLimit(10, 15*time.Minute)).Post("/login/mfa/webauthn/begin", h.BeginWebAuthnLogin)
			r.With(h.RateLimit(10, 15*time.Minute)).Post("/login/mfa/webauthn/finish", h.FinishWebAuthnLogin)

			// Password Change (Protected)
			r.With(h.Auth).Post("/change-password", h.ChangePassword)

			// Account Self-Deletion (Protected, GDPR)
			r.With(h.Auth).Post("/delete-account", h.DeleteOwnAccount)

			// Waitlist (Public)
			r.With(h.RateLimit(5, time.Hour)).Post("/waitlist", h.JoinWaitlist)
			r.Get("/waitlist/status", h.GetWaitlistStatus)
		})

		// User Management (requires permissions)
		r.Route("/users", func(r chi.Router) {
			r.Use(h.Auth)
			r.With(h.RequirePermission("users:read")).Get("/", h.ListUsers)
			r.With(h.RequirePermission("users:write")).Post("/", h.CreateUser)
			r.With(h.RequirePermission("users:read")).Get("/{id}", h.GetUser)
			r.With(h.RequirePermission("users:write")).Put("/{id}", h.UpdateUser)
			r.With(h.RequirePermission("users:delete")).Delete("/{id}", h.DeleteUser)
		})

		// Audit Logs (requires permission)
		r.Route("/audit", func(r chi.Router) {
			r.Use(h.Auth)
			r.With(h.RequirePermission("audit:read")).Get("/logs", h.ListAuditLogs)
		})

		// Admin (requires admin role)
		r.Route("/admin", func(r chi.Router) {
			r.Use(h.Auth)
			r.Use(h.RequireRole("admin"))
			r.Get("/stats", h.GetSystemStats)
			r.Get("/services", h.GetServicesStatus)
			r.Get("/settings", h.ListSettings)
			r.Patch("/settings/{key}", h.UpdateSetting)
			r.Post("/users/{id}/roles", h.AssignUserRole)
			r.Delete("/users/{id}/roles/{roleId}", h.RemoveUserRole)

			// User impersonation
			r.With(h.RequirePermission("users:impersonate")).Post("/users/{id}/impersonate", h.ImpersonateUser)
			r.Get("/impersonation-sessions", h.ListImpersonationSessions)

			// Bulk user operations
			r.Post("/users/import", h.ImportUsersJSON)
			r.Post("/users/import/csv", h.ImportUsersCSV)
			r.Get("/users/export", h.ExportUsers)

			// Role management
			r.Get("/roles", h.ListRoles)
			r.Post("/roles", h.CreateRole)
			r.Get("/roles/{id}", h.GetRole)
			r.Put("/roles/{id}", h.UpdateRole)
			r.Delete("/roles/{id}", h.DeleteRole)
			r.Get("/roles/{id}/permissions", h.GetRolePermissions)
			r.Post("/roles/{id}/permissions", h.AssignPermissionToRole)
			r.Delete("/roles/{id}/permissions/{permissionId}", h.RemovePermissionFromRole)

			// Permission management
			r.Get("/permissions", h.ListPermissions)

			// Email template management
			if h.emailTemplateHandler != nil {
				r.Route("/email-templates", func(r chi.Router) {
					r.Get("/", h.emailTemplateHandler.ListTemplates)
					r.Get("/variables", h.emailTemplateHandler.ListAvailableVariables)
					r.Get("/stats", h.emailTemplateHandler.GetEmailStats)
					r.Get("/stats/export", h.emailTemplateHandler.ExportEmailStats)
					r.Get("/export", h.emailTemplateHandler.ExportTemplates)
					r.Post("/import", h.emailTemplateHandler.ImportTemplates)
					r.Get("/preview-all", h.emailTemplateHandler.PreviewAllTemplates)
					r.Get("/{type}", h.emailTemplateHandler.GetTemplate)
					r.Put("/{type}", h.emailTemplateHandler.UpdateTemplate)
					r.Delete("/{type}", h.emailTemplateHandler.DeleteTemplate)
					r.Post("/{type}/preview", h.emailTemplateHandler.PreviewTemplate)
					r.Post("/{type}/test", h.emailTemplateHandler.SendTestEmail)
					r.Post("/{type}/validate", h.emailTemplateHandler.ValidateTemplate)
					r.Get("/{type}/versions", h.emailTemplateHandler.ListTemplateVersions)
					r.Get("/{type}/versions/{versionId}", h.emailTemplateHandler.GetTemplateVersion)
					r.Post("/{type}/versions/{versionId}/restore", h.emailTemplateHandler.RestoreTemplateVersion)
				})
				r.Route("/email-branding", func(r chi.Router) {
					r.Get("/", h.emailTemplateHandler.GetBranding)
					r.Put("/", h.emailTemplateHandler.UpdateBranding)
					r.Get("/advanced", h.emailTemplateHandler.GetAdvancedBranding)
					r.Put("/advanced", h.emailTemplateHandler.UpdateAdvancedBranding)
				})
				r.Route("/email-bounces", func(r chi.Router) {
					r.Get("/", h.emailTemplateHandler.ListEmailBounces)
				})
				r.Route("/email-suppressions", func(r chi.Router) {
					r.Get("/", h.emailTemplateHandler.ListSuppressions)
					r.Post("/", h.emailTemplateHandler.AddSuppression)
					r.Delete("/{email}", h.emailTemplateHandler.RemoveSuppression)
				})
				r.Route("/email-ab-tests", func(r chi.Router) {
					r.Get("/", h.emailTemplateHandler.ListABTests)
					r.Post("/", h.emailTemplateHandler.CreateABTest)
					r.Get("/{testId}", h.emailTemplateHandler.GetABTest)
					r.Post("/{testId}/winner", h.emailTemplateHandler.DeclareABTestWinner)
				})
			}
		})

		// Tenant Management (requires admin role)
		if h.tenantHandler != nil {
			r.Route("/tenants", func(r chi.Router) {
				r.Use(h.Auth)
				r.Use(h.RequireRole("admin"))
				r.Mount("/", h.tenantHandler.TenantRoutes())
			})
		}

		// Device Management (requires auth)
		if h.deviceHandler != nil {
			r.Route("/devices", func(r chi.Router) {
				r.Use(h.Auth)
				r.Mount("/", h.deviceHandler.DeviceRoutes())
			})

			// Session Management (requires auth)
			r.Route("/sessions", func(r chi.Router) {
				r.Use(h.Auth)
				r.Get("/", h.ListSessions)
				r.Delete("/{id}", h.RevokeSession)
				r.Mount("/", h.deviceHandler.SessionRoutes())
			})
		}

		// API Key Management (requires auth)
		if h.apiKeyHandler != nil {
			r.Route("/api-keys", func(r chi.Router) {
				r.Use(h.Auth)
				r.Mount("/", h.apiKeyHandler.APIKeyRoutes())
			})
		}

		// Webhook Management (requires auth)
		if h.webhookHandler != nil {
			r.Route("/webhooks", func(r chi.Router) {
				r.Use(h.Auth)
				r.Mount("/", h.webhookHandler.WebhookRoutes())
			})
		}

		// Invitation Management (requires auth)
		if h.invitationHandler != nil {
			r.Route("/invitations", func(r chi.Router) {
				r.Use(h.Auth)
				r.Mount("/", h.invitationHandler.InvitationRoutes())
			})

			// Public invitation routes (no auth required)
			r.Route("/invitations/public", func(r chi.Router) {
				r.Mount("/", h.invitationHandler.PublicInvitationRoutes())
			})
		}

		// Group Management (requires auth)
		if h.groupHandler != nil {
			r.Route("/groups", func(r chi.Router) {
				r.Use(h.Auth)
				r.Mount("/", h.groupHandler.GroupRoutes())
			})
		}

		// OAuth routes (no auth required for login)
		if h.oauthHandler != nil {
			r.Route("/oauth", func(r chi.Router) {
				r.Mount("/", h.oauthHandler.OAuthRoutes())
			})
		}

		// Analytics routes (requires admin role)
		if h.analyticsHandler != nil {
			r.Route("/analytics", func(r chi.Router) {
				r.Use(h.Auth)
				r.Use(h.RequireRole("admin"))
				r.Mount("/", h.analyticsHandler.AnalyticsRoutes())
			})
		}

		// External webhooks (unauthenticated, verified by signature)
		if h.sendGridWebhookHandler != nil {
			r.Route("/webhooks/external", func(r chi.Router) {
				r.Mount("/", h.sendGridWebhookHandler.WebhookRoutes())
			})
		}

		// Email tracking pixels (unauthenticated)
		if h.emailTemplateHandler != nil {
			r.Route("/email/track", func(r chi.Router) {
				r.Get("/open/{pixelID}", h.emailTemplateHandler.TrackEmailOpen)
				r.Get("/click/{trackingID}", h.emailTemplateHandler.TrackEmailClick)
			})
		}
	})

	return r
}
