// Package http provides HTTP routing for ModernAuth API.
package http

import (
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Router returns the configured chi router with all routes.
func (h *Handler) Router() *chi.Mux {
	r := chi.NewRouter()

	// Global middleware - CORS
	corsOptions := cors.Options{
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-Tenant-ID"},
		ExposedHeaders:   []string{"Link"},
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
			r.With(h.RateLimit(5, time.Hour)).Post("/register", h.Register)
			r.With(h.RateLimit(10, 15*time.Minute)).Post("/login", h.Login)
			r.With(h.RateLimit(10, 15*time.Minute)).Post("/login/mfa", h.LoginMFA)
			r.With(h.RateLimit(100, 15*time.Minute)).Post("/refresh", h.Refresh)
			r.With(h.Auth).Post("/logout", h.Logout)
			r.With(h.Auth).Get("/me", h.Me)
			r.Get("/settings", h.GetPublicSettings)

			// Email Verification
			r.With(h.RateLimit(5, time.Hour)).Post("/verify-email", h.VerifyEmail)
			r.With(h.Auth).Post("/send-verification", h.SendVerificationEmail)

			// Password Reset
			r.With(h.RateLimit(5, time.Hour)).Post("/forgot-password", h.ForgotPassword)
			r.With(h.RateLimit(5, time.Hour)).Post("/reset-password", h.ResetPassword)

			// Session Management (Protected)
			r.With(h.Auth).Post("/revoke-all-sessions", h.RevokeAllSessions)

			// MFA Management (Protected)
			r.Group(func(r chi.Router) {
				r.Use(h.Auth)
				r.Post("/mfa/setup", h.SetupMFA)
				r.Post("/mfa/enable", h.EnableMFA)
				r.Post("/mfa/disable", h.DisableMFA)
				r.Post("/mfa/backup-codes", h.GenerateBackupCodes)
				r.Get("/mfa/backup-codes/count", h.GetBackupCodeCount)
			})

			// MFA Login with Backup Code (no auth required)
			r.With(h.RateLimit(10, 15*time.Minute)).Post("/login/mfa/backup", h.LoginMFABackup)

			// Password Change (Protected)
			r.With(h.Auth).Post("/change-password", h.ChangePassword)
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

		// OAuth routes (no auth required for login)
		if h.oauthHandler != nil {
			r.Route("/oauth", func(r chi.Router) {
				r.Mount("/", h.oauthHandler.OAuthRoutes())
			})
		}
	})

	return r
}
