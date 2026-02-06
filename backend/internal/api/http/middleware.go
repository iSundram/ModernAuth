package http

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type contextKey string

const (
	userIDKey    contextKey = "user_id"
	sessionIDKey contextKey = "session_id"
)

// getUserIDFromContext safely extracts user ID from context.
func getUserIDFromContext(ctx context.Context) (uuid.UUID, error) {
	userIDStr, ok := ctx.Value(userIDKey).(string)
	if !ok || userIDStr == "" {
		return uuid.Nil, fmt.Errorf("user ID not found in context")
	}
	return uuid.Parse(userIDStr)
}

// Auth middleware validates the JWT access token and adds user information to the context.
func (h *Handler) Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			h.writeError(w, http.StatusUnauthorized, "Authorization header required", nil)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			h.writeError(w, http.StatusUnauthorized, "Bearer token required", nil)
			return
		}

		claims, err := h.tokenService.ValidateAccessToken(tokenString)
		if err != nil {
			h.writeError(w, http.StatusUnauthorized, "Invalid or expired token", err)
			return
		}

		// Check if token is blacklisted
		if h.tokenBlacklist != nil {
			blacklisted, err := h.tokenBlacklist.IsBlacklisted(r.Context(), tokenString)
			if err != nil {
				h.logger.Error("Failed to check token blacklist", "error", err)
				// Continue if blacklist check fails (fail open for availability)
			} else if blacklisted {
				h.writeError(w, http.StatusUnauthorized, "Token has been revoked", nil)
				return
			}
		}

		ctx := context.WithValue(r.Context(), userIDKey, claims.UserID)
		ctx = context.WithValue(ctx, sessionIDKey, claims.SessionID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RateLimit middleware limits the number of requests from a single IP.
// Returns standard rate limit headers: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, Retry-After
func (h *Handler) RateLimit(limit int, window time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip rate limiting if Redis is not configured
			if h.rdb == nil {
				next.ServeHTTP(w, r)
				return
			}

			ip := r.RemoteAddr
			// Handle cases where RemoteAddr includes port
			if lastColon := len(ip) - 1; lastColon >= 0 {
				for i := lastColon; i >= 0; i-- {
					if ip[i] == ':' {
						ip = ip[:i]
						break
					}
				}
			}

			key := fmt.Sprintf("ratelimit:%s:%s", r.URL.Path, ip)
			ctx := r.Context()

			count, err := h.rdb.Incr(ctx, key).Result()
			if err != nil {
				h.logger.Error("Rate limit error", "error", err)
				next.ServeHTTP(w, r)
				return
			}

			// Get TTL for reset time calculation
			ttl, err := h.rdb.TTL(ctx, key).Result()
			if err != nil || ttl < 0 {
				ttl = window
			}

			if count == 1 {
				h.rdb.Expire(ctx, key, window)
				ttl = window
			}

			// Calculate remaining requests and reset time
			remaining := int64(limit) - count
			if remaining < 0 {
				remaining = 0
			}
			resetTime := time.Now().Add(ttl).Unix()

			// Set rate limit headers on all responses
			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
			w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
			w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", resetTime))

			if count > int64(limit) {
				// Add Retry-After header when rate limited
				retryAfter := int(ttl.Seconds())
				if retryAfter < 1 {
					retryAfter = 1
				}
				w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))

				h.logger.Warn("Rate limit exceeded", "ip", ip, "path", r.URL.Path)
				h.writeError(w, http.StatusTooManyRequests, "Rate limit exceeded", nil)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// responseWriter is a wrapper for http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Metrics middleware tracks request counts and durations.
func (h *Handler) Metrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		rw := &responseWriter{w, http.StatusOK}
		next.ServeHTTP(rw, r)

		duration := time.Since(start).Seconds()
		path := r.URL.Path
		method := r.Method
		status := fmt.Sprintf("%d", rw.statusCode)

		httpRequestsTotal.WithLabelValues(path, method, status).Inc()
		httpRequestDuration.WithLabelValues(path, method).Observe(duration)
	})
}

// RequireRole middleware checks if the authenticated user has a specific role.
func (h *Handler) RequireRole(roleName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userIDStr, ok := r.Context().Value(userIDKey).(string)
			if !ok || userIDStr == "" {
				h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
				return
			}

			userID, err := uuid.Parse(userIDStr)
			if err != nil {
				h.writeError(w, http.StatusUnauthorized, "Invalid user ID", err)
				return
			}

			var hasRole bool

			// Check if we are in a tenant context (e.g. via URL param or header if implemented)
			// For now, let's look for a tenant ID in the request context or URL
			// This is a simplified check - in a real app, tenant ID might come from
			// a parent middleware or route param. Let's assume there's a way to get it.
			// Since we don't have a standard way to get tenant ID here yet, we'll
			// default to checking global roles, unless we can find a tenant ID.

			// NOTE: This implementation assumes tenant ID might be available in context
			// or we might need to update this middleware signature or logic if we want strict
			// tenant scoping here. For now, we'll use the existing UserHasRole for backwards compat
			// if no tenant is found, but we should upgrade this.

			// Let's see if we can get tenant ID from chi URL param if it exists in the path
			tenantIDStr := chi.URLParam(r, "tenantId")
			if tenantIDStr == "" {
				// Try "id" parameter if the route is /tenants/{id}/...
				// Be careful not to pick up other IDs.
				// For now, let's stick to the non-tenant check if not explicit.
				hasRole, err = h.authService.UserHasRole(r.Context(), userID, roleName)
			} else {
				tenantID, tErr := uuid.Parse(tenantIDStr)
				if tErr == nil {
					hasRole, err = h.authService.UserHasRoleInTenant(r.Context(), userID, roleName, tenantID)
				} else {
					// Fallback
					hasRole, err = h.authService.UserHasRole(r.Context(), userID, roleName)
				}
			}

			if err != nil {
				h.writeError(w, http.StatusInternalServerError, "Failed to check role", err)
				return
			}

			if !hasRole {
				h.writeError(w, http.StatusForbidden, "Insufficient permissions", nil)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermission middleware checks if the authenticated user has a specific permission.
func (h *Handler) RequirePermission(permissionName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userIDStr, ok := r.Context().Value(userIDKey).(string)
			if !ok || userIDStr == "" {
				h.writeError(w, http.StatusUnauthorized, "Authentication required", nil)
				return
			}

			userID, err := uuid.Parse(userIDStr)
			if err != nil {
				h.writeError(w, http.StatusUnauthorized, "Invalid user ID", err)
				return
			}

			var hasPermission bool

			// Same tenant logic as RequireRole
			tenantIDStr := chi.URLParam(r, "tenantId")
			if tenantIDStr == "" {
				hasPermission, err = h.authService.UserHasPermission(r.Context(), userID, permissionName)
			} else {
				tenantID, tErr := uuid.Parse(tenantIDStr)
				if tErr == nil {
					hasPermission, err = h.authService.UserHasPermissionInTenant(r.Context(), userID, permissionName, tenantID)
				} else {
					hasPermission, err = h.authService.UserHasPermission(r.Context(), userID, permissionName)
				}
			}

			if err != nil {
				h.writeError(w, http.StatusInternalServerError, "Failed to check permission", err)
				return
			}

			if !hasPermission {
				h.writeError(w, http.StatusForbidden, "Insufficient permissions", nil)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders middleware adds essential security headers to all responses.
func (h *Handler) SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent clickjacking attacks
		w.Header().Set("X-Frame-Options", "DENY")
		// Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Enable XSS filter in older browsers
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		// Enforce HTTPS (1 year, include subdomains)
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		// Prevent information leakage via Referer header
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// Restrict permissions/features the browser can use
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		next.ServeHTTP(w, r)
	})
}

// MaxBodySize middleware limits the size of request bodies.
func (h *Handler) MaxBodySize(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > maxBytes {
				h.writeError(w, http.StatusRequestEntityTooLarge, "Request body too large", nil)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}
