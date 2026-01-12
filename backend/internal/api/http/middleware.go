package http

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

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

			if count == 1 {
				h.rdb.Expire(ctx, key, window)
			}

			if count > int64(limit) {
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

			hasRole, err := h.authService.UserHasRole(r.Context(), userID, roleName)
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

			hasPermission, err := h.authService.UserHasPermission(r.Context(), userID, permissionName)
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
