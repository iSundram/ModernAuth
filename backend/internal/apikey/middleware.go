// Package apikey provides API key authentication middleware.
package apikey

import (
	"context"
	"net/http"
	"strings"
)

type contextKey string

const (
	// APIKeyContextKey is the context key for the current API key.
	APIKeyContextKey contextKey = "api_key"
)

// Middleware provides API key authentication.
type Middleware struct {
	service *Service
}

// NewMiddleware creates a new API key middleware.
func NewMiddleware(service *Service) *Middleware {
	return &Middleware{service: service}
}

// Authenticate validates API key from Authorization header or X-API-Key header.
func (m *Middleware) Authenticate(requiredScopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Try X-API-Key header first
			apiKey := r.Header.Get("X-API-Key")

			// Fall back to Authorization header with Bearer scheme
			if apiKey == "" {
				authHeader := r.Header.Get("Authorization")
				if strings.HasPrefix(authHeader, "Bearer mk_") {
					apiKey = strings.TrimPrefix(authHeader, "Bearer ")
				}
			}

			if apiKey == "" {
				http.Error(w, "API key required", http.StatusUnauthorized)
				return
			}

			// Get client IP
			clientIP := r.RemoteAddr
			if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
				// Take the first IP in the chain
				if idx := strings.Index(forwardedFor, ","); idx != -1 {
					clientIP = strings.TrimSpace(forwardedFor[:idx])
				} else {
					clientIP = strings.TrimSpace(forwardedFor)
				}
			}
			// Remove port if present
			if idx := strings.LastIndex(clientIP, ":"); idx != -1 {
				clientIP = clientIP[:idx]
			}

			// Validate the API key
			key, err := m.service.ValidateAPIKey(r.Context(), apiKey, requiredScopes, clientIP)
			if err != nil {
				switch err {
				case ErrAPIKeyNotFound, ErrAPIKeyRevoked, ErrAPIKeyInactive:
					http.Error(w, "Invalid API key", http.StatusUnauthorized)
				case ErrAPIKeyExpired:
					http.Error(w, "API key expired", http.StatusUnauthorized)
				case ErrIPNotAllowed:
					http.Error(w, "IP not allowed", http.StatusForbidden)
				case ErrInsufficientScope:
					http.Error(w, "Insufficient scope", http.StatusForbidden)
				default:
					http.Error(w, "Authentication failed", http.StatusInternalServerError)
				}
				return
			}

			// Add API key to context
			ctx := context.WithValue(r.Context(), APIKeyContextKey, key)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetAPIKeyFromContext retrieves the API key from the context.
func GetAPIKeyFromContext(ctx context.Context) *APIKeyInfo {
	if key, ok := ctx.Value(APIKeyContextKey).(*APIKeyInfo); ok {
		return key
	}
	return nil
}

// APIKeyInfo represents minimal API key info stored in context.
type APIKeyInfo struct {
	ID       string   `json:"id"`
	TenantID *string  `json:"tenant_id,omitempty"`
	UserID   *string  `json:"user_id,omitempty"`
	Scopes   []string `json:"scopes,omitempty"`
}
