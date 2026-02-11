// Package http provides OAuth HTTP handlers.
package http

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/auth"
	"github.com/iSundram/ModernAuth/internal/device"
	"github.com/iSundram/ModernAuth/internal/oauth"
	"github.com/iSundram/ModernAuth/internal/storage"
	"github.com/iSundram/ModernAuth/internal/utils"
)

// OAuthHandler handles OAuth authentication requests.
type OAuthHandler struct {
	oauthService  *oauth.Service
	tokenService  *auth.TokenService
	storage       storage.Storage
	baseURL       string
	deviceHandler *DeviceHandler
}

// NewOAuthHandler creates a new OAuth handler.
func NewOAuthHandler(oauthService *oauth.Service, tokenService *auth.TokenService, stor storage.Storage, baseURL string) *OAuthHandler {
	return &OAuthHandler{
		oauthService: oauthService,
		tokenService: tokenService,
		storage:      stor,
		baseURL:      baseURL,
	}
}

// SetDeviceHandler sets the device handler for login history recording.
func (h *OAuthHandler) SetDeviceHandler(dh *DeviceHandler) {
	h.deviceHandler = dh
}

// OAuthRoutes returns OAuth routes.
func (h *OAuthHandler) OAuthRoutes() chi.Router {
	r := chi.NewRouter()

	// Get available providers
	r.Get("/providers", h.GetProviders)

	// Provider-specific routes
	r.Route("/{provider}", func(r chi.Router) {
		r.Get("/authorize", h.Authorize)
		r.Get("/callback", h.Callback)
		r.Post("/callback", h.Callback) // Some providers POST
	})

	return r
}

// GetProvidersResponse represents the response for available OAuth providers.
type GetProvidersResponse struct {
	Providers []string `json:"providers"`
}

// GetProviders returns the list of configured OAuth providers.
func (h *OAuthHandler) GetProviders(w http.ResponseWriter, r *http.Request) {
	providers := h.oauthService.GetConfiguredProviders()

	providerNames := make([]string, len(providers))
	for i, p := range providers {
		providerNames[i] = string(p)
	}

	writeJSON(w, http.StatusOK, GetProvidersResponse{
		Providers: providerNames,
	})
}

// AuthorizeResponse contains the OAuth authorization URL.
type AuthorizeResponse struct {
	AuthorizationURL string `json:"authorization_url"`
	State            string `json:"state"`
}

// Authorize initiates the OAuth flow for a provider.
func (h *OAuthHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	providerName := chi.URLParam(r, "provider")
	provider := oauth.Provider(providerName)

	if !h.oauthService.IsProviderConfigured(provider) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "OAuth provider not configured: " + providerName,
		})
		return
	}

	// Build redirect URL
	redirectURL := h.baseURL + "/v1/oauth/" + providerName + "/callback"

	// Generate authorization URL with stored state for CSRF protection
	authURL, state, err := h.oauthService.GetAuthorizationURLWithStoredState(r.Context(), provider, redirectURL)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to generate authorization URL",
		})
		return
	}

	// Return the URL for the client to redirect to
	// Alternatively, redirect directly: http.Redirect(w, r, authURL, http.StatusFound)
	writeJSON(w, http.StatusOK, AuthorizeResponse{
		AuthorizationURL: authURL,
		State:            state,
	})
}

// CallbackRequest represents the OAuth callback parameters.
type CallbackRequest struct {
	Code  string `json:"code"`
	State string `json:"state"`
	Error string `json:"error,omitempty"`
}

// CallbackResponse contains the authentication result.
type CallbackResponse struct {
	User         OAuthUserResponse `json:"user"`
	AccessToken  string            `json:"access_token"`
	RefreshToken string            `json:"refresh_token"`
	TokenType    string            `json:"token_type"`
	ExpiresIn    int               `json:"expires_in"`
	IsNewUser    bool              `json:"is_new_user"`
}

// OAuthUserResponse represents the user info from OAuth.
type OAuthUserResponse struct {
	ID              string  `json:"id"`
	Email           string  `json:"email"`
	FirstName       *string `json:"first_name,omitempty"`
	LastName        *string `json:"last_name,omitempty"`
	AvatarURL       *string `json:"avatar_url,omitempty"`
	IsEmailVerified bool    `json:"is_email_verified"`
	Provider        string  `json:"provider"`
}

// Callback handles the OAuth callback from the provider.
func (h *OAuthHandler) Callback(w http.ResponseWriter, r *http.Request) {
	providerName := chi.URLParam(r, "provider")
	provider := oauth.Provider(providerName)

	// Get callback parameters
	var code, state, oauthError string

	if r.Method == http.MethodPost {
		var req CallbackRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "Invalid request body",
			})
			return
		}
		code = req.Code
		state = req.State
		oauthError = req.Error
	} else {
		code = r.URL.Query().Get("code")
		state = r.URL.Query().Get("state")
		oauthError = r.URL.Query().Get("error")
	}

	// Check for OAuth error
	if oauthError != "" {
		errorDesc := r.URL.Query().Get("error_description")
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":       oauthError,
			"description": errorDesc,
		})
		return
	}

	// Validate required parameters
	if code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "Authorization code is required",
		})
		return
	}

	// Validate OAuth state (CSRF protection)
	stateRecord, err := h.oauthService.ValidateAndConsumeState(r.Context(), provider, state)
	if err != nil {
		if err == oauth.ErrInvalidState {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "Invalid or expired state parameter",
			})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to validate state",
		})
		return
	}

	// Build redirect URL (must match what was used in authorize)
	redirectURL := h.baseURL + "/v1/oauth/" + providerName + "/callback"

	// Use stored redirect URL if available
	if stateRecord != nil && stateRecord.RedirectURI != "" {
		redirectURL = stateRecord.RedirectURI
	}

	// Exchange code for user info
	userInfo, err := h.oauthService.ExchangeCode(r.Context(), provider, code, redirectURL)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "Failed to authenticate with provider: " + err.Error(),
		})
		return
	}

	// Check if email is verified (optional, depends on your security requirements)
	if !userInfo.EmailVerified {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "Email not verified by provider. Please verify your email first.",
		})
		return
	}

	// Find or create user
	user, isNew, err := h.oauthService.FindOrCreateUser(r.Context(), userInfo)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to create or find user: " + err.Error(),
		})
		return
	}

	// Create a session for the user
	now := time.Now()
	session := &storage.Session{
		ID:        uuid.New(),
		UserID:    user.ID,
		CreatedAt: now,
		ExpiresAt: now.Add(7 * 24 * time.Hour), // 7 days
		Revoked:   false,
	}

	if err := h.storage.CreateSession(r.Context(), session); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to create session",
		})
		return
	}

	// Generate tokens
	tokenPair, err := h.tokenService.GenerateTokenPair(user.ID, session.ID, nil)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to generate tokens",
		})
		return
	}

	// Store the refresh token hash
	refreshToken := &storage.RefreshToken{
		ID:        uuid.New(),
		SessionID: session.ID,
		TokenHash: utils.HashToken(tokenPair.RefreshToken),
		IssuedAt:  now,
		ExpiresAt: now.Add(30 * 24 * time.Hour), // 30 days
		Revoked:   false,
	}

	if err := h.storage.CreateRefreshToken(r.Context(), refreshToken); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to store refresh token",
		})
		return
	}

	// Record login history and device for OAuth
	if h.deviceHandler != nil {
		method := "oauth_" + providerName
		ip := utils.GetClientIP(r)
		ua := r.UserAgent()
		status := "success"
		
		go func() {
			// Record device first to get ID
			d, _, err := h.deviceHandler.RecordDevice(context.Background(), &device.RecordDeviceRequest{
				UserID:    user.ID,
				UserAgent: ua,
				IPAddress: ip,
			})
			
			var deviceID *uuid.UUID
			if err == nil && d != nil {
				deviceID = &d.ID
				
				// Update session with device ID
				session.DeviceID = deviceID
				if err := h.storage.UpdateSession(context.Background(), session); err != nil {
					slog.Error("Failed to link OAuth session to device", "error", err, "session_id", session.ID)
				}
			} else if err != nil {
				slog.Error("Failed to record OAuth device", "error", err, "user_id", user.ID)
			}

			history := &storage.LoginHistory{
				UserID:      user.ID,
				SessionID:   &session.ID,
				DeviceID:    deviceID,
				IPAddress:   &ip,
				UserAgent:   &ua,
				LoginMethod: &method,
				Status:      status,
			}
			if err := h.deviceHandler.RecordLogin(context.Background(), history); err != nil {
				slog.Error("Failed to record OAuth login history", "error", err, "user_id", user.ID)
			}
		}()
	}

	response := CallbackResponse{
		User: OAuthUserResponse{
			ID:              user.ID.String(),
			Email:           user.Email,
			FirstName:       user.FirstName,
			LastName:        user.LastName,
			AvatarURL:       user.AvatarURL,
			IsEmailVerified: user.IsEmailVerified,
			Provider:        providerName,
		},
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		TokenType:    tokenPair.TokenType,
		ExpiresIn:    int(tokenPair.ExpiresIn),
		IsNewUser:    isNew,
	}

	writeJSON(w, http.StatusOK, response)
}

// LinkProvider links an OAuth provider to the authenticated user.
func (h *OAuthHandler) LinkProvider(w http.ResponseWriter, r *http.Request) {
	// This would require authentication middleware
	// Implementation similar to Callback but links to existing user instead of creating new
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error": "Not implemented",
	})
}

// UnlinkProvider unlinks an OAuth provider from the authenticated user.
func (h *OAuthHandler) UnlinkProvider(w http.ResponseWriter, r *http.Request) {
	// This would require authentication middleware
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error": "Not implemented",
	})
}

// GetLinkedProviders returns the OAuth providers linked to the authenticated user.
func (h *OAuthHandler) GetLinkedProviders(w http.ResponseWriter, r *http.Request) {
	// This would require authentication middleware
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error": "Not implemented",
	})
}
