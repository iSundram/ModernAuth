// Package http provides OAuth HTTP handlers.
package http

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/iSundram/ModernAuth/internal/oauth"
)

// OAuthHandler handles OAuth authentication requests.
type OAuthHandler struct {
	oauthService *oauth.Service
	authService  interface {
		CreateSessionForUser(userID interface{}) (interface{}, error)
	}
	baseURL string
}

// NewOAuthHandler creates a new OAuth handler.
func NewOAuthHandler(oauthService *oauth.Service, baseURL string) *OAuthHandler {
	return &OAuthHandler{
		oauthService: oauthService,
		baseURL:      baseURL,
	}
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

	// Note: Token generation should be done through authService
	// This is a simplified response - in production, integrate with AuthService
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
		IsNewUser: isNew,
		// Tokens should be generated by authService.CreateSessionForOAuthUser()
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
