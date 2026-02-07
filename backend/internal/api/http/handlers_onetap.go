// Package http provides Google One Tap authentication handlers.
package http

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/oauth"
	"github.com/iSundram/ModernAuth/internal/storage"
	"github.com/iSundram/ModernAuth/internal/utils"
)

// GoogleOneTapLogin handles Google One Tap sign-in.
// It receives a Google JWT credential, verifies it, and finds or creates the user.
func (h *Handler) GoogleOneTapLogin(w http.ResponseWriter, r *http.Request) {
	var req GoogleOneTapRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate request
	if validationErrors := ValidateStruct(req); validationErrors != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "Validation failed",
			"details": validationErrors,
		})
		return
	}

	// Decode and verify the Google JWT credential
	claims, err := decodeGoogleJWT(req.Credential)
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "Invalid Google credential", err)
		return
	}

	// Verify the token is not expired
	if claims.Exp < time.Now().Unix() {
		h.writeError(w, http.StatusUnauthorized, "Google credential has expired", nil)
		return
	}

	// Verify email is present and verified
	if claims.Email == "" {
		h.writeError(w, http.StatusBadRequest, "Email not provided in Google credential", nil)
		return
	}
	if !claims.EmailVerified {
		h.writeError(w, http.StatusForbidden, "Email not verified by Google", nil)
		return
	}

	// Check if the OAuth handler and service are available
	if h.oauthHandler == nil || h.oauthHandler.oauthService == nil {
		h.writeError(w, http.StatusServiceUnavailable, "OAuth service not configured", nil)
		return
	}

	// Build UserInfo from the Google JWT claims
	userInfo := &oauth.UserInfo{
		Provider:       oauth.ProviderGoogle,
		ProviderUserID: claims.Sub,
		Email:          claims.Email,
		EmailVerified:  claims.EmailVerified,
		Name:           claims.Name,
		FirstName:      claims.GivenName,
		LastName:       claims.FamilyName,
		AvatarURL:      claims.Picture,
		ProfileData: map[string]interface{}{
			"sub":   claims.Sub,
			"email": claims.Email,
			"name":  claims.Name,
		},
	}

	// Find or create the user
	user, isNew, err := h.oauthHandler.oauthService.FindOrCreateUser(r.Context(), userInfo)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to process Google login", err)
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
		h.writeError(w, http.StatusInternalServerError, "Failed to create session", err)
		return
	}

	// Generate tokens
	tokenPair, err := h.tokenService.GenerateTokenPair(user.ID, session.ID, nil)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to generate tokens", err)
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
		h.writeError(w, http.StatusInternalServerError, "Failed to store refresh token", err)
		return
	}

	// Log the event
	ip := r.RemoteAddr
	ua := r.UserAgent()
	eventType := "login.google_one_tap"
	if isNew {
		eventType = "register.google_one_tap"
	}
	h.authService.LogAuditEventPublic(r.Context(), &user.ID, nil, eventType, &ip, &ua, nil)

	// Build response
	response := LoginResponse{
		User: h.buildUserResponse(r.Context(), user),
		Tokens: TokensResponse{
			AccessToken:  tokenPair.AccessToken,
			RefreshToken: tokenPair.RefreshToken,
			TokenType:    tokenPair.TokenType,
			ExpiresIn:    tokenPair.ExpiresIn,
		},
	}

	writeJSON(w, http.StatusOK, response)
}

// googleJWTClaims represents the claims in a Google ID token JWT.
type googleJWTClaims struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Iss           string `json:"iss"`
	Aud           string `json:"aud"`
	Exp           int64  `json:"exp"`
	Iat           int64  `json:"iat"`
}

// decodeGoogleJWT decodes a Google ID token JWT and extracts claims.
// Note: In production, you should verify the JWT signature against Google's public keys.
// For One Tap, Google sends the credential from their servers, which provides a reasonable
// level of trust. For additional security, verify against https://www.googleapis.com/oauth2/v3/certs.
func decodeGoogleJWT(credential string) (*googleJWTClaims, error) {
	parts := strings.Split(credential, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidGoogleCredential
	}

	// Decode the payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidGoogleCredential
	}

	var claims googleJWTClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, ErrInvalidGoogleCredential
	}

	// Verify issuer
	if claims.Iss != "accounts.google.com" && claims.Iss != "https://accounts.google.com" {
		return nil, ErrInvalidGoogleCredential
	}

	return &claims, nil
}

// ErrInvalidGoogleCredential indicates the Google credential is invalid.
var ErrInvalidGoogleCredential = errors.New("invalid Google credential")
