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

	// Record login history and device
	method := "google_one_tap"
	h.recordLogin(r, user.ID, method, &session.ID, "")

	// Log the event
	ip := utils.GetClientIP(r)
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
//
// SECURITY TODO: This function only decodes the JWT payload without verifying
// the cryptographic signature. In production, you MUST verify the JWT signature
// against Google's public keys from https://www.googleapis.com/oauth2/v3/certs
//
// To implement proper verification:
// 1. Fetch Google's public keys from https://www.googleapis.com/oauth2/v3/certs (cache them)
// 2. Parse the JWT header to get the "kid" (key ID)
// 3. Find the matching public key
// 4. Verify the signature using the public key
// 5. Verify the "aud" claim matches your Google Client ID
// 6. Verify the "iss" claim is accounts.google.com or https://accounts.google.com
//
// Recommended: Use a library like github.com/golang-jwt/jwt/v5 with google.golang.org/api/idtoken
// for proper verification: idtoken.Validate(ctx, credential, clientID)
//
// Current mitigation: We verify the issuer claim as a basic check, but this does NOT
// prevent token forgery. An attacker could craft a fake JWT with a valid-looking payload.
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

	// Verify issuer - basic check but NOT sufficient without signature verification
	if claims.Iss != "accounts.google.com" && claims.Iss != "https://accounts.google.com" {
		return nil, ErrInvalidGoogleCredential
	}

	// SECURITY WARNING: Without signature verification, an attacker could forge this token.
	// The checks above only validate the token structure and issuer claim, not authenticity.

	return &claims, nil
}

// ErrInvalidGoogleCredential indicates the Google credential is invalid.
var ErrInvalidGoogleCredential = errors.New("invalid Google credential")
