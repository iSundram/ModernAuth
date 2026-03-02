// Package http provides Google One Tap authentication handlers.
package http

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/oauth"
	"github.com/iSundram/ModernAuth/internal/storage"
	"github.com/iSundram/ModernAuth/internal/utils"
)

// Google JWKS endpoint for public key verification
const googleJWKSURL = "https://www.googleapis.com/oauth2/v3/certs"

// googleJWKS caches Google's public keys
var (
	googleJWKSCache     *googleJWKSResponse
	googleJWKSCacheMu   sync.RWMutex
	googleJWKSCacheTime time.Time
	googleJWKSCacheTTL  = 1 * time.Hour
)

// googleJWKSResponse represents Google's JWKS response
type googleJWKSResponse struct {
	Keys []googleJWK `json:"keys"`
}

// googleJWK represents a single key in Google's JWKS
type googleJWK struct {
	Kid string `json:"kid"` // Key ID
	Kty string `json:"kty"` // Key type (RSA)
	Alg string `json:"alg"` // Algorithm (RS256)
	Use string `json:"use"` // Key use (sig)
	N   string `json:"n"`   // RSA modulus
	E   string `json:"e"`   // RSA exponent
}

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

	// Get Google client ID for verification
	var expectedClientID string
	if h.oauthHandler != nil && h.oauthHandler.oauthService != nil {
		expectedClientID = h.oauthHandler.oauthService.GetGoogleClientID()
	}
	if expectedClientID == "" {
		h.writeError(w, http.StatusServiceUnavailable, "Google OAuth not configured", nil)
		return
	}

	// Verify and decode the Google JWT credential with signature verification
	claims, err := verifyGoogleJWT(req.Credential, expectedClientID)
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
	tokenPair, err := h.tokenService.GenerateTokenPair(user.ID, session.ID, user.TenantID, nil)
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

// fetchGoogleJWKS fetches Google's public keys from their JWKS endpoint.
// Keys are cached for 1 hour to avoid excessive requests.
func fetchGoogleJWKS() (*googleJWKSResponse, error) {
	googleJWKSCacheMu.RLock()
	if googleJWKSCache != nil && time.Since(googleJWKSCacheTime) < googleJWKSCacheTTL {
		cache := googleJWKSCache
		googleJWKSCacheMu.RUnlock()
		return cache, nil
	}
	googleJWKSCacheMu.RUnlock()

	// Fetch fresh keys
	googleJWKSCacheMu.Lock()
	defer googleJWKSCacheMu.Unlock()

	// Double-check after acquiring write lock
	if googleJWKSCache != nil && time.Since(googleJWKSCacheTime) < googleJWKSCacheTTL {
		return googleJWKSCache, nil
	}

	resp, err := http.Get(googleJWKSURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Google JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Google JWKS returned status %d", resp.StatusCode)
	}

	var jwks googleJWKSResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode Google JWKS: %w", err)
	}

	googleJWKSCache = &jwks
	googleJWKSCacheTime = time.Now()
	return &jwks, nil
}

// getGooglePublicKey retrieves the RSA public key for the given key ID.
func getGooglePublicKey(kid string) (*rsa.PublicKey, error) {
	jwks, err := fetchGoogleJWKS()
	if err != nil {
		return nil, err
	}

	for _, key := range jwks.Keys {
		if key.Kid == kid && key.Kty == "RSA" {
			// Decode modulus
			nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
			if err != nil {
				return nil, fmt.Errorf("failed to decode modulus: %w", err)
			}
			n := new(big.Int).SetBytes(nBytes)

			// Decode exponent
			eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
			if err != nil {
				return nil, fmt.Errorf("failed to decode exponent: %w", err)
			}
			e := int(new(big.Int).SetBytes(eBytes).Int64())

			return &rsa.PublicKey{N: n, E: e}, nil
		}
	}

	return nil, fmt.Errorf("key with kid %s not found in Google JWKS", kid)
}

// verifyGoogleJWT verifies a Google ID token JWT with full cryptographic verification.
// It fetches Google's public keys and verifies the signature, issuer, audience, and expiration.
func verifyGoogleJWT(credential, expectedClientID string) (*googleJWTClaims, error) {
	// Parse the JWT without verification first to get the header
	parts := strings.Split(credential, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidGoogleCredential
	}

	// Decode header to get kid
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalidGoogleCredential
	}

	var header struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, ErrInvalidGoogleCredential
	}

	if header.Alg != "RS256" {
		return nil, fmt.Errorf("unsupported algorithm: %s", header.Alg)
	}

	// Get the public key for this kid
	publicKey, err := getGooglePublicKey(header.Kid)
	if err != nil {
		return nil, fmt.Errorf("failed to get Google public key: %w", err)
	}

	// Parse and verify the JWT with the public key
	token, err := jwt.Parse(credential, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("JWT verification failed: %w", err)
	}

	if !token.Valid {
		return nil, ErrInvalidGoogleCredential
	}

	// Extract claims
	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidGoogleCredential
	}

	claims := &googleJWTClaims{}

	// Extract standard claims
	if sub, ok := mapClaims["sub"].(string); ok {
		claims.Sub = sub
	}
	if email, ok := mapClaims["email"].(string); ok {
		claims.Email = email
	}
	if emailVerified, ok := mapClaims["email_verified"].(bool); ok {
		claims.EmailVerified = emailVerified
	}
	if name, ok := mapClaims["name"].(string); ok {
		claims.Name = name
	}
	if givenName, ok := mapClaims["given_name"].(string); ok {
		claims.GivenName = givenName
	}
	if familyName, ok := mapClaims["family_name"].(string); ok {
		claims.FamilyName = familyName
	}
	if picture, ok := mapClaims["picture"].(string); ok {
		claims.Picture = picture
	}
	if iss, ok := mapClaims["iss"].(string); ok {
		claims.Iss = iss
	}
	if aud, ok := mapClaims["aud"].(string); ok {
		claims.Aud = aud
	}
	if exp, ok := mapClaims["exp"].(float64); ok {
		claims.Exp = int64(exp)
	}
	if iat, ok := mapClaims["iat"].(float64); ok {
		claims.Iat = int64(iat)
	}

	// Verify issuer
	if claims.Iss != "accounts.google.com" && claims.Iss != "https://accounts.google.com" {
		return nil, fmt.Errorf("invalid issuer: %s", claims.Iss)
	}

	// Verify audience matches our client ID
	if claims.Aud != expectedClientID {
		return nil, fmt.Errorf("invalid audience: expected %s, got %s", expectedClientID, claims.Aud)
	}

	// Verify expiration
	if claims.Exp < time.Now().Unix() {
		return nil, fmt.Errorf("token expired")
	}

	return claims, nil
}

// ErrInvalidGoogleCredential indicates the Google credential is invalid.
var ErrInvalidGoogleCredential = errors.New("invalid Google credential")
