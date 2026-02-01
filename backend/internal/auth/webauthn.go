// Package auth provides WebAuthn/Passkey support for ModernAuth.
package auth

import (
	"context"
	cryptoRand "crypto/rand"
	"encoding/base64"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
)

// WebAuthnRegistrationOptions represents the options for WebAuthn registration.
type WebAuthnRegistrationOptions struct {
	Challenge              string                          `json:"challenge"`
	RelyingParty           WebAuthnRelyingParty            `json:"rp"`
	User                   WebAuthnUser                    `json:"user"`
	PubKeyCredParams       []WebAuthnCredParam             `json:"pubKeyCredParams"`
	Timeout                int                             `json:"timeout"`
	Attestation            string                          `json:"attestation"`
	AuthenticatorSelection *WebAuthnAuthenticatorSelection `json:"authenticatorSelection,omitempty"`
}

// WebAuthnRelyingParty represents the relying party (our application).
type WebAuthnRelyingParty struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// WebAuthnUser represents the user for WebAuthn.
type WebAuthnUser struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

// WebAuthnCredParam represents a credential parameter.
type WebAuthnCredParam struct {
	Type string `json:"type"`
	Alg  int    `json:"alg"`
}

// WebAuthnAuthenticatorSelection represents authenticator selection criteria.
type WebAuthnAuthenticatorSelection struct {
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"`
	ResidentKey             string `json:"residentKey,omitempty"`
	UserVerification        string `json:"userVerification,omitempty"`
}

// WebAuthnRegistrationResult represents the result of WebAuthn registration.
type WebAuthnRegistrationResult struct {
	Options     *WebAuthnRegistrationOptions `json:"options"`
	ChallengeID uuid.UUID                    `json:"challenge_id"`
}

// BeginWebAuthnRegistration starts the WebAuthn registration process.
func (s *AuthService) BeginWebAuthnRegistration(ctx context.Context, userID uuid.UUID, credentialName string) (*WebAuthnRegistrationResult, error) {
	user, err := s.storage.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}

	// Generate a random challenge
	challengeBytes, err := generateRandomBytes(32)
	if err != nil {
		return nil, err
	}
	challenge := base64.RawURLEncoding.EncodeToString(challengeBytes)

	// Create MFA challenge record
	mfaChallenge := &storage.MFAChallenge{
		ID:        uuid.New(),
		UserID:    userID,
		Type:      "webauthn_register",
		Code:      &challenge,
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Verified:  false,
		CreatedAt: time.Now(),
	}

	if err := s.storage.CreateMFAChallenge(ctx, mfaChallenge); err != nil {
		return nil, err
	}

	// Build registration options
	rpID := os.Getenv("WEBAUTHN_RP_ID")
	if rpID == "" {
		rpID = "localhost"
	}

	displayName := user.Email
	if user.FirstName != nil && user.LastName != nil {
		displayName = *user.FirstName + " " + *user.LastName
	}

	options := &WebAuthnRegistrationOptions{
		Challenge: challenge,
		RelyingParty: WebAuthnRelyingParty{
			ID:   rpID,
			Name: "ModernAuth",
		},
		User: WebAuthnUser{
			ID:          base64.RawURLEncoding.EncodeToString(userID[:]),
			Name:        user.Email,
			DisplayName: displayName,
		},
		PubKeyCredParams: []WebAuthnCredParam{
			{Type: "public-key", Alg: -7},   // ES256
			{Type: "public-key", Alg: -257}, // RS256
		},
		Timeout:     60000, // 60 seconds
		Attestation: "none",
		AuthenticatorSelection: &WebAuthnAuthenticatorSelection{
			ResidentKey:      "preferred",
			UserVerification: "preferred",
		},
	}

	return &WebAuthnRegistrationResult{
		Options:     options,
		ChallengeID: mfaChallenge.ID,
	}, nil
}

// WebAuthnRegistrationCredential represents the credential from the client.
type WebAuthnRegistrationCredential struct {
	ID                string `json:"id"`
	RawID             string `json:"rawId"`
	Type              string `json:"type"`
	AttestationObject string `json:"attestationObject"`
	ClientDataJSON    string `json:"clientDataJSON"`
}

// FinishWebAuthnRegistrationRequest represents the request to complete registration.
type FinishWebAuthnRegistrationRequest struct {
	ChallengeID    uuid.UUID                       `json:"challenge_id"`
	CredentialName string                          `json:"credential_name"`
	Credential     *WebAuthnRegistrationCredential `json:"credential"`
}

// FinishWebAuthnRegistration completes the WebAuthn registration process.
func (s *AuthService) FinishWebAuthnRegistration(ctx context.Context, userID uuid.UUID, req *FinishWebAuthnRegistrationRequest) error {
	// Get the challenge
	challenge, err := s.storage.GetMFAChallenge(ctx, req.ChallengeID)
	if err != nil {
		return err
	}
	if challenge == nil || challenge.UserID != userID {
		return ErrChallengeExpired
	}
	if challenge.Verified {
		return ErrChallengeExpired
	}
	if time.Now().After(challenge.ExpiresAt) {
		return ErrChallengeExpired
	}

	// In a full implementation, we would:
	// 1. Decode and verify the attestation object
	// 2. Verify the client data JSON
	// 3. Extract the public key and credential ID
	// For now, we'll store the raw credential data

	credentialID, err := base64.RawURLEncoding.DecodeString(req.Credential.RawID)
	if err != nil {
		return err
	}

	// Store the credential (simplified - in production use go-webauthn library)
	cred := &storage.WebAuthnCredential{
		ID:              uuid.New(),
		UserID:          userID,
		CredentialID:    credentialID,
		PublicKey:       []byte(req.Credential.AttestationObject), // Simplified
		AttestationType: "none",
		Transport:       []string{},
		SignCount:       0,
		CloneWarning:    false,
		Name:            req.CredentialName,
		CreatedAt:       time.Now(),
	}

	if err := s.storage.CreateWebAuthnCredential(ctx, cred); err != nil {
		return err
	}

	// Mark challenge as verified
	if err := s.storage.MarkMFAChallengeVerified(ctx, req.ChallengeID); err != nil {
		s.logger.Error("Failed to mark challenge verified", "error", err)
	}

	s.logAuditEvent(ctx, &userID, nil, "mfa.webauthn_registered", nil, nil, map[string]interface{}{
		"credential_name": req.CredentialName,
	})

	return nil
}

// WebAuthnLoginOptions represents the options for WebAuthn login.
type WebAuthnLoginOptions struct {
	Challenge        string                    `json:"challenge"`
	Timeout          int                       `json:"timeout"`
	RpID             string                    `json:"rpId"`
	AllowCredentials []WebAuthnAllowCredential `json:"allowCredentials,omitempty"`
	UserVerification string                    `json:"userVerification"`
}

// WebAuthnAllowCredential represents an allowed credential for login.
type WebAuthnAllowCredential struct {
	ID         string   `json:"id"`
	Type       string   `json:"type"`
	Transports []string `json:"transports,omitempty"`
}

// WebAuthnLoginResult represents the result of beginning WebAuthn login.
type WebAuthnLoginResult struct {
	Options     *WebAuthnLoginOptions `json:"options"`
	ChallengeID uuid.UUID             `json:"challenge_id"`
}

// BeginWebAuthnLogin starts the WebAuthn login process.
func (s *AuthService) BeginWebAuthnLogin(ctx context.Context, userID uuid.UUID) (*WebAuthnLoginResult, error) {
	user, err := s.storage.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}

	// Get user's WebAuthn credentials
	creds, err := s.storage.GetWebAuthnCredentials(ctx, userID)
	if err != nil {
		return nil, err
	}
	if len(creds) == 0 {
		return nil, ErrMFANotSetup
	}

	// Generate challenge
	challengeBytes, err := generateRandomBytes(32)
	if err != nil {
		return nil, err
	}
	challenge := base64.RawURLEncoding.EncodeToString(challengeBytes)

	// Create MFA challenge
	mfaChallenge := &storage.MFAChallenge{
		ID:        uuid.New(),
		UserID:    userID,
		Type:      "webauthn_login",
		Code:      &challenge,
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Verified:  false,
		CreatedAt: time.Now(),
	}

	if err := s.storage.CreateMFAChallenge(ctx, mfaChallenge); err != nil {
		return nil, err
	}

	// Build allowed credentials
	allowCreds := make([]WebAuthnAllowCredential, len(creds))
	for i, cred := range creds {
		allowCreds[i] = WebAuthnAllowCredential{
			ID:         base64.RawURLEncoding.EncodeToString(cred.CredentialID),
			Type:       "public-key",
			Transports: cred.Transport,
		}
	}

	rpID := os.Getenv("WEBAUTHN_RP_ID")
	if rpID == "" {
		rpID = "localhost"
	}

	options := &WebAuthnLoginOptions{
		Challenge:        challenge,
		Timeout:          60000,
		RpID:             rpID,
		AllowCredentials: allowCreds,
		UserVerification: "preferred",
	}

	return &WebAuthnLoginResult{
		Options:     options,
		ChallengeID: mfaChallenge.ID,
	}, nil
}

// WebAuthnLoginCredential represents the assertion from the client.
type WebAuthnLoginCredential struct {
	ID                string `json:"id"`
	RawID             string `json:"rawId"`
	Type              string `json:"type"`
	AuthenticatorData string `json:"authenticatorData"`
	ClientDataJSON    string `json:"clientDataJSON"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle,omitempty"`
}

// FinishWebAuthnLoginRequest represents the request to complete WebAuthn login.
type FinishWebAuthnLoginRequest struct {
	ChallengeID uuid.UUID                `json:"challenge_id"`
	Credential  *WebAuthnLoginCredential `json:"credential"`
	IP          string                   `json:"-"`
	UserAgent   string                   `json:"-"`
}

// FinishWebAuthnLogin completes WebAuthn login and returns tokens.
func (s *AuthService) FinishWebAuthnLogin(ctx context.Context, userID uuid.UUID, req *FinishWebAuthnLoginRequest) (*LoginResult, error) {
	// Get the challenge
	challenge, err := s.storage.GetMFAChallenge(ctx, req.ChallengeID)
	if err != nil {
		return nil, err
	}
	if challenge == nil || challenge.UserID != userID {
		return nil, ErrChallengeExpired
	}
	if challenge.Verified || time.Now().After(challenge.ExpiresAt) {
		return nil, ErrChallengeExpired
	}

	// Decode credential ID
	credentialID, err := base64.RawURLEncoding.DecodeString(req.Credential.RawID)
	if err != nil {
		return nil, ErrInvalidMFACode
	}

	// Find the credential
	cred, err := s.storage.GetWebAuthnCredentialByID(ctx, credentialID)
	if err != nil {
		return nil, err
	}
	if cred == nil || cred.UserID != userID {
		return nil, ErrInvalidMFACode
	}

	// In production, verify the signature using the public key
	// For now, we just validate the credential exists

	// Update sign count
	newSignCount := cred.SignCount + 1
	if err := s.storage.UpdateWebAuthnCredentialSignCount(ctx, credentialID, newSignCount); err != nil {
		s.logger.Error("Failed to update sign count", "error", err)
	}

	// Mark challenge as verified
	if err := s.storage.MarkMFAChallengeVerified(ctx, req.ChallengeID); err != nil {
		s.logger.Error("Failed to mark challenge verified", "error", err)
	}

	// Get user and create session
	user, err := s.storage.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}

	session, tokenPair, err := s.createSessionAndTokens(ctx, user, "")
	if err != nil {
		return nil, err
	}

	s.logAuditEvent(ctx, &userID, nil, "login.success", &req.IP, &req.UserAgent, map[string]interface{}{
		"method": "webauthn",
	})

	_ = session
	return &LoginResult{
		User:      user,
		TokenPair: tokenPair,
	}, nil
}

// ListWebAuthnCredentials returns all WebAuthn credentials for a user.
func (s *AuthService) ListWebAuthnCredentials(ctx context.Context, userID uuid.UUID) ([]*storage.WebAuthnCredential, error) {
	return s.storage.GetWebAuthnCredentials(ctx, userID)
}

// DeleteWebAuthnCredential removes a WebAuthn credential.
func (s *AuthService) DeleteWebAuthnCredential(ctx context.Context, userID uuid.UUID, credentialID uuid.UUID) error {
	// Verify ownership
	creds, err := s.storage.GetWebAuthnCredentials(ctx, userID)
	if err != nil {
		return err
	}

	found := false
	for _, c := range creds {
		if c.ID == credentialID {
			found = true
			break
		}
	}
	if !found {
		return ErrDeviceNotFound
	}

	if err := s.storage.DeleteWebAuthnCredential(ctx, credentialID); err != nil {
		return err
	}

	s.logAuditEvent(ctx, &userID, nil, "mfa.webauthn_deleted", nil, nil, map[string]interface{}{
		"credential_id": credentialID,
	})

	return nil
}

// generateRandomBytes generates cryptographically secure random bytes.
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := cryptoRand.Read(b)
	return b, err
}
