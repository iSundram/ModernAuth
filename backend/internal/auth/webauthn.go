// Package auth provides WebAuthn/Passkey support for ModernAuth.
package auth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptoRand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/fxamacker/cbor/v2"
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

	// Decode and verify the attestation object and client data
	credentialID, err := base64.RawURLEncoding.DecodeString(req.Credential.RawID)
	if err != nil {
		return err
	}

	clientDataJSON, err := base64.RawURLEncoding.DecodeString(req.Credential.ClientDataJSON)
	if err != nil {
		return ErrInvalidWebAuthnData
	}

	attestationObject, err := base64.RawURLEncoding.DecodeString(req.Credential.AttestationObject)
	if err != nil {
		return ErrInvalidWebAuthnData
	}

	// Verify client data JSON
	clientData, err := parseClientDataJSON(clientDataJSON)
	if err != nil {
		return ErrInvalidWebAuthnData
	}

	// Verify the challenge matches
	if clientData.Challenge != *challenge.Code {
		s.logger.Warn("WebAuthn registration challenge mismatch",
			"expected", *challenge.Code,
			"got", clientData.Challenge,
		)
		return ErrChallengeMismatch
	}

	// Verify the operation type
	if clientData.Type != "webauthn.create" {
		s.logger.Warn("WebAuthn registration type mismatch", "type", clientData.Type)
		return ErrInvalidWebAuthnData
	}

	// Parse attestation object and extract public key
	attestation, err := parseAttestationObject(attestationObject)
	if err != nil {
		return ErrInvalidWebAuthnData
	}

	// Verify RP ID hash in authenticator data
	rpID := os.Getenv("WEBAUTHN_RP_ID")
	if rpID == "" {
		rpID = "localhost"
	}
	if !attestation.VerifyRPIDHash(rpID) {
		s.logger.Warn("WebAuthn RP ID hash verification failed")
		return ErrInvalidWebAuthnData
	}

	// For "none" attestation, we skip signature verification but still validate structure
	// For other attestation types (packed, tpm, etc.), signature verification would be required
	// Production systems should use a full WebAuthn library like go-webauthn/webauthn

	// Store the credential with the extracted public key
	cred := &storage.WebAuthnCredential{
		ID:              uuid.New(),
		UserID:          userID,
		CredentialID:    credentialID,
		PublicKey:       attestation.PublicKey,
		AttestationType: attestation.Format,
		Transport:       []string{},
		SignCount:       attestation.SignCount,
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

	// Decode the assertion data
	authenticatorData, err := base64.RawURLEncoding.DecodeString(req.Credential.AuthenticatorData)
	if err != nil {
		return nil, ErrInvalidWebAuthnData
	}

	clientDataJSON, err := base64.RawURLEncoding.DecodeString(req.Credential.ClientDataJSON)
	if err != nil {
		return nil, ErrInvalidWebAuthnData
	}

	signature, err := base64.RawURLEncoding.DecodeString(req.Credential.Signature)
	if err != nil {
		return nil, ErrInvalidWebAuthnData
	}

	// Verify client data JSON
	clientData, err := parseClientDataJSON(clientDataJSON)
	if err != nil {
		return nil, ErrInvalidWebAuthnData
	}

	// Verify the challenge matches
	if clientData.Challenge != *challenge.Code {
		s.logger.Warn("WebAuthn login challenge mismatch",
			"expected", *challenge.Code,
			"got", clientData.Challenge,
		)
		return nil, ErrChallengeMismatch
	}

	// Verify the operation type
	if clientData.Type != "webauthn.get" {
		s.logger.Warn("WebAuthn login type mismatch", "type", clientData.Type)
		return nil, ErrInvalidWebAuthnData
	}

	// Parse assertion data
	assertion, err := parseAssertionData(authenticatorData, clientDataJSON, signature)
	if err != nil {
		return nil, ErrInvalidWebAuthnData
	}

	// Verify RP ID hash
	rpID := os.Getenv("WEBAUTHN_RP_ID")
	if rpID == "" {
		rpID = "localhost"
	}
	if !assertion.VerifyRPIDHash(rpID) {
		s.logger.Warn("WebAuthn RP ID hash verification failed")
		return nil, ErrInvalidWebAuthnData
	}

	// Verify the cryptographic signature using the stored public key
	if err := assertion.VerifySignature(cred.PublicKey); err != nil {
		s.logger.Warn("WebAuthn signature verification failed", "error", err)
		return nil, ErrSignatureInvalid
	}

	// Check for potential cloned authenticator (sign count should increase)
	if assertion.SignCount > 0 && assertion.SignCount <= cred.SignCount {
		s.logger.Warn("WebAuthn potential cloned authenticator detected",
			"stored_count", cred.SignCount,
			"received_count", assertion.SignCount,
		)
		// Set clone warning but allow login (user should be notified)
		cred.CloneWarning = true
	}

	// Update sign count
	if err := s.storage.UpdateWebAuthnCredentialSignCount(ctx, credentialID, assertion.SignCount); err != nil {
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

// clientData represents the parsed clientDataJSON from WebAuthn.
type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

// parseClientDataJSON parses the clientDataJSON from WebAuthn.
func parseClientDataJSON(data []byte) (*clientData, error) {
	var cd clientData
	if err := json.Unmarshal(data, &cd); err != nil {
		return nil, fmt.Errorf("failed to parse clientDataJSON: %w", err)
	}
	return &cd, nil
}

// attestationData represents parsed attestation object data.
type attestationData struct {
	Format            string
	AuthenticatorData []byte
	PublicKey         []byte
	SignCount         uint32
	RPIDHash          []byte
}

// parseAttestationObject parses the attestation object from WebAuthn registration.
func parseAttestationObject(data []byte) (*attestationData, error) {
	var attestation struct {
		Format   string                 `cbor:"fmt"`
		AttStmt  map[string]interface{} `cbor:"attStmt"`
		AuthData []byte                 `cbor:"authData"`
	}

	if err := cbor.Unmarshal(data, &attestation); err != nil {
		return nil, fmt.Errorf("failed to parse attestation object: %w", err)
	}

	if len(attestation.AuthData) < 37 {
		return nil, fmt.Errorf("authenticator data too short")
	}

	result := &attestationData{
		Format:            attestation.Format,
		AuthenticatorData: attestation.AuthData,
		RPIDHash:          attestation.AuthData[:32],
	}

	// Parse flags (byte 32)
	flags := attestation.AuthData[32]
	// AT flag (bit 6) indicates attested credential data is present
	hasAttestedCredentialData := (flags & 0x40) != 0

	// Sign count is bytes 33-36 (big endian)
	result.SignCount = uint32(attestation.AuthData[33])<<24 |
		uint32(attestation.AuthData[34])<<16 |
		uint32(attestation.AuthData[35])<<8 |
		uint32(attestation.AuthData[36])

	if hasAttestedCredentialData && len(attestation.AuthData) > 55 {
		// Skip AAGUID (16 bytes) and credential ID length (2 bytes) and credential ID
		credentialIDLength := int(attestation.AuthData[53])<<8 | int(attestation.AuthData[54])
		publicKeyStart := 55 + credentialIDLength

		if publicKeyStart < len(attestation.AuthData) {
			// Parse COSE key to extract public key
			publicKeyBytes := attestation.AuthData[publicKeyStart:]
			result.PublicKey = publicKeyBytes
		}
	}

	return result, nil
}

// VerifyRPIDHash verifies the RP ID hash in the authenticator data.
func (a *attestationData) VerifyRPIDHash(rpID string) bool {
	expectedHash := sha256.Sum256([]byte(rpID))
	return bytes.Equal(a.RPIDHash, expectedHash[:])
}

// assertionData represents parsed assertion data for WebAuthn login.
type assertionData struct {
	AuthenticatorData []byte
	ClientDataHash    []byte
	Signature         []byte
	RPIDHash          []byte
	Flags             byte
	SignCount         uint32
}

// parseAssertionData parses the assertion response from WebAuthn login.
func parseAssertionData(authenticatorData, clientDataJSON, signature []byte) (*assertionData, error) {
	if len(authenticatorData) < 37 {
		return nil, fmt.Errorf("authenticator data too short")
	}

	clientDataHash := sha256.Sum256(clientDataJSON)

	result := &assertionData{
		AuthenticatorData: authenticatorData,
		ClientDataHash:    clientDataHash[:],
		Signature:         signature,
		RPIDHash:          authenticatorData[:32],
		Flags:             authenticatorData[32],
	}

	// Sign count is bytes 33-36 (big endian)
	result.SignCount = uint32(authenticatorData[33])<<24 |
		uint32(authenticatorData[34])<<16 |
		uint32(authenticatorData[35])<<8 |
		uint32(authenticatorData[36])

	return result, nil
}

// VerifyRPIDHash verifies the RP ID hash in the assertion.
func (a *assertionData) VerifyRPIDHash(rpID string) bool {
	expectedHash := sha256.Sum256([]byte(rpID))
	return bytes.Equal(a.RPIDHash, expectedHash[:])
}

// VerifySignature verifies the WebAuthn assertion signature using the stored public key.
func (a *assertionData) VerifySignature(publicKeyBytes []byte) error {
	// The signed data is authenticatorData || clientDataHash
	signedData := append(a.AuthenticatorData, a.ClientDataHash...)
	hash := sha256.Sum256(signedData)

	// Parse the COSE key
	pubKey, err := parseCOSEKey(publicKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	switch key := pubKey.(type) {
	case *ecdsa.PublicKey:
		// Parse the ECDSA signature (ASN.1 DER format)
		if !ecdsa.VerifyASN1(key, hash[:], a.Signature) {
			return ErrSignatureInvalid
		}
	case *rsa.PublicKey:
		// RSA PKCS#1 v1.5 signature
		if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], a.Signature); err != nil {
			return ErrSignatureInvalid
		}
	default:
		return fmt.Errorf("unsupported key type")
	}

	return nil
}

// parseCOSEKey parses a COSE encoded public key.
func parseCOSEKey(data []byte) (interface{}, error) {
	var coseKey map[int]interface{}
	if err := cbor.Unmarshal(data, &coseKey); err != nil {
		return nil, fmt.Errorf("failed to unmarshal COSE key: %w", err)
	}

	// Key type (1 = OKP, 2 = EC2, 3 = RSA)
	kty, ok := coseKey[1].(int64)
	if !ok {
		// Try uint64
		if ktyU, ok := coseKey[1].(uint64); ok {
			kty = int64(ktyU)
		} else {
			return nil, fmt.Errorf("invalid key type")
		}
	}

	switch kty {
	case 2: // EC2 (Elliptic Curve)
		return parseEC2Key(coseKey)
	case 3: // RSA
		return parseRSAKey(coseKey)
	default:
		return nil, fmt.Errorf("unsupported key type: %d", kty)
	}
}

// parseEC2Key parses an EC2 COSE key.
func parseEC2Key(coseKey map[int]interface{}) (*ecdsa.PublicKey, error) {
	// Algorithm (-1 = crv, -2 = x, -3 = y)
	xBytes, ok := coseKey[-2].([]byte)
	if !ok {
		return nil, fmt.Errorf("missing x coordinate")
	}
	yBytes, ok := coseKey[-3].([]byte)
	if !ok {
		return nil, fmt.Errorf("missing y coordinate")
	}

	// Construct uncompressed point format (0x04 || x || y)
	pointBytes := append([]byte{0x04}, xBytes...)
	pointBytes = append(pointBytes, yBytes...)

	// Parse using x509
	pubKey, err := x509.ParsePKIXPublicKey(pointBytes)
	if err != nil {
		// Try constructing ECDSA key directly
		curve := getCurveFromCOSE(coseKey)
		if curve == nil {
			return nil, fmt.Errorf("unsupported curve")
		}

		x := new(big.Int).SetBytes(xBytes)
		y := new(big.Int).SetBytes(yBytes)
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	}

	ecKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA key")
	}
	return ecKey, nil
}

// getCurveFromCOSE returns the elliptic curve from COSE key parameters.
func getCurveFromCOSE(coseKey map[int]interface{}) elliptic.Curve {
	crv, ok := coseKey[-1].(int64)
	if !ok {
		if crvU, ok := coseKey[-1].(uint64); ok {
			crv = int64(crvU)
		} else {
			return nil
		}
	}

	switch crv {
	case 1: // P-256
		return elliptic.P256()
	case 2: // P-384
		return elliptic.P384()
	case 3: // P-521
		return elliptic.P521()
	default:
		return nil
	}
}

// parseRSAKey parses an RSA COSE key.
func parseRSAKey(coseKey map[int]interface{}) (*rsa.PublicKey, error) {
	// -1 = n (modulus), -2 = e (exponent)
	nBytes, ok := coseKey[-1].([]byte)
	if !ok {
		return nil, fmt.Errorf("missing modulus")
	}
	eBytes, ok := coseKey[-2].([]byte)
	if !ok {
		return nil, fmt.Errorf("missing exponent")
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}
