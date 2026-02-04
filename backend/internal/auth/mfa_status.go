// Package auth provides authentication services for ModernAuth.
package auth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
	"github.com/iSundram/ModernAuth/internal/utils"
)

// Email MFA code settings
const (
	EmailMFACodeLength = 6
	EmailMFACodeTTL    = 10 * time.Minute
)

// MFAStatus represents the MFA configuration status for a user.
type MFAStatus struct {
	IsEnabled            bool       `json:"is_enabled"`
	Methods              []string   `json:"methods"`
	PreferredMethod      string     `json:"preferred_method"`
	BackupCodesRemaining int        `json:"backup_codes_remaining"`
	TOTPSetupAt          *time.Time `json:"totp_setup_at,omitempty"`
	WebAuthnCredentials  int        `json:"webauthn_credentials"`
}

// GetMFAStatus returns the MFA configuration status for a user.
func (s *AuthService) GetMFAStatus(ctx context.Context, userID uuid.UUID) (*MFAStatus, error) {
	settings, err := s.storage.GetMFASettings(ctx, userID)
	if err != nil {
		return nil, err
	}

	status := &MFAStatus{
		IsEnabled:       false,
		Methods:         []string{},
		PreferredMethod: "totp",
	}

	if settings != nil {
		if settings.IsTOTPEnabled {
			status.Methods = append(status.Methods, "totp")
			status.IsEnabled = true
		}
		if settings.IsEmailMFAEnabled {
			status.Methods = append(status.Methods, "email")
			status.IsEnabled = true
		}
		if settings.IsSMSMFAEnabled {
			status.Methods = append(status.Methods, "sms")
			status.IsEnabled = true
		}
		status.PreferredMethod = settings.PreferredMethod
		status.BackupCodesRemaining = len(settings.BackupCodes)
		status.TOTPSetupAt = settings.TOTPSetupAt
	}

	// Count WebAuthn credentials
	creds, err := s.storage.GetWebAuthnCredentials(ctx, userID)
	if err == nil && len(creds) > 0 {
		status.WebAuthnCredentials = len(creds)
		status.Methods = append(status.Methods, "webauthn")
		status.IsEnabled = true
	}

	return status, nil
}

// EnableEmailMFA enables email-based MFA for a user.
func (s *AuthService) EnableEmailMFA(ctx context.Context, userID uuid.UUID) error {
	// Verify user exists and has verified email
	user, err := s.storage.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}
	if !user.IsEmailVerified {
		return errors.New("email must be verified before enabling email MFA")
	}

	settings, err := s.storage.GetMFASettings(ctx, userID)
	if err != nil {
		return err
	}
	if settings == nil {
		settings = &storage.MFASettings{
			UserID:          userID,
			PreferredMethod: "email",
		}
	}

	settings.IsEmailMFAEnabled = true
	if err := s.storage.UpdateMFASettings(ctx, settings); err != nil {
		return err
	}

	s.logAuditEvent(ctx, &userID, nil, "mfa.email_enabled", nil, nil, nil)
	return nil
}

// DisableEmailMFA disables email-based MFA for a user.
func (s *AuthService) DisableEmailMFA(ctx context.Context, userID uuid.UUID) error {
	settings, err := s.storage.GetMFASettings(ctx, userID)
	if err != nil {
		return err
	}
	if settings == nil {
		return nil
	}

	settings.IsEmailMFAEnabled = false
	// If this was the preferred method, switch to another available method
	if settings.PreferredMethod == "email" {
		if settings.IsTOTPEnabled {
			settings.PreferredMethod = "totp"
		}
	}

	if err := s.storage.UpdateMFASettings(ctx, settings); err != nil {
		return err
	}

	s.logAuditEvent(ctx, &userID, nil, "mfa.email_disabled", nil, nil, nil)
	return nil
}

// SendEmailMFACode sends an MFA verification code to the user's email.
func (s *AuthService) SendEmailMFACode(ctx context.Context, userID uuid.UUID) error {
	user, err := s.storage.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	settings, err := s.storage.GetMFASettings(ctx, userID)
	if err != nil {
		return err
	}
	if settings == nil || !settings.IsEmailMFAEnabled {
		return ErrMFANotSetup
	}

	// Generate a 6-digit code
	code := utils.GenerateNumericCode(EmailMFACodeLength)
	codeHash := utils.HashToken(code)

	// Create MFA challenge
	challenge := &storage.MFAChallenge{
		ID:        uuid.New(),
		UserID:    userID,
		Type:      "email",
		Code:      &codeHash,
		ExpiresAt: time.Now().Add(EmailMFACodeTTL),
		Verified:  false,
		CreatedAt: time.Now(),
	}

	if err := s.storage.CreateMFAChallenge(ctx, challenge); err != nil {
		return err
	}

	// Log that email MFA code was generated (code not logged for security)
	s.logger.Info("Email MFA code generated", "user_id", userID)
	// TODO: Send email with code via email service
	// For now, code is stored in MFA challenge for verification
	s.logAuditEvent(ctx, &userID, nil, "mfa.email_code_sent", nil, nil, nil)
	return nil
}

// LoginWithEmailMFARequest represents a request to login with email MFA.
type LoginWithEmailMFARequest struct {
	UserID      uuid.UUID `json:"user_id"`
	Code        string    `json:"code"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	IP          string    `json:"-"`
	UserAgent   string    `json:"-"`
}

// LoginWithEmailMFA verifies the email MFA code and completes login.
func (s *AuthService) LoginWithEmailMFA(ctx context.Context, req *LoginWithEmailMFARequest) (*LoginResult, error) {
	user, err := s.storage.GetUserByID(ctx, req.UserID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}

	// Get the pending email challenge
	challenge, err := s.storage.GetPendingMFAChallenge(ctx, req.UserID, "email")
	if err != nil {
		return nil, err
	}
	if challenge == nil {
		return nil, ErrChallengeExpired
	}

	// Verify the code
	codeHash := utils.HashToken(req.Code)
	if challenge.Code == nil || *challenge.Code != codeHash {
		s.logAuditEvent(ctx, &user.ID, nil, "login.email_mfa_failed", &req.IP, &req.UserAgent, nil)
		return nil, ErrInvalidMFACode
	}

	// Mark challenge as verified
	if err := s.storage.MarkMFAChallengeVerified(ctx, challenge.ID); err != nil {
		s.logger.Error("Failed to mark challenge verified", "error", err)
	}

	// Create session and tokens
	session, tokenPair, err := s.createSessionAndTokens(ctx, user, req.Fingerprint)
	if err != nil {
		return nil, err
	}

	s.logAuditEvent(ctx, &user.ID, nil, "login.success", &req.IP, &req.UserAgent, map[string]interface{}{
		"method": "email_mfa",
	})

	_ = session
	return &LoginResult{
		User:      user,
		TokenPair: tokenPair,
	}, nil
}

// TrustDeviceForMFA marks a device as trusted for MFA for the specified number of days.
func (s *AuthService) TrustDeviceForMFA(ctx context.Context, userID uuid.UUID, deviceFingerprint string, trustDays int) error {
	// Find the device
	devices, err := s.storage.ListUserDevices(ctx, userID)
	if err != nil {
		return err
	}

	var deviceID *uuid.UUID
	for _, d := range devices {
		if d.DeviceFingerprint != nil && *d.DeviceFingerprint == deviceFingerprint {
			deviceID = &d.ID
			break
		}
	}

	if deviceID == nil {
		return ErrDeviceNotFound
	}

	trustedUntil := time.Now().AddDate(0, 0, trustDays)
	trustToken := utils.GenerateRandomToken(32)

	if err := s.storage.SetDeviceMFATrust(ctx, *deviceID, trustedUntil, trustToken); err != nil {
		return err
	}

	s.logAuditEvent(ctx, &userID, nil, "mfa.device_trusted", nil, nil, map[string]interface{}{
		"device_fingerprint": deviceFingerprint,
		"trust_days":         trustDays,
	})
	return nil
}

// RevokeMFATrust removes MFA trust from a device.
func (s *AuthService) RevokeMFATrust(ctx context.Context, userID uuid.UUID, deviceFingerprint string) error {
	devices, err := s.storage.ListUserDevices(ctx, userID)
	if err != nil {
		return err
	}

	var deviceID *uuid.UUID
	for _, d := range devices {
		if d.DeviceFingerprint != nil && *d.DeviceFingerprint == deviceFingerprint {
			deviceID = &d.ID
			break
		}
	}

	if deviceID == nil {
		return nil // Device not found, nothing to revoke
	}

	if err := s.storage.ClearDeviceMFATrust(ctx, *deviceID); err != nil {
		return err
	}

	s.logAuditEvent(ctx, &userID, nil, "mfa.device_trust_revoked", nil, nil, map[string]interface{}{
		"device_fingerprint": deviceFingerprint,
	})
	return nil
}

// IsDeviceMFATrusted checks if a device is trusted for MFA.
func (s *AuthService) IsDeviceMFATrusted(ctx context.Context, userID uuid.UUID, deviceFingerprint string) (bool, error) {
	if deviceFingerprint == "" {
		return false, nil
	}

	trustedUntil, err := s.storage.GetDeviceMFATrust(ctx, userID, deviceFingerprint)
	if err != nil {
		return false, err
	}

	return trustedUntil != nil && trustedUntil.After(time.Now()), nil
}

// SetPreferredMFAMethod sets the user's preferred MFA method.
func (s *AuthService) SetPreferredMFAMethod(ctx context.Context, userID uuid.UUID, method string) error {
	settings, err := s.storage.GetMFASettings(ctx, userID)
	if err != nil {
		return err
	}
	if settings == nil {
		return ErrMFANotSetup
	}

	// Verify the method is enabled
	switch method {
	case "totp":
		if !settings.IsTOTPEnabled {
			return ErrMFANotSetup
		}
	case "email":
		if !settings.IsEmailMFAEnabled {
			return ErrMFANotSetup
		}
	case "sms":
		if !settings.IsSMSMFAEnabled {
			return ErrMFANotSetup
		}
	case "webauthn":
		creds, err := s.storage.GetWebAuthnCredentials(ctx, userID)
		if err != nil || len(creds) == 0 {
			return ErrMFANotSetup
		}
	default:
		return errors.New("invalid MFA method")
	}

	settings.PreferredMethod = method
	if err := s.storage.UpdateMFASettings(ctx, settings); err != nil {
		return err
	}

	s.logAuditEvent(ctx, &userID, nil, "mfa.preferred_method_changed", nil, nil, map[string]interface{}{
		"method": method,
	})
	return nil
}

// CheckMFAPolicy checks if MFA is required for the user and not yet satisfied.
// Returns true if MFA is required but the device is not trusted.
func (s *AuthService) CheckMFAPolicy(ctx context.Context, userID uuid.UUID, deviceFingerprint string) (bool, error) {
	// Check if user has MFA enabled
	status, err := s.GetMFAStatus(ctx, userID)
	if err != nil {
		return false, err
	}

	// Helper to see if any MFA method is configured
	hasAnyMFA := status != nil && status.IsEnabled

	// Determine whether MFA is required by system or tenant policy.
	mfaRequired := false

	// 1) System-wide policy via settings key "mfa_required"
	if setting, err := s.storage.GetSetting(ctx, "mfa_required"); err == nil && setting != nil {
		if required, ok := setting.Value.(bool); ok && required {
			mfaRequired = true
		}
		if requiredStr, ok := setting.Value.(string); ok && requiredStr == "true" {
			mfaRequired = true
		}
	}

	// 2) Tenant-specific policy via tenant settings.features.mfa_required
	if user, err := s.storage.GetUserByID(ctx, userID); err == nil && user != nil && user.TenantID != nil {
		if tenant, err := s.storage.GetTenantByID(ctx, *user.TenantID); err == nil && tenant != nil {
			if tenant.Settings != nil {
				if featuresRaw, ok := tenant.Settings["features"].(map[string]interface{}); ok {
					if v, ok := featuresRaw["mfa_required"].(bool); ok && v {
						mfaRequired = true
					}
					if vs, ok := featuresRaw["mfa_required"].(string); ok && vs == "true" {
						mfaRequired = true
					}
				}
			}
		}
	}

	// MFA is required if: (1) policy requires it, or (2) user has MFA enabled (they must complete it at login).
	needMFA := mfaRequired || hasAnyMFA
	if !needMFA {
		return false, nil
	}

	// Policy requires MFA but user has none configured.
	if mfaRequired && !hasAnyMFA {
		return true, nil
	}

	// MFA is configured; apply device trust.
	if deviceFingerprint != "" {
		trusted, err := s.IsDeviceMFATrusted(ctx, userID, deviceFingerprint)
		if err != nil {
			s.logger.Error("Failed to check device MFA trust", "error", err)
		}
		if trusted {
			return false, nil // Device is trusted, no MFA needed
		}
	}

	// MFA is required and user has MFA configured, and device is not trusted.
	return true, nil
}

// NotifyLowBackupCodes sends a notification when backup codes are running low.
func (s *AuthService) NotifyLowBackupCodes(ctx context.Context, userID uuid.UUID, remaining int) error {
	settings, err := s.storage.GetMFASettings(ctx, userID)
	if err != nil {
		return err
	}
	if settings == nil {
		return nil
	}

	// Check if we've already notified
	if settings.LowBackupCodesNotified {
		return nil
	}

	// Mark as notified
	settings.LowBackupCodesNotified = true
	if err := s.storage.UpdateMFASettings(ctx, settings); err != nil {
		return err
	}

	// Get user email for notification
	user, err := s.storage.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return err
	}

	// Send email notification via email service
	if s.emailService != nil {
		if emailService, ok := s.emailService.(interface {
			SendLowBackupCodesEmail(context.Context, *storage.User, int) error
		}); ok {
			if err := emailService.SendLowBackupCodesEmail(ctx, user, remaining); err != nil {
				s.logger.Error("Failed to send low backup codes email", "error", err, "user_id", userID, "remaining", remaining)
			}
		}
	}

	s.logger.Warn("User has low backup codes", "user_id", userID, "email", user.Email, "remaining", remaining)

	s.logAuditEvent(ctx, &userID, nil, "mfa.low_backup_codes_warning", nil, nil, map[string]interface{}{
		"remaining": remaining,
	})
	return nil
}
