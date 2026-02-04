package pg

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/iSundram/ModernAuth/internal/storage"
)

// GetMFASettings retrieves MFA settings for a user.
func (s *PostgresStorage) GetMFASettings(ctx context.Context, userID uuid.UUID) (*storage.MFASettings, error) {
	query := `
		SELECT user_id, totp_secret, is_totp_enabled, backup_codes, updated_at,
		       COALESCE(is_email_mfa_enabled, false), COALESCE(is_sms_mfa_enabled, false),
		       COALESCE(preferred_method, 'totp'), totp_setup_at, COALESCE(low_backup_codes_notified, false)
		FROM user_mfa_settings
		WHERE user_id = $1
	`
	settings := &storage.MFASettings{}
	err := s.pool.QueryRow(ctx, query, userID).Scan(
		&settings.UserID,
		&settings.TOTPSecret,
		&settings.IsTOTPEnabled,
		&settings.BackupCodes,
		&settings.UpdatedAt,
		&settings.IsEmailMFAEnabled,
		&settings.IsSMSMFAEnabled,
		&settings.PreferredMethod,
		&settings.TOTPSetupAt,
		&settings.LowBackupCodesNotified,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return settings, nil
}

// UpdateMFASettings updates or creates MFA settings for a user.
func (s *PostgresStorage) UpdateMFASettings(ctx context.Context, settings *storage.MFASettings) error {
	query := `
		INSERT INTO user_mfa_settings (user_id, totp_secret, is_totp_enabled, backup_codes, updated_at,
		                               is_email_mfa_enabled, is_sms_mfa_enabled, preferred_method, 
		                               totp_setup_at, low_backup_codes_notified)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (user_id) DO UPDATE
		SET totp_secret = $2, is_totp_enabled = $3, backup_codes = $4, updated_at = $5,
		    is_email_mfa_enabled = $6, is_sms_mfa_enabled = $7, preferred_method = $8,
		    totp_setup_at = $9, low_backup_codes_notified = $10
	`
	settings.UpdatedAt = time.Now()
	_, err := s.pool.Exec(ctx, query,
		settings.UserID,
		settings.TOTPSecret,
		settings.IsTOTPEnabled,
		settings.BackupCodes,
		settings.UpdatedAt,
		settings.IsEmailMFAEnabled,
		settings.IsSMSMFAEnabled,
		settings.PreferredMethod,
		settings.TOTPSetupAt,
		settings.LowBackupCodesNotified,
	)
	return err
}

// CreateMFAChallenge creates a new MFA challenge.
func (s *PostgresStorage) CreateMFAChallenge(ctx context.Context, challenge *storage.MFAChallenge) error {
	query := `
		INSERT INTO mfa_challenges (id, user_id, session_id, type, code, expires_at, verified, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := s.pool.Exec(ctx, query,
		challenge.ID,
		challenge.UserID,
		challenge.SessionID,
		challenge.Type,
		challenge.Code,
		challenge.ExpiresAt,
		challenge.Verified,
		challenge.CreatedAt,
	)
	return err
}

// GetMFAChallenge retrieves an MFA challenge by ID.
func (s *PostgresStorage) GetMFAChallenge(ctx context.Context, id uuid.UUID) (*storage.MFAChallenge, error) {
	query := `
		SELECT id, user_id, session_id, type, code, expires_at, verified, created_at
		FROM mfa_challenges
		WHERE id = $1
	`
	challenge := &storage.MFAChallenge{}
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&challenge.ID,
		&challenge.UserID,
		&challenge.SessionID,
		&challenge.Type,
		&challenge.Code,
		&challenge.ExpiresAt,
		&challenge.Verified,
		&challenge.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return challenge, nil
}

// GetPendingMFAChallenge gets the latest pending (non-expired, non-verified) challenge.
func (s *PostgresStorage) GetPendingMFAChallenge(ctx context.Context, userID uuid.UUID, challengeType string) (*storage.MFAChallenge, error) {
	query := `
		SELECT id, user_id, session_id, type, code, expires_at, verified, created_at
		FROM mfa_challenges
		WHERE user_id = $1 AND type = $2 AND verified = false AND expires_at > now()
		ORDER BY created_at DESC
		LIMIT 1
	`
	challenge := &storage.MFAChallenge{}
	err := s.pool.QueryRow(ctx, query, userID, challengeType).Scan(
		&challenge.ID,
		&challenge.UserID,
		&challenge.SessionID,
		&challenge.Type,
		&challenge.Code,
		&challenge.ExpiresAt,
		&challenge.Verified,
		&challenge.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return challenge, nil
}

// MarkMFAChallengeVerified marks a challenge as verified.
func (s *PostgresStorage) MarkMFAChallengeVerified(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE mfa_challenges SET verified = true WHERE id = $1`
	_, err := s.pool.Exec(ctx, query, id)
	return err
}

// DeleteExpiredMFAChallenges removes expired challenges.
func (s *PostgresStorage) DeleteExpiredMFAChallenges(ctx context.Context) error {
	query := `DELETE FROM mfa_challenges WHERE expires_at < now()`
	_, err := s.pool.Exec(ctx, query)
	return err
}

// CreateWebAuthnCredential stores a new WebAuthn credential.
func (s *PostgresStorage) CreateWebAuthnCredential(ctx context.Context, cred *storage.WebAuthnCredential) error {
	query := `
		INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, attestation_type,
		                                  transport, aaguid, sign_count, clone_warning, name, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`
	_, err := s.pool.Exec(ctx, query,
		cred.ID,
		cred.UserID,
		cred.CredentialID,
		cred.PublicKey,
		cred.AttestationType,
		cred.Transport,
		cred.AAGUID,
		cred.SignCount,
		cred.CloneWarning,
		cred.Name,
		cred.CreatedAt,
	)
	return err
}

// GetWebAuthnCredentials retrieves all WebAuthn credentials for a user.
func (s *PostgresStorage) GetWebAuthnCredentials(ctx context.Context, userID uuid.UUID) ([]*storage.WebAuthnCredential, error) {
	query := `
		SELECT id, user_id, credential_id, public_key, attestation_type, transport, aaguid,
		       sign_count, clone_warning, name, created_at, last_used_at
		FROM webauthn_credentials
		WHERE user_id = $1
		ORDER BY created_at DESC
	`
	rows, err := s.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []*storage.WebAuthnCredential
	for rows.Next() {
		cred := &storage.WebAuthnCredential{}
		err := rows.Scan(
			&cred.ID,
			&cred.UserID,
			&cred.CredentialID,
			&cred.PublicKey,
			&cred.AttestationType,
			&cred.Transport,
			&cred.AAGUID,
			&cred.SignCount,
			&cred.CloneWarning,
			&cred.Name,
			&cred.CreatedAt,
			&cred.LastUsedAt,
		)
		if err != nil {
			return nil, err
		}
		creds = append(creds, cred)
	}
	return creds, nil
}

// GetWebAuthnCredentialByID retrieves a credential by its credential ID.
func (s *PostgresStorage) GetWebAuthnCredentialByID(ctx context.Context, credentialID []byte) (*storage.WebAuthnCredential, error) {
	query := `
		SELECT id, user_id, credential_id, public_key, attestation_type, transport, aaguid,
		       sign_count, clone_warning, name, created_at, last_used_at
		FROM webauthn_credentials
		WHERE credential_id = $1
	`
	cred := &storage.WebAuthnCredential{}
	err := s.pool.QueryRow(ctx, query, credentialID).Scan(
		&cred.ID,
		&cred.UserID,
		&cred.CredentialID,
		&cred.PublicKey,
		&cred.AttestationType,
		&cred.Transport,
		&cred.AAGUID,
		&cred.SignCount,
		&cred.CloneWarning,
		&cred.Name,
		&cred.CreatedAt,
		&cred.LastUsedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return cred, nil
}

// UpdateWebAuthnCredentialSignCount updates the sign count after authentication.
func (s *PostgresStorage) UpdateWebAuthnCredentialSignCount(ctx context.Context, credentialID []byte, signCount uint32) error {
	query := `UPDATE webauthn_credentials SET sign_count = $2, last_used_at = now() WHERE credential_id = $1`
	_, err := s.pool.Exec(ctx, query, credentialID, signCount)
	return err
}

// DeleteWebAuthnCredential removes a WebAuthn credential.
func (s *PostgresStorage) DeleteWebAuthnCredential(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM webauthn_credentials WHERE id = $1`
	_, err := s.pool.Exec(ctx, query, id)
	return err
}

// SetDeviceMFATrust marks a device as MFA-trusted until the specified time.
func (s *PostgresStorage) SetDeviceMFATrust(ctx context.Context, deviceID uuid.UUID, trustedUntil time.Time, trustToken string) error {
	query := `UPDATE user_devices SET mfa_trusted_until = $2, mfa_trust_token = $3 WHERE id = $1`
	_, err := s.pool.Exec(ctx, query, deviceID, trustedUntil, trustToken)
	return err
}

// ClearDeviceMFATrust removes MFA trust from a device.
func (s *PostgresStorage) ClearDeviceMFATrust(ctx context.Context, deviceID uuid.UUID) error {
	query := `UPDATE user_devices SET mfa_trusted_until = NULL, mfa_trust_token = NULL WHERE id = $1`
	_, err := s.pool.Exec(ctx, query, deviceID)
	return err
}

// GetDeviceMFATrust checks if a device is MFA-trusted for a user.
func (s *PostgresStorage) GetDeviceMFATrust(ctx context.Context, userID uuid.UUID, deviceFingerprint string) (*time.Time, error) {
	query := `
		SELECT mfa_trusted_until
		FROM user_devices
		WHERE user_id = $1 AND device_fingerprint = $2 AND mfa_trusted_until > now()
	`
	var trustedUntil *time.Time
	err := s.pool.QueryRow(ctx, query, userID, deviceFingerprint).Scan(&trustedUntil)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return trustedUntil, nil
}
