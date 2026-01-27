-- Rollback MFA Enhancements

-- Remove WebAuthn credentials table
DROP TABLE IF EXISTS webauthn_credentials;

-- Remove MFA settings columns
ALTER TABLE user_mfa_settings DROP COLUMN IF EXISTS is_email_mfa_enabled;
ALTER TABLE user_mfa_settings DROP COLUMN IF EXISTS is_sms_mfa_enabled;
ALTER TABLE user_mfa_settings DROP COLUMN IF EXISTS preferred_method;
ALTER TABLE user_mfa_settings DROP COLUMN IF EXISTS totp_setup_at;
ALTER TABLE user_mfa_settings DROP COLUMN IF EXISTS low_backup_codes_notified;

-- Remove device MFA trust columns
ALTER TABLE user_devices DROP COLUMN IF EXISTS mfa_trusted_until;
ALTER TABLE user_devices DROP COLUMN IF EXISTS mfa_trust_token;

-- Remove tenant MFA columns
ALTER TABLE tenants DROP COLUMN IF EXISTS mfa_required;
ALTER TABLE tenants DROP COLUMN IF EXISTS mfa_methods;

-- Remove system settings
DELETE FROM system_settings WHERE key IN ('mfa_required', 'mfa_methods');

-- Remove indexes (automatically dropped with tables/columns)
