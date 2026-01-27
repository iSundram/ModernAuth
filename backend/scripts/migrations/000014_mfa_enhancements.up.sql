-- MFA Enhancements Migration
-- Adds support for: Email MFA, SMS MFA, WebAuthn, Device MFA Trust, MFA Policy

-- Add MFA policy settings to tenants
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS mfa_required BOOLEAN DEFAULT false;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS mfa_methods TEXT[] DEFAULT ARRAY['totp'];

-- Add MFA trust to devices (skip MFA for trusted devices)
ALTER TABLE user_devices ADD COLUMN IF NOT EXISTS mfa_trusted_until TIMESTAMP WITH TIME ZONE;
ALTER TABLE user_devices ADD COLUMN IF NOT EXISTS mfa_trust_token TEXT;

-- Enhance MFA settings for multiple methods
ALTER TABLE user_mfa_settings ADD COLUMN IF NOT EXISTS is_email_mfa_enabled BOOLEAN DEFAULT false;
ALTER TABLE user_mfa_settings ADD COLUMN IF NOT EXISTS is_sms_mfa_enabled BOOLEAN DEFAULT false;
ALTER TABLE user_mfa_settings ADD COLUMN IF NOT EXISTS preferred_method TEXT DEFAULT 'totp';
ALTER TABLE user_mfa_settings ADD COLUMN IF NOT EXISTS totp_setup_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE user_mfa_settings ADD COLUMN IF NOT EXISTS low_backup_codes_notified BOOLEAN DEFAULT false;

-- WebAuthn credentials table
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL UNIQUE,
    public_key BYTEA NOT NULL,
    attestation_type TEXT,
    transport TEXT[],
    aaguid BYTEA,
    sign_count INTEGER DEFAULT 0,
    clone_warning BOOLEAN DEFAULT false,
    name TEXT,  -- User-friendly name like "YubiKey 5"
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    last_used_at TIMESTAMP WITH TIME ZONE
);

-- Add SMS phone number to users (if not already captured by phone field)
-- The existing 'phone' column in users table will be used

-- Add system setting for global MFA policy
INSERT INTO system_settings (key, value, description, updated_at)
VALUES ('mfa_required', 'false', 'Require MFA for all users', now())
ON CONFLICT (key) DO NOTHING;

INSERT INTO system_settings (key, value, description, updated_at)
VALUES ('mfa_methods', '["totp","email","webauthn"]', 'Allowed MFA methods', now())
ON CONFLICT (key) DO NOTHING;

-- Indexes
CREATE INDEX IF NOT EXISTS idx_webauthn_user_id ON webauthn_credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_credential_id ON webauthn_credentials(credential_id);
CREATE INDEX IF NOT EXISTS idx_user_devices_mfa_trust ON user_devices(user_id, mfa_trusted_until) WHERE mfa_trusted_until IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_user_type ON mfa_challenges(user_id, type);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_expires ON mfa_challenges(expires_at);
