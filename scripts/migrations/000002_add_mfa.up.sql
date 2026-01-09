-- Add MFA support tables

-- user_mfa_settings
CREATE TABLE IF NOT EXISTS user_mfa_settings (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    totp_secret TEXT,
    is_totp_enabled BOOLEAN DEFAULT false,
    backup_codes TEXT[],
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- mfa_challenge
CREATE TABLE IF NOT EXISTS mfa_challenges (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    session_id UUID REFERENCES sessions(id) ON DELETE CASCADE,
    type TEXT NOT NULL, -- 'totp', 'email', etc.
    code TEXT, -- for email/sms mfa if implemented later
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    verified BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);
