-- Migration 000015: Enhancements
-- Adds password history, magic links, session limits, user impersonation, and risk assessment

-- Password history for preventing password reuse
CREATE TABLE IF NOT EXISTS password_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_password_history_user_id ON password_history(user_id);
CREATE INDEX IF NOT EXISTS idx_password_history_created_at ON password_history(created_at);

-- Magic links for passwordless authentication
CREATE TABLE IF NOT EXISTS magic_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_magic_links_token_hash ON magic_links(token_hash);
CREATE INDEX IF NOT EXISTS idx_magic_links_email ON magic_links(email);
CREATE INDEX IF NOT EXISTS idx_magic_links_expires_at ON magic_links(expires_at);

-- Session concurrent limits stored in system_settings (no new table needed)
-- But we need to track active session count per user efficiently

-- User impersonation sessions
CREATE TABLE IF NOT EXISTS impersonation_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    admin_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reason TEXT,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at TIMESTAMPTZ,
    ip_address TEXT,
    user_agent TEXT
);

CREATE INDEX IF NOT EXISTS idx_impersonation_sessions_admin_id ON impersonation_sessions(admin_user_id);
CREATE INDEX IF NOT EXISTS idx_impersonation_sessions_target_id ON impersonation_sessions(target_user_id);
CREATE INDEX IF NOT EXISTS idx_impersonation_sessions_session_id ON impersonation_sessions(session_id);

-- Risk assessment for adaptive authentication
CREATE TABLE IF NOT EXISTS risk_assessments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id UUID REFERENCES sessions(id) ON DELETE SET NULL,
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    risk_level TEXT NOT NULL CHECK (risk_level IN ('low', 'medium', 'high')),
    factors JSONB NOT NULL DEFAULT '{}',
    action_taken TEXT NOT NULL CHECK (action_taken IN ('allowed', 'mfa_required', 'blocked', 'warned')),
    ip_address TEXT,
    user_agent TEXT,
    location_country TEXT,
    location_city TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_risk_assessments_user_id ON risk_assessments(user_id);
CREATE INDEX IF NOT EXISTS idx_risk_assessments_created_at ON risk_assessments(created_at);
CREATE INDEX IF NOT EXISTS idx_risk_assessments_risk_level ON risk_assessments(risk_level);

-- Compromised password check cache (to avoid repeated API calls)
CREATE TABLE IF NOT EXISTS password_breach_cache (
    sha1_prefix TEXT PRIMARY KEY, -- First 5 chars of SHA1 hash
    response_data TEXT NOT NULL,  -- API response
    checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_password_breach_cache_checked_at ON password_breach_cache(checked_at);

-- Additional system settings for new features
INSERT INTO system_settings (key, value, category, is_secret, description) VALUES
    ('max_concurrent_sessions', '5', 'security', false, 'Maximum number of concurrent sessions per user'),
    ('session_limit_action', '"revoke_oldest"', 'security', false, 'Action when session limit exceeded: revoke_oldest, reject_new'),
    ('password_history_depth', '5', 'security', false, 'Number of previous passwords to check against'),
    ('magic_link_expiry_minutes', '15', 'security', false, 'Magic link expiration time in minutes'),
    ('magic_link_rate_limit', '3', 'security', false, 'Maximum magic link requests per email per hour'),
    ('risk_based_auth_enabled', 'false', 'security', false, 'Enable risk-based authentication'),
    ('risk_high_threshold', '70', 'security', false, 'Risk score threshold for high risk (block)'),
    ('risk_medium_threshold', '40', 'security', false, 'Risk score threshold for medium risk (require MFA)'),
    ('compromised_password_check_enabled', 'true', 'security', false, 'Check passwords against known breach databases'),
    ('impersonation_enabled', 'true', 'security', false, 'Allow admin user impersonation'),
    ('impersonation_session_ttl_minutes', '30', 'security', false, 'Impersonation session time-to-live')
ON CONFLICT (key) DO NOTHING;

-- Add new permissions for impersonation
INSERT INTO permissions (id, name, description) VALUES
    (gen_random_uuid(), 'users:impersonate', 'Impersonate other users for support purposes')
ON CONFLICT (name) DO NOTHING;
