-- Seed default dynamic settings
-- These settings can be updated via the admin API at runtime

-- Rate Limits
INSERT INTO system_settings (key, value, category, is_secret, description, updated_at)
VALUES 
    ('rate_limit.login', '10', 'security', false, 'Login attempts per 15 minutes', NOW()),
    ('rate_limit.register', '5', 'security', false, 'Registrations per hour', NOW()),
    ('rate_limit.password_reset', '5', 'security', false, 'Password resets per hour', NOW()),
    ('rate_limit.mfa', '10', 'security', false, 'MFA attempts per 15 minutes', NOW()),
    ('rate_limit.magic_link', '3', 'security', false, 'Magic links per hour', NOW()),
    ('rate_limit.export_data', '1', 'security', false, 'Data exports per 24 hours', NOW()),
    ('rate_limit.refresh', '100', 'security', false, 'Token refreshes per 15 minutes', NOW()),
    ('rate_limit.verify_email', '5', 'security', false, 'Email verifications per hour', NOW())
ON CONFLICT (key) DO NOTHING;

-- Lockout Settings
INSERT INTO system_settings (key, value, category, is_secret, description, updated_at)
VALUES 
    ('lockout.max_attempts', '5', 'security', false, 'Failed attempts before lockout', NOW()),
    ('lockout.window_minutes', '15', 'security', false, 'Window for counting failed attempts (minutes)', NOW()),
    ('lockout.duration_minutes', '30', 'security', false, 'Lockout duration (minutes)', NOW()),
    ('session.max_concurrent', '5', 'security', false, 'Max concurrent sessions per user', NOW())
ON CONFLICT (key) DO NOTHING;

-- Token TTLs
INSERT INTO system_settings (key, value, category, is_secret, description, updated_at)
VALUES 
    ('token.access_ttl_minutes', '15', 'auth', false, 'Access token TTL (minutes)', NOW()),
    ('token.refresh_ttl_hours', '168', 'auth', false, 'Refresh token TTL (hours, 168=7 days)', NOW()),
    ('session.ttl_hours', '168', 'auth', false, 'Session TTL (hours)', NOW())
ON CONFLICT (key) DO NOTHING;

-- Password Policy
INSERT INTO system_settings (key, value, category, is_secret, description, updated_at)
VALUES 
    ('password.min_length', '8', 'security', false, 'Minimum password length', NOW()),
    ('password.max_length', '128', 'security', false, 'Maximum password length', NOW()),
    ('password.require_uppercase', 'true', 'security', false, 'Require uppercase letter', NOW()),
    ('password.require_lowercase', 'true', 'security', false, 'Require lowercase letter', NOW()),
    ('password.require_digit', 'true', 'security', false, 'Require digit', NOW()),
    ('password.require_special', 'false', 'security', false, 'Require special character', NOW())
ON CONFLICT (key) DO NOTHING;

-- Feature Toggles
INSERT INTO system_settings (key, value, category, is_secret, description, updated_at)
VALUES 
    ('feature.hibp_enabled', 'false', 'feature', false, 'Enable breached password checking', NOW()),
    ('feature.captcha_enabled', 'false', 'feature', false, 'Enable CAPTCHA on auth endpoints', NOW()),
    ('feature.captcha_provider', '"none"', 'feature', false, 'CAPTCHA provider (none, recaptcha_v2, recaptcha_v3, turnstile)', NOW()),
    ('feature.captcha_min_score', '0.5', 'feature', false, 'reCAPTCHA v3 minimum score', NOW()),
    ('feature.magic_link_enabled', 'true', 'feature', false, 'Enable passwordless magic link login', NOW()),
    ('feature.oauth_enabled', 'true', 'feature', false, 'Enable OAuth social login', NOW()),
    ('feature.email_queue_enabled', 'true', 'feature', false, 'Enable async email queue', NOW()),
    ('feature.email_rate_limit_enabled', 'true', 'feature', false, 'Enable email rate limiting', NOW())
ON CONFLICT (key) DO NOTHING;

-- Email Rate Limits
INSERT INTO system_settings (key, value, category, is_secret, description, updated_at)
VALUES 
    ('email.verification_rate_limit', '3', 'email', false, 'Verification emails per hour', NOW()),
    ('email.password_reset_rate_limit', '5', 'email', false, 'Password reset emails per hour', NOW()),
    ('email.mfa_code_rate_limit', '10', 'email', false, 'MFA code emails per hour', NOW()),
    ('email.login_alert_rate_limit', '10', 'email', false, 'Login alert emails per hour', NOW())
ON CONFLICT (key) DO NOTHING;

-- Branding (if not already set)
INSERT INTO system_settings (key, value, category, is_secret, description, updated_at)
VALUES 
    ('site.name', '"ModernAuth"', 'branding', false, 'Application name', NOW()),
    ('site.logo_url', '""', 'branding', false, 'Logo URL', NOW())
ON CONFLICT (key) DO NOTHING;

-- Authentication settings
INSERT INTO system_settings (key, value, category, is_secret, description, updated_at)
VALUES 
    ('auth.allow_registration', 'true', 'auth', false, 'Allow new user registration', NOW()),
    ('auth.require_email_verification', 'true', 'auth', false, 'Require email verification', NOW()),
    ('auth.mfa_enabled', 'true', 'auth', false, 'Enable MFA globally', NOW())
ON CONFLICT (key) DO NOTHING;
