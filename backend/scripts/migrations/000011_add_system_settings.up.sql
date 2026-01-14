CREATE TABLE IF NOT EXISTS system_settings (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL,
    category TEXT NOT NULL,
    is_secret BOOLEAN DEFAULT FALSE,
    description TEXT,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Trigger to update updated_at
CREATE OR REPLACE FUNCTION update_system_settings_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_system_settings_updated_at
    BEFORE UPDATE ON system_settings
    FOR EACH ROW
    EXECUTE FUNCTION update_system_settings_updated_at();

-- Insert initial default settings
INSERT INTO system_settings (key, value, category, is_secret, description) VALUES
('auth.allow_registration', 'true', 'authentication', false, 'Allow new users to create accounts'),
('auth.require_email_verification', 'false', 'authentication', false, 'Require users to verify email before logging in'),
('auth.mfa_enabled', 'true', 'authentication', false, 'Global toggle for MFA features'),
('email.provider', '"console"', 'email', false, 'Email delivery provider (console, smtp)'),
('email.from_name', '"ModernAuth"', 'email', false, 'Name used in outgoing emails'),
('email.from_email', '"noreply@modernauth.local"', 'email', false, 'Email address used in outgoing emails'),
('email.smtp_host', '""', 'email', false, 'SMTP server host'),
('email.smtp_port', '587', 'email', false, 'SMTP server port'),
('email.smtp_user', '""', 'email', false, 'SMTP server username'),
('email.smtp_password', '""', 'email', true, 'SMTP server password'),
('site.name', '"ModernAuth"', 'branding', false, 'The name of your application'),
('site.logo_url', '""', 'branding', false, 'URL to your custom logo')
ON CONFLICT (key) DO NOTHING;
