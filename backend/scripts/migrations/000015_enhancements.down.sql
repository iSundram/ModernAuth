-- Migration 000015: Rollback enhancements

-- Remove permissions
DELETE FROM permissions WHERE name = 'users:impersonate';

-- Remove system settings
DELETE FROM system_settings WHERE key IN (
    'max_concurrent_sessions',
    'session_limit_action', 
    'password_history_depth',
    'magic_link_expiry_minutes',
    'magic_link_rate_limit',
    'risk_based_auth_enabled',
    'risk_high_threshold',
    'risk_medium_threshold',
    'compromised_password_check_enabled',
    'impersonation_enabled',
    'impersonation_session_ttl_minutes'
);

-- Drop tables
DROP TABLE IF EXISTS password_breach_cache;
DROP TABLE IF EXISTS risk_assessments;
DROP TABLE IF EXISTS impersonation_sessions;
DROP TABLE IF EXISTS magic_links;
DROP TABLE IF EXISTS password_history;
