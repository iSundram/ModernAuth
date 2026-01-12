-- Rollback device and session management

DROP INDEX IF EXISTS idx_blocked_ips_ip;
DROP INDEX IF EXISTS idx_blocked_ips_tenant_id;
DROP INDEX IF EXISTS idx_trusted_ips_user_id;
DROP INDEX IF EXISTS idx_trusted_ips_tenant_id;
DROP INDEX IF EXISTS idx_login_history_ip;
DROP INDEX IF EXISTS idx_login_history_created_at;
DROP INDEX IF EXISTS idx_login_history_user_id;
DROP INDEX IF EXISTS idx_sessions_device_id;
DROP INDEX IF EXISTS idx_user_devices_last_seen;
DROP INDEX IF EXISTS idx_user_devices_fingerprint;
DROP INDEX IF EXISTS idx_user_devices_user_id;

DROP TABLE IF EXISTS blocked_ips;
DROP TABLE IF EXISTS trusted_ips;
DROP TABLE IF EXISTS login_history;

ALTER TABLE sessions DROP COLUMN IF EXISTS device_id;

DROP TABLE IF EXISTS user_devices;
