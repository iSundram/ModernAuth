-- Rollback API keys

DROP INDEX IF EXISTS idx_api_key_usage_created_at;
DROP INDEX IF EXISTS idx_api_key_usage_api_key_id;
DROP INDEX IF EXISTS idx_api_keys_is_active;
DROP INDEX IF EXISTS idx_api_keys_key_prefix;
DROP INDEX IF EXISTS idx_api_keys_key_hash;
DROP INDEX IF EXISTS idx_api_keys_user_id;
DROP INDEX IF EXISTS idx_api_keys_tenant_id;

DROP TABLE IF EXISTS api_key_usage;
DROP TABLE IF EXISTS api_keys;
