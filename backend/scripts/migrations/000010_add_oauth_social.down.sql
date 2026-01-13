-- Rollback OAuth2 and social login

DROP INDEX IF EXISTS idx_user_providers_user_id;
DROP INDEX IF EXISTS idx_social_login_states_state_hash;
DROP INDEX IF EXISTS idx_social_providers_tenant_id;
DROP INDEX IF EXISTS idx_oauth_access_tokens_token_hash;
DROP INDEX IF EXISTS idx_oauth_access_tokens_user_id;
DROP INDEX IF EXISTS idx_oauth_access_tokens_client_id;
DROP INDEX IF EXISTS idx_oauth_auth_codes_code_hash;
DROP INDEX IF EXISTS idx_oauth_auth_codes_user_id;
DROP INDEX IF EXISTS idx_oauth_auth_codes_client_id;

-- Remove OAuth permissions
DELETE FROM role_permissions WHERE permission_id IN (
    SELECT id FROM permissions WHERE name IN ('oauth:read', 'oauth:write', 'social:manage')
);
DELETE FROM permissions WHERE name IN ('oauth:read', 'oauth:write', 'social:manage');

DROP TABLE IF EXISTS social_login_states;
DROP TABLE IF EXISTS social_providers;
DROP TABLE IF EXISTS oauth_access_tokens;
DROP TABLE IF EXISTS oauth_authorization_codes;

-- Revert user_providers changes
ALTER TABLE user_providers DROP COLUMN IF EXISTS updated_at;
ALTER TABLE user_providers DROP COLUMN IF EXISTS profile_data;
ALTER TABLE user_providers DROP COLUMN IF EXISTS token_expires_at;
ALTER TABLE user_providers DROP COLUMN IF EXISTS refresh_token_encrypted;
ALTER TABLE user_providers DROP COLUMN IF EXISTS access_token_encrypted;
