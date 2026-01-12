-- Rollback enhanced user profiles

DROP INDEX IF EXISTS idx_users_last_login_at;
DROP INDEX IF EXISTS idx_users_is_active;
DROP INDEX IF EXISTS idx_password_history_user_id;
DROP INDEX IF EXISTS idx_user_invitations_email;
DROP INDEX IF EXISTS idx_user_invitations_token_hash;
DROP INDEX IF EXISTS idx_user_invitations_tenant_id;
DROP INDEX IF EXISTS idx_user_group_members_group_id;
DROP INDEX IF EXISTS idx_user_group_members_user_id;
DROP INDEX IF EXISTS idx_user_groups_tenant_id;

DROP TABLE IF EXISTS password_history;
DROP TABLE IF EXISTS user_invitations;
DROP TABLE IF EXISTS group_roles;
DROP TABLE IF EXISTS user_group_members;
DROP TABLE IF EXISTS user_groups;

ALTER TABLE users DROP COLUMN IF EXISTS password_changed_at;
ALTER TABLE users DROP COLUMN IF EXISTS last_login_at;
ALTER TABLE users DROP COLUMN IF EXISTS is_active;
ALTER TABLE users DROP COLUMN IF EXISTS metadata;
ALTER TABLE users DROP COLUMN IF EXISTS locale;
ALTER TABLE users DROP COLUMN IF EXISTS timezone;
ALTER TABLE users DROP COLUMN IF EXISTS avatar_url;
ALTER TABLE users DROP COLUMN IF EXISTS last_name;
ALTER TABLE users DROP COLUMN IF EXISTS first_name;
