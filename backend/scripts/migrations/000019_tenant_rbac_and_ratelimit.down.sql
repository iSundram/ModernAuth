-- Revert roles uniqueness to global
DROP INDEX IF EXISTS idx_roles_name_tenant;
DROP INDEX IF EXISTS idx_roles_name_system;
ALTER TABLE roles ADD CONSTRAINT roles_name_key UNIQUE (name);

-- Revert user_roles changes
DROP INDEX IF EXISTS idx_user_roles_unique_assignment;
ALTER TABLE user_roles DROP COLUMN IF EXISTS tenant_id;

-- Re-add global primary key or unique constraint if needed
-- We can't easily restore the exact state if data violates it, but we can try to add the constraint back.
-- ALTER TABLE user_roles ADD PRIMARY KEY (user_id, role_id);
