-- Rollback multi-tenancy

DROP VIEW IF EXISTS tenant_members;
DROP TABLE IF EXISTS tenant_invitations;

-- Remove tenant_id from tables
ALTER TABLE audit_logs DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE sessions DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE roles DROP COLUMN IF EXISTS is_system;
ALTER TABLE roles DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE users DROP COLUMN IF EXISTS tenant_id;

DROP TABLE IF EXISTS tenants;
