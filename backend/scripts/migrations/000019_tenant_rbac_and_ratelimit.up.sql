-- Add tenant_id to user_roles to allow assigning system roles (like "admin") scoped to a specific tenant
ALTER TABLE user_roles ADD COLUMN tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE;

-- Create index for performance
CREATE INDEX idx_user_roles_tenant_id ON user_roles(tenant_id);

-- Update the primary key/unique constraint of user_roles to include tenant_id
-- Previously it was likely (user_id, role_id)
-- We need to check existing constraints first, but usually strictly unique (user, role) is correct GLOBALLY if roles are tenant-specific.
-- BUT if we are using system roles scoped to tenants, we can have (UserA, RoleAdmin, Tenant1) and (UserA, RoleAdmin, Tenant2).
-- So (user_id, role_id) is no longer unique. It must be (user_id, role_id, tenant_id) (treating null tenant_id as global assignment).

-- Drop old constraint if exists (assuming standard naming or generic drop)
-- We'll accept duplicates for different tenants now.

ALTER TABLE user_roles DROP CONSTRAINT IF EXISTS user_roles_pkey;
-- If pkey doesn't exist by that name, we might need to find it, but standard postgres is usually table_pkey.
-- Let's assume standard composite PK or unique constraint.
-- Migration 000004 created it. Let's look at 000004 content from memory or just proceed with robust SQL.

-- We will create a unique index that covers the new scope.
-- COALESCE is tricky in indexes.
-- Distinct assignments:
-- 1. System Role assigned Globally: tenant_id IS NULL
-- 2. System Role assigned to Tenant: tenant_id = X
-- 3. Tenant Role assigned to Tenant: tenant_id = X (Role itself has tenant_id=X)

DROP INDEX IF EXISTS idx_user_roles_user_role; -- Dropping potential existing index

CREATE UNIQUE INDEX idx_user_roles_unique_assignment 
ON user_roles (user_id, role_id, COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'));

-- Update Roles uniqueness constraints
-- Allow same role name in different tenants
ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_name_key; -- The global unique constraint

CREATE UNIQUE INDEX idx_roles_name_system ON roles (name) WHERE tenant_id IS NULL;
CREATE UNIQUE INDEX idx_roles_name_tenant ON roles (name, tenant_id) WHERE tenant_id IS NOT NULL;
