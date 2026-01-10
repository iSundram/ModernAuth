-- RBAC (Role-Based Access Control) Schema
-- This script adds roles and permissions support

-- roles table
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- permissions table
CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- role_permissions (many-to-many)
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- user_roles (many-to-many)
CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    assigned_by UUID REFERENCES users(id),
    PRIMARY KEY (user_id, role_id)
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id);

-- Insert default roles
INSERT INTO roles (id, name, description) VALUES 
    ('00000000-0000-0000-0000-000000000001', 'admin', 'Full system access'),
    ('00000000-0000-0000-0000-000000000002', 'user', 'Standard user access')
ON CONFLICT (name) DO NOTHING;

-- Insert default permissions
INSERT INTO permissions (id, name, description) VALUES 
    ('00000000-0000-0000-0000-000000000001', 'users:read', 'View users'),
    ('00000000-0000-0000-0000-000000000002', 'users:write', 'Create/update users'),
    ('00000000-0000-0000-0000-000000000003', 'users:delete', 'Delete users'),
    ('00000000-0000-0000-0000-000000000004', 'audit:read', 'View audit logs'),
    ('00000000-0000-0000-0000-000000000005', 'admin:access', 'Access admin endpoints'),
    ('00000000-0000-0000-0000-000000000006', 'roles:manage', 'Manage roles and permissions')
ON CONFLICT (name) DO NOTHING;

-- Assign all permissions to admin role
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000001', id FROM permissions
ON CONFLICT DO NOTHING;

-- Assign basic permissions to user role (only users:read for self)
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000001')
ON CONFLICT DO NOTHING;
