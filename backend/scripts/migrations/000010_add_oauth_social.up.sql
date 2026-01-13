-- OAuth2 Provider and Social Login
-- This script adds OAuth2 provider capabilities and social login support

-- OAuth2 authorization codes
CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
    id UUID PRIMARY KEY,
    client_id UUID REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL UNIQUE,
    redirect_uri TEXT NOT NULL,
    scope TEXT,
    code_challenge TEXT,  -- PKCE
    code_challenge_method TEXT,  -- plain or S256
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- OAuth2 access tokens (for acting as provider)
CREATE TABLE IF NOT EXISTS oauth_access_tokens (
    id UUID PRIMARY KEY,
    client_id UUID REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    scope TEXT,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Social identity providers configuration
CREATE TABLE IF NOT EXISTS social_providers (
    id UUID PRIMARY KEY,
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,  -- google, github, microsoft, facebook, apple, etc.
    client_id TEXT NOT NULL,
    client_secret_encrypted TEXT NOT NULL,
    scopes TEXT[] DEFAULT '{}',
    additional_params JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    UNIQUE(tenant_id, provider)
);

-- Social login state (CSRF protection)
CREATE TABLE IF NOT EXISTS social_login_states (
    id UUID PRIMARY KEY,
    tenant_id UUID REFERENCES tenants(id),
    provider TEXT NOT NULL,
    state_hash TEXT NOT NULL UNIQUE,
    redirect_uri TEXT,
    code_verifier TEXT,  -- PKCE
    metadata JSONB DEFAULT '{}',
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Enhance user_providers table (already exists from init, adding more fields)
ALTER TABLE user_providers ADD COLUMN IF NOT EXISTS access_token_encrypted TEXT;
ALTER TABLE user_providers ADD COLUMN IF NOT EXISTS refresh_token_encrypted TEXT;
ALTER TABLE user_providers ADD COLUMN IF NOT EXISTS token_expires_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE user_providers ADD COLUMN IF NOT EXISTS profile_data JSONB DEFAULT '{}';
ALTER TABLE user_providers ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT now();

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_oauth_auth_codes_client_id ON oauth_authorization_codes(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_auth_codes_user_id ON oauth_authorization_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_auth_codes_code_hash ON oauth_authorization_codes(code_hash);
CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_client_id ON oauth_access_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_user_id ON oauth_access_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_token_hash ON oauth_access_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_social_providers_tenant_id ON social_providers(tenant_id);
CREATE INDEX IF NOT EXISTS idx_social_login_states_state_hash ON social_login_states(state_hash);
CREATE INDEX IF NOT EXISTS idx_user_providers_user_id ON user_providers(user_id);

-- Insert default OAuth scopes/permissions
INSERT INTO permissions (id, name, description) VALUES 
    ('00000000-0000-0000-0000-000000000010', 'oauth:read', 'Read OAuth client information'),
    ('00000000-0000-0000-0000-000000000011', 'oauth:write', 'Manage OAuth clients'),
    ('00000000-0000-0000-0000-000000000012', 'social:manage', 'Manage social login providers')
ON CONFLICT (name) DO NOTHING;

-- Assign OAuth permissions to admin role
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000001', id FROM permissions WHERE name IN ('oauth:read', 'oauth:write', 'social:manage')
ON CONFLICT DO NOTHING;
