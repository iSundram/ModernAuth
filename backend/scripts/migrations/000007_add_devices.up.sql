-- Device and Session Management
-- This script adds device tracking and enhanced session management

-- User devices table
CREATE TABLE IF NOT EXISTS user_devices (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    device_fingerprint TEXT,
    device_name TEXT,
    device_type TEXT,  -- mobile, desktop, tablet, unknown
    browser TEXT,
    browser_version TEXT,
    os TEXT,
    os_version TEXT,
    ip_address TEXT,
    location_country TEXT,
    location_city TEXT,
    location_coords TEXT,
    is_trusted BOOLEAN DEFAULT false,
    is_current BOOLEAN DEFAULT false,
    last_seen_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Link sessions to devices
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS device_id UUID REFERENCES user_devices(id);

-- Login history (detailed login tracking)
CREATE TABLE IF NOT EXISTS login_history (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID REFERENCES tenants(id),
    session_id UUID REFERENCES sessions(id),
    device_id UUID REFERENCES user_devices(id),
    ip_address TEXT,
    user_agent TEXT,
    location_country TEXT,
    location_city TEXT,
    login_method TEXT,  -- password, mfa, social, magic_link, api_key
    status TEXT NOT NULL,  -- success, failed, blocked, mfa_required
    failure_reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Trusted IPs for users/tenants
CREATE TABLE IF NOT EXISTS trusted_ips (
    id UUID PRIMARY KEY,
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    ip_address TEXT NOT NULL,
    ip_range TEXT,  -- CIDR notation for ranges
    description TEXT,
    created_by UUID REFERENCES users(id),
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    CHECK (user_id IS NOT NULL OR tenant_id IS NOT NULL)
);

-- Blocked IPs
CREATE TABLE IF NOT EXISTS blocked_ips (
    id UUID PRIMARY KEY,
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    ip_address TEXT NOT NULL,
    ip_range TEXT,
    reason TEXT,
    blocked_by UUID REFERENCES users(id),
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_user_devices_user_id ON user_devices(user_id);
CREATE INDEX IF NOT EXISTS idx_user_devices_fingerprint ON user_devices(device_fingerprint);
CREATE INDEX IF NOT EXISTS idx_user_devices_last_seen ON user_devices(last_seen_at);
CREATE INDEX IF NOT EXISTS idx_sessions_device_id ON sessions(device_id);
CREATE INDEX IF NOT EXISTS idx_login_history_user_id ON login_history(user_id);
CREATE INDEX IF NOT EXISTS idx_login_history_created_at ON login_history(created_at);
CREATE INDEX IF NOT EXISTS idx_login_history_ip ON login_history(ip_address);
CREATE INDEX IF NOT EXISTS idx_trusted_ips_tenant_id ON trusted_ips(tenant_id);
CREATE INDEX IF NOT EXISTS idx_trusted_ips_user_id ON trusted_ips(user_id);
CREATE INDEX IF NOT EXISTS idx_blocked_ips_tenant_id ON blocked_ips(tenant_id);
CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips(ip_address);
