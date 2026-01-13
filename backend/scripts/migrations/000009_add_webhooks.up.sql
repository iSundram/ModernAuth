-- Webhooks System
-- This script adds webhook support for event notifications

-- Webhooks table
CREATE TABLE IF NOT EXISTS webhooks (
    id UUID PRIMARY KEY,
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    url TEXT NOT NULL,
    secret TEXT NOT NULL,  -- For HMAC signature verification
    events TEXT[] NOT NULL,  -- Array of event types to subscribe to
    headers JSONB DEFAULT '{}',  -- Custom headers to send
    is_active BOOLEAN DEFAULT true,
    retry_count INT DEFAULT 3,
    timeout_seconds INT DEFAULT 30,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Webhook deliveries (delivery attempts and status)
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id UUID PRIMARY KEY,
    webhook_id UUID REFERENCES webhooks(id) ON DELETE CASCADE,
    event_id UUID NOT NULL,
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    request_headers JSONB,
    response_status_code INT,
    response_headers JSONB,
    response_body TEXT,
    response_time_ms INT,
    attempt_number INT DEFAULT 1,
    status TEXT NOT NULL,  -- pending, success, failed, retrying
    error_message TEXT,
    next_retry_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    completed_at TIMESTAMP WITH TIME ZONE
);

-- Webhook events log (all events, even if no webhook subscribed)
CREATE TABLE IF NOT EXISTS webhook_events (
    id UUID PRIMARY KEY,
    tenant_id UUID REFERENCES tenants(id),
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_webhooks_tenant_id ON webhooks(tenant_id);
CREATE INDEX IF NOT EXISTS idx_webhooks_is_active ON webhooks(is_active);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook_id ON webhook_deliveries(webhook_id);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_status ON webhook_deliveries(status);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_next_retry ON webhook_deliveries(next_retry_at) WHERE status = 'retrying';
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_created_at ON webhook_deliveries(created_at);
CREATE INDEX IF NOT EXISTS idx_webhook_events_tenant_id ON webhook_events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_webhook_events_event_type ON webhook_events(event_type);
CREATE INDEX IF NOT EXISTS idx_webhook_events_created_at ON webhook_events(created_at);

-- Common webhook event types (as comments for documentation):
-- user.created, user.updated, user.deleted
-- user.login, user.logout, user.login.failed
-- user.password.changed, user.password.reset
-- user.email.verified, user.mfa.enabled, user.mfa.disabled
-- session.created, session.revoked
-- tenant.created, tenant.updated
-- role.assigned, role.removed
-- api_key.created, api_key.revoked
