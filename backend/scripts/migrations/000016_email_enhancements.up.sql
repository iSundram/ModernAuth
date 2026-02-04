-- Email Template Version History for tracking changes
CREATE TABLE IF NOT EXISTS email_template_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    template_id UUID NOT NULL,
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    template_type TEXT NOT NULL,
    version INT NOT NULL,
    subject TEXT NOT NULL,
    html_body TEXT NOT NULL,
    text_body TEXT,
    changed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    change_reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_template_versions_template_id ON email_template_versions(template_id);
CREATE INDEX idx_template_versions_tenant_type ON email_template_versions(tenant_id, template_type);

-- Email Bounces for tracking delivery failures
CREATE TABLE IF NOT EXISTS email_bounces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    bounce_type TEXT NOT NULL, -- 'hard', 'soft', 'complaint', 'unsubscribe'
    bounce_subtype TEXT, -- 'general', 'no_email', 'suppressed', etc.
    event_id TEXT, -- ID from email provider (SendGrid)
    template_type TEXT, -- Which template caused the bounce
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_email_bounces_email ON email_bounces(email);
CREATE INDEX idx_email_bounces_tenant ON email_bounces(tenant_id);
CREATE INDEX idx_email_bounces_type ON email_bounces(bounce_type);

-- Email Events for analytics (sent, delivered, opened, clicked)
CREATE TABLE IF NOT EXISTS email_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    job_id TEXT, -- Reference to the email job
    template_type TEXT NOT NULL,
    event_type TEXT NOT NULL, -- 'sent', 'delivered', 'opened', 'clicked', 'bounced', 'dropped'
    recipient TEXT NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    metadata JSONB,
    event_id TEXT, -- ID from email provider
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_email_events_tenant ON email_events(tenant_id);
CREATE INDEX idx_email_events_template ON email_events(template_type);
CREATE INDEX idx_email_events_type ON email_events(event_type);
CREATE INDEX idx_email_events_recipient ON email_events(recipient);
CREATE INDEX idx_email_events_created ON email_events(created_at);

-- Suppression List for emails that should not receive emails
CREATE TABLE IF NOT EXISTS email_suppressions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    reason TEXT NOT NULL, -- 'hard_bounce', 'complaint', 'unsubscribe', 'manual'
    source TEXT, -- 'sendgrid_webhook', 'admin', 'user_request'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(tenant_id, email)
);

CREATE INDEX idx_email_suppressions_email ON email_suppressions(email);
CREATE INDEX idx_email_suppressions_tenant ON email_suppressions(tenant_id);
