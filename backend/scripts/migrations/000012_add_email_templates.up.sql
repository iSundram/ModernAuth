-- Email Templates Schema
-- Supports customizable email templates per tenant with branding

-- email_templates table - stores customizable templates
CREATE TABLE IF NOT EXISTS email_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    subject TEXT NOT NULL,
    html_body TEXT NOT NULL,
    text_body TEXT,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    UNIQUE(tenant_id, type)
);

-- email_branding table - stores branding settings per tenant
CREATE TABLE IF NOT EXISTS email_branding (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID UNIQUE REFERENCES tenants(id) ON DELETE CASCADE,
    app_name TEXT NOT NULL DEFAULT 'ModernAuth',
    logo_url TEXT,
    primary_color TEXT DEFAULT '#667eea',
    secondary_color TEXT DEFAULT '#764ba2',
    company_name TEXT,
    support_email TEXT,
    footer_text TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_email_templates_tenant_id ON email_templates(tenant_id);
CREATE INDEX IF NOT EXISTS idx_email_templates_type ON email_templates(type);
CREATE INDEX IF NOT EXISTS idx_email_branding_tenant_id ON email_branding(tenant_id);

-- Insert default global branding (tenant_id = NULL means global default)
INSERT INTO email_branding (id, tenant_id, app_name, company_name, support_email, footer_text)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    NULL,
    'ModernAuth',
    'ModernAuth',
    'support@modernauth.local',
    '© {{.CurrentYear}} {{.CompanyName}}. All rights reserved.'
) ON CONFLICT DO NOTHING;
