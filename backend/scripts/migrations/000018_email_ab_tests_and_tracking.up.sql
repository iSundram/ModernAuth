-- Email A/B Testing
CREATE TABLE IF NOT EXISTS email_ab_tests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    template_type TEXT NOT NULL,
    name TEXT NOT NULL,
    variant_a TEXT NOT NULL, -- Template ID or content for variant A
    variant_b TEXT NOT NULL, -- Template ID or content for variant B
    weight_a DECIMAL(5,2) DEFAULT 50.0, -- Percentage weight for variant A (0-100)
    weight_b DECIMAL(5,2) DEFAULT 50.0, -- Percentage weight for variant B (0-100)
    is_active BOOLEAN DEFAULT true,
    start_date TEXT, -- Optional start date
    end_date TEXT, -- Optional end date
    winner_variant TEXT, -- 'a' or 'b' when test is concluded
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_email_ab_tests_tenant ON email_ab_tests(tenant_id);
CREATE INDEX idx_email_ab_tests_template ON email_ab_tests(template_type);
CREATE INDEX idx_email_ab_tests_active ON email_ab_tests(is_active);

-- Email A/B Test Results (for tracking which variant was sent to whom)
CREATE TABLE IF NOT EXISTS email_ab_test_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ab_test_id UUID NOT NULL REFERENCES email_ab_tests(id) ON DELETE CASCADE,
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    variant TEXT NOT NULL, -- 'a' or 'b'
    recipient TEXT NOT NULL,
    template_type TEXT NOT NULL,
    event_type TEXT NOT NULL, -- 'sent', 'delivered', 'opened', 'clicked'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_email_ab_test_results_test ON email_ab_test_results(ab_test_id);
CREATE INDEX idx_email_ab_test_results_variant ON email_ab_test_results(ab_test_id, variant);
CREATE INDEX idx_email_ab_test_results_recipient ON email_ab_test_results(recipient);

-- Email Advanced Branding (extends email_branding with additional settings)
CREATE TABLE IF NOT EXISTS email_branding_advanced (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID UNIQUE REFERENCES tenants(id) ON DELETE CASCADE,
    social_links JSONB, -- {"facebook": "...", "twitter": "...", etc.}
    custom_css TEXT,
    header_image_url TEXT,
    font_family TEXT,
    font_family_url TEXT, -- URL to load custom font
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_email_branding_advanced_tenant ON email_branding_advanced(tenant_id);

-- Email Tracking Pixels for open tracking
CREATE TABLE IF NOT EXISTS email_tracking_pixels (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email_job_id UUID, -- Reference to the email job
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    recipient TEXT NOT NULL,
    template_id TEXT NOT NULL, -- Template type
    url TEXT NOT NULL, -- Full URL of the tracking pixel
    is_opened BOOLEAN DEFAULT false,
    opened_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_email_tracking_pixels_job ON email_tracking_pixels(email_job_id);
CREATE INDEX idx_email_tracking_pixels_tenant ON email_tracking_pixels(tenant_id);
CREATE INDEX idx_email_tracking_pixels_recipient ON email_tracking_pixels(recipient);
CREATE INDEX idx_email_tracking_pixels_opened ON email_tracking_pixels(is_opened);

-- Insert default global advanced branding (tenant_id = NULL means global default)
INSERT INTO email_branding_advanced (id, tenant_id, social_links, custom_css, header_image_url, font_family, font_family_url)
VALUES (
    '00000000-0000-0000-0000-000000000002',
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
) ON CONFLICT DO NOTHING;
