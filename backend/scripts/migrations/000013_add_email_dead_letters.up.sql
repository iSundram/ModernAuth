-- Dead Letter Queue for failed emails
-- Stores emails that failed after all retries for debugging and manual retry

CREATE TABLE IF NOT EXISTS email_dead_letters (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    job_type TEXT NOT NULL,
    recipient TEXT NOT NULL,
    subject TEXT,
    payload JSONB NOT NULL,
    error_message TEXT NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    failed_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    retried_at TIMESTAMP WITH TIME ZONE,
    resolved BOOLEAN DEFAULT false
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_email_dead_letters_tenant_id ON email_dead_letters(tenant_id);
CREATE INDEX IF NOT EXISTS idx_email_dead_letters_job_type ON email_dead_letters(job_type);
CREATE INDEX IF NOT EXISTS idx_email_dead_letters_resolved ON email_dead_letters(resolved);
CREATE INDEX IF NOT EXISTS idx_email_dead_letters_failed_at ON email_dead_letters(failed_at);
