-- Revert to old gradient color defaults
ALTER TABLE email_branding 
    ALTER COLUMN primary_color SET DEFAULT '#667eea',
    ALTER COLUMN secondary_color SET DEFAULT '#764ba2';

-- Note: We don't revert data changes as we can't know which rows were originally set to old values
