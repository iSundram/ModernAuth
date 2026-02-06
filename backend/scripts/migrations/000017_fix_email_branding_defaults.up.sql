-- Fix default email branding colors to match templates.go
-- Old: #667eea (primary), #764ba2 (secondary) - gradient colors
-- New: #2B2B2B (primary), #B3B3B3 (secondary) - consistent dark theme

-- Update default column values for new rows
ALTER TABLE email_branding 
    ALTER COLUMN primary_color SET DEFAULT '#2B2B2B',
    ALTER COLUMN secondary_color SET DEFAULT '#B3B3B3';

-- Update existing rows that still have the old default gradient colors
UPDATE email_branding 
SET primary_color = '#2B2B2B', secondary_color = '#B3B3B3'
WHERE primary_color = '#667eea' AND secondary_color = '#764ba2';
