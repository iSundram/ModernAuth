-- Remove seeded dynamic settings (but keep any custom values)
-- This is a no-op since we used ON CONFLICT DO NOTHING
-- Settings that were customized will be preserved

-- Note: We intentionally don't delete settings on rollback
-- as that could cause data loss for production configurations
