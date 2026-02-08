CREATE TABLE user_preferences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- Notifications
    email_security_alerts BOOLEAN DEFAULT true,
    email_marketing BOOLEAN DEFAULT false,
    email_product_updates BOOLEAN DEFAULT true,
    email_digest_frequency VARCHAR(20) DEFAULT 'weekly',
    push_enabled BOOLEAN DEFAULT false,
    
    -- Appearance (theme handled separately, skip dark mode)
    accent_color VARCHAR(7) DEFAULT '#3b82f6',
    font_size VARCHAR(10) DEFAULT 'medium',
    high_contrast BOOLEAN DEFAULT false,
    reduced_motion BOOLEAN DEFAULT false,
    
    -- Privacy
    profile_visibility VARCHAR(20) DEFAULT 'public',
    show_activity_status BOOLEAN DEFAULT true,
    show_email_publicly BOOLEAN DEFAULT false,
    
    -- Accessibility
    keyboard_shortcuts_enabled BOOLEAN DEFAULT true,
    
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    
    UNIQUE(user_id)
);

CREATE INDEX idx_user_preferences_user_id ON user_preferences(user_id);
