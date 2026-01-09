-- ModernAuth Database Schema
-- This script initializes the database schema for the ModernAuth service

-- users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    phone TEXT,
    username TEXT UNIQUE,
    hashed_password TEXT NOT NULL,
    is_email_verified BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- user_providers (social / external ids)
CREATE TABLE IF NOT EXISTS user_providers (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    UNIQUE(provider, provider_user_id)
);

-- sessions
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    fingerprint TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    expires_at TIMESTAMP WITH TIME ZONE,
    revoked BOOLEAN DEFAULT false,
    metadata JSONB
);

-- refresh_tokens
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY,
    session_id UUID REFERENCES sessions(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    issued_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    expires_at TIMESTAMP WITH TIME ZONE,
    revoked BOOLEAN DEFAULT false,
    replaced_by UUID
);

-- oauth_clients
CREATE TABLE IF NOT EXISTS oauth_clients (
    id UUID PRIMARY KEY,
    client_id TEXT UNIQUE NOT NULL,
    client_secret_hash TEXT,
    redirect_uris TEXT[],
    confidential BOOLEAN DEFAULT true,
    scopes TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- audit_logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY,
    user_id UUID,
    actor_id UUID,
    event_type TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT,
    data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Create indexes for frequently queried columns
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_session_id ON refresh_tokens(session_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
