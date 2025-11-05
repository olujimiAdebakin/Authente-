-- =============================================================================
-- AUTHENTICATION SYSTEM SCHEMA
-- This schema supports both traditional email/password and OAuth authentication
-- Includes support for 2FA, refresh tokens, and OTP verification
-- =============================================================================

-- =============================================================================
-- USERS TABLE (UPDATED FOR OAUTH)
-- =============================================================================
-- Stores user accounts with support for both local and OAuth authentication
-- Password is nullable to support OAuth-only users
-- =============================================================================
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,                           -- Auto-incrementing primary key
    first_name VARCHAR(100) NOT NULL,                   -- User's first name
    last_name VARCHAR(100) NOT NULL,                    -- User's last name
    email VARCHAR(255) UNIQUE NOT NULL,                 -- Unique email address
    password VARCHAR(255) NULL,                         -- Hashed password (nullable for OAuth users)
    is_active BOOLEAN DEFAULT TRUE,                     -- Account activation status
    provider VARCHAR(50) DEFAULT 'email',               -- Auth provider: 'email', 'google', 'github', etc.
    provider_id VARCHAR(255) NULL,                      -- Provider's unique user identifier
    avatar_url TEXT NULL,                               -- Profile picture URL from OAuth provider
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE NULL,           -- Soft delete timestamp
    last_login_at TIMESTAMP WITH TIME ZONE NULL         -- Track last login time
);

-- =============================================================================
-- REFRESH TOKENS TABLE (UPDATED)
-- =============================================================================
-- Stores refresh tokens for maintaining user sessions
-- Supports token revocation and expiration management
-- =============================================================================
CREATE TABLE refresh_tokens (
    id BIGSERIAL PRIMARY KEY,                           -- Auto-incrementing primary key
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,  -- Foreign key to users
    token VARCHAR(255) UNIQUE NOT NULL,                 -- JWT refresh token
    revoked BOOLEAN DEFAULT FALSE,                      -- Token revocation status
    expires_at TIMESTAMP WITH TIME ZONE,                -- Token expiration timestamp
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE NULL            -- Soft delete timestamp
);

-- =============================================================================
-- OTPS TABLE (UPDATED)
-- =============================================================================
-- Stores One-Time Passwords for email verification, password reset, etc.
-- Supports multiple OTP types with expiration tracking
-- =============================================================================
CREATE TABLE otps (
    id BIGSERIAL PRIMARY KEY,                           -- Auto-incrementing primary key
    user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,  -- Foreign key to users (nullable for pre-registration)
    email VARCHAR(255) NOT NULL,                        -- Email address the OTP was sent to
    code VARCHAR(64) NOT NULL,                          -- The OTP code (hashed)
    type VARCHAR(50) NOT NULL,                          -- OTP type: 'verification', 'password_reset', 'login'
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,       -- OTP expiration time
    used BOOLEAN DEFAULT FALSE,                         -- Whether OTP has been used
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE NULL            -- Soft delete timestamp
);

-- =============================================================================
-- TWO-FA CONFIGURATION TABLE
-- =============================================================================
-- Stores two-factor authentication settings for users
-- Supports multiple 2FA methods (TOTP, SMS, etc.)
-- =============================================================================
CREATE TABLE two_fa_configs (
    id BIGSERIAL PRIMARY KEY,                           -- Auto-incrementing primary key
    user_id BIGINT UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,  -- One-to-one with users
    method VARCHAR(50) NOT NULL,                        -- 2FA method: 'totp', 'sms', 'email'
    secret TEXT,                                        -- TOTP secret key (encrypted)
    enabled BOOLEAN DEFAULT FALSE,                      -- Whether 2FA is enabled for user
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE NULL            -- Soft delete timestamp
);

-- =============================================================================
-- NEW INDEXES FOR OAUTH PERFORMANCE
-- =============================================================================
-- Optimize queries for OAuth provider lookups and general provider queries
-- =============================================================================
CREATE INDEX idx_users_provider_provider_id ON users(provider, provider_id);  -- Composite index for OAuth lookups
CREATE INDEX idx_users_provider ON users(provider);                           -- Index for provider-based queries

-- =============================================================================
-- ADD TRIGGERS FOR UPDATED_AT TIMESTAMPS
-- =============================================================================
-- Automatically update the updated_at timestamp on record modification
-- Assumes update_updated_at_column() function exists in the database
-- =============================================================================

-- Trigger for refresh_tokens table
CREATE TRIGGER update_refresh_tokens_updated_at
    BEFORE UPDATE ON refresh_tokens
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Trigger for otps table
CREATE TRIGGER update_otps_updated_at
    BEFORE UPDATE ON otps
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Trigger for two_fa_configs table
CREATE TRIGGER update_two_fa_configs_updated_at
    BEFORE UPDATE ON two_fa_configs
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- END OF AUTHENTICATION SCHEMA
-- =============================================================================