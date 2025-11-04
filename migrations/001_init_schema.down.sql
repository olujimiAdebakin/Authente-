-- Rollback all changes in REVERSE order of creation

-- ===== 1. DROP TRIGGERS =====
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
DROP FUNCTION IF EXISTS update_updated_at_column();
DROP TRIGGER IF EXISTS update_two_fa_configs_updated_at ON two_fa_configs;

-- (refresh token indexes removed via their own names)

DROP INDEX IF EXISTS idx_otps_user_id;
DROP INDEX IF EXISTS idx_otps_expires_at;
DROP INDEX IF EXISTS idx_otps_email_code_type;
DROP INDEX IF EXISTS idx_two_fa_configs_user_id;

DROP INDEX IF EXISTS idx_users_is_active;
DROP INDEX IF EXISTS idx_users_deleted_at;
DROP INDEX IF EXISTS idx_users_email;

DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS otps;
DROP TABLE IF EXISTS two_fa_configs;

DROP TABLE IF EXISTS users;