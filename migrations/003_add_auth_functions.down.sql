DROP TRIGGER IF EXISTS update_users_updated_at ON users;
DROP FUNCTION IF EXISTS update_updated_at_column();
DROP FUNCTION IF EXISTS cleanup_expired_tokens();
DROP FUNCTION IF EXISTS revoke_all_user_tokens(BIGINT);
DROP FUNCTION IF EXISTS get_user_stats();
DROP FUNCTION IF EXISTS get_token_stats();
