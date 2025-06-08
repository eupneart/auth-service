-- SQL standard has no `DROP COMMENT`, so these stay unless overridden later.
-- Replace them with empty strings to "remove" them:
COMMENT ON TABLE users IS '';
COMMENT ON TABLE token_metadata IS '';
COMMENT ON COLUMN users.id IS '';
COMMENT ON COLUMN users.email IS '';
COMMENT ON COLUMN users.password IS '';
COMMENT ON COLUMN users.role IS '';
COMMENT ON COLUMN users.is_active IS '';
COMMENT ON COLUMN token_metadata.id IS '';
COMMENT ON COLUMN token_metadata.user_id IS '';
COMMENT ON COLUMN token_metadata.token_type IS '';
COMMENT ON COLUMN token_metadata.is_revoked IS '';
COMMENT ON FUNCTION cleanup_expired_tokens() IS '';
COMMENT ON FUNCTION revoke_all_user_tokens(BIGINT) IS '';
COMMENT ON FUNCTION get_user_stats() IS '';
COMMENT ON FUNCTION get_token_stats() IS '';
COMMENT ON VIEW user_profiles IS '';
COMMENT ON VIEW active_user_sessions IS '';
