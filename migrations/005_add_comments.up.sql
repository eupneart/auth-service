-- Table comments
COMMENT ON TABLE users IS 'Application users with authentication and authorization data';
COMMENT ON TABLE token_metadata IS 'JWT token metadata for authentication and session management';

-- Users columns
COMMENT ON COLUMN users.id IS 'Unique user identifier (auto-incrementing)';
COMMENT ON COLUMN users.email IS 'User email address (unique, used for login)';
COMMENT ON COLUMN users.password IS 'Hashed password for authentication';
COMMENT ON COLUMN users.role IS 'User role for authorization';
COMMENT ON COLUMN users.is_active IS 'Whether the user account is active';

-- Token metadata columns
COMMENT ON COLUMN token_metadata.id IS 'Unique token identifier (JTI claim)';
COMMENT ON COLUMN token_metadata.user_id IS 'Reference to the user who owns this token';
COMMENT ON COLUMN token_metadata.token_type IS 'Type of token: access or refresh';
COMMENT ON COLUMN token_metadata.is_revoked IS 'Whether the token has been revoked/blacklisted';

-- Function comments
COMMENT ON FUNCTION cleanup_expired_tokens() IS 'Removes expired tokens from the database';
COMMENT ON FUNCTION revoke_all_user_tokens(BIGINT) IS 'Revokes all tokens for a specific user';
COMMENT ON FUNCTION get_user_stats() IS 'Returns statistics about users in the system';
COMMENT ON FUNCTION get_token_stats() IS 'Returns statistics about tokens in the system';

-- View comments
COMMENT ON VIEW user_profiles IS 'User data view excluding sensitive information';
COMMENT ON VIEW active_user_sessions IS 'Shows active user sessions based on valid refresh tokens';
