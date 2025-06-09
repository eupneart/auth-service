-- Update timestamp function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger on users table
CREATE TRIGGER update_users_updated_at 
    BEFORE UPDATE ON users 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Cleanup expired tokens
CREATE OR REPLACE FUNCTION cleanup_expired_tokens()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM token_metadata WHERE expires_at < CURRENT_TIMESTAMP;
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Revoke tokens for a user
CREATE OR REPLACE FUNCTION revoke_all_user_tokens(p_user_id BIGINT)
RETURNS INTEGER AS $$
DECLARE
    updated_count INTEGER;
BEGIN
    UPDATE token_metadata 
    SET is_revoked = TRUE 
    WHERE user_id = p_user_id AND is_revoked = FALSE;
    GET DIAGNOSTICS updated_count = ROW_COUNT;
    RETURN updated_count;
END;
$$ LANGUAGE plpgsql;

-- User stats
CREATE OR REPLACE FUNCTION get_user_stats()
RETURNS TABLE(
    total_users BIGINT,
    active_users BIGINT,
    inactive_users BIGINT,
    admin_users BIGINT,
    manager_users BIGINT,
    regular_users BIGINT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        COUNT(*),
        COUNT(*) FILTER (WHERE is_active = TRUE),
        COUNT(*) FILTER (WHERE is_active = FALSE),
        COUNT(*) FILTER (WHERE role = 'admin'),
        COUNT(*) FILTER (WHERE role = 'manager'),
        COUNT(*) FILTER (WHERE role = 'user')
    FROM users;
END;
$$ LANGUAGE plpgsql;

-- Token stats
CREATE OR REPLACE FUNCTION get_token_stats()
RETURNS TABLE(
    total_tokens BIGINT,
    active_tokens BIGINT,
    revoked_tokens BIGINT,
    expired_tokens BIGINT,
    access_tokens BIGINT,
    refresh_tokens BIGINT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        COUNT(*),
        COUNT(*) FILTER (WHERE is_revoked = FALSE AND expires_at > CURRENT_TIMESTAMP),
        COUNT(*) FILTER (WHERE is_revoked = TRUE),
        COUNT(*) FILTER (WHERE expires_at <= CURRENT_TIMESTAMP),
        COUNT(*) FILTER (WHERE token_type = 'access'),
        COUNT(*) FILTER (WHERE token_type = 'refresh')
    FROM token_metadata;
END;
$$ LANGUAGE plpgsql;
