CREATE OR REPLACE VIEW user_profiles AS
SELECT 
    id,
    email,
    first_name,
    last_name,
    role,
    is_active,
    created_at,
    last_login
FROM users;

CREATE OR REPLACE VIEW active_user_sessions AS
SELECT 
    u.id as user_id,
    u.email,
    u.first_name,
    u.last_name,
    COUNT(tm.id) as active_sessions,
    MAX(tm.last_used_at) as last_activity
FROM users u
LEFT JOIN token_metadata tm ON u.id = tm.user_id 
    AND tm.token_type = 'refresh' 
    AND tm.is_revoked = FALSE 
    AND tm.expires_at > CURRENT_TIMESTAMP
WHERE u.is_active = TRUE
GROUP BY u.id, u.email, u.first_name, u.last_name;
