-- Replace password hash!
INSERT INTO users (email, first_name, last_name, password, role, is_active)
VALUES (
    'admin@example.com',
    'System',
    'Administrator',
    '$2y$12$W3hppTiaO.r1KbgYtal13eWrWR/W6eXZzgj5QL8LHt46tKRvwlqhC',
    'admin',
    TRUE
) ON CONFLICT (email) DO NOTHING;
