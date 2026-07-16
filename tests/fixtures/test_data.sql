-- Test data seed for auth_db_test database
-- Run this file to populate test database with seed data

-- Seed admin user
INSERT INTO users (email, first_name, last_name, password_hash, role, is_active, created_at, updated_at)
VALUES (
    'admin@test.com',
    'Admin',
    'User',
    '$2a$12$K8H1.eDM011arfsrIaVK6OPST9/PgBkqquzi.Ss7KIUgO2t0jKm6',  -- "admin123"
    'admin',
    true,
    NOW(),
    NOW()
) ON CONFLICT (email) DO NOTHING;

-- Seed regular user
INSERT INTO users (email, first_name, last_name, password_hash, role, is_active, created_at, updated_at)
VALUES (
    'user@test.com',
    'Test',
    'User',
    '$2a$12$gSvqqUPHg0xveiK3Bu992OPST9/PgBkqquzi.Ss7KIUgO2t0jKm6',  -- "user123"
    'user',
    true,
    NOW(),
    NOW()
) ON CONFLICT (email) DO NOTHING;

-- Seed inactive user
INSERT INTO users (email, first_name, last_name, password_hash, role, is_active, created_at, updated_at)
VALUES (
    'inactive@test.com',
    'Inactive',
    'User',
    '$2a$12$iVwqqUPHg0xveiK3Bu992OPST9/PgBkqquzi.Ss7KIUgO2t0jKm6',  -- "inactive123"
    'user',
    false,
    NOW(),
    NOW()
) ON CONFLICT (email) DO NOTHING;
