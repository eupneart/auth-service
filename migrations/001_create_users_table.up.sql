CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active);
CREATE INDEX IF NOT EXISTS idx_users_last_name ON users(last_name);
CREATE INDEX IF NOT EXISTS idx_users_active_role ON users(is_active, role) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_users_name_search ON users(last_name, first_name);
CREATE INDEX IF NOT EXISTS idx_users_active_email ON users(email) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_users_last_name_sorted ON users(last_name, first_name, id);

-- Constraints
ALTER TABLE users 
    ADD CONSTRAINT chk_users_email_format 
    CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$');

ALTER TABLE users 
    ADD CONSTRAINT chk_users_role_valid 
    CHECK (role IN ('admin', 'manager', 'user', 'guest'));

ALTER TABLE users 
    ADD CONSTRAINT chk_users_name_not_empty 
    CHECK (LENGTH(TRIM(first_name)) > 0 AND LENGTH(TRIM(last_name)) > 0);

ALTER TABLE users 
    ADD CONSTRAINT chk_users_password_not_empty 
    CHECK (LENGTH(password) > 0);
