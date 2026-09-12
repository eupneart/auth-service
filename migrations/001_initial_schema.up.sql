-- Initial schema for the authentication service.
--
-- CHECK constraints are declared inline rather than added afterwards so the
-- whole file is re-runnable: a trailing ALTER TABLE ... ADD CONSTRAINT has no
-- IF NOT EXISTS form and fails on a second application.

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
    last_login TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_users_email_format
        CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    -- Bounds the roles the service will accept even if application validation
    -- is bypassed.
    CONSTRAINT chk_users_role_valid
        CHECK (role IN ('admin', 'manager', 'user', 'guest')),
    CONSTRAINT chk_users_name_not_empty
        CHECK (LENGTH(TRIM(first_name)) > 0 AND LENGTH(TRIM(last_name)) > 0),
    -- Guards against a row whose password column was never written; an empty
    -- hash would make bcrypt comparison the only thing standing between an
    -- account and anyone.
    CONSTRAINT chk_users_password_not_empty
        CHECK (LENGTH(password) > 0)
);

CREATE INDEX IF NOT EXISTS idx_users_last_name ON users(last_name);

CREATE TABLE IF NOT EXISTS token_metadata (
    id VARCHAR(255) PRIMARY KEY,
    user_id BIGINT NOT NULL,
    token_type VARCHAR(50) NOT NULL,
    device_id VARCHAR(255),
    client_id VARCHAR(255),
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_used_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_token_metadata_user_id
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE,
    CONSTRAINT chk_token_type_valid
        CHECK (token_type IN ('access', 'refresh')),
    CONSTRAINT chk_expires_at_future
        CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS idx_token_metadata_user_id ON token_metadata(user_id);
-- Supports the periodic expired-token sweep.
CREATE INDEX IF NOT EXISTS idx_token_metadata_cleanup ON token_metadata(expires_at, is_revoked);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    -- SHA-256 of the token from the emailed link; the raw value is never stored.
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    -- Non-null once redeemed, which is what makes a reset link single-use.
    consumed_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_password_reset_tokens_user_id
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE,
    CONSTRAINT chk_password_reset_tokens_expires_at_future
        CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_cleanup
    ON password_reset_tokens(expires_at) WHERE consumed_at IS NULL;
