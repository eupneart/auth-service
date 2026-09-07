CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    consumed_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT fk_password_reset_tokens_user_id
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_token_hash ON password_reset_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);
-- Supports the expired-token cleanup job
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_cleanup ON password_reset_tokens(expires_at) WHERE consumed_at IS NULL;

-- Constraints
ALTER TABLE password_reset_tokens
    ADD CONSTRAINT chk_password_reset_tokens_expires_at_future
    CHECK (expires_at > created_at);
