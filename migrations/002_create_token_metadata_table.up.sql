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
        ON DELETE CASCADE
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_token_metadata_user_id ON token_metadata(user_id);
CREATE INDEX IF NOT EXISTS idx_token_metadata_token_type ON token_metadata(token_type);
CREATE INDEX IF NOT EXISTS idx_token_metadata_expires_at ON token_metadata(expires_at);
CREATE INDEX IF NOT EXISTS idx_token_metadata_is_revoked ON token_metadata(is_revoked);
CREATE INDEX IF NOT EXISTS idx_token_metadata_user_token_type ON token_metadata(user_id, token_type);
CREATE INDEX IF NOT EXISTS idx_token_metadata_active_tokens ON token_metadata(user_id, is_revoked, expires_at) WHERE is_revoked = FALSE;
CREATE INDEX IF NOT EXISTS idx_token_metadata_cleanup ON token_metadata(expires_at, is_revoked);
CREATE INDEX IF NOT EXISTS idx_token_metadata_device ON token_metadata(device_id) WHERE device_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_token_metadata_client ON token_metadata(client_id) WHERE client_id IS NOT NULL;

-- Constraints
ALTER TABLE token_metadata 
    ADD CONSTRAINT chk_token_type_valid 
    CHECK (token_type IN ('access', 'refresh'));

ALTER TABLE token_metadata 
    ADD CONSTRAINT chk_expires_at_future 
    CHECK (expires_at > created_at);
