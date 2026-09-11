-- Tokens issued for one login share a session id, so logout can revoke the
-- access token, its refresh token, and any access token later rotated from that
-- refresh token, in a single statement. Nullable: rows written before this
-- migration belong to no session.
ALTER TABLE token_metadata ADD COLUMN IF NOT EXISTS session_id VARCHAR(255);

-- Backs the logout revocation, the only query that filters on this column.
CREATE INDEX IF NOT EXISTS idx_token_metadata_session_id
    ON token_metadata(session_id);
