DROP INDEX IF EXISTS idx_token_metadata_session_id;

ALTER TABLE token_metadata DROP COLUMN IF EXISTS session_id;
