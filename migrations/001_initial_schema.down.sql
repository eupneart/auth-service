-- Reverse dependency order; CASCADE covers the foreign keys either way.
DROP TABLE IF EXISTS password_reset_tokens CASCADE;
DROP TABLE IF EXISTS token_metadata CASCADE;
DROP TABLE IF EXISTS users CASCADE;
