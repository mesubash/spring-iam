-- The token audience (aud) a session was opened for. Kept on the session so refreshed access
-- tokens carry the same aud. Nullable: sessions from before this column, or with the feature off,
-- fall back to the configured default when minted.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS audience VARCHAR(200);
