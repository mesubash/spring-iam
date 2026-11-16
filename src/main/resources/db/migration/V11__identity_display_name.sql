-- Human-readable name for an identity, captured at registration and editable by admins.
-- Optional: consoles fall back to the email when it is null.
ALTER TABLE identities ADD COLUMN IF NOT EXISTS display_name VARCHAR(150);
