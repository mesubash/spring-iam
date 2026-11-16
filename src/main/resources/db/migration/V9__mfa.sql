-- TOTP multi-factor authentication. mfa_methods is a table (not a column) so another factor
-- type (e.g. WebAuthn) can be added later. The TOTP secret is AES-GCM encrypted at rest.
CREATE TABLE IF NOT EXISTS mfa_methods (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id  UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    type         VARCHAR(20) NOT NULL DEFAULT 'TOTP',
    secret_enc   TEXT NOT NULL,
    confirmed_at TIMESTAMPTZ,           -- null = pending (setup started, not yet verified)
    last_step    BIGINT,                -- last consumed TOTP counter: replay guard
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_mfa_identity_type UNIQUE (identity_id, type)
);

CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    code_hash   TEXT NOT NULL,          -- bcrypt(recovery code)
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_mfa_recovery_identity ON mfa_recovery_codes (identity_id) WHERE used_at IS NULL;

ALTER TABLE security_events DROP CONSTRAINT IF EXISTS security_events_event_type_check;
ALTER TABLE security_events ADD CONSTRAINT security_events_event_type_check
    CHECK (event_type IN (
        'LOGIN_SUCCESS', 'LOGIN_FAILED', 'PASSWORD_CHANGED',
        'ACCOUNT_LOCKED', 'ACCOUNT_UNLOCKED', 'TOKEN_REVOKED',
        'PASSWORD_RESET', 'MFA_ENABLED', 'MFA_DISABLED',
        'ACCOUNT_SUSPENDED', 'ACCOUNT_DEACTIVATED',
        'SESSION_EVICTED', 'REUSE_DETECTED', 'OAUTH_LINKED', 'EMAIL_CHANGED',
        'MFA_VERIFIED', 'MFA_FAILED', 'MFA_RECOVERY_USED', 'MFA_RESET_BY_ADMIN'
    ));

-- Authentication methods (RFC 8176 amr) the session was opened with, e.g. "pwd,otp,mfa".
-- Kept on the session so refreshed access tokens carry the same amr claim.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS amr VARCHAR(100);
