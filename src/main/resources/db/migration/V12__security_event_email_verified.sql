-- EMAIL_VERIFIED: an admin marked a user's email verified (invited accounts, dead inboxes).
-- Without it in the CHECK the event write fails.
ALTER TABLE security_events DROP CONSTRAINT IF EXISTS security_events_event_type_check;
ALTER TABLE security_events ADD CONSTRAINT security_events_event_type_check
    CHECK (event_type IN (
        'LOGIN_SUCCESS', 'LOGIN_FAILED', 'PASSWORD_CHANGED',
        'ACCOUNT_LOCKED', 'ACCOUNT_UNLOCKED', 'TOKEN_REVOKED',
        'PASSWORD_RESET', 'MFA_ENABLED', 'MFA_DISABLED',
        'ACCOUNT_SUSPENDED', 'ACCOUNT_DEACTIVATED',
        'SESSION_EVICTED', 'REUSE_DETECTED', 'OAUTH_LINKED', 'EMAIL_CHANGED',
        'MFA_VERIFIED', 'MFA_FAILED', 'MFA_RECOVERY_USED', 'MFA_RESET_BY_ADMIN',
        'EMAIL_VERIFIED'
    ));
