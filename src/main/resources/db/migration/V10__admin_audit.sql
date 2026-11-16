-- Admin action audit: who changed the IAM configuration, and when. Written for every
-- successful mutating (POST/PUT/PATCH/DELETE) call to the admin API (/api/v1/*) by
-- AdminAuditFilter. Distinct from authorization_audit (PDP decisions) and
-- security_events (authentication events).
CREATE TABLE IF NOT EXISTS admin_audit (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id     UUID,
    actor_email  TEXT,
    method       VARCHAR(10) NOT NULL,
    path         TEXT        NOT NULL,
    status       INT         NOT NULL,
    ip           TEXT,
    user_agent   TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_admin_audit_created ON admin_audit (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admin_audit_actor   ON admin_audit (actor_id, created_at DESC);
