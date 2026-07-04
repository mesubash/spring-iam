-- ============================================================================
-- V3 — ADVANCED: deny rules, policies, resource grants, groups, services,
--                context attributes, permission groups, authorization audit
-- Tables for flag-gated layers ship here; unused tables cost nothing.
-- ============================================================================

-- L2: explicit overrides, checked first, always win.
-- permission_key: segments of (name | *), optional trailing '**' (any depth).
CREATE TABLE deny_rules (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    subject_id     VARCHAR(255) NOT NULL,
    subject_type   VARCHAR(20) NOT NULL DEFAULT 'USER'
        CHECK (subject_type IN ('USER', 'SERVICE', 'GROUP')),
    permission_key VARCHAR(150) NOT NULL
        CHECK (permission_key ~ '^(\*\*|(\*|[a-z][a-z0-9_]*)(\.(\*|[a-z][a-z0-9_]*))*(\.\*\*)?)$'),
    scope_id       UUID REFERENCES scopes(id) ON DELETE CASCADE,
    reason         TEXT NOT NULL CHECK (LENGTH(TRIM(reason)) > 0),
    reference_id   VARCHAR(100),
    created_by     VARCHAR(100) NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at     TIMESTAMPTZ,
    active         BOOLEAN NOT NULL DEFAULT TRUE,

    CONSTRAINT chk_deny_expiry CHECK (expires_at IS NULL OR expires_at > created_at)
);

CREATE INDEX idx_deny_rules_subject ON deny_rules(subject_id, active);
CREATE INDEX idx_deny_rules_active  ON deny_rules(active) WHERE active = TRUE;
CREATE INDEX idx_deny_rules_expires ON deny_rules(expires_at)
    WHERE expires_at IS NOT NULL AND active = TRUE;

COMMENT ON TABLE deny_rules IS 'Checked FIRST; DENY always wins. scope_id NULL = everywhere. ** = any remaining depth.';

-- L4: ABAC condition trees. SHADOW mode evaluates + audits but never decides.
CREATE TABLE policies (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name             VARCHAR(120) UNIQUE NOT NULL,
    description      TEXT,
    permission_key   VARCHAR(150),
    resource_type    VARCHAR(100),
    scope_id         UUID REFERENCES scopes(id) ON DELETE CASCADE,
    effect           VARCHAR(10) NOT NULL DEFAULT 'ALLOW' CHECK (effect IN ('ALLOW', 'DENY')),
    priority         INT NOT NULL DEFAULT 0,
    conditions       JSONB NOT NULL DEFAULT '{}',
    enforcement_mode VARCHAR(10) NOT NULL DEFAULT 'ENFORCE'
        CHECK (enforcement_mode IN ('ENFORCE', 'SHADOW')),
    active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by       VARCHAR(100)
);

CREATE INDEX idx_policies_permission ON policies(permission_key);
CREATE INDEX idx_policies_resource   ON policies(resource_type);
CREATE INDEX idx_policies_active     ON policies(active) WHERE active = TRUE;

CREATE TRIGGER trg_policies_updated_at
    BEFORE UPDATE ON policies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- L5: per-instance ReBAC grants — additional allow path, deny rules still win.
CREATE TABLE resource_grants (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    subject_id     VARCHAR(255) NOT NULL,
    subject_type   VARCHAR(20) NOT NULL DEFAULT 'USER'
        CHECK (subject_type IN ('USER', 'SERVICE', 'GROUP')),
    permission_key VARCHAR(150) NOT NULL
        CHECK (permission_key ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){1,4}\.([a-z][a-z0-9_]*|\*)$'),
    resource_type  VARCHAR(100) NOT NULL,
    resource_id    VARCHAR(255) NOT NULL,
    scope_id       UUID REFERENCES scopes(id) ON DELETE CASCADE,
    granted_by     VARCHAR(100) NOT NULL,
    granted_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at     TIMESTAMPTZ,
    revoked_at     TIMESTAMPTZ,
    revoked_by     VARCHAR(100),

    CONSTRAINT uq_resource_grant
        UNIQUE (subject_id, permission_key, resource_type, resource_id)
);

CREATE INDEX idx_rg_subject  ON resource_grants(subject_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_rg_resource ON resource_grants(resource_type, resource_id) WHERE revoked_at IS NULL;

COMMENT ON TABLE resource_grants IS 'Direct per-instance permission (share X with Y). Wildcard only on action segment.';

-- Subject groups (flag: iam.features.groups). Flat membership, no nesting.
CREATE TABLE subject_groups (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    active      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by  VARCHAR(100)
);

CREATE TABLE subject_group_members (
    group_id   UUID NOT NULL REFERENCES subject_groups(id) ON DELETE CASCADE,
    subject_id VARCHAR(255) NOT NULL,
    added_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    added_by   VARCHAR(100),
    PRIMARY KEY (group_id, subject_id)
);

CREATE INDEX idx_sgm_subject ON subject_group_members(subject_id);

-- Service registry (flag: iam.features.service-registry).
CREATE TABLE services (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name          VARCHAR(100) NOT NULL UNIQUE,
    display_name  VARCHAR(150) NOT NULL,
    owned_domains TEXT[] NOT NULL DEFAULT '{}',
    api_key_hash  VARCHAR(128) NOT NULL,
    active        BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at  TIMESTAMPTZ
);

COMMENT ON TABLE services IS 'Consumer registry: per-service API keys + owned permission domains for manifest sync.';

-- Policy vocabulary registry: which context.additional.* attributes exist.
CREATE TABLE context_attributes (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        VARCHAR(50) NOT NULL UNIQUE,
    value_type  VARCHAR(20) NOT NULL DEFAULT 'STRING'
        CHECK (value_type IN ('STRING', 'NUMBER', 'BOOLEAN', 'TIMESTAMP')),
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by  VARCHAR(100)
);

INSERT INTO context_attributes (name, value_type, description, created_by) VALUES
('mfa',         'BOOLEAN', 'Caller asserts MFA-verified session',      'SYSTEM_INIT'),
('department',  'STRING',  'Requesting user department',               'SYSTEM_INIT'),
('region',      'STRING',  'Request origin region',                    'SYSTEM_INIT'),
('environment', 'STRING',  'Deployment environment (dev/stage/prod)',  'SYSTEM_INIT'),
('deviceType',  'STRING',  'Client device type',                       'SYSTEM_INIT'),
('channel',     'STRING',  'Request channel (web/mobile/ci/internal)', 'SYSTEM_INIT');

-- Admin-UI grouping only — never consulted by the decision pipeline.
CREATE TABLE permission_groups (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            VARCHAR(100) UNIQUE NOT NULL,
    description     TEXT,
    parent_group_id UUID REFERENCES permission_groups(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE permission_group_members (
    group_id      UUID NOT NULL REFERENCES permission_groups(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, permission_id)
);

-- ============================================================================
-- AUTHORIZATION AUDIT — immutable, monthly range-partitioned
-- ============================================================================

CREATE TABLE authorization_audit (
    id             UUID NOT NULL DEFAULT uuid_generate_v4(),
    subject_id     VARCHAR(255) NOT NULL,
    permission_key VARCHAR(150) NOT NULL,
    resource_type  VARCHAR(100),
    resource_id    VARCHAR(255),
    scope_id       UUID,
    decision       BOOLEAN NOT NULL,
    reason         TEXT NOT NULL,
    context        JSONB NOT NULL DEFAULT '{}',
    request_id     VARCHAR(100),
    ip_address     INET,
    user_agent     TEXT,
    timestamp      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

CREATE TABLE authorization_audit_default PARTITION OF authorization_audit DEFAULT;

CREATE INDEX idx_audit_subject    ON authorization_audit(subject_id, timestamp DESC);
CREATE INDEX idx_audit_permission ON authorization_audit(permission_key, timestamp DESC);
CREATE INDEX idx_audit_resource   ON authorization_audit(resource_type, resource_id, timestamp DESC);
CREATE INDEX idx_audit_timestamp  ON authorization_audit(timestamp DESC);
CREATE INDEX idx_audit_decision   ON authorization_audit(decision, timestamp DESC);
CREATE INDEX idx_audit_request    ON authorization_audit(request_id);

CREATE RULE no_update_authz_audit AS ON UPDATE TO authorization_audit DO INSTEAD NOTHING;
CREATE RULE no_delete_authz_audit AS ON DELETE TO authorization_audit DO INSTEAD NOTHING;

COMMENT ON TABLE authorization_audit IS 'Immutable audit trail of every /authorize decision. Monthly partitions pre-created by scheduled job.';

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
