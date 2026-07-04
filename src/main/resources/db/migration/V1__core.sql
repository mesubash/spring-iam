-- ============================================================================
-- V1 — CORE: extensions, AuthN tables, AuthZ L0 (permissions, roles)
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "ltree";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Shared trigger: auto-update updated_at
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;


-- ============================================================================
-- AUTHN
-- ============================================================================

CREATE TABLE identities (
    id                    UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    primary_email         VARCHAR(150) UNIQUE NOT NULL,
    email_verified        BOOLEAN NOT NULL DEFAULT FALSE,
    account_status        VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
        CHECK (account_status IN ('ACTIVE', 'LOCKED', 'SUSPENDED', 'DEACTIVATED')),
    failed_login_attempts INT NOT NULL DEFAULT 0,
    account_locked_until  TIMESTAMPTZ,
    last_login_at         TIMESTAMPTZ,
    last_login_ip         INET,
    mfa_enabled           BOOLEAN NOT NULL DEFAULT FALSE,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_identities_email  ON identities(primary_email);
CREATE INDEX idx_identities_status ON identities(account_status);

COMMENT ON TABLE identities IS 'Core identity anchor. identities.id is THE universal subject_id used in JWT sub claim, assignments, and all services.';

CREATE TABLE credentials (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identity_id     UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    credential_type VARCHAR(30) NOT NULL
        CHECK (credential_type IN ('PASSWORD', 'GOOGLE', 'APPLE', 'MICROSOFT')),
    identifier      VARCHAR(200) NOT NULL,
    secret_hash     TEXT,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    last_used_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (credential_type, identifier)
);

CREATE INDEX idx_credentials_identity ON credentials(identity_id);
CREATE INDEX idx_credentials_lookup   ON credentials(credential_type, identifier)
    WHERE is_active = TRUE;

COMMENT ON TABLE credentials IS 'Login methods. PASSWORD stores bcrypt in secret_hash. OAuth types store NULL secret_hash; identifier is provider user ID.';

-- NOTE: restructured into sessions + rotation chains in Phase 2.
CREATE TABLE refresh_tokens (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identity_id   UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    token_hash    VARCHAR(128) NOT NULL,
    ip_address    INET,
    user_agent    TEXT,
    expires_at    TIMESTAMPTZ NOT NULL,
    revoked_at    TIMESTAMPTZ,
    revoke_reason VARCHAR(30)
        CHECK (revoke_reason IN ('LOGOUT', 'ROTATION', 'ADMIN', 'SECURITY', 'EXPIRED')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_refresh_tokens_hash     ON refresh_tokens(token_hash)  WHERE revoked_at IS NULL;
CREATE INDEX idx_refresh_tokens_identity ON refresh_tokens(identity_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_refresh_tokens_expires  ON refresh_tokens(expires_at);

CREATE TABLE security_events (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    event_type  VARCHAR(30) NOT NULL
        CHECK (event_type IN (
            'LOGIN_SUCCESS', 'LOGIN_FAILED', 'PASSWORD_CHANGED',
            'ACCOUNT_LOCKED', 'ACCOUNT_UNLOCKED', 'TOKEN_REVOKED',
            'PASSWORD_RESET', 'MFA_ENABLED', 'MFA_DISABLED',
            'ACCOUNT_SUSPENDED', 'ACCOUNT_DEACTIVATED',
            'SESSION_EVICTED', 'REUSE_DETECTED', 'OAUTH_LINKED', 'EMAIL_CHANGED'
        )),
    ip_address  INET,
    user_agent  TEXT,
    metadata    JSONB DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_security_events_identity ON security_events(identity_id, created_at DESC);
CREATE INDEX idx_security_events_type     ON security_events(event_type, created_at DESC);

COMMENT ON TABLE security_events IS 'Immutable AuthN audit log. Separate from AuthZ authorization_audit.';

CREATE TRIGGER trg_identities_updated_at
    BEFORE UPDATE ON identities
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_credentials_updated_at
    BEFORE UPDATE ON credentials
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();


-- ============================================================================
-- AUTHZ L0: PERMISSIONS + ROLES
-- ============================================================================

-- Permission key: 3-6 dot-separated segments, domain.<resource-path>.action.
-- Segments admit digits. Immutable registry — deprecate, never delete.
CREATE TABLE permissions (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key           VARCHAR(150) UNIQUE NOT NULL,
    domain        VARCHAR(50)  NOT NULL,
    resource      VARCHAR(100) NOT NULL,
    action        VARCHAR(50)  NOT NULL,
    description   TEXT,
    is_deprecated BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by    VARCHAR(100),

    CONSTRAINT chk_permission_key_format
        CHECK (key ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){2,5}$'),
    CONSTRAINT chk_permission_key_matches
        CHECK (key = domain || '.' || resource || '.' || action)
);

CREATE INDEX idx_permissions_domain ON permissions(domain);
CREATE INDEX idx_permissions_active ON permissions(is_deprecated) WHERE is_deprecated = FALSE;

COMMENT ON TABLE permissions IS 'Immutable permission registry: domain.<resource-path>.action, 3-6 segments.';

-- owner_scope_id: NULL = global role; set = tenant-scoped role usable only
-- within that subtree. FK added in V2 (scopes exist there).
CREATE TABLE roles (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name           VARCHAR(100) NOT NULL,
    display_name   VARCHAR(200),
    description    TEXT,
    is_system_role BOOLEAN NOT NULL DEFAULT FALSE,
    org_type       VARCHAR(50),
    owner_scope_id UUID,
    active         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by     VARCHAR(100),

    CONSTRAINT chk_role_name_format CHECK (name ~ '^[A-Za-z][A-Za-z0-9_]*$'),
    CONSTRAINT chk_role_system_cannot_deactivate CHECK (is_system_role = FALSE OR active = TRUE)
);

-- Tenant-scoped uniqueness: same role name may exist under different owner scopes.
CREATE UNIQUE INDEX uq_roles_owner_name ON roles (owner_scope_id, name) NULLS NOT DISTINCT;
CREATE INDEX idx_roles_active ON roles(active) WHERE active = TRUE;
CREATE INDEX idx_roles_owner  ON roles(owner_scope_id) WHERE owner_scope_id IS NOT NULL;

CREATE TRIGGER trg_roles_updated_at
    BEFORE UPDATE ON roles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TABLE role_permissions (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    role_id       UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE RESTRICT,
    granted_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by    VARCHAR(100),
    UNIQUE (role_id, permission_id)
);

CREATE INDEX idx_role_permissions_role       ON role_permissions(role_id);
CREATE INDEX idx_role_permissions_permission ON role_permissions(permission_id);

CREATE TABLE role_hierarchy (
    parent_role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    child_role_id  UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (parent_role_id, child_role_id),
    CONSTRAINT chk_role_hierarchy_no_self_reference CHECK (parent_role_id != child_role_id)
);

CREATE INDEX idx_role_hierarchy_parent ON role_hierarchy(parent_role_id);
CREATE INDEX idx_role_hierarchy_child  ON role_hierarchy(child_role_id);

COMMENT ON TABLE role_hierarchy IS 'Role inheritance DAG. Child roles inherit all permissions from parent roles.';
