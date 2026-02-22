-- ============================================================================
-- IDENTITY PLATFORM — UNIFIED PRODUCTION SCHEMA
-- Database: PostgreSQL 14+
-- Extensions: uuid-ossp, ltree
-- Modules: AuthN (authentication) + AuthZ (authorization)
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "ltree";


-- ============================================================================
-- MODULE: AUTHENTICATION (AuthN)
-- ============================================================================

-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE: identities
-- The anchor entity. identities.id = universal subject_id.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE identities (
    id                    UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    primary_email         VARCHAR(150) UNIQUE NOT NULL,
    email_verified        BOOLEAN NOT NULL DEFAULT FALSE,
    account_status        VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
        CHECK (account_status IN ('ACTIVE', 'LOCKED', 'SUSPENDED', 'DEACTIVATED')),
    failed_login_attempts INT NOT NULL DEFAULT 0,
    account_locked_until  TIMESTAMP WITH TIME ZONE,
    last_login_at         TIMESTAMP WITH TIME ZONE,
    last_login_ip         INET,
    mfa_enabled           BOOLEAN NOT NULL DEFAULT FALSE,
    created_at            TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_identities_email ON identities(primary_email);
CREATE INDEX idx_identities_status ON identities(account_status);

COMMENT ON TABLE identities IS 'Core identity anchor. identities.id is THE universal subject_id used in JWT sub claim, assignments, and all services.';

-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE: credentials
-- Multiple login methods per identity (password + Google + Apple).
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE credentials (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identity_id     UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    credential_type VARCHAR(30) NOT NULL
        CHECK (credential_type IN ('PASSWORD', 'GOOGLE', 'APPLE', 'MICROSOFT')),
    identifier      VARCHAR(200) NOT NULL,
    secret_hash     TEXT,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    last_used_at    TIMESTAMP WITH TIME ZONE,
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    UNIQUE (credential_type, identifier)
);

CREATE INDEX idx_credentials_identity ON credentials(identity_id);
CREATE INDEX idx_credentials_lookup ON credentials(credential_type, identifier)
    WHERE is_active = TRUE;

COMMENT ON TABLE credentials IS 'Login methods. PASSWORD stores bcrypt in secret_hash. OAuth types store NULL secret_hash; identifier is provider user ID.';

-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE: refresh_tokens
-- Active session tracking with rotation support.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE refresh_tokens (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identity_id   UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    token_hash    VARCHAR(128) NOT NULL,
    ip_address    INET,
    user_agent    TEXT,
    expires_at    TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at    TIMESTAMP WITH TIME ZONE,
    revoke_reason VARCHAR(30)
        CHECK (revoke_reason IN ('LOGOUT', 'ROTATION', 'ADMIN', 'SECURITY', 'EXPIRED')),
    created_at    TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_refresh_tokens_hash ON refresh_tokens(token_hash)
    WHERE revoked_at IS NULL;
CREATE INDEX idx_refresh_tokens_identity ON refresh_tokens(identity_id)
    WHERE revoked_at IS NULL;
CREATE INDEX idx_refresh_tokens_expires ON refresh_tokens(expires_at);

COMMENT ON TABLE refresh_tokens IS 'Active sessions. Revoked tokens remain for audit. Query WHERE revoked_at IS NULL for active sessions.';

-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE: identity_profiles
-- Shared user profile visible to all services (1:1 with identities).
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE identity_profiles (
    identity_id  UUID PRIMARY KEY REFERENCES identities(id) ON DELETE CASCADE,
    display_name VARCHAR(150) NOT NULL,
    phone        VARCHAR(30),
    email        VARCHAR(150),
    country      VARCHAR(100),
    avatar_url   VARCHAR(500),
    created_at   TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE identity_profiles IS '1:1 with identities. Shared profile data readable by any service. No role or status — those live in AuthZ and identities.';

-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE: security_events
-- Immutable AuthN audit trail.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE security_events (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    event_type  VARCHAR(30) NOT NULL
        CHECK (event_type IN (
            'LOGIN_SUCCESS', 'LOGIN_FAILED', 'PASSWORD_CHANGED',
            'ACCOUNT_LOCKED', 'ACCOUNT_UNLOCKED', 'TOKEN_REVOKED',
            'PASSWORD_RESET', 'MFA_ENABLED', 'MFA_DISABLED',
            'ACCOUNT_SUSPENDED', 'ACCOUNT_DEACTIVATED'
        )),
    ip_address  INET,
    user_agent  TEXT,
    metadata    JSONB DEFAULT '{}',
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_security_events_identity ON security_events(identity_id, created_at DESC);
CREATE INDEX idx_security_events_type ON security_events(event_type, created_at DESC);

COMMENT ON TABLE security_events IS 'Immutable AuthN audit log. Tracks logins, password changes, lockouts. Separate from AuthZ authorization_audit.';


-- ============================================================================
-- MODULE: AUTHORIZATION (AuthZ)
-- ============================================================================

-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE: permissions
-- Immutable dictionary of all possible actions. Developer-seeded only.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE permissions (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key           VARCHAR(100) UNIQUE NOT NULL,
    domain        VARCHAR(50) NOT NULL,
    resource      VARCHAR(50) NOT NULL,
    action        VARCHAR(50) NOT NULL,
    description   TEXT,
    is_deprecated BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by    VARCHAR(100),

    CONSTRAINT chk_permission_key_format
        CHECK (key ~ '^[a-z_]+\.[a-z_]+\.[a-z_]+$'),
    CONSTRAINT chk_permission_key_matches
        CHECK (key = domain || '.' || resource || '.' || action)
);

CREATE INDEX idx_permissions_domain ON permissions(domain);
CREATE INDEX idx_permissions_key ON permissions(key);
CREATE INDEX idx_permissions_active ON permissions(is_deprecated)
    WHERE is_deprecated = FALSE;

COMMENT ON TABLE permissions IS 'Immutable permission registry. Developer-seeded via migrations. Never deleted — only deprecated.';
COMMENT ON COLUMN permissions.key IS 'Unique identifier: domain.resource.action (e.g. order.order.approve)';

-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE: roles
-- Named bundles of permissions. Says WHAT you can do, never WHERE.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE roles (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name           VARCHAR(100) UNIQUE NOT NULL,
    display_name   VARCHAR(200),
    description    TEXT,
    is_system_role BOOLEAN NOT NULL DEFAULT FALSE,
    org_type       VARCHAR(50)
        CHECK (org_type IN (
            'OPERATIONS',
            'TRAVEL_AGENCY',
            'SALES_AGENCY',
            'RESCUE_CENTRE',
            'RESCUE_COMPANY',
            'INSURANCE_COMPANY',
            'HOSPITAL',
            'SERVICE_PROVIDER',
            'GOVERNMENT_BODY',
            'GENERAL'
        )),
    active         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by     VARCHAR(100),

    CONSTRAINT chk_role_name_format
        CHECK (name ~ '^[A-Za-z][A-Za-z0-9_]*$'),
    CONSTRAINT chk_role_system_cannot_deactivate
        CHECK (is_system_role = FALSE OR active = TRUE)
);

CREATE INDEX idx_roles_name ON roles(name);
CREATE INDEX idx_roles_org_type ON roles(org_type) WHERE org_type IS NOT NULL;
CREATE INDEX idx_roles_active ON roles(active) WHERE active = TRUE;
CREATE INDEX idx_roles_system ON roles(is_system_role) WHERE is_system_role = TRUE;

COMMENT ON TABLE roles IS 'Permission bundles. org_type is a UI hint for filtering. is_system_role prevents deactivation.';
COMMENT ON COLUMN roles.display_name IS 'Human-readable label (e.g. "Travel Agency Administrator")';

-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE: role_permissions
-- Which permissions each role grants.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE role_permissions (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    role_id       UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE RESTRICT,
    granted_at    TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    granted_by    VARCHAR(100),

    UNIQUE (role_id, permission_id)
);

CREATE INDEX idx_role_permissions_role ON role_permissions(role_id);
CREATE INDEX idx_role_permissions_permission ON role_permissions(permission_id);

COMMENT ON TABLE role_permissions IS 'Many-to-many: roles ↔ permissions. DELETE RESTRICT on permissions prevents removing active permissions.';

-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE: scopes
-- Hierarchical organizational boundaries.
-- GLOBAL → REGION → COUNTRY → ORG → DEPT → TEAM → PROJECT
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE scopes (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    type       VARCHAR(20) NOT NULL
        CHECK (type IN ('GLOBAL', 'REGION', 'COUNTRY', 'ORG', 'DEPT', 'TEAM', 'PROJECT')),
    name       VARCHAR(200) NOT NULL,
    code       VARCHAR(50) UNIQUE,
    parent_id  UUID REFERENCES scopes(id) ON DELETE RESTRICT,
    path       LTREE NOT NULL,
    depth      INT NOT NULL DEFAULT 0,
    metadata   JSONB NOT NULL DEFAULT '{}',
    active     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by VARCHAR(100),

    CONSTRAINT chk_scope_global_no_parent
        CHECK (type != 'GLOBAL' OR parent_id IS NULL),
    CONSTRAINT chk_scope_non_global_has_parent
        CHECK (type = 'GLOBAL' OR parent_id IS NOT NULL)
);

CREATE INDEX idx_scopes_path ON scopes USING GIST(path);
CREATE INDEX idx_scopes_parent ON scopes(parent_id);
CREATE INDEX idx_scopes_type ON scopes(type);
CREATE INDEX idx_scopes_active ON scopes(active) WHERE active = TRUE;
CREATE INDEX idx_scopes_code ON scopes(code) WHERE code IS NOT NULL;
CREATE INDEX idx_scopes_metadata ON scopes USING GIN(metadata);

COMMENT ON TABLE scopes IS 'Hierarchical org tree. Path format: GLOBAL.ASIA_PACIFIC.NEPAL.NEPAL_TRAVEL_AGENCY';
COMMENT ON COLUMN scopes.path IS 'Materialized path using ltree for efficient hierarchy queries';
COMMENT ON COLUMN scopes.depth IS 'Depth in hierarchy: GLOBAL=0, REGION=1, COUNTRY=2, ORG=3, DEPT=4, TEAM=5, PROJECT=6';
COMMENT ON COLUMN scopes.metadata IS 'Type-specific data (e.g. country_code, org_type, license_number)';

-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE: scope_closure
-- Pre-computed ancestor-descendant pairs for O(1) containment checks.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE scope_closure (
    ancestor_id   UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    descendant_id UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    depth         INT NOT NULL CHECK (depth >= 0),

    PRIMARY KEY (ancestor_id, descendant_id)
);

CREATE INDEX idx_closure_ancestor ON scope_closure(ancestor_id);
CREATE INDEX idx_closure_descendant ON scope_closure(descendant_id);

COMMENT ON TABLE scope_closure IS 'Transitive closure for O(1) scope containment. Auto-maintained by trigger.';
COMMENT ON COLUMN scope_closure.depth IS 'Distance between ancestor and descendant (0 = self-reference)';

-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE: assignments
-- The glue: Subject + Role + Scope = access grant.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE assignments (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    subject_id    VARCHAR(100) NOT NULL,
    subject_type  VARCHAR(20) NOT NULL DEFAULT 'USER'
        CHECK (subject_type IN ('USER', 'SERVICE', 'GROUP')),
    role_id       UUID NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
    scope_id      UUID NOT NULL REFERENCES scopes(id) ON DELETE RESTRICT,
    effect        VARCHAR(10) NOT NULL DEFAULT 'ALLOW'
        CHECK (effect IN ('ALLOW', 'DENY')),
    granted_by    VARCHAR(100) NOT NULL,
    granted_at    TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMP WITH TIME ZONE,
    conditions    JSONB NOT NULL DEFAULT '{}',
    active        BOOLEAN NOT NULL DEFAULT TRUE,
    revoked_at    TIMESTAMP WITH TIME ZONE,
    revoked_by    VARCHAR(100),
    revoke_reason TEXT,

    CONSTRAINT chk_assignment_expiry
        CHECK (expires_at IS NULL OR expires_at > granted_at),
    CONSTRAINT chk_assignment_revoke_consistency
        CHECK ((revoked_at IS NULL AND revoked_by IS NULL) OR
               (revoked_at IS NOT NULL AND revoked_by IS NOT NULL))
);

CREATE INDEX idx_assignments_subject ON assignments(subject_id, active);
CREATE INDEX idx_assignments_role ON assignments(role_id);
CREATE INDEX idx_assignments_scope ON assignments(scope_id);
CREATE INDEX idx_assignments_active ON assignments(active) WHERE active = TRUE;
CREATE INDEX idx_assignments_expires ON assignments(expires_at)
    WHERE expires_at IS NOT NULL AND active = TRUE;
CREATE INDEX idx_assignments_subject_role_scope ON assignments(subject_id, role_id, scope_id)
    WHERE active = TRUE;

COMMENT ON TABLE assignments IS 'Connects subjects to roles at specific scopes. This is where ROLE × SCOPE happens.';
COMMENT ON COLUMN assignments.subject_type IS 'USER (default), SERVICE (future), GROUP (future)';
COMMENT ON COLUMN assignments.conditions IS 'ABAC conditions (e.g. time_window, ip_ranges, require_mfa, ownership)';
COMMENT ON COLUMN assignments.expires_at IS 'For temporary grants (e.g. contractor access). NULL = permanent.';

-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE: deny_rules
-- Emergency overrides. DENY always wins.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE deny_rules (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    subject_id     VARCHAR(100) NOT NULL,
    permission_key VARCHAR(100) NOT NULL,
    scope_id       UUID REFERENCES scopes(id) ON DELETE CASCADE,
    reason         TEXT NOT NULL,
    reference_id   VARCHAR(100),
    created_by     VARCHAR(100) NOT NULL,
    created_at     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at     TIMESTAMP WITH TIME ZONE,
    active         BOOLEAN NOT NULL DEFAULT TRUE,

    CONSTRAINT chk_deny_permission_format
        CHECK (permission_key ~ '^[a-z_*]+\.[a-z_*]+\.[a-z_*]+$'),
    CONSTRAINT chk_deny_reason_not_empty
        CHECK (LENGTH(TRIM(reason)) > 0),
    CONSTRAINT chk_deny_expiry
        CHECK (expires_at IS NULL OR expires_at > created_at)
);

CREATE INDEX idx_deny_rules_subject ON deny_rules(subject_id, active);
CREATE INDEX idx_deny_rules_permission ON deny_rules(permission_key, active);
CREATE INDEX idx_deny_rules_scope ON deny_rules(scope_id);
CREATE INDEX idx_deny_rules_active ON deny_rules(active) WHERE active = TRUE;
CREATE INDEX idx_deny_rules_expires ON deny_rules(expires_at)
    WHERE expires_at IS NOT NULL AND active = TRUE;

COMMENT ON TABLE deny_rules IS 'Explicit denials checked FIRST in every authorization decision. DENY always wins.';
COMMENT ON COLUMN deny_rules.permission_key IS 'Specific (order.order.approve) or wildcard (*.*.*) for full suspension';
COMMENT ON COLUMN deny_rules.scope_id IS 'NULL = applies everywhere. Non-null = applies in this scope and descendants.';
COMMENT ON COLUMN deny_rules.reference_id IS 'External reference (e.g. case number, ticket ID)';

-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE: policies
-- ABAC/ReBAC conditional rules evaluated after role-based checks.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE policies (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name           VARCHAR(120) UNIQUE NOT NULL,
    description    TEXT,
    permission_key VARCHAR(100),
    resource_type  VARCHAR(100),
    scope_id       UUID REFERENCES scopes(id) ON DELETE CASCADE,
    effect         VARCHAR(10) NOT NULL DEFAULT 'ALLOW'
        CHECK (effect IN ('ALLOW', 'DENY')),
    priority       INT NOT NULL DEFAULT 0,
    conditions     JSONB NOT NULL DEFAULT '{}',
    active         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by     VARCHAR(100)
);

CREATE INDEX idx_policies_permission ON policies(permission_key);
CREATE INDEX idx_policies_resource ON policies(resource_type);
CREATE INDEX idx_policies_active ON policies(active) WHERE active = TRUE;
CREATE INDEX idx_policies_scope ON policies(scope_id);

COMMENT ON TABLE policies IS 'ABAC/ReBAC policies evaluated after role-based checks. Supports complex condition evaluation.';

-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE: permission_groups + permission_group_members
-- Logical grouping of permissions for UI and management.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE permission_groups (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            VARCHAR(100) UNIQUE NOT NULL,
    description     TEXT,
    parent_group_id UUID REFERENCES permission_groups(id),
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TABLE permission_group_members (
    group_id      UUID NOT NULL REFERENCES permission_groups(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, permission_id)
);

COMMENT ON TABLE permission_groups IS 'Organize permissions into logical groups for admin UI and bulk management.';

-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE: role_hierarchy
-- Role inheritance: child roles inherit parent permissions.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE role_hierarchy (
    parent_role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    child_role_id  UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (parent_role_id, child_role_id),

    CONSTRAINT chk_role_hierarchy_no_self_reference
        CHECK (parent_role_id != child_role_id)
);

CREATE INDEX idx_role_hierarchy_parent ON role_hierarchy(parent_role_id);
CREATE INDEX idx_role_hierarchy_child ON role_hierarchy(child_role_id);

COMMENT ON TABLE role_hierarchy IS 'Role inheritance. Child roles inherit all permissions from parent roles.';

-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE: authorization_audit
-- Immutable log of every /authorize decision. Partitioned by month.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE authorization_audit (
    id             UUID NOT NULL DEFAULT uuid_generate_v4(),
    subject_id     VARCHAR(100) NOT NULL,
    permission_key VARCHAR(100) NOT NULL,
    resource_type  VARCHAR(100),
    resource_id    VARCHAR(100),
    scope_id       UUID,
    decision       BOOLEAN NOT NULL,
    reason         TEXT NOT NULL,
    context        JSONB NOT NULL DEFAULT '{}',
    request_id     VARCHAR(100),
    ip_address     INET,
    user_agent     TEXT,
    timestamp      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

-- Default partition catches all data (create monthly partitions via scheduled job)
CREATE TABLE authorization_audit_default PARTITION OF authorization_audit DEFAULT;

CREATE INDEX idx_audit_subject ON authorization_audit(subject_id, timestamp DESC);
CREATE INDEX idx_audit_permission ON authorization_audit(permission_key, timestamp DESC);
CREATE INDEX idx_audit_resource ON authorization_audit(resource_type, resource_id, timestamp DESC);
CREATE INDEX idx_audit_timestamp ON authorization_audit(timestamp DESC);
CREATE INDEX idx_audit_decision ON authorization_audit(decision, timestamp DESC);
CREATE INDEX idx_audit_request ON authorization_audit(request_id);

-- Immutable: no updates or deletes
CREATE RULE no_update_authz_audit AS ON UPDATE TO authorization_audit DO INSTEAD NOTHING;
CREATE RULE no_delete_authz_audit AS ON DELETE TO authorization_audit DO INSTEAD NOTHING;

COMMENT ON TABLE authorization_audit IS 'Immutable audit trail of every /authorize decision. Partitioned by month.';
COMMENT ON COLUMN authorization_audit.context IS 'Request context (session_id, operation_id, client_info)';
COMMENT ON COLUMN authorization_audit.request_id IS 'Correlation ID for tracing authorization decisions back to HTTP requests';


-- ============================================================================
-- TRIGGERS
-- ============================================================================

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- AuthN triggers
CREATE TRIGGER trg_identities_updated_at
    BEFORE UPDATE ON identities
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_credentials_updated_at
    BEFORE UPDATE ON credentials
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_identity_profiles_updated_at
    BEFORE UPDATE ON identity_profiles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- AuthZ triggers
CREATE TRIGGER trg_roles_updated_at
    BEFORE UPDATE ON roles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_scopes_updated_at
    BEFORE UPDATE ON scopes
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_policies_updated_at
    BEFORE UPDATE ON policies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Auto-maintain scope_closure on scope insert
CREATE OR REPLACE FUNCTION maintain_scope_closure()
RETURNS TRIGGER AS $$
BEGIN
    -- Self-reference
    INSERT INTO scope_closure (ancestor_id, descendant_id, depth)
    VALUES (NEW.id, NEW.id, 0);

    -- Paths from all ancestors
    IF NEW.parent_id IS NOT NULL THEN
        INSERT INTO scope_closure (ancestor_id, descendant_id, depth)
        SELECT ancestor_id, NEW.id, depth + 1
        FROM scope_closure
        WHERE descendant_id = NEW.parent_id;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_scope_closure_insert
    AFTER INSERT ON scopes
    FOR EACH ROW EXECUTE FUNCTION maintain_scope_closure();

-- Prevent scope parent changes (would corrupt closure table)
CREATE OR REPLACE FUNCTION prevent_scope_parent_change()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.parent_id IS DISTINCT FROM NEW.parent_id THEN
        RAISE EXCEPTION 'Changing scope parent is not allowed. Create a new scope instead.';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_scope_prevent_parent_change
    BEFORE UPDATE ON scopes
    FOR EACH ROW EXECUTE FUNCTION prevent_scope_parent_change();

-- Validate scope depth matches type
CREATE OR REPLACE FUNCTION validate_scope_depth()
RETURNS TRIGGER AS $$
DECLARE
    expected_depth INT;
BEGIN
    expected_depth := CASE NEW.type
        WHEN 'GLOBAL'  THEN 0
        WHEN 'REGION'  THEN 1
        WHEN 'COUNTRY' THEN 2
        WHEN 'ORG'     THEN 3
        WHEN 'DEPT'    THEN 4
        WHEN 'TEAM'    THEN 5
        WHEN 'PROJECT' THEN 6
        ELSE NULL
    END;

    IF expected_depth IS NOT NULL AND NEW.depth != expected_depth THEN
        RAISE EXCEPTION 'Scope depth % does not match type %. Expected depth: %',
            NEW.depth, NEW.type, expected_depth;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_scopes_validate_depth
    BEFORE INSERT OR UPDATE ON scopes
    FOR EACH ROW EXECUTE FUNCTION validate_scope_depth();

-- Auto-deactivate assignment on revocation
CREATE OR REPLACE FUNCTION auto_deactivate_on_revoke()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.revoked_at IS NOT NULL AND OLD.revoked_at IS NULL THEN
        NEW.active = FALSE;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_assignment_auto_deactivate
    BEFORE UPDATE ON assignments
    FOR EACH ROW EXECUTE FUNCTION auto_deactivate_on_revoke();


-- ============================================================================
-- UTILITY FUNCTIONS
-- ============================================================================

-- Check if one scope contains another (O(1) via closure table)
CREATE OR REPLACE FUNCTION scope_contains(p_ancestor UUID, p_descendant UUID)
RETURNS BOOLEAN AS $$
    SELECT EXISTS (
        SELECT 1 FROM scope_closure
        WHERE ancestor_id = p_ancestor AND descendant_id = p_descendant
    );
$$ LANGUAGE sql STABLE;

COMMENT ON FUNCTION scope_contains IS 'Returns TRUE if ancestor scope contains descendant scope.';

-- Get all active permissions for a role
CREATE OR REPLACE FUNCTION get_role_permissions(p_role_id UUID)
RETURNS TABLE (permission_key VARCHAR) AS $$
BEGIN
    RETURN QUERY
    SELECT DISTINCT p.key
    FROM role_permissions rp
    JOIN permissions p ON p.id = rp.permission_id
    WHERE rp.role_id = p_role_id
      AND p.is_deprecated = FALSE;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION get_role_permissions IS 'Returns all active (non-deprecated) permission keys for a role.';


-- ============================================================================
-- SEED DATA
-- ============================================================================

-- Global scope (required root of the hierarchy)
INSERT INTO scopes (id, type, name, code, path, depth, created_by)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'GLOBAL', 'Global', 'GLOBAL', 'GLOBAL'::ltree, 0, 'SYSTEM_INIT'
);


-- ============================================================================
-- SECURITY
-- ============================================================================

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;


-- ============================================================================
-- PERFORMANCE TUNING
-- ============================================================================

ANALYZE identities;
ANALYZE credentials;
ANALYZE refresh_tokens;
ANALYZE identity_profiles;
ANALYZE security_events;
ANALYZE permissions;
ANALYZE roles;
ANALYZE role_permissions;
ANALYZE scopes;
ANALYZE scope_closure;
ANALYZE assignments;
ANALYZE deny_rules;
ANALYZE policies;
ANALYZE permission_groups;
ANALYZE permission_group_members;
ANALYZE role_hierarchy;
ANALYZE authorization_audit;


-- ============================================================================
-- SCHEMA VERSION
-- ============================================================================

CREATE TABLE schema_version (
    version     VARCHAR(20) PRIMARY KEY,
    applied_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    description TEXT
);

INSERT INTO schema_version (version, description)
VALUES ('2.0.0', 'Unified Identity Platform schema — AuthN + AuthZ');
