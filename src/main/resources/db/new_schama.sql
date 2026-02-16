-- ============================================================================
-- IDENTITY PLATFORM - PRODUCTION DATABASE SCHEMA
-- Single service: AuthN + AuthZ modules
-- PostgreSQL 14+
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "ltree";

-- ============================================================================
-- MODULE: AUTHENTICATION (AuthN)
-- ============================================================================

-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE 1: identities
-- The anchor entity. identities.id = subject_id everywhere.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE identities (
                            id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                            primary_email           VARCHAR(150) UNIQUE NOT NULL,
                            email_verified          BOOLEAN NOT NULL DEFAULT FALSE,
                            account_status          VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
                                CHECK (account_status IN ('ACTIVE', 'LOCKED', 'SUSPENDED', 'DEACTIVATED')),
                            failed_login_attempts   INT NOT NULL DEFAULT 0,
                            account_locked_until    TIMESTAMP WITH TIME ZONE,
                            last_login_at           TIMESTAMP WITH TIME ZONE,
                            last_login_ip           INET,
                            mfa_enabled             BOOLEAN NOT NULL DEFAULT FALSE,
                            created_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                            updated_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_identities_email ON identities(primary_email);
CREATE INDEX idx_identities_status ON identities(account_status);

COMMENT ON TABLE identities IS 'Core identity anchor. identities.id is THE subject_id referenced by AuthZ assignments, JWT sub claim, and all business services.';

-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE 2: credentials
-- One identity can have multiple login methods (password + Google + Apple).
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE credentials (
                             id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                             identity_id             UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
                             credential_type         VARCHAR(30) NOT NULL
                                 CHECK (credential_type IN ('PASSWORD', 'GOOGLE', 'APPLE', 'MICROSOFT')),
                             identifier              VARCHAR(200) NOT NULL,
                             secret_hash             TEXT,
                             is_active               BOOLEAN NOT NULL DEFAULT TRUE,
                             last_used_at            TIMESTAMP WITH TIME ZONE,
                             created_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                             updated_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

                             UNIQUE (credential_type, identifier)
);

CREATE INDEX idx_credentials_identity ON credentials(identity_id);
CREATE INDEX idx_credentials_lookup ON credentials(credential_type, identifier) WHERE is_active = TRUE;

COMMENT ON TABLE credentials IS 'Login methods per identity. PASSWORD type stores bcrypt hash in secret_hash. OAuth types store NULL secret_hash — identifier is provider user ID.';

-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE 3: refresh_tokens
-- Active session tracking with rotation support.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE refresh_tokens (
                                id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                                identity_id             UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
                                token_hash              VARCHAR(128) NOT NULL,
                                ip_address              INET,
                                user_agent              TEXT,
                                expires_at              TIMESTAMP WITH TIME ZONE NOT NULL,
                                revoked_at              TIMESTAMP WITH TIME ZONE,
                                revoke_reason           VARCHAR(30)
                                    CHECK (revoke_reason IN ('LOGOUT', 'ROTATION', 'ADMIN', 'SECURITY', 'EXPIRED')),
                                created_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_refresh_tokens_hash ON refresh_tokens(token_hash) WHERE revoked_at IS NULL;
CREATE INDEX idx_refresh_tokens_identity ON refresh_tokens(identity_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_refresh_tokens_expires ON refresh_tokens(expires_at);

COMMENT ON TABLE refresh_tokens IS 'Active refresh tokens. Revoked tokens stay for audit trail. Query WHERE revoked_at IS NULL for active sessions.';

-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE 4: identity_profiles
-- Shared user profile visible to all services.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE identity_profiles (
                                   identity_id             UUID PRIMARY KEY REFERENCES identities(id) ON DELETE CASCADE,
                                   display_name            VARCHAR(150) NOT NULL,
                                   phone                   VARCHAR(30),
                                   email                   VARCHAR(150),
                                   country                 VARCHAR(100),
                                   avatar_url              VARCHAR(500),
                                   created_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                                   updated_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE identity_profiles IS '1:1 with identities. Shared profile data that any service can read. Does NOT contain role or status — those live in AuthZ and identities respectively.';

-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE 5: security_events
-- Authentication audit trail.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE security_events (
                                 id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                                 identity_id             UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
                                 event_type              VARCHAR(30) NOT NULL
                                     CHECK (event_type IN (
                                                           'LOGIN_SUCCESS', 'LOGIN_FAILED', 'PASSWORD_CHANGED',
                                                           'ACCOUNT_LOCKED', 'ACCOUNT_UNLOCKED', 'TOKEN_REVOKED',
                                                           'PASSWORD_RESET', 'MFA_ENABLED', 'MFA_DISABLED',
                                                           'ACCOUNT_SUSPENDED', 'ACCOUNT_DEACTIVATED'
                                         )),
                                 ip_address              INET,
                                 user_agent              TEXT,
                                 metadata                JSONB DEFAULT '{}',
                                 created_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_security_events_identity ON security_events(identity_id, created_at DESC);
CREATE INDEX idx_security_events_type ON security_events(event_type, created_at DESC);

COMMENT ON TABLE security_events IS 'Immutable AuthN audit log. Tracks logins, failures, password changes, lockouts. Separate from AuthZ authorization_audit.';


-- ============================================================================
-- MODULE: AUTHORIZATION (AuthZ)
-- ============================================================================

-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE 6: permissions
-- Immutable dictionary of all possible actions. Managed by developers only.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE permissions (
                             id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                             key                     VARCHAR(100) UNIQUE NOT NULL,
                             domain                  VARCHAR(50) NOT NULL,
                             resource                VARCHAR(50) NOT NULL,
                             action                  VARCHAR(50) NOT NULL,
                             description             TEXT,
                             is_deprecated           BOOLEAN NOT NULL DEFAULT FALSE,
                             created_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

                             CONSTRAINT chk_permission_key_format
                                 CHECK (key ~ '^[a-z_]+\.[a-z_]+\.[a-z_]+$'),
    CONSTRAINT chk_permission_key_matches
        CHECK (key = domain || '.' || resource || '.' || action)
);

CREATE INDEX idx_permissions_domain ON permissions(domain);
CREATE INDEX idx_permissions_key ON permissions(key);
CREATE INDEX idx_permissions_active ON permissions(is_deprecated) WHERE is_deprecated = FALSE;

COMMENT ON TABLE permissions IS 'Immutable permission registry. Created via migrations/seeds by developers. Never exposed for creation via admin API. Never deleted — only deprecated.';

-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE 7: roles
-- Named bundles of permissions. Says WHAT you can do, never WHERE.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE roles (
                       id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                       name                    VARCHAR(100) UNIQUE NOT NULL,
                       description             TEXT,
                       is_system_role          BOOLEAN NOT NULL DEFAULT FALSE,
                       org_type                VARCHAR(50)
                           CHECK (org_type IN (
                                               'TRAVEL_AGENCY', 'SALES_COMPANY', 'RESCUE_COMPANY',
                                               'RESCUE_CENTRE', 'INSURANCE', 'HOSPITAL', NULL
                               )),
                       created_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                       updated_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

                       CONSTRAINT chk_role_name_format
                           CHECK (name ~ '^[A-Za-z][A-Za-z0-9_]*$')
    );

CREATE INDEX idx_roles_name ON roles(name);
CREATE INDEX idx_roles_org_type ON roles(org_type) WHERE org_type IS NOT NULL;

COMMENT ON TABLE roles IS 'Permission bundles. org_type is a UI hint — filters which roles to show when managing a specific org type. is_system_role prevents deletion.';

-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE 8: role_permissions
-- Which permissions each role grants.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE role_permissions (
                                  role_id                 UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
                                  permission_id           UUID NOT NULL REFERENCES permissions(id) ON DELETE RESTRICT,
                                  granted_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

                                  PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX idx_role_permissions_role ON role_permissions(role_id);

COMMENT ON TABLE role_permissions IS 'Many-to-many: roles ↔ permissions. DELETE RESTRICT on permissions prevents removing active permissions.';

-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE 9: scopes
-- Hierarchical organizational boundaries.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE scopes (
                        id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        type                    VARCHAR(20) NOT NULL
                            CHECK (type IN ('GLOBAL', 'REGION', 'COUNTRY', 'ORG', 'DEPT', 'TEAM')),
                        name                    VARCHAR(200) NOT NULL,
                        code                    VARCHAR(50) UNIQUE,
                        parent_id               UUID REFERENCES scopes(id) ON DELETE RESTRICT,
                        path                    LTREE NOT NULL,
                        metadata                JSONB NOT NULL DEFAULT '{}',
                        active                  BOOLEAN NOT NULL DEFAULT TRUE,
                        created_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                        updated_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

                        CONSTRAINT chk_scope_global_no_parent
                            CHECK (type != 'GLOBAL' OR parent_id IS NULL),
    CONSTRAINT chk_scope_non_global_has_parent
        CHECK (type = 'GLOBAL' OR parent_id IS NOT NULL)
);

CREATE INDEX idx_scopes_path ON scopes USING GIST(path);
CREATE INDEX idx_scopes_parent ON scopes(parent_id);
CREATE INDEX idx_scopes_type ON scopes(type);
CREATE INDEX idx_scopes_active ON scopes(active) WHERE active = TRUE;
CREATE INDEX idx_scopes_metadata ON scopes USING GIN(metadata);

COMMENT ON TABLE scopes IS 'Hierarchical org tree. Path format: GLOBAL.ASIA.NEPAL.EVEREST_TRAVELS. metadata stores org_type, country_code, etc.';

-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE 10: scope_closure
-- Pre-computed ancestor-descendant pairs for O(1) containment checks.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE scope_closure (
                               ancestor_id             UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
                               descendant_id           UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
                               depth                   INT NOT NULL CHECK (depth >= 0),

                               PRIMARY KEY (ancestor_id, descendant_id)
);

CREATE INDEX idx_closure_ancestor ON scope_closure(ancestor_id);
CREATE INDEX idx_closure_descendant ON scope_closure(descendant_id);

COMMENT ON TABLE scope_closure IS 'Transitive closure for instant scope containment. Auto-maintained by trigger. "Does scope A contain scope B?" = single row lookup.';

-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE 11: assignments
-- The glue: Subject + Role + Scope = access grant.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE assignments (
                             id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                             subject_id              UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
                             role_id                 UUID NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
                             scope_id                UUID NOT NULL REFERENCES scopes(id) ON DELETE RESTRICT,
                             granted_by              UUID NOT NULL REFERENCES identities(id),
                             granted_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                             expires_at              TIMESTAMP WITH TIME ZONE,
                             conditions              JSONB NOT NULL DEFAULT '{}',
                             active                  BOOLEAN NOT NULL DEFAULT TRUE,
                             revoked_at              TIMESTAMP WITH TIME ZONE,
                             revoked_by              UUID REFERENCES identities(id),
                             revoke_reason           TEXT,

                             CONSTRAINT chk_assignment_expiry
                                 CHECK (expires_at IS NULL OR expires_at > granted_at),
                             CONSTRAINT chk_assignment_revoke_consistency
                                 CHECK ((revoked_at IS NULL AND revoked_by IS NULL) OR
                                        (revoked_at IS NOT NULL AND revoked_by IS NOT NULL))
);

CREATE INDEX idx_assignments_subject ON assignments(subject_id) WHERE active = TRUE;
CREATE INDEX idx_assignments_role ON assignments(role_id);
CREATE INDEX idx_assignments_scope ON assignments(scope_id);
CREATE INDEX idx_assignments_subject_role_scope ON assignments(subject_id, role_id, scope_id) WHERE active = TRUE;
CREATE INDEX idx_assignments_expires ON assignments(expires_at) WHERE expires_at IS NOT NULL AND active = TRUE;

COMMENT ON TABLE assignments IS 'Connects identity → role → scope. One person can have multiple assignments. conditions holds ABAC rules (time_window, ip_ranges, ownership).';

-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE 12: deny_rules
-- Emergency overrides. DENY always wins.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE deny_rules (
                            id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                            subject_id              UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
                            permission_key          VARCHAR(100) NOT NULL,
                            scope_id                UUID REFERENCES scopes(id) ON DELETE CASCADE,
                            reason                  TEXT NOT NULL,
                            created_by              UUID NOT NULL REFERENCES identities(id),
                            created_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                            expires_at              TIMESTAMP WITH TIME ZONE,
                            active                  BOOLEAN NOT NULL DEFAULT TRUE,

                            CONSTRAINT chk_deny_reason_not_empty
                                CHECK (LENGTH(TRIM(reason)) > 0),
                            CONSTRAINT chk_deny_expiry
                                CHECK (expires_at IS NULL OR expires_at > created_at)
);

CREATE INDEX idx_deny_rules_subject ON deny_rules(subject_id) WHERE active = TRUE;
CREATE INDEX idx_deny_rules_permission ON deny_rules(permission_key) WHERE active = TRUE;
CREATE INDEX idx_deny_rules_expires ON deny_rules(expires_at) WHERE expires_at IS NOT NULL AND active = TRUE;

COMMENT ON TABLE deny_rules IS 'Explicit denials checked FIRST in every authorization decision. scope_id NULL = global deny. permission_key supports *.*.* for full suspension.';

-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE 13: authorization_audit
-- Immutable log of every /authorize decision. Partitioned by month.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE authorization_audit (
                                     id                      UUID NOT NULL DEFAULT uuid_generate_v4(),
                                     subject_id              UUID NOT NULL,
                                     permission_key          VARCHAR(100) NOT NULL,
                                     resource_type           VARCHAR(100),
                                     resource_id             VARCHAR(100),
                                     scope_id                UUID,
                                     decision                BOOLEAN NOT NULL,
                                     reason                  TEXT NOT NULL,
                                     ip_address              INET,
                                     context                 JSONB NOT NULL DEFAULT '{}',
                                     created_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

                                     PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

-- Create partition for current month (automate via cron for future months)
CREATE TABLE authorization_audit_default PARTITION OF authorization_audit DEFAULT;

CREATE INDEX idx_authz_audit_subject ON authorization_audit(subject_id, created_at DESC);
CREATE INDEX idx_authz_audit_permission ON authorization_audit(permission_key, created_at DESC);
CREATE INDEX idx_authz_audit_decision ON authorization_audit(decision, created_at DESC);

-- Immutable: no updates or deletes
CREATE RULE no_update_authz_audit AS ON UPDATE TO authorization_audit DO INSTEAD NOTHING;
CREATE RULE no_delete_authz_audit AS ON DELETE TO authorization_audit DO INSTEAD NOTHING;

COMMENT ON TABLE authorization_audit IS 'Immutable audit trail of every /authorize call. Written only by authorization engine. No external write API. Partitioned by month.';


-- ============================================================================
-- TRIGGERS
-- ============================================================================

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
    FOR EACH ROW
    EXECUTE FUNCTION maintain_scope_closure();

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
    FOR EACH ROW
    EXECUTE FUNCTION prevent_scope_parent_change();

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
    FOR EACH ROW
    EXECUTE FUNCTION auto_deactivate_on_revoke();

-- Auto-update updated_at
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_identities_updated_at BEFORE UPDATE ON identities
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_credentials_updated_at BEFORE UPDATE ON credentials
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_identity_profiles_updated_at BEFORE UPDATE ON identity_profiles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_roles_updated_at BEFORE UPDATE ON roles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_scopes_updated_at BEFORE UPDATE ON scopes
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();


-- ============================================================================
-- UTILITY FUNCTIONS
-- ============================================================================

-- Check if one scope contains another
CREATE OR REPLACE FUNCTION scope_contains(p_ancestor UUID, p_descendant UUID)
RETURNS BOOLEAN AS $$
SELECT EXISTS (
    SELECT 1 FROM scope_closure
    WHERE ancestor_id = p_ancestor AND descendant_id = p_descendant
);
$$ LANGUAGE sql STABLE;

COMMENT ON FUNCTION scope_contains IS 'Returns TRUE if ancestor scope contains descendant scope. Used in authorization checks.';


-- ============================================================================
-- SEED DATA
-- ============================================================================

-- Global scope (required root)
INSERT INTO scopes (id, type, name, code, parent_id, path)
VALUES (
           '00000000-0000-0000-0000-000000000001',
           'GLOBAL', 'Global', 'GLOBAL', NULL, 'GLOBAL'::ltree
       );

-- Schema version tracking
CREATE TABLE schema_version (
                                version     VARCHAR(20) PRIMARY KEY,
                                applied_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                                description TEXT
);

INSERT INTO schema_version (version, description)
VALUES ('1.0.0', 'Initial Identity Platform schema — AuthN + AuthZ');