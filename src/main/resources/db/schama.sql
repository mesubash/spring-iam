-- ============================================================================
-- AUTHORIZATION SYSTEM - PRODUCTION DATABASE SCHEMA
-- Database: PostgreSQL 14+
-- Required Extensions: uuid-ossp, ltree
-- ============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "ltree";

-- ============================================================================
-- TABLE 1: permissions
-- Purpose: Immutable registry of all permissions in the system
-- ============================================================================

CREATE TABLE permissions (
                             id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                             key VARCHAR(100) UNIQUE NOT NULL,
                             domain VARCHAR(50) NOT NULL,
                             resource VARCHAR(50) NOT NULL,
                             action VARCHAR(50) NOT NULL,
                             description TEXT,
                             is_deprecated BOOLEAN DEFAULT false,
                             created_at TIMESTAMP DEFAULT NOW(),
                             created_by VARCHAR(100),

    -- Constraints
                             CONSTRAINT chk_permission_key_format
                                 CHECK (key ~ '^[a-z_]+\.[a-z_]+\.[a-z_]+$'),
    CONSTRAINT chk_permission_domain_lowercase
        CHECK (domain = LOWER(domain)),
    CONSTRAINT chk_permission_resource_lowercase
        CHECK (resource = LOWER(resource)),
    CONSTRAINT chk_permission_action_lowercase
        CHECK (action = LOWER(action))
);

-- Indexes
CREATE INDEX idx_permissions_domain ON permissions(domain);
CREATE INDEX idx_permissions_key ON permissions(key);
CREATE INDEX idx_permissions_active ON permissions(is_deprecated)
    WHERE is_deprecated = false;

-- Comments
COMMENT ON TABLE permissions IS 'Central registry of all permissions in the system. Permissions are NEVER deleted, only deprecated.';
COMMENT ON COLUMN permissions.key IS 'Unique permission identifier in format: domain.resource.action (e.g., order.order.approve)';
COMMENT ON COLUMN permissions.is_deprecated IS 'Soft delete flag. Deprecated permissions cannot be assigned to new roles but existing assignments remain valid.';

-- ============================================================================
-- TABLE 2: scopes
-- Purpose: Hierarchical organization structure (Global → Region → Country → Org → Dept → Team)
-- ============================================================================

CREATE TABLE scopes (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        type VARCHAR(50) NOT NULL,
                        name VARCHAR(200) NOT NULL,
                        code VARCHAR(50),
                        parent_id UUID REFERENCES scopes(id) ON DELETE RESTRICT,
                        path LTREE NOT NULL,
                        depth INT NOT NULL DEFAULT 0,
                        metadata JSONB DEFAULT '{}',
                        active BOOLEAN DEFAULT true,
                        created_at TIMESTAMP DEFAULT NOW(),
                        updated_at TIMESTAMP DEFAULT NOW(),
                        created_by VARCHAR(100),

    -- Constraints
                        CONSTRAINT chk_scope_type CHECK (type IN (
                                                                  'GLOBAL', 'REGION', 'COUNTRY','ORG', 'DEPT', 'TEAM', 'PROJECT'
                            )),
                        CONSTRAINT chk_scope_global_no_parent
                            CHECK (type != 'GLOBAL' OR parent_id IS NULL),
    CONSTRAINT chk_scope_non_global_has_parent
        CHECK (type = 'GLOBAL' OR parent_id IS NOT NULL),
    CONSTRAINT uq_scope_code UNIQUE (code)
);

-- Indexes
CREATE INDEX idx_scopes_path ON scopes USING GIST(path);
CREATE INDEX idx_scopes_parent ON scopes(parent_id);
CREATE INDEX idx_scopes_type ON scopes(type);
CREATE INDEX idx_scopes_active ON scopes(active) WHERE active = true;
CREATE INDEX idx_scopes_code ON scopes(code) WHERE code IS NOT NULL;
CREATE INDEX idx_scopes_metadata ON scopes USING GIN(metadata);

-- Comments
COMMENT ON TABLE scopes IS 'Hierarchical organizational structure. Uses ltree for efficient hierarchy queries.';
COMMENT ON COLUMN scopes.path IS 'Materialized path using ltree (e.g., GLOBAL.ASIA.NEPAL.EVEREST_TRAVELS)';
COMMENT ON COLUMN scopes.depth IS 'Depth in hierarchy: GLOBAL=0, REGION=1, COUNTRY=2, etc.';
COMMENT ON COLUMN scopes.metadata IS 'Flexible storage for type-specific data (e.g., country_code, org_type, license_number)';

-- ============================================================================
-- TABLE 3: scope_closure
-- Purpose: Pre-computed transitive closure for O(1) containment checks
-- ============================================================================

CREATE TABLE scope_closure (
                               ancestor_id UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
                               descendant_id UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
                               depth INT NOT NULL,

                               PRIMARY KEY (ancestor_id, descendant_id),

                               CONSTRAINT chk_closure_depth_non_negative CHECK (depth >= 0)
);

-- Indexes
CREATE INDEX idx_closure_ancestor ON scope_closure(ancestor_id);
CREATE INDEX idx_closure_descendant ON scope_closure(descendant_id);
CREATE INDEX idx_closure_depth ON scope_closure(depth);

-- Comments
COMMENT ON TABLE scope_closure IS 'Transitive closure table for instant scope containment checks. Auto-maintained by triggers.';
COMMENT ON COLUMN scope_closure.depth IS 'Distance between ancestor and descendant (0 = self-reference)';

-- ============================================================================
-- TABLE 4: roles
-- Purpose: Named bundles of permissions
-- ============================================================================

CREATE TABLE roles (
                       id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                       name VARCHAR(100) UNIQUE NOT NULL,
                       display_name VARCHAR(200),
                       description TEXT,
                       is_system_role BOOLEAN DEFAULT false,
                       org_type VARCHAR(50),
                       active BOOLEAN DEFAULT true,
                       created_at TIMESTAMP DEFAULT NOW(),
                       updated_at TIMESTAMP DEFAULT NOW(),
                       created_by VARCHAR(100),

    -- Constraints
                       CONSTRAINT chk_role_org_type CHECK (org_type IN (
                                                                        'TRAVEL_AGENCY', 'RESCUE_COMPANY', 'INSURANCE', 'HOSPITAL', 'GENERAL', NULL
                           )),
                       CONSTRAINT chk_role_name_format
                           CHECK (name ~ '^[A-Za-z][A-Za-z0-9_]*$')
    );

-- Indexes
CREATE INDEX idx_roles_name ON roles(name);
CREATE INDEX idx_roles_org_type ON roles(org_type);
CREATE INDEX idx_roles_active ON roles(active) WHERE active = true;
CREATE INDEX idx_roles_system ON roles(is_system_role) WHERE is_system_role = true;

-- Prevent deletion of system roles
ALTER TABLE roles ADD CONSTRAINT chk_role_system_cannot_delete
    CHECK (is_system_role = false OR active = true);

-- Comments
COMMENT ON TABLE roles IS 'Named collections of permissions. Reusable across different scopes.';
COMMENT ON COLUMN roles.is_system_role IS 'System roles cannot be deleted (e.g., SuperAdmin, CountryAdmin)';
COMMENT ON COLUMN roles.org_type IS 'Suggests which organization types this role is designed for';

-- ============================================================================
-- TABLE 5: role_permissions
-- Purpose: Many-to-many mapping between roles and permissions
-- ============================================================================

CREATE TABLE role_permissions (
                                  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                                  role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
                                  permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE RESTRICT,
                                  granted_at TIMESTAMP DEFAULT NOW(),
                                  granted_by VARCHAR(100),

                                  UNIQUE(role_id, permission_id)
);

-- Indexes
CREATE INDEX idx_role_permissions_role ON role_permissions(role_id);
CREATE INDEX idx_role_permissions_permission ON role_permissions(permission_id);

-- Comments
COMMENT ON TABLE role_permissions IS 'Defines which permissions each role grants';

-- ============================================================================
-- TABLE 6: assignments
-- Purpose: Assigns roles to subjects (users/services) at specific scopes
-- ============================================================================

CREATE TABLE assignments (
                             id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                             subject_id VARCHAR(100) NOT NULL,
                             subject_type VARCHAR(20) DEFAULT 'USER',
                             role_id UUID NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
                             scope_id UUID NOT NULL REFERENCES scopes(id) ON DELETE RESTRICT,
                             effect VARCHAR(10) DEFAULT 'ALLOW',
                             granted_by VARCHAR(100) NOT NULL,
                             granted_at TIMESTAMP DEFAULT NOW(),
                             expires_at TIMESTAMP,
                             conditions JSONB DEFAULT '{}',
                             active BOOLEAN DEFAULT true,
                             revoked_at TIMESTAMP,
                             revoked_by VARCHAR(100),
                             revoke_reason TEXT,

    -- Constraints
                             CONSTRAINT chk_assignment_effect CHECK (effect IN ('ALLOW', 'DENY')),
                             CONSTRAINT chk_assignment_subject_type CHECK (subject_type IN ('USER', 'SERVICE', 'GROUP')),
                             CONSTRAINT chk_assignment_expiry_future
                                 CHECK (expires_at IS NULL OR expires_at > granted_at),
                             CONSTRAINT chk_assignment_revoke_consistency
                                 CHECK ((revoked_at IS NULL AND revoked_by IS NULL) OR
                                        (revoked_at IS NOT NULL AND revoked_by IS NOT NULL))
);

-- Indexes
CREATE INDEX idx_assignments_subject ON assignments(subject_id, active);
CREATE INDEX idx_assignments_role ON assignments(role_id);
CREATE INDEX idx_assignments_scope ON assignments(scope_id);
CREATE INDEX idx_assignments_active ON assignments(active) WHERE active = true;
CREATE INDEX idx_assignments_expires ON assignments(expires_at)
    WHERE expires_at IS NOT NULL AND active = true;
CREATE INDEX idx_assignments_subject_role_scope ON assignments(subject_id, role_id, scope_id);

-- Comments
COMMENT ON TABLE assignments IS 'Connects subjects to roles at specific scopes. This is where ROLE × SCOPE happens.';
COMMENT ON COLUMN assignments.conditions IS 'ABAC conditions (e.g., time_window, ip_ranges, resource_ownership)';
COMMENT ON COLUMN assignments.expires_at IS 'For temporary grants (e.g., contractor access). NULL = permanent.';

-- ============================================================================
-- TABLE 7: deny_rules
-- Purpose: Explicit denials that override all ALLOW rules
-- ============================================================================

CREATE TABLE deny_rules (
                            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                            subject_id VARCHAR(100) NOT NULL,
                            permission_key VARCHAR(100) NOT NULL,
                            scope_id UUID REFERENCES scopes(id) ON DELETE CASCADE,
                            reason TEXT NOT NULL,
                            reference_id VARCHAR(100),
                            created_by VARCHAR(100) NOT NULL,
                            created_at TIMESTAMP DEFAULT NOW(),
                            expires_at TIMESTAMP,
                            active BOOLEAN DEFAULT true,

    -- Constraints
                            CONSTRAINT chk_deny_permission_format
                                CHECK (permission_key ~ '^[a-z_*]+\\.[a-z_*]+\\.[a-z_*]+$'),
                            CONSTRAINT chk_deny_reason_not_empty
                                CHECK (LENGTH(TRIM(reason)) > 0),
                            CONSTRAINT chk_deny_expiry_future
                                CHECK (expires_at IS NULL OR expires_at > created_at)
);

-- Indexes
CREATE INDEX idx_deny_rules_subject ON deny_rules(subject_id, active);
CREATE INDEX idx_deny_rules_permission ON deny_rules(permission_key, active);
CREATE INDEX idx_deny_rules_scope ON deny_rules(scope_id);
CREATE INDEX idx_deny_rules_active ON deny_rules(active) WHERE active = true;
CREATE INDEX idx_deny_rules_expires ON deny_rules(expires_at)
    WHERE expires_at IS NOT NULL AND active = true;

-- Comments
COMMENT ON TABLE deny_rules IS 'Explicit denials. DENY always wins, regardless of role assignments.';
COMMENT ON COLUMN deny_rules.permission_key IS 'Can be specific (order.order.approve) or wildcard (*.*.*) for global suspension';
COMMENT ON COLUMN deny_rules.scope_id IS 'NULL = applies everywhere. Non-null = applies only in this scope and descendants.';
COMMENT ON COLUMN deny_rules.reference_id IS 'External reference (e.g., case number, ticket ID)';

-- ============================================================================
-- TABLE 8: authorization_audit
-- Purpose: Immutable audit log of all authorization decisions
-- ============================================================================

CREATE TABLE authorization_audit (
                                     id UUID NOT NULL DEFAULT uuid_generate_v4(),
                                     subject_id VARCHAR(100) NOT NULL,
                                     permission_key VARCHAR(100),
                                     resource_type VARCHAR(100),
                                     resource_id VARCHAR(100),
                                     scope_id UUID,
                                     decision BOOLEAN NOT NULL,
                                     reason TEXT NOT NULL,
                                     context JSONB DEFAULT '{}',
                                     request_id VARCHAR(100),
                                     ip_address INET,
                                     user_agent TEXT,
                                     timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
                                     PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

-- Partition by month (example for January 2026)
-- In production, create partitions dynamically
CREATE TABLE authorization_audit_2026_01 PARTITION OF authorization_audit
    FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');

-- Indexes
CREATE INDEX idx_audit_subject ON authorization_audit(subject_id, timestamp DESC);
CREATE INDEX idx_audit_permission ON authorization_audit(permission_key, timestamp DESC);
CREATE INDEX idx_audit_resource ON authorization_audit(resource_type, resource_id, timestamp DESC);
CREATE INDEX idx_audit_timestamp ON authorization_audit(timestamp DESC);
CREATE INDEX idx_audit_decision ON authorization_audit(decision, timestamp DESC);
CREATE INDEX idx_audit_request ON authorization_audit(request_id);

-- Make audit table immutable
CREATE RULE no_update_audit AS ON UPDATE TO authorization_audit DO INSTEAD NOTHING;
CREATE RULE no_delete_audit AS ON DELETE TO authorization_audit DO INSTEAD NOTHING;

-- Comments
COMMENT ON TABLE authorization_audit IS 'Immutable audit trail. Every authorization decision is logged here.';
COMMENT ON COLUMN authorization_audit.context IS 'Additional context (session_id, operation_id, client_info, etc.)';

-- ============================================================================
-- TABLE 9: permission_groups (Optional - for organization)
-- Purpose: Logical grouping of permissions for easier management
-- ============================================================================

CREATE TABLE permission_groups (
                                   id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                                   name VARCHAR(100) UNIQUE NOT NULL,
                                   description TEXT,
                                   parent_group_id UUID REFERENCES permission_groups(id),
                                   created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE permission_group_members (
                                          group_id UUID NOT NULL REFERENCES permission_groups(id) ON DELETE CASCADE,
                                          permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
                                          PRIMARY KEY (group_id, permission_id)
);

-- Comments
COMMENT ON TABLE permission_groups IS 'Optional: Organize permissions into logical groups for UI and management';

-- ============================================================================
-- TABLE 10: role_hierarchy (Optional - for role inheritance)
-- Purpose: Allow roles to inherit permissions from other roles
-- ============================================================================

CREATE TABLE role_hierarchy (
                                parent_role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
                                child_role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
                                PRIMARY KEY (parent_role_id, child_role_id),

    -- Prevent circular inheritance
                                CONSTRAINT chk_role_hierarchy_no_self_reference
                                    CHECK (parent_role_id != child_role_id)
    );

CREATE INDEX idx_role_hierarchy_parent ON role_hierarchy(parent_role_id);
CREATE INDEX idx_role_hierarchy_child ON role_hierarchy(child_role_id);

-- Comments
COMMENT ON TABLE role_hierarchy IS 'Optional: Role inheritance. Child roles inherit all permissions from parent roles.';

-- ============================================================================
-- TABLE 11: policies (ABAC/ReBAC rules)
-- Purpose: Attribute-based and relationship-based access policies
-- ============================================================================

CREATE TABLE policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(120) UNIQUE NOT NULL,
    description TEXT,
    permission_key VARCHAR(100),
    resource_type VARCHAR(100),
    scope_id UUID REFERENCES scopes(id) ON DELETE CASCADE,
    effect VARCHAR(10) NOT NULL DEFAULT 'ALLOW',
    priority INT NOT NULL DEFAULT 0,
    conditions JSONB DEFAULT '{}',
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    created_by VARCHAR(100)
);

CREATE INDEX idx_policies_permission ON policies(permission_key);
CREATE INDEX idx_policies_resource ON policies(resource_type);
CREATE INDEX idx_policies_active ON policies(active) WHERE active = true;
CREATE INDEX idx_policies_scope ON policies(scope_id);

COMMENT ON TABLE policies IS 'ABAC/ReBAC policies evaluated after role-based checks';

CREATE TRIGGER trg_policies_updated_at
    BEFORE UPDATE ON policies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- TRIGGERS
-- ============================================================================

-- Trigger 1: Auto-maintain scope_closure table
CREATE OR REPLACE FUNCTION maintain_scope_closure()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        -- Add self-reference
        INSERT INTO scope_closure (ancestor_id, descendant_id, depth)
        VALUES (NEW.id, NEW.id, 0);

        -- Add paths from all ancestors
INSERT INTO scope_closure (ancestor_id, descendant_id, depth)
SELECT ancestor_id, NEW.id, depth + 1
FROM scope_closure
WHERE descendant_id = NEW.parent_id;

ELSIF TG_OP = 'UPDATE' AND OLD.parent_id IS DISTINCT FROM NEW.parent_id THEN
        -- Parent changed - rebuild closure for this node and descendants
        -- This is complex and expensive - consider restricting parent changes
        RAISE EXCEPTION 'Changing scope parent is not allowed for data integrity. Create new scope instead.';
END IF;

RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_scope_closure_insert
    AFTER INSERT ON scopes
    FOR EACH ROW
    EXECUTE FUNCTION maintain_scope_closure();

-- Trigger 2: Update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_scopes_updated_at
    BEFORE UPDATE ON scopes
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_roles_updated_at
    BEFORE UPDATE ON roles
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Trigger 3: Auto-deactivate assignments on revocation
CREATE OR REPLACE FUNCTION auto_deactivate_on_revoke()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.revoked_at IS NOT NULL AND OLD.revoked_at IS NULL THEN
        NEW.active = false;
END IF;
RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_assignments_auto_deactivate
    BEFORE UPDATE ON assignments
    FOR EACH ROW
    EXECUTE FUNCTION auto_deactivate_on_revoke();

-- Trigger 4: Validate scope depth matches type
CREATE OR REPLACE FUNCTION validate_scope_depth()
RETURNS TRIGGER AS $$
DECLARE
expected_depth INT;
BEGIN
    expected_depth := CASE NEW.type
        WHEN 'GLOBAL' THEN 0
        WHEN 'REGION' THEN 1
        WHEN 'COUNTRY' THEN 2
        WHEN 'ORG' THEN 3
        WHEN 'DEPT' THEN 4
        WHEN 'TEAM' THEN 5
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
                         FOR EACH ROW
                         EXECUTE FUNCTION validate_scope_depth();

-- ============================================================================
-- FUNCTIONS FOR AUTHORIZATION
-- ============================================================================

-- Function 1: Check if scope contains another scope
CREATE OR REPLACE FUNCTION scope_contains(
    p_ancestor_id UUID,
    p_descendant_id UUID
)
RETURNS BOOLEAN AS $$
BEGIN
RETURN EXISTS (
    SELECT 1 FROM scope_closure
    WHERE ancestor_id = p_ancestor_id
      AND descendant_id = p_descendant_id
);
END;
$$ LANGUAGE plpgsql IMMUTABLE;

COMMENT ON FUNCTION scope_contains IS 'Returns true if ancestor_scope contains descendant_scope';

-- Function 2: Get all permissions for a role (including inherited)
CREATE OR REPLACE FUNCTION get_role_permissions(p_role_id UUID)
RETURNS TABLE (permission_key VARCHAR) AS $$
BEGIN
RETURN QUERY
SELECT DISTINCT p.key
FROM role_permissions rp
         JOIN permissions p ON p.id = rp.permission_id
WHERE rp.role_id = p_role_id
  AND p.is_deprecated = false;
END;
$$ LANGUAGE plpgsql STABLE;

-- Function 3: Authorize (main authorization check)
CREATE OR REPLACE FUNCTION authorize(
    p_subject_id VARCHAR,
    p_permission_key VARCHAR,
    p_resource_scope_id UUID
)
RETURNS TABLE (
    authorized BOOLEAN,
    reason TEXT
) AS $$
DECLARE
v_deny_exists BOOLEAN;
    v_has_permission BOOLEAN;
    v_has_scope BOOLEAN;
BEGIN
    -- Step 1: Check DENY rules
SELECT EXISTS (
    SELECT 1 FROM deny_rules dr
    WHERE dr.subject_id = p_subject_id
      AND (dr.permission_key = p_permission_key OR dr.permission_key = '*.*.*')
      AND dr.active = true
      AND (dr.expires_at IS NULL OR dr.expires_at > NOW())
      AND (dr.scope_id IS NULL OR scope_contains(dr.scope_id, p_resource_scope_id))
) INTO v_deny_exists;

IF v_deny_exists THEN
        RETURN QUERY SELECT false, 'DENY: Explicit deny rule exists';
RETURN;
END IF;

    -- Step 2 & 3: Check if user has permission through any active assignment
SELECT EXISTS (
    SELECT 1
    FROM assignments a
             JOIN role_permissions rp ON rp.role_id = a.role_id
             JOIN permissions p ON p.id = rp.permission_id
    WHERE a.subject_id = p_subject_id
      AND a.active = true
      AND (a.expires_at IS NULL OR a.expires_at > NOW())
      AND p.key = p_permission_key
      AND scope_contains(a.scope_id, p_resource_scope_id)
) INTO v_has_permission;

IF NOT v_has_permission THEN
        RETURN QUERY SELECT false, 'DENY: No valid assignment grants this permission';
RETURN;
END IF;

    -- If we got here, authorization passes
RETURN QUERY SELECT true, 'ALLOW: Permission granted';
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION authorize IS 'Main authorization function. Returns (authorized, reason).';

-- ============================================================================
-- INITIAL DATA - GLOBAL SCOPE
-- ============================================================================

-- Insert GLOBAL scope (required)
INSERT INTO scopes (id, type, name, path, depth, created_by)
VALUES (
           '00000000-0000-0000-0000-000000000001',
           'GLOBAL',
           'Global',
           'GLOBAL'::ltree,
           0,
           'SYSTEM_INIT'
       );

-- ============================================================================
-- PERFORMANCE TUNING
-- ============================================================================

-- Analyze tables for query planner
ANALYZE permissions;
ANALYZE scopes;
ANALYZE scope_closure;
ANALYZE roles;
ANALYZE role_permissions;
ANALYZE assignments;
ANALYZE deny_rules;
ANALYZE authorization_audit;

-- ============================================================================
-- SECURITY
-- ============================================================================

-- Revoke public access
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;

-- Create roles (adjust to your needs)
-- CREATE ROLE iam_service_role;
-- GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO iam_service_role;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO iam_service_role;

-- ============================================================================
-- BACKUP & MAINTENANCE RECOMMENDATIONS
-- ============================================================================

-- 1. Regular backups (especially authorization_audit)
-- 2. Monitor scope_closure table size (can grow large)
-- 3. Partition authorization_audit by month
-- 4. Archive old audit logs to cold storage after 2 years
-- 5. Regular VACUUM and ANALYZE on high-write tables

-- ============================================================================
-- SCHEMA VERSION
-- ============================================================================

CREATE TABLE schema_version (
                                version VARCHAR(20) PRIMARY KEY,
                                applied_at TIMESTAMP DEFAULT NOW(),
                                description TEXT
);

INSERT INTO schema_version (version, description)
VALUES ('1.0.0', 'Initial authorization system schema');
