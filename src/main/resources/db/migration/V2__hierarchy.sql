-- ============================================================================
-- V2 — HIERARCHY: scope_types, scopes (flexible levels), closure, assignments
-- ============================================================================

-- Deployment-defined level registry. Empty = free-form mode (any type label,
-- any nesting). Populated = strict mode (service layer validates type + parent).
CREATE TABLE scope_types (
    id                   UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                 VARCHAR(50)  NOT NULL UNIQUE,
    display_name         VARCHAR(100) NOT NULL,
    allowed_parent_types TEXT[]       NOT NULL DEFAULT '{}',  -- empty = may only sit under ROOT
    level_order          INT,
    description          TEXT,
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE scope_types IS 'Optional level registry. Empty table = free-form hierarchy.';

-- Flexible tree: type is free-form (or registry-validated), depth derived from
-- parent, path segment = code (sibling-unique). Exactly one root.
CREATE TABLE scopes (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    type       VARCHAR(50)  NOT NULL,
    name       VARCHAR(200) NOT NULL,
    code       VARCHAR(50)  NOT NULL,
    parent_id  UUID REFERENCES scopes(id) ON DELETE RESTRICT,
    path       LTREE NOT NULL,
    depth      INT   NOT NULL,
    metadata   JSONB NOT NULL DEFAULT '{}',
    active     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by VARCHAR(100),

    CONSTRAINT chk_scope_code_format CHECK (code ~ '^[A-Za-z0-9_]{1,50}$'),
    CONSTRAINT chk_scope_root_depth  CHECK ((parent_id IS NULL) = (depth = 0))
);

CREATE UNIQUE INDEX uq_scopes_single_root  ON scopes ((1)) WHERE parent_id IS NULL;
CREATE UNIQUE INDEX uq_scopes_sibling_code ON scopes (parent_id, code) NULLS NOT DISTINCT;
CREATE INDEX idx_scopes_path     ON scopes USING GIST(path);
CREATE INDEX idx_scopes_parent   ON scopes(parent_id);
CREATE INDEX idx_scopes_type     ON scopes(type);
CREATE INDEX idx_scopes_active   ON scopes(active) WHERE active = TRUE;
CREATE INDEX idx_scopes_metadata ON scopes USING GIN(metadata);

COMMENT ON TABLE scopes IS 'Hierarchical org tree. path = parent.path || code (sibling-unique). Levels are deployment-defined.';

CREATE TRIGGER trg_scopes_updated_at
    BEFORE UPDATE ON scopes
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Pre-computed transitive closure for O(1) containment checks.
CREATE TABLE scope_closure (
    ancestor_id   UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    descendant_id UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    depth         INT NOT NULL CHECK (depth >= 0),
    PRIMARY KEY (ancestor_id, descendant_id)
);

CREATE INDEX idx_closure_ancestor   ON scope_closure(ancestor_id);
CREATE INDEX idx_closure_descendant ON scope_closure(descendant_id);

CREATE OR REPLACE FUNCTION maintain_scope_closure()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO scope_closure (ancestor_id, descendant_id, depth)
    VALUES (NEW.id, NEW.id, 0);

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

-- Direct parent changes are blocked; re-parenting goes through the managed
-- move operation (POST /scopes/{id}/move) which rebuilds closure + paths.
CREATE OR REPLACE FUNCTION prevent_scope_parent_change()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.parent_id IS DISTINCT FROM NEW.parent_id THEN
        RAISE EXCEPTION 'Direct parent change is not allowed. Use the scope move operation.';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_scope_prevent_parent_change
    BEFORE UPDATE ON scopes
    FOR EACH ROW EXECUTE FUNCTION prevent_scope_parent_change();

CREATE OR REPLACE FUNCTION scope_contains(p_ancestor UUID, p_descendant UUID)
RETURNS BOOLEAN AS $$
    SELECT EXISTS (
        SELECT 1 FROM scope_closure
        WHERE ancestor_id = p_ancestor AND descendant_id = p_descendant
    );
$$ LANGUAGE sql STABLE;

-- Now that scopes exist: tenant-scoped roles FK.
ALTER TABLE roles
    ADD CONSTRAINT fk_roles_owner_scope
    FOREIGN KEY (owner_scope_id) REFERENCES scopes(id) ON DELETE RESTRICT;

-- ============================================================================
-- ASSIGNMENTS — the grant tuple: subject × role × scope (+ conditions L3)
-- No effect column: denies live exclusively in deny_rules.
-- ============================================================================

CREATE TABLE assignments (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    subject_id    VARCHAR(255) NOT NULL,
    subject_type  VARCHAR(20) NOT NULL DEFAULT 'USER'
        CHECK (subject_type IN ('USER', 'SERVICE', 'GROUP')),
    role_id       UUID NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
    scope_id      UUID NOT NULL REFERENCES scopes(id) ON DELETE RESTRICT,
    granted_by    VARCHAR(100) NOT NULL,
    granted_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ,
    conditions    JSONB NOT NULL DEFAULT '{}',
    origin        VARCHAR(20) NOT NULL DEFAULT 'STANDARD'
        CHECK (origin IN ('STANDARD', 'BREAK_GLASS', 'MIGRATION')),
    active        BOOLEAN NOT NULL DEFAULT TRUE,
    revoked_at    TIMESTAMPTZ,
    revoked_by    VARCHAR(100),
    revoke_reason TEXT,

    CONSTRAINT chk_assignment_expiry
        CHECK (expires_at IS NULL OR expires_at > granted_at),
    CONSTRAINT chk_assignment_revoke_consistency
        CHECK ((revoked_at IS NULL AND revoked_by IS NULL) OR
               (revoked_at IS NOT NULL AND revoked_by IS NOT NULL))
);

CREATE INDEX idx_assignments_subject ON assignments(subject_id, active);
CREATE INDEX idx_assignments_role    ON assignments(role_id);
CREATE INDEX idx_assignments_scope   ON assignments(scope_id);
CREATE INDEX idx_assignments_expires ON assignments(expires_at)
    WHERE expires_at IS NOT NULL AND active = TRUE;

COMMENT ON TABLE assignments IS 'Subject × role × scope grants. Never hard-deleted — revocation preserves the row for as-of queries.';

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
-- ROOT SCOPE SEED — fixed UUID; baseline deployments assign everything here.
-- ============================================================================

INSERT INTO scopes (id, type, name, code, path, depth, created_by)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'ROOT', 'Root', 'ROOT', 'ROOT'::ltree, 0, 'SYSTEM_INIT'
);
