-- ============================================================================
-- POLICIES TABLE (ABAC / ReBAC rules)
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
