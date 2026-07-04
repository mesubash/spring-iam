-- ============================================================================
-- V5 — EXAMPLE SEED: development bootstrap. REPLACE for production.
-- Shows the pattern: your scopes, your permissions, your roles, your admin.
-- ============================================================================

-- Example hierarchy under ROOT (types are free-form unless scope_types is populated)
INSERT INTO scopes (id, type, name, code, parent_id, path, depth, created_by)
VALUES (
    '00000000-0000-0000-0000-000000000010',
    'REGION', 'Example Region', 'EXAMPLE_REGION',
    '00000000-0000-0000-0000-000000000001',
    'ROOT.EXAMPLE_REGION'::ltree, 1, 'SYSTEM_INIT'
);

INSERT INTO scopes (id, type, name, code, parent_id, path, depth, metadata, created_by)
VALUES (
    '00000000-0000-0000-0000-000000000100',
    'COUNTRY', 'Example Country', 'EXAMPLE_COUNTRY',
    '00000000-0000-0000-0000-000000000010',
    'ROOT.EXAMPLE_REGION.EXAMPLE_COUNTRY'::ltree, 2,
    '{"country_code": "XX", "currency": "USD"}'::jsonb,
    'SYSTEM_INIT'
);

-- Bootstrap SuperAdmin — change these credentials immediately outside dev.
INSERT INTO identities (id, primary_email, email_verified, account_status)
VALUES ('00000000-1000-0000-0000-000000000001', 'admin@example.com', true, 'ACTIVE')
ON CONFLICT (primary_email) DO NOTHING;

INSERT INTO credentials (identity_id, credential_type, identifier, secret_hash)
VALUES (
    '00000000-1000-0000-0000-000000000001',
    'PASSWORD', 'admin@example.com',
    crypt('Admin@123!', gen_salt('bf', 10))
)
ON CONFLICT DO NOTHING;

INSERT INTO assignments (subject_id, subject_type, role_id, scope_id, granted_by, origin)
VALUES (
    '00000000-1000-0000-0000-000000000001',
    'USER',
    '10000000-0000-0000-0000-000000000001',  -- SuperAdmin
    '00000000-0000-0000-0000-000000000001',  -- ROOT
    'SYSTEM_INIT', 'MIGRATION'
);

-- Pattern for your own domain permissions:
-- INSERT INTO permissions (key, domain, resource, action, description, created_by)
-- VALUES ('myapp.thing.create', 'myapp', 'thing', 'create', 'Create thing', 'SYSTEM_INIT');
--
-- Pattern for your own roles + mappings:
-- INSERT INTO roles (name, display_name, created_by) VALUES ('MyAppAdmin', 'My App Admin', 'SYSTEM_INIT');
-- INSERT INTO role_permissions (role_id, permission_id, granted_by)
-- SELECT r.id, p.id, 'SYSTEM_INIT' FROM roles r, permissions p
-- WHERE r.name = 'MyAppAdmin' AND p.key LIKE 'myapp.%';
