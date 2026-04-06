-- ============================================================================
-- EXAMPLE SEED: Development Bootstrap
-- ============================================================================
-- This migration creates a minimal development environment with:
--   1. A sample scope hierarchy (Region -> Country)
--   2. A SuperAdmin user with credentials
--   3. Example domain permissions (shows how to add your own)
--   4. An example org-level role
--
-- IMPORTANT: Delete or replace this file for production deployments.
-- Each project should create its own seed migration with project-specific
-- permissions, roles, scopes, and users.
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";


-- ============================================================================
-- EXAMPLE SCOPE HIERARCHY
-- ============================================================================
-- Your project should define its own hierarchy here.
-- The GLOBAL scope is already created by V1.

INSERT INTO scopes (id, type, name, code, parent_id, path, depth, created_by)
VALUES (
    '00000000-0000-0000-0000-000000000010',
    'REGION', 'Example Region', 'EXAMPLE_REGION',
    '00000000-0000-0000-0000-000000000001',
    'GLOBAL.EXAMPLE_REGION'::ltree, 1, 'SYSTEM_INIT'
);

INSERT INTO scopes (id, type, name, code, parent_id, path, depth, metadata, created_by)
VALUES (
    '00000000-0000-0000-0000-000000000100',
    'COUNTRY', 'Example Country', 'EXAMPLE_COUNTRY',
    '00000000-0000-0000-0000-000000000010',
    'GLOBAL.EXAMPLE_REGION.EXAMPLE_COUNTRY'::ltree, 2,
    '{"country_code": "XX", "currency": "USD"}'::jsonb,
    'SYSTEM_INIT'
);


-- ============================================================================
-- BOOTSTRAP SUPERADMIN
-- ============================================================================
-- Create a SuperAdmin identity so you can log in and manage the system.
-- Change these credentials immediately in production.

INSERT INTO identities (id, primary_email, email_verified, account_status)
VALUES ('00000000-1000-0000-0000-000000000001', 'admin@example.com', true, 'ACTIVE')
ON CONFLICT (primary_email) DO NOTHING;

INSERT INTO credentials (id, identity_id, credential_type, identifier, secret_hash)
VALUES (
    uuid_generate_v4(),
    '00000000-1000-0000-0000-000000000001',
    'PASSWORD',
    'admin@example.com',
    crypt('Admin@123!', gen_salt('bf', 10))
)
ON CONFLICT DO NOTHING;

INSERT INTO identity_profiles (identity_id, display_name, email)
VALUES ('00000000-1000-0000-0000-000000000001', 'System Administrator', 'admin@example.com')
ON CONFLICT (identity_id) DO NOTHING;

-- Assign SuperAdmin role at GLOBAL scope
INSERT INTO assignments (id, subject_id, subject_type, role_id, scope_id, granted_by, effect, active)
VALUES (
    uuid_generate_v4(),
    '00000000-1000-0000-0000-000000000001',
    'USER',
    '10000000-0000-0000-0000-000000000001',  -- SuperAdmin role
    '00000000-0000-0000-0000-000000000001',  -- GLOBAL scope
    'SYSTEM_INIT',
    'ALLOW',
    true
)
ON CONFLICT DO NOTHING;


-- ============================================================================
-- EXAMPLE: Adding Domain-Specific Permissions
-- ============================================================================
-- Below shows how a project would add its own domain permissions.
-- Copy this pattern for your project's domains (e.g., order, payment, booking).
--
-- INSERT INTO permissions (key, domain, resource, action, description, created_by) VALUES
-- ('myapp.resource.create', 'myapp', 'resource', 'create', 'Create resource', 'SYSTEM_INIT'),
-- ('myapp.resource.read',   'myapp', 'resource', 'read',   'Read resource',   'SYSTEM_INIT'),
-- ('myapp.resource.update', 'myapp', 'resource', 'update', 'Update resource', 'SYSTEM_INIT'),
-- ('myapp.resource.delete', 'myapp', 'resource', 'delete', 'Delete resource', 'SYSTEM_INIT');


-- ============================================================================
-- EXAMPLE: Adding Org-Specific Roles
-- ============================================================================
-- Below shows how a project would create org-level roles.
-- The org_type field is free-form — use whatever types your project needs.
--
-- INSERT INTO roles (id, name, display_name, description, org_type, created_by) VALUES
-- (uuid_generate_v4(), 'MyAppOrgAdmin', 'My App Org Admin', 'Admin for my org type', 'MY_ORG_TYPE', 'SYSTEM_INIT');
--
-- Then map permissions to the role:
-- INSERT INTO role_permissions (role_id, permission_id, granted_by)
-- SELECT '<role-uuid>', id, 'SYSTEM_INIT'
-- FROM permissions WHERE key IN ('myapp.resource.create', 'myapp.resource.read');
