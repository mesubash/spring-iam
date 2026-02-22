-- ============================================================================
-- DEV SEED: Bootstrap core users for local development and testing
-- ============================================================================
-- Passwords are hashed at migration time via pgcrypto (BCrypt cost 10).
--
-- Users created:
--
--   superadmin@hgn.com    / Admin@123!
--     -> SuperAdmin at GLOBAL scope
--
--   nepal.admin@hgn.com   / Nepal@123!
--     -> CountryAdmin at NEPAL scope
--
--   access.admin@hgn.com  / Access@123!
--     -> AccessAdmin at NEPAL scope
--
--   security.admin@hgn.com / Security@123!
--     -> SecurityAdmin at GLOBAL scope
--
--   test@hgn.com          / Test@123!
--     -> No role assigned (denial testing)
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- IDENTITIES
-- ============================================================================

INSERT INTO identities (id, primary_email, email_verified, account_status)
VALUES
    ('00000000-1000-0000-0000-000000000001', 'superadmin@hgn.com',    true, 'ACTIVE'),
    ('00000000-1000-0000-0000-000000000002', 'nepal.admin@hgn.com',   true, 'ACTIVE'),
    ('00000000-1000-0000-0000-000000000003', 'access.admin@hgn.com',  true, 'ACTIVE'),
    ('00000000-1000-0000-0000-000000000004', 'security.admin@hgn.com',true, 'ACTIVE'),
    ('00000000-1000-0000-0000-000000000005', 'test@hgn.com',          true, 'ACTIVE')
ON CONFLICT (primary_email) DO NOTHING;

-- ============================================================================
-- CREDENTIALS
-- ============================================================================

INSERT INTO credentials (id, identity_id, credential_type, identifier, secret_hash)
VALUES
    (uuid_generate_v4(), '00000000-1000-0000-0000-000000000001', 'PASSWORD', 'superadmin@hgn.com',     crypt('Admin@123!',    gen_salt('bf', 10))),
    (uuid_generate_v4(), '00000000-1000-0000-0000-000000000002', 'PASSWORD', 'nepal.admin@hgn.com',    crypt('Nepal@123!',    gen_salt('bf', 10))),
    (uuid_generate_v4(), '00000000-1000-0000-0000-000000000003', 'PASSWORD', 'access.admin@hgn.com',   crypt('Access@123!',   gen_salt('bf', 10))),
    (uuid_generate_v4(), '00000000-1000-0000-0000-000000000004', 'PASSWORD', 'security.admin@hgn.com', crypt('Security@123!', gen_salt('bf', 10))),
    (uuid_generate_v4(), '00000000-1000-0000-0000-000000000005', 'PASSWORD', 'test@hgn.com',           crypt('Test@123!',     gen_salt('bf', 10)))
ON CONFLICT DO NOTHING;

-- ============================================================================
-- IDENTITY PROFILES
-- ============================================================================

INSERT INTO identity_profiles (identity_id, display_name, email)
VALUES
    ('00000000-1000-0000-0000-000000000001', 'HGN Super Admin',      'superadmin@hgn.com'),
    ('00000000-1000-0000-0000-000000000002', 'Nepal Country Admin',  'nepal.admin@hgn.com'),
    ('00000000-1000-0000-0000-000000000003', 'Nepal Access Admin',   'access.admin@hgn.com'),
    ('00000000-1000-0000-0000-000000000004', 'Nepal Security Admin', 'security.admin@hgn.com'),
    ('00000000-1000-0000-0000-000000000005', 'Test User',            'test@hgn.com')
ON CONFLICT (identity_id) DO NOTHING;

-- ============================================================================
-- ROLE ASSIGNMENTS
-- ============================================================================

-- superadmin -> SuperAdmin at GLOBAL
INSERT INTO assignments (id, subject_id, subject_type, role_id, scope_id, granted_by, effect, active)
VALUES (
    uuid_generate_v4(),
    '00000000-1000-0000-0000-000000000001',
    'USER',
    '10000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001',
    'SYSTEM_INIT',
    'ALLOW',
    true
)
ON CONFLICT DO NOTHING;

-- nepal.admin -> CountryAdmin at NEPAL
INSERT INTO assignments (id, subject_id, subject_type, role_id, scope_id, granted_by, effect, active)
VALUES (
    uuid_generate_v4(),
    '00000000-1000-0000-0000-000000000002',
    'USER',
    '10000000-0000-0000-0000-000000000002',
    '00000000-0000-0000-0000-000000000100',
    'SYSTEM_INIT',
    'ALLOW',
    true
)
ON CONFLICT DO NOTHING;

-- access.admin -> AccessAdmin at NEPAL
INSERT INTO assignments (id, subject_id, subject_type, role_id, scope_id, granted_by, effect, active)
VALUES (
    uuid_generate_v4(),
    '00000000-1000-0000-0000-000000000003',
    'USER',
    '10000000-0000-0000-0000-000000000003',
    '00000000-0000-0000-0000-000000000100',
    'SYSTEM_INIT',
    'ALLOW',
    true
)
ON CONFLICT DO NOTHING;

-- security.admin -> SecurityAdmin at GLOBAL
INSERT INTO assignments (id, subject_id, subject_type, role_id, scope_id, granted_by, effect, active)
VALUES (
    uuid_generate_v4(),
    '00000000-1000-0000-0000-000000000004',
    'USER',
    '10000000-0000-0000-0000-000000000004',
    '00000000-0000-0000-0000-000000000001',
    'SYSTEM_INIT',
    'ALLOW',
    true
)
ON CONFLICT DO NOTHING;

-- test user intentionally has no assignment
