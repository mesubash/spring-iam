-- ============================================================================
-- DEV SEED: Nepal organizations with admin and operator users
-- ============================================================================
-- 9 organizations under NEPAL scope, each with 2 users:
--
--   OPERATIONS
--     admin@operations.hgn       / OrgAdmin@123! -> OperationsOrgAdmin
--     officer@operations.hgn     / OrgUser@123!  -> OperationsOfficer
--
--   TRAVEL AGENCY
--     admin@travel-agency.hgn    / OrgAdmin@123! -> TravelAgencyAdmin
--     manager@travel-agency.hgn  / OrgUser@123!  -> TravelAgencyManager
--
--   SALES AGENCY
--     admin@sales-agency.hgn     / OrgAdmin@123! -> SalesAgencyAdmin
--     agent@sales-agency.hgn     / OrgUser@123!  -> SalesAgencyAgent
--
--   RESCUE CENTRE
--     admin@rescue-centre.hgn    / OrgAdmin@123! -> RescueCentreAdmin
--     dispatcher@rescue-centre.hgn / OrgUser@123! -> RescueDispatcher
--
--   RESCUE COMPANY
--     admin@rescue-company.hgn   / OrgAdmin@123! -> RescueCompanyAdmin
--     operator@rescue-company.hgn / OrgUser@123! -> RescueOperator
--
--   INSURANCE COMPANY
--     admin@insurance-company.hgn / OrgAdmin@123! -> InsuranceCompanyAdmin
--     reviewer@insurance-company.hgn / OrgUser@123! -> InsuranceReviewer
--
--   HOSPITAL
--     admin@hospital.hgn         / OrgAdmin@123! -> HospitalAdmin
--     clinician@hospital.hgn     / OrgUser@123!  -> HospitalOperator
--
--   SERVICE PROVIDER
--     admin@service-provider.hgn / OrgAdmin@123! -> ServiceProviderAdmin
--     operator@service-provider.hgn / OrgUser@123! -> ServiceProviderOperator
--
--   GOVERNMENT BODIES
--     admin@gov-bodies.hgn       / OrgAdmin@123! -> GovernmentBodyAdmin
--     analyst@gov-bodies.hgn     / OrgUser@123!  -> GovernmentBodyAnalyst
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- ORG SCOPES (type=ORG, depth=3, parent=NEPAL)
-- Hierarchy: GLOBAL -> ASIA_PACIFIC -> NEPAL -> ORG
-- ============================================================================

INSERT INTO scopes (id, type, name, code, parent_id, path, depth, metadata, created_by)
VALUES
    ('00000000-0000-0000-0001-000000000001', 'ORG', 'Nepal Operations',      'NEPAL_OPERATIONS',      '00000000-0000-0000-0000-000000000100', 'GLOBAL.ASIA_PACIFIC.NEPAL.NEPAL_OPERATIONS'::ltree,      3, '{"org_type": "OPERATIONS", "license": "OPS-NP-001"}'::jsonb, 'SYSTEM_INIT'),
    ('00000000-0000-0000-0001-000000000002', 'ORG', 'Nepal Travel Agency',   'NEPAL_TRAVEL_AGENCY',   '00000000-0000-0000-0000-000000000100', 'GLOBAL.ASIA_PACIFIC.NEPAL.NEPAL_TRAVEL_AGENCY'::ltree,   3, '{"org_type": "TRAVEL_AGENCY", "license": "TA-NP-001"}'::jsonb, 'SYSTEM_INIT'),
    ('00000000-0000-0000-0001-000000000003', 'ORG', 'Nepal Sales Agency',    'NEPAL_SALES_AGENCY',    '00000000-0000-0000-0000-000000000100', 'GLOBAL.ASIA_PACIFIC.NEPAL.NEPAL_SALES_AGENCY'::ltree,    3, '{"org_type": "SALES_AGENCY", "license": "SA-NP-001"}'::jsonb, 'SYSTEM_INIT'),
    ('00000000-0000-0000-0001-000000000004', 'ORG', 'Nepal Rescue Centre',   'NEPAL_RESCUE_CENTRE',   '00000000-0000-0000-0000-000000000100', 'GLOBAL.ASIA_PACIFIC.NEPAL.NEPAL_RESCUE_CENTRE'::ltree,   3, '{"org_type": "RESCUE_CENTRE", "license": "RC-NP-001"}'::jsonb, 'SYSTEM_INIT'),
    ('00000000-0000-0000-0001-000000000005', 'ORG', 'Nepal Rescue Company',  'NEPAL_RESCUE_COMPANY',  '00000000-0000-0000-0000-000000000100', 'GLOBAL.ASIA_PACIFIC.NEPAL.NEPAL_RESCUE_COMPANY'::ltree,  3, '{"org_type": "RESCUE_COMPANY", "license": "RCO-NP-001"}'::jsonb, 'SYSTEM_INIT'),
    ('00000000-0000-0000-0001-000000000006', 'ORG', 'Nepal Insurance Company','NEPAL_INSURANCE_COMPANY','00000000-0000-0000-0000-000000000100', 'GLOBAL.ASIA_PACIFIC.NEPAL.NEPAL_INSURANCE_COMPANY'::ltree,3, '{"org_type": "INSURANCE_COMPANY", "license": "IC-NP-001"}'::jsonb, 'SYSTEM_INIT'),
    ('00000000-0000-0000-0001-000000000007', 'ORG', 'Nepal Hospital',        'NEPAL_HOSPITAL',        '00000000-0000-0000-0000-000000000100', 'GLOBAL.ASIA_PACIFIC.NEPAL.NEPAL_HOSPITAL'::ltree,        3, '{"org_type": "HOSPITAL", "license": "HSP-NP-001"}'::jsonb, 'SYSTEM_INIT'),
    ('00000000-0000-0000-0001-000000000008', 'ORG', 'Nepal Service Provider','NEPAL_SERVICE_PROVIDER', '00000000-0000-0000-0000-000000000100', 'GLOBAL.ASIA_PACIFIC.NEPAL.NEPAL_SERVICE_PROVIDER'::ltree, 3, '{"org_type": "SERVICE_PROVIDER", "license": "SP-NP-001"}'::jsonb, 'SYSTEM_INIT'),
    ('00000000-0000-0000-0001-000000000009', 'ORG', 'Nepal Government Bodies','NEPAL_GOVERNMENT_BODIES','00000000-0000-0000-0000-000000000100', 'GLOBAL.ASIA_PACIFIC.NEPAL.NEPAL_GOVERNMENT_BODIES'::ltree,3, '{"org_type": "GOVERNMENT_BODY", "license": "GOV-NP-001"}'::jsonb, 'SYSTEM_INIT')
ON CONFLICT DO NOTHING;

-- ============================================================================
-- IDENTITIES (18 users, 2 per org)
-- ============================================================================

INSERT INTO identities (id, primary_email, email_verified, account_status)
VALUES
    ('00000000-2000-0000-0000-000000000001', 'admin@operations.hgn',          true, 'ACTIVE'),
    ('00000000-2000-0000-0000-000000000002', 'officer@operations.hgn',        true, 'ACTIVE'),

    ('00000000-2000-0000-0000-000000000003', 'admin@travel-agency.hgn',       true, 'ACTIVE'),
    ('00000000-2000-0000-0000-000000000004', 'manager@travel-agency.hgn',     true, 'ACTIVE'),

    ('00000000-2000-0000-0000-000000000005', 'admin@sales-agency.hgn',        true, 'ACTIVE'),
    ('00000000-2000-0000-0000-000000000006', 'agent@sales-agency.hgn',        true, 'ACTIVE'),

    ('00000000-2000-0000-0000-000000000007', 'admin@rescue-centre.hgn',       true, 'ACTIVE'),
    ('00000000-2000-0000-0000-000000000008', 'dispatcher@rescue-centre.hgn',  true, 'ACTIVE'),

    ('00000000-2000-0000-0000-000000000009', 'admin@rescue-company.hgn',      true, 'ACTIVE'),
    ('00000000-2000-0000-0000-000000000010', 'operator@rescue-company.hgn',   true, 'ACTIVE'),

    ('00000000-2000-0000-0000-000000000011', 'admin@insurance-company.hgn',   true, 'ACTIVE'),
    ('00000000-2000-0000-0000-000000000012', 'reviewer@insurance-company.hgn',true, 'ACTIVE'),

    ('00000000-2000-0000-0000-000000000013', 'admin@hospital.hgn',             true, 'ACTIVE'),
    ('00000000-2000-0000-0000-000000000014', 'clinician@hospital.hgn',         true, 'ACTIVE'),

    ('00000000-2000-0000-0000-000000000015', 'admin@service-provider.hgn',    true, 'ACTIVE'),
    ('00000000-2000-0000-0000-000000000016', 'operator@service-provider.hgn', true, 'ACTIVE'),

    ('00000000-2000-0000-0000-000000000017', 'admin@gov-bodies.hgn',          true, 'ACTIVE'),
    ('00000000-2000-0000-0000-000000000018', 'analyst@gov-bodies.hgn',        true, 'ACTIVE')
ON CONFLICT (primary_email) DO NOTHING;

-- ============================================================================
-- CREDENTIALS
-- ============================================================================

INSERT INTO credentials (id, identity_id, credential_type, identifier, secret_hash)
VALUES
    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000001', 'PASSWORD', 'admin@operations.hgn',            crypt('OrgAdmin@123!', gen_salt('bf', 10))),
    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000002', 'PASSWORD', 'officer@operations.hgn',          crypt('OrgUser@123!',  gen_salt('bf', 10))),

    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000003', 'PASSWORD', 'admin@travel-agency.hgn',         crypt('OrgAdmin@123!', gen_salt('bf', 10))),
    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000004', 'PASSWORD', 'manager@travel-agency.hgn',       crypt('OrgUser@123!',  gen_salt('bf', 10))),

    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000005', 'PASSWORD', 'admin@sales-agency.hgn',          crypt('OrgAdmin@123!', gen_salt('bf', 10))),
    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000006', 'PASSWORD', 'agent@sales-agency.hgn',          crypt('OrgUser@123!',  gen_salt('bf', 10))),

    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000007', 'PASSWORD', 'admin@rescue-centre.hgn',         crypt('OrgAdmin@123!', gen_salt('bf', 10))),
    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000008', 'PASSWORD', 'dispatcher@rescue-centre.hgn',    crypt('OrgUser@123!',  gen_salt('bf', 10))),

    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000009', 'PASSWORD', 'admin@rescue-company.hgn',        crypt('OrgAdmin@123!', gen_salt('bf', 10))),
    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000010', 'PASSWORD', 'operator@rescue-company.hgn',     crypt('OrgUser@123!',  gen_salt('bf', 10))),

    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000011', 'PASSWORD', 'admin@insurance-company.hgn',     crypt('OrgAdmin@123!', gen_salt('bf', 10))),
    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000012', 'PASSWORD', 'reviewer@insurance-company.hgn',  crypt('OrgUser@123!',  gen_salt('bf', 10))),

    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000013', 'PASSWORD', 'admin@hospital.hgn',              crypt('OrgAdmin@123!', gen_salt('bf', 10))),
    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000014', 'PASSWORD', 'clinician@hospital.hgn',          crypt('OrgUser@123!',  gen_salt('bf', 10))),

    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000015', 'PASSWORD', 'admin@service-provider.hgn',      crypt('OrgAdmin@123!', gen_salt('bf', 10))),
    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000016', 'PASSWORD', 'operator@service-provider.hgn',   crypt('OrgUser@123!',  gen_salt('bf', 10))),

    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000017', 'PASSWORD', 'admin@gov-bodies.hgn',            crypt('OrgAdmin@123!', gen_salt('bf', 10))),
    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000018', 'PASSWORD', 'analyst@gov-bodies.hgn',          crypt('OrgUser@123!',  gen_salt('bf', 10)))
ON CONFLICT DO NOTHING;

-- ============================================================================
-- IDENTITY PROFILES
-- ============================================================================

INSERT INTO identity_profiles (identity_id, display_name, email)
VALUES
    ('00000000-2000-0000-0000-000000000001', 'Nepal Operations Admin',            'admin@operations.hgn'),
    ('00000000-2000-0000-0000-000000000002', 'Nepal Operations Officer',          'officer@operations.hgn'),

    ('00000000-2000-0000-0000-000000000003', 'Nepal Travel Agency Admin',         'admin@travel-agency.hgn'),
    ('00000000-2000-0000-0000-000000000004', 'Nepal Travel Agency Manager',       'manager@travel-agency.hgn'),

    ('00000000-2000-0000-0000-000000000005', 'Nepal Sales Agency Admin',          'admin@sales-agency.hgn'),
    ('00000000-2000-0000-0000-000000000006', 'Nepal Sales Agency Agent',          'agent@sales-agency.hgn'),

    ('00000000-2000-0000-0000-000000000007', 'Nepal Rescue Centre Admin',         'admin@rescue-centre.hgn'),
    ('00000000-2000-0000-0000-000000000008', 'Nepal Rescue Centre Dispatcher',    'dispatcher@rescue-centre.hgn'),

    ('00000000-2000-0000-0000-000000000009', 'Nepal Rescue Company Admin',        'admin@rescue-company.hgn'),
    ('00000000-2000-0000-0000-000000000010', 'Nepal Rescue Company Operator',     'operator@rescue-company.hgn'),

    ('00000000-2000-0000-0000-000000000011', 'Nepal Insurance Company Admin',     'admin@insurance-company.hgn'),
    ('00000000-2000-0000-0000-000000000012', 'Nepal Insurance Reviewer',          'reviewer@insurance-company.hgn'),

    ('00000000-2000-0000-0000-000000000013', 'Nepal Hospital Admin',              'admin@hospital.hgn'),
    ('00000000-2000-0000-0000-000000000014', 'Nepal Hospital Clinician',          'clinician@hospital.hgn'),

    ('00000000-2000-0000-0000-000000000015', 'Nepal Service Provider Admin',      'admin@service-provider.hgn'),
    ('00000000-2000-0000-0000-000000000016', 'Nepal Service Provider Operator',   'operator@service-provider.hgn'),

    ('00000000-2000-0000-0000-000000000017', 'Nepal Government Bodies Admin',     'admin@gov-bodies.hgn'),
    ('00000000-2000-0000-0000-000000000018', 'Nepal Government Bodies Analyst',   'analyst@gov-bodies.hgn')
ON CONFLICT (identity_id) DO NOTHING;

-- ============================================================================
-- ROLE ASSIGNMENTS
-- ============================================================================

INSERT INTO assignments (id, subject_id, subject_type, role_id, scope_id, granted_by, effect, active)
VALUES
    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000001', 'USER', '70000000-0000-0000-0000-000000000001', '00000000-0000-0000-0001-000000000001', 'SYSTEM_INIT', 'ALLOW', true),
    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000002', 'USER', '70000000-0000-0000-0000-000000000002', '00000000-0000-0000-0001-000000000001', 'SYSTEM_INIT', 'ALLOW', true),

    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000003', 'USER', '20000000-0000-0000-0000-000000000001', '00000000-0000-0000-0001-000000000002', 'SYSTEM_INIT', 'ALLOW', true),
    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000004', 'USER', '20000000-0000-0000-0000-000000000002', '00000000-0000-0000-0001-000000000002', 'SYSTEM_INIT', 'ALLOW', true),

    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000005', 'USER', '20000000-0000-0000-0000-000000000010', '00000000-0000-0000-0001-000000000003', 'SYSTEM_INIT', 'ALLOW', true),
    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000006', 'USER', '20000000-0000-0000-0000-000000000011', '00000000-0000-0000-0001-000000000003', 'SYSTEM_INIT', 'ALLOW', true),

    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000007', 'USER', '30000000-0000-0000-0000-000000000004', '00000000-0000-0000-0001-000000000004', 'SYSTEM_INIT', 'ALLOW', true),
    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000008', 'USER', '30000000-0000-0000-0000-000000000003', '00000000-0000-0000-0001-000000000004', 'SYSTEM_INIT', 'ALLOW', true),

    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000009', 'USER', '30000000-0000-0000-0000-000000000001', '00000000-0000-0000-0001-000000000005', 'SYSTEM_INIT', 'ALLOW', true),
    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000010', 'USER', '30000000-0000-0000-0000-000000000002', '00000000-0000-0000-0001-000000000005', 'SYSTEM_INIT', 'ALLOW', true),

    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000011', 'USER', '40000000-0000-0000-0000-000000000001', '00000000-0000-0000-0001-000000000006', 'SYSTEM_INIT', 'ALLOW', true),
    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000012', 'USER', '40000000-0000-0000-0000-000000000002', '00000000-0000-0000-0001-000000000006', 'SYSTEM_INIT', 'ALLOW', true),

    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000013', 'USER', '50000000-0000-0000-0000-000000000001', '00000000-0000-0000-0001-000000000007', 'SYSTEM_INIT', 'ALLOW', true),
    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000014', 'USER', '50000000-0000-0000-0000-000000000002', '00000000-0000-0000-0001-000000000007', 'SYSTEM_INIT', 'ALLOW', true),

    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000015', 'USER', '80000000-0000-0000-0000-000000000001', '00000000-0000-0000-0001-000000000008', 'SYSTEM_INIT', 'ALLOW', true),
    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000016', 'USER', '80000000-0000-0000-0000-000000000002', '00000000-0000-0000-0001-000000000008', 'SYSTEM_INIT', 'ALLOW', true),

    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000017', 'USER', '60000000-0000-0000-0000-000000000010', '00000000-0000-0000-0001-000000000009', 'SYSTEM_INIT', 'ALLOW', true),
    (uuid_generate_v4(), '00000000-2000-0000-0000-000000000018', 'USER', '60000000-0000-0000-0000-000000000011', '00000000-0000-0000-0001-000000000009', 'SYSTEM_INIT', 'ALLOW', true);
