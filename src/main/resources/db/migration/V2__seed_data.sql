-- ============================================================================
-- SEED DATA: Platform Permissions, System Roles, Role-Permission Mappings
-- ============================================================================
-- This migration seeds the MINIMUM data required for the IAM platform to function.
-- It contains ONLY:
--   1. Platform (IAM) permissions — the permissions the IAM service itself needs
--   2. Organization governance permissions — basic org/member management
--   3. User domain permissions — user profile and account management
--   4. System roles — SuperAdmin, CountryAdmin, AccessAdmin, SecurityAdmin, AuditViewer, OperationsAdmin, GovernmentOversight
--   5. Role-permission mappings for system roles
--
-- Domain-specific permissions (order, payment, rescue, etc.) and org-specific
-- roles should be added by each deploying project in their own migration files.
-- ============================================================================


-- ============================================================================
-- PERMISSIONS: Platform / IAM
-- ============================================================================

INSERT INTO permissions (key, domain, resource, action, description, created_by) VALUES
('platform.identity.create',     'platform', 'identity',    'create',    'Create identity',              'SYSTEM_INIT'),
('platform.identity.read',       'platform', 'identity',    'read',      'Read identity',                'SYSTEM_INIT'),
('platform.identity.update',     'platform', 'identity',    'update',    'Update identity',              'SYSTEM_INIT'),
('platform.identity.suspend',    'platform', 'identity',    'suspend',   'Suspend identity',             'SYSTEM_INIT'),
('platform.identity.deactivate', 'platform', 'identity',    'deactivate','Deactivate identity',          'SYSTEM_INIT'),
('platform.role.create',         'platform', 'role',        'create',    'Create role',                  'SYSTEM_INIT'),
('platform.role.read',           'platform', 'role',        'read',      'Read role',                    'SYSTEM_INIT'),
('platform.role.update',         'platform', 'role',        'update',    'Update role',                  'SYSTEM_INIT'),
('platform.role.delete',         'platform', 'role',        'delete',    'Delete/deactivate role',       'SYSTEM_INIT'),
('platform.scope.create',        'platform', 'scope',       'create',    'Create scope',                 'SYSTEM_INIT'),
('platform.scope.read',          'platform', 'scope',       'read',      'Read scope',                   'SYSTEM_INIT'),
('platform.scope.update',        'platform', 'scope',       'update',    'Update scope',                 'SYSTEM_INIT'),
('platform.assignment.create',   'platform', 'assignment',  'create',    'Create assignment',            'SYSTEM_INIT'),
('platform.assignment.read',     'platform', 'assignment',  'read',      'Read assignment',              'SYSTEM_INIT'),
('platform.assignment.revoke',   'platform', 'assignment',  'revoke',    'Revoke assignment',            'SYSTEM_INIT'),
('platform.deny_rule.create',    'platform', 'deny_rule',   'create',    'Create deny rule',             'SYSTEM_INIT'),
('platform.deny_rule.read',      'platform', 'deny_rule',   'read',      'Read deny rule',               'SYSTEM_INIT'),
('platform.deny_rule.delete',    'platform', 'deny_rule',   'delete',    'Delete deny rule',             'SYSTEM_INIT'),
('platform.policy.create',       'platform', 'policy',      'create',    'Create policy',                'SYSTEM_INIT'),
('platform.policy.read',         'platform', 'policy',      'read',      'Read policy',                  'SYSTEM_INIT'),
('platform.policy.update',       'platform', 'policy',      'update',    'Update policy',                'SYSTEM_INIT'),
('platform.policy.delete',       'platform', 'policy',      'delete',    'Delete policy',                'SYSTEM_INIT'),
('platform.audit.read',          'platform', 'audit',       'read',      'Read authorization audit',     'SYSTEM_INIT'),
('platform.permission.read',     'platform', 'permission',  'read',      'Read permissions registry',    'SYSTEM_INIT'),
('platform.analytics.view',      'platform', 'analytics',   'view',      'View analytics',               'SYSTEM_INIT');


-- ============================================================================
-- PERMISSIONS: Organization Governance
-- ============================================================================

INSERT INTO permissions (key, domain, resource, action, description, created_by) VALUES
('organization.organization.create', 'organization', 'organization', 'create',  'Create organization',  'SYSTEM_INIT'),
('organization.organization.read',   'organization', 'organization', 'read',    'Read organization',    'SYSTEM_INIT'),
('organization.organization.update', 'organization', 'organization', 'update',  'Update organization',  'SYSTEM_INIT'),
('organization.organization.approve','organization', 'organization', 'approve', 'Approve organization', 'SYSTEM_INIT'),
('organization.organization.suspend','organization', 'organization', 'suspend', 'Suspend organization', 'SYSTEM_INIT'),
('organization.member.create',       'organization', 'member',       'create',  'Create org member',    'SYSTEM_INIT'),
('organization.member.read',         'organization', 'member',       'read',    'Read org member',      'SYSTEM_INIT'),
('organization.member.update',       'organization', 'member',       'update',  'Update org member',    'SYSTEM_INIT'),
('organization.member.remove',       'organization', 'member',       'remove',  'Remove org member',    'SYSTEM_INIT');


-- ============================================================================
-- PERMISSIONS: User Domain
-- ============================================================================

INSERT INTO permissions (key, domain, resource, action, description, created_by) VALUES
('user.profile.create',    'user', 'profile', 'create',     'Create user profile',      'SYSTEM_INIT'),
('user.profile.read',      'user', 'profile', 'read',       'Read user profile',        'SYSTEM_INIT'),
('user.profile.update',    'user', 'profile', 'update',     'Update user profile',      'SYSTEM_INIT'),
('user.profile.delete',    'user', 'profile', 'delete',     'Delete user profile',      'SYSTEM_INIT'),
('user.account.read',      'user', 'account', 'read',       'Read user account',        'SYSTEM_INIT'),
('user.account.update',    'user', 'account', 'update',     'Update user account',      'SYSTEM_INIT'),
('user.account.suspend',   'user', 'account', 'suspend',    'Suspend user account',     'SYSTEM_INIT'),
('user.account.deactivate','user', 'account', 'deactivate', 'Deactivate user account',  'SYSTEM_INIT'),
('user.session.read',      'user', 'session', 'read',       'Read user sessions',       'SYSTEM_INIT'),
('user.session.revoke',    'user', 'session', 'revoke',     'Revoke user session',      'SYSTEM_INIT');


-- ============================================================================
-- SYSTEM ROLES
-- ============================================================================
-- These are the built-in roles that every deployment needs.
-- Domain-specific roles (e.g., TravelAgencyAdmin) should be created
-- by each project in their own migration or via the API.

INSERT INTO roles (id, name, display_name, description, is_system_role, created_by) VALUES
('10000000-0000-0000-0000-000000000001', 'SuperAdmin',
 'Super Administrator',
 'Global super user with full platform access.',
 true, 'SYSTEM_INIT'),

('10000000-0000-0000-0000-000000000002', 'CountryAdmin',
 'Country Administrator',
 'Country-level administrator for all organizations and governance.',
 true, 'SYSTEM_INIT'),

('10000000-0000-0000-0000-000000000003', 'AccessAdmin',
 'Access Administrator',
 'Manages roles, assignments, deny rules, and policies.',
 true, 'SYSTEM_INIT'),

('10000000-0000-0000-0000-000000000004', 'SecurityAdmin',
 'Security Administrator',
 'Manages identity lifecycle and security controls.',
 true, 'SYSTEM_INIT'),

('10000000-0000-0000-0000-000000000005', 'AuditViewer',
 'Audit Viewer',
 'Read-only access to audit and reporting.',
 true, 'SYSTEM_INIT'),

('10000000-0000-0000-0000-000000000006', 'OperationsAdmin',
 'Operations Administrator',
 'Cross-domain operations role for incidents and workflows.',
 true, 'SYSTEM_INIT'),

('10000000-0000-0000-0000-000000000007', 'GovernmentOversight',
 'Government Oversight',
 'Read-only oversight across domains at country level.',
 true, 'SYSTEM_INIT');


-- ============================================================================
-- ROLE-PERMISSION MAPPINGS: System Roles
-- ============================================================================

-- SuperAdmin -> ALL permissions
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '10000000-0000-0000-0000-000000000001', id, 'SYSTEM_INIT'
FROM permissions
WHERE is_deprecated = false;

-- CountryAdmin -> platform + organization + read/approve breadth
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '10000000-0000-0000-0000-000000000002', id, 'SYSTEM_INIT'
FROM permissions
WHERE is_deprecated = false
  AND (
      domain IN ('platform', 'organization')
      OR action IN ('read', 'approve')
  );

-- AccessAdmin -> role, scope, assignment, deny_rule, policy management
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '10000000-0000-0000-0000-000000000003', id, 'SYSTEM_INIT'
FROM permissions
WHERE is_deprecated = false
  AND (
      key LIKE 'platform.role.%'
      OR key LIKE 'platform.scope.%'
      OR key LIKE 'platform.assignment.%'
      OR key LIKE 'platform.deny_rule.%'
      OR key LIKE 'platform.policy.%'
      OR key = 'platform.permission.read'
  );

-- SecurityAdmin -> identity lifecycle + security
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '10000000-0000-0000-0000-000000000004', id, 'SYSTEM_INIT'
FROM permissions
WHERE is_deprecated = false
  AND (
      key LIKE 'platform.identity.%'
      OR key = 'platform.audit.read'
      OR key LIKE 'user.account.%'
      OR key LIKE 'user.session.%'
      OR key = 'user.profile.read'
  );

-- AuditViewer -> all read + analytics
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '10000000-0000-0000-0000-000000000005', id, 'SYSTEM_INIT'
FROM permissions
WHERE is_deprecated = false
  AND (action = 'read' OR key = 'platform.analytics.view');

-- OperationsAdmin -> broad read + approve + org member read
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '10000000-0000-0000-0000-000000000006', id, 'SYSTEM_INIT'
FROM permissions
WHERE is_deprecated = false
  AND (
      action = 'read'
      OR key = 'organization.member.read'
      OR key = 'user.profile.read'
  );

-- GovernmentOversight -> read-only across all domains + analytics
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '10000000-0000-0000-0000-000000000007', id, 'SYSTEM_INIT'
FROM permissions
WHERE is_deprecated = false
  AND (action = 'read' OR key = 'platform.analytics.view');
