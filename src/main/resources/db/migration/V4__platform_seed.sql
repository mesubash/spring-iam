-- ============================================================================
-- V4 — PLATFORM SEED: IAM's own permissions + system roles
-- Project-specific permissions/roles belong in your own migration (see V5).
-- ============================================================================

INSERT INTO permissions (key, domain, resource, action, description, created_by) VALUES
('platform.identity.create',     'platform', 'identity',    'create',    'Create identity',           'SYSTEM_INIT'),
('platform.identity.read',       'platform', 'identity',    'read',      'Read identity',             'SYSTEM_INIT'),
('platform.identity.update',     'platform', 'identity',    'update',    'Update identity',           'SYSTEM_INIT'),
('platform.identity.suspend',    'platform', 'identity',    'suspend',   'Suspend identity',          'SYSTEM_INIT'),
('platform.identity.deactivate', 'platform', 'identity',    'deactivate','Deactivate identity',       'SYSTEM_INIT'),
('platform.role.create',         'platform', 'role',        'create',    'Create role',               'SYSTEM_INIT'),
('platform.role.read',           'platform', 'role',        'read',      'Read role',                 'SYSTEM_INIT'),
('platform.role.update',         'platform', 'role',        'update',    'Update role',               'SYSTEM_INIT'),
('platform.role.delete',         'platform', 'role',        'delete',    'Delete/deactivate role',    'SYSTEM_INIT'),
('platform.scope.create',        'platform', 'scope',       'create',    'Create scope',              'SYSTEM_INIT'),
('platform.scope.read',          'platform', 'scope',       'read',      'Read scope',                'SYSTEM_INIT'),
('platform.scope.update',        'platform', 'scope',       'update',    'Update scope',              'SYSTEM_INIT'),
('platform.scope.move',          'platform', 'scope',       'move',      'Move scope subtree',        'SYSTEM_INIT'),
('platform.assignment.create',   'platform', 'assignment',  'create',    'Create assignment',         'SYSTEM_INIT'),
('platform.assignment.read',     'platform', 'assignment',  'read',      'Read assignment',           'SYSTEM_INIT'),
('platform.assignment.revoke',   'platform', 'assignment',  'revoke',    'Revoke assignment',         'SYSTEM_INIT'),
('platform.deny_rule.create',    'platform', 'deny_rule',   'create',    'Create deny rule',          'SYSTEM_INIT'),
('platform.deny_rule.read',      'platform', 'deny_rule',   'read',      'Read deny rule',            'SYSTEM_INIT'),
('platform.deny_rule.delete',    'platform', 'deny_rule',   'delete',    'Delete deny rule',          'SYSTEM_INIT'),
('platform.policy.create',       'platform', 'policy',      'create',    'Create policy',             'SYSTEM_INIT'),
('platform.policy.read',         'platform', 'policy',      'read',      'Read policy',               'SYSTEM_INIT'),
('platform.policy.update',       'platform', 'policy',      'update',    'Update policy',             'SYSTEM_INIT'),
('platform.policy.delete',       'platform', 'policy',      'delete',    'Delete policy',             'SYSTEM_INIT'),
('platform.audit.read',          'platform', 'audit',       'read',      'Read authorization audit',  'SYSTEM_INIT'),
('platform.permission.read',     'platform', 'permission',  'read',      'Read permissions registry', 'SYSTEM_INIT'),
('platform.analytics.view',      'platform', 'analytics',   'view',      'View analytics',            'SYSTEM_INIT');

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

INSERT INTO permissions (key, domain, resource, action, description, created_by) VALUES
('user.account.read',      'user', 'account', 'read',       'Read user account',       'SYSTEM_INIT'),
('user.account.update',    'user', 'account', 'update',     'Update user account',     'SYSTEM_INIT'),
('user.account.suspend',   'user', 'account', 'suspend',    'Suspend user account',    'SYSTEM_INIT'),
('user.account.deactivate','user', 'account', 'deactivate', 'Deactivate user account', 'SYSTEM_INIT'),
('user.session.read',      'user', 'session', 'read',       'Read user sessions',      'SYSTEM_INIT'),
('user.session.revoke',    'user', 'session', 'revoke',     'Revoke user session',     'SYSTEM_INIT');

-- System roles: protected by is_system_role (cannot deactivate without
-- clearing the flag first — two-step retirement by design).
INSERT INTO roles (id, name, display_name, description, is_system_role, created_by) VALUES
('10000000-0000-0000-0000-000000000001', 'SuperAdmin',
 'Super Administrator', 'Full platform access.', true, 'SYSTEM_INIT'),
('10000000-0000-0000-0000-000000000002', 'CountryAdmin',
 'Country Administrator', 'Country-level governance.', true, 'SYSTEM_INIT'),
('10000000-0000-0000-0000-000000000003', 'AccessAdmin',
 'Access Administrator', 'Manages roles, assignments, deny rules, policies.', true, 'SYSTEM_INIT'),
('10000000-0000-0000-0000-000000000004', 'SecurityAdmin',
 'Security Administrator', 'Identity lifecycle and security controls.', true, 'SYSTEM_INIT'),
('10000000-0000-0000-0000-000000000005', 'AuditViewer',
 'Audit Viewer', 'Read-only audit and reporting.', true, 'SYSTEM_INIT'),
('10000000-0000-0000-0000-000000000006', 'OperationsAdmin',
 'Operations Administrator', 'Cross-domain operations.', true, 'SYSTEM_INIT'),
('10000000-0000-0000-0000-000000000007', 'GovernmentOversight',
 'Government Oversight', 'Read-only oversight at country level.', true, 'SYSTEM_INIT');

-- SuperAdmin: everything
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '10000000-0000-0000-0000-000000000001', id, 'SYSTEM_INIT'
FROM permissions WHERE is_deprecated = false;

-- CountryAdmin: platform + organization + read/approve breadth
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '10000000-0000-0000-0000-000000000002', id, 'SYSTEM_INIT'
FROM permissions
WHERE is_deprecated = false
  AND (domain IN ('platform', 'organization') OR action IN ('read', 'approve'));

-- AccessAdmin: authz object management
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '10000000-0000-0000-0000-000000000003', id, 'SYSTEM_INIT'
FROM permissions
WHERE is_deprecated = false
  AND (key LIKE 'platform.role.%' OR key LIKE 'platform.scope.%'
       OR key LIKE 'platform.assignment.%' OR key LIKE 'platform.deny_rule.%'
       OR key LIKE 'platform.policy.%' OR key = 'platform.permission.read');

-- SecurityAdmin: identity lifecycle + security
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '10000000-0000-0000-0000-000000000004', id, 'SYSTEM_INIT'
FROM permissions
WHERE is_deprecated = false
  AND (key LIKE 'platform.identity.%' OR key = 'platform.audit.read'
       OR key LIKE 'user.account.%' OR key LIKE 'user.session.%');

-- AuditViewer / GovernmentOversight: read-only + analytics
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT r.id, p.id, 'SYSTEM_INIT'
FROM roles r, permissions p
WHERE r.id IN ('10000000-0000-0000-0000-000000000005',
               '10000000-0000-0000-0000-000000000007')
  AND p.is_deprecated = false
  AND (p.action = 'read' OR p.key = 'platform.analytics.view');

-- OperationsAdmin: broad read
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '10000000-0000-0000-0000-000000000006', id, 'SYSTEM_INIT'
FROM permissions
WHERE is_deprecated = false AND action = 'read';
