-- ============================================================================
-- SEED DATA: Permissions, Roles, Role-Permission Mappings, Scopes
-- ============================================================================

-- ============================================================================
-- SCOPE HIERARCHY: GLOBAL -> REGION -> COUNTRY
-- ============================================================================

-- Asia Pacific region
INSERT INTO scopes (id, type, name, code, parent_id, path, depth, created_by)
VALUES (
    '00000000-0000-0000-0000-000000000010',
    'REGION', 'Asia Pacific', 'ASIA_PACIFIC',
    '00000000-0000-0000-0000-000000000001',
    'GLOBAL.ASIA_PACIFIC'::ltree, 1, 'SYSTEM_INIT'
);

-- Nepal country
INSERT INTO scopes (id, type, name, code, parent_id, path, depth, metadata, created_by)
VALUES (
    '00000000-0000-0000-0000-000000000100',
    'COUNTRY', 'Nepal', 'NEPAL',
    '00000000-0000-0000-0000-000000000010',
    'GLOBAL.ASIA_PACIFIC.NEPAL'::ltree, 2,
    '{"country_code": "NP", "currency": "NPR"}'::jsonb,
    'SYSTEM_INIT'
);


-- ============================================================================
-- PERMISSIONS: domain.resource.action
-- ============================================================================

-- Platform / IAM
INSERT INTO permissions (key, domain, resource, action, description, created_by) VALUES
('platform.identity.create',     'platform', 'identity',    'create',   'Create identity',                         'SYSTEM_INIT'),
('platform.identity.read',       'platform', 'identity',    'read',     'Read identity',                           'SYSTEM_INIT'),
('platform.identity.update',     'platform', 'identity',    'update',   'Update identity',                         'SYSTEM_INIT'),
('platform.identity.suspend',    'platform', 'identity',    'suspend',  'Suspend identity',                        'SYSTEM_INIT'),
('platform.identity.deactivate', 'platform', 'identity',    'deactivate','Deactivate identity',                    'SYSTEM_INIT'),
('platform.role.create',         'platform', 'role',        'create',   'Create role',                             'SYSTEM_INIT'),
('platform.role.read',           'platform', 'role',        'read',     'Read role',                               'SYSTEM_INIT'),
('platform.role.update',         'platform', 'role',        'update',   'Update role',                             'SYSTEM_INIT'),
('platform.role.delete',         'platform', 'role',        'delete',   'Delete/deactivate role',                  'SYSTEM_INIT'),
('platform.scope.create',        'platform', 'scope',       'create',   'Create scope',                            'SYSTEM_INIT'),
('platform.scope.read',          'platform', 'scope',       'read',     'Read scope',                              'SYSTEM_INIT'),
('platform.scope.update',        'platform', 'scope',       'update',   'Update scope',                            'SYSTEM_INIT'),
('platform.assignment.create',   'platform', 'assignment',  'create',   'Create assignment',                       'SYSTEM_INIT'),
('platform.assignment.read',     'platform', 'assignment',  'read',     'Read assignment',                         'SYSTEM_INIT'),
('platform.assignment.revoke',   'platform', 'assignment',  'revoke',   'Revoke assignment',                       'SYSTEM_INIT'),
('platform.deny_rule.create',    'platform', 'deny_rule',   'create',   'Create deny rule',                        'SYSTEM_INIT'),
('platform.deny_rule.read',      'platform', 'deny_rule',   'read',     'Read deny rule',                          'SYSTEM_INIT'),
('platform.deny_rule.delete',    'platform', 'deny_rule',   'delete',   'Delete deny rule',                        'SYSTEM_INIT'),
('platform.policy.create',       'platform', 'policy',      'create',   'Create policy',                           'SYSTEM_INIT'),
('platform.policy.read',         'platform', 'policy',      'read',     'Read policy',                             'SYSTEM_INIT'),
('platform.policy.update',       'platform', 'policy',      'update',   'Update policy',                           'SYSTEM_INIT'),
('platform.policy.delete',       'platform', 'policy',      'delete',   'Delete policy',                           'SYSTEM_INIT'),
('platform.audit.read',          'platform', 'audit',       'read',     'Read authorization audit',                'SYSTEM_INIT'),
('platform.permission.read',     'platform', 'permission',  'read',     'Read permissions registry',               'SYSTEM_INIT'),
('platform.analytics.view',      'platform', 'analytics',   'view',     'View analytics',                          'SYSTEM_INIT');

-- Organization governance
INSERT INTO permissions (key, domain, resource, action, description, created_by) VALUES
('organization.organization.create', 'organization', 'organization', 'create',  'Create organization',     'SYSTEM_INIT'),
('organization.organization.read',   'organization', 'organization', 'read',    'Read organization',       'SYSTEM_INIT'),
('organization.organization.update', 'organization', 'organization', 'update',  'Update organization',     'SYSTEM_INIT'),
('organization.organization.approve','organization', 'organization', 'approve', 'Approve organization',    'SYSTEM_INIT'),
('organization.organization.suspend','organization', 'organization', 'suspend', 'Suspend organization',    'SYSTEM_INIT'),
('organization.member.create',       'organization', 'member',       'create',  'Create org member',       'SYSTEM_INIT'),
('organization.member.read',         'organization', 'member',       'read',    'Read org member',         'SYSTEM_INIT'),
('organization.member.update',       'organization', 'member',       'update',  'Update org member',       'SYSTEM_INIT'),
('organization.member.remove',       'organization', 'member',       'remove',  'Remove org member',       'SYSTEM_INIT');

-- User domain
INSERT INTO permissions (key, domain, resource, action, description, created_by) VALUES
('user.profile.create',    'user', 'profile', 'create',     'Create user profile',               'SYSTEM_INIT'),
('user.profile.read',      'user', 'profile', 'read',       'Read user profile',                 'SYSTEM_INIT'),
('user.profile.update',    'user', 'profile', 'update',     'Update user profile',               'SYSTEM_INIT'),
('user.profile.delete',    'user', 'profile', 'delete',     'Delete user profile',               'SYSTEM_INIT'),
('user.account.read',      'user', 'account', 'read',       'Read user account',                 'SYSTEM_INIT'),
('user.account.update',    'user', 'account', 'update',     'Update user account',               'SYSTEM_INIT'),
('user.account.suspend',   'user', 'account', 'suspend',    'Suspend user account',              'SYSTEM_INIT'),
('user.account.deactivate','user', 'account', 'deactivate', 'Deactivate user account',           'SYSTEM_INIT'),
('user.session.read',      'user', 'session', 'read',       'Read user sessions',                'SYSTEM_INIT'),
('user.session.revoke',    'user', 'session', 'revoke',     'Revoke user session',               'SYSTEM_INIT');

-- Order domain
INSERT INTO permissions (key, domain, resource, action, description, created_by) VALUES
('order.order.create',   'order', 'order',  'create',  'Create order',                      'SYSTEM_INIT'),
('order.order.read',     'order', 'order',  'read',    'Read order',                        'SYSTEM_INIT'),
('order.order.update',   'order', 'order',  'update',  'Update order',                      'SYSTEM_INIT'),
('order.order.approve',  'order', 'order',  'approve', 'Approve order',                     'SYSTEM_INIT'),
('order.order.cancel',   'order', 'order',  'cancel',  'Cancel order',                      'SYSTEM_INIT'),
('order.order.delete',   'order', 'order',  'delete',  'Delete order',                      'SYSTEM_INIT'),
('order.item.create',    'order', 'item',   'create',  'Create order item',                 'SYSTEM_INIT'),
('order.item.read',      'order', 'item',   'read',    'Read order item',                   'SYSTEM_INIT'),
('order.item.update',    'order', 'item',   'update',  'Update order item',                 'SYSTEM_INIT'),
('order.item.delete',    'order', 'item',   'delete',  'Delete order item',                 'SYSTEM_INIT'),
('order.group.create',   'order', 'group',  'create',  'Create order group',                'SYSTEM_INIT'),
('order.group.read',     'order', 'group',  'read',    'Read order group',                  'SYSTEM_INIT'),
('order.group.update',   'order', 'group',  'update',  'Update order group',                'SYSTEM_INIT'),
('order.group.delete',   'order', 'group',  'delete',  'Delete order group',                'SYSTEM_INIT'),
('order.report.read',    'order', 'report', 'read',    'Read order report',                 'SYSTEM_INIT'),
('order.report.export',  'order', 'report', 'export',  'Export order report',               'SYSTEM_INIT');

-- Payment domain
INSERT INTO permissions (key, domain, resource, action, description, created_by) VALUES
('payment.transaction.initiate', 'payment', 'transaction', 'initiate', 'Initiate transaction',          'SYSTEM_INIT'),
('payment.transaction.read',     'payment', 'transaction', 'read',     'Read transaction',              'SYSTEM_INIT'),
('payment.transaction.approve',  'payment', 'transaction', 'approve',  'Approve transaction',           'SYSTEM_INIT'),
('payment.transaction.refund',   'payment', 'transaction', 'refund',   'Refund transaction',            'SYSTEM_INIT'),
('payment.transaction.settle',   'payment', 'transaction', 'settle',   'Settle transaction',            'SYSTEM_INIT'),
('payment.invoice.create',       'payment', 'invoice',     'create',   'Create invoice',                'SYSTEM_INIT'),
('payment.invoice.read',         'payment', 'invoice',     'read',     'Read invoice',                  'SYSTEM_INIT'),
('payment.invoice.update',       'payment', 'invoice',     'update',   'Update invoice',                'SYSTEM_INIT'),
('payment.report.read',          'payment', 'report',      'read',     'Read payment report',           'SYSTEM_INIT'),
('payment.report.export',        'payment', 'report',      'export',   'Export payment report',         'SYSTEM_INIT');

-- Insurance domain
INSERT INTO permissions (key, domain, resource, action, description, created_by) VALUES
('insurance.provider.create', 'insurance', 'provider', 'create',  'Create insurance provider',         'SYSTEM_INIT'),
('insurance.provider.read',   'insurance', 'provider', 'read',    'Read insurance provider',           'SYSTEM_INIT'),
('insurance.provider.update', 'insurance', 'provider', 'update',  'Update insurance provider',         'SYSTEM_INIT'),
('insurance.policy.create',   'insurance', 'policy',   'create',  'Create insurance policy',           'SYSTEM_INIT'),
('insurance.policy.read',     'insurance', 'policy',   'read',    'Read insurance policy',             'SYSTEM_INIT'),
('insurance.policy.update',   'insurance', 'policy',   'update',  'Update insurance policy',           'SYSTEM_INIT'),
('insurance.policy.approve',  'insurance', 'policy',   'approve', 'Approve insurance policy',          'SYSTEM_INIT'),
('insurance.claim.create',    'insurance', 'claim',    'create',  'Create insurance claim',            'SYSTEM_INIT'),
('insurance.claim.read',      'insurance', 'claim',    'read',    'Read insurance claim',              'SYSTEM_INIT'),
('insurance.claim.approve',   'insurance', 'claim',    'approve', 'Approve insurance claim',           'SYSTEM_INIT'),
('insurance.claim.reject',    'insurance', 'claim',    'reject',  'Reject insurance claim',            'SYSTEM_INIT'),
('insurance.claim.settle',    'insurance', 'claim',    'settle',  'Settle insurance claim',            'SYSTEM_INIT');

-- Rescue domain
INSERT INTO permissions (key, domain, resource, action, description, created_by) VALUES
('rescue.sos.read',        'rescue', 'sos',      'read',     'Read SOS',                       'SYSTEM_INIT'),
('rescue.sos.respond',     'rescue', 'sos',      'respond',  'Respond SOS',                    'SYSTEM_INIT'),
('rescue.sos.escalate',    'rescue', 'sos',      'escalate', 'Escalate SOS',                   'SYSTEM_INIT'),
('rescue.mission.create',  'rescue', 'mission',  'create',   'Create mission',                 'SYSTEM_INIT'),
('rescue.mission.read',    'rescue', 'mission',  'read',     'Read mission',                   'SYSTEM_INIT'),
('rescue.mission.update',  'rescue', 'mission',  'update',   'Update mission',                 'SYSTEM_INIT'),
('rescue.mission.close',   'rescue', 'mission',  'close',    'Close mission',                  'SYSTEM_INIT'),
('rescue.dispatch.create', 'rescue', 'dispatch', 'create',   'Create dispatch',                'SYSTEM_INIT'),
('rescue.dispatch.read',   'rescue', 'dispatch', 'read',     'Read dispatch',                  'SYSTEM_INIT'),
('rescue.dispatch.update', 'rescue', 'dispatch', 'update',   'Update dispatch',                'SYSTEM_INIT');

-- Document domain
INSERT INTO permissions (key, domain, resource, action, description, created_by) VALUES
('document.file.upload',     'document', 'file',     'upload',   'Upload file',                 'SYSTEM_INIT'),
('document.file.read',       'document', 'file',     'read',     'Read file',                   'SYSTEM_INIT'),
('document.file.update',     'document', 'file',     'update',   'Update file metadata',        'SYSTEM_INIT'),
('document.file.delete',     'document', 'file',     'delete',   'Delete file',                 'SYSTEM_INIT'),
('document.file.download',   'document', 'file',     'download', 'Download file',               'SYSTEM_INIT'),
('document.file.export',     'document', 'file',     'export',   'Export file',                 'SYSTEM_INIT'),
('document.template.create', 'document', 'template', 'create',   'Create template',             'SYSTEM_INIT'),
('document.template.read',   'document', 'template', 'read',     'Read template',               'SYSTEM_INIT'),
('document.template.update', 'document', 'template', 'update',   'Update template',             'SYSTEM_INIT'),
('document.template.delete', 'document', 'template', 'delete',   'Delete template',             'SYSTEM_INIT');

-- Notification domain
INSERT INTO permissions (key, domain, resource, action, description, created_by) VALUES
('notification.message.send',      'notification', 'message',  'send',      'Send notification message',  'SYSTEM_INIT'),
('notification.message.read',      'notification', 'message',  'read',      'Read notification message',  'SYSTEM_INIT'),
('notification.message.retry',     'notification', 'message',  'retry',     'Retry notification message', 'SYSTEM_INIT'),
('notification.campaign.create',   'notification', 'campaign', 'create',    'Create campaign',            'SYSTEM_INIT'),
('notification.campaign.read',     'notification', 'campaign', 'read',      'Read campaign',              'SYSTEM_INIT'),
('notification.campaign.update',   'notification', 'campaign', 'update',    'Update campaign',            'SYSTEM_INIT'),
('notification.campaign.schedule', 'notification', 'campaign', 'schedule',  'Schedule campaign',          'SYSTEM_INIT'),
('notification.campaign.send',     'notification', 'campaign', 'send',      'Send campaign',              'SYSTEM_INIT'),
('notification.template.create',   'notification', 'template', 'create',    'Create notification template','SYSTEM_INIT'),
('notification.template.read',     'notification', 'template', 'read',      'Read notification template',  'SYSTEM_INIT'),
('notification.template.update',   'notification', 'template', 'update',    'Update notification template','SYSTEM_INIT'),
('notification.template.delete',   'notification', 'template', 'delete',    'Delete notification template','SYSTEM_INIT');


-- ============================================================================
-- ROLES
-- ============================================================================

-- System roles (not tied to org type)
INSERT INTO roles (id, name, display_name, description, is_system_role, created_by) VALUES
('10000000-0000-0000-0000-000000000001', 'SuperAdmin',
 'Super Administrator',
 'Global super user with full platform access. Not an organization role.',
 true, 'SYSTEM_INIT'),
('10000000-0000-0000-0000-000000000002', 'CountryAdmin',
 'Country Administrator',
 'Country-level administrator for all organizations and governance operations.',
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
 'Read-only access to audit and reporting capabilities.',
 true, 'SYSTEM_INIT'),
('10000000-0000-0000-0000-000000000006', 'OperationsAdmin',
 'Operations Administrator',
 'Cross-domain operations role for handling incidents and operations workflows.',
 true, 'SYSTEM_INIT'),
('10000000-0000-0000-0000-000000000007', 'GovernmentOversight',
 'Government Oversight',
 'Read-only oversight across domains at country level.',
 true, 'SYSTEM_INIT');

-- Operations organization roles
INSERT INTO roles (id, name, display_name, description, org_type, created_by) VALUES
('70000000-0000-0000-0000-000000000001', 'OperationsOrgAdmin',
 'Operations Org Administrator',
 'Admin role for Operations organization.',
 'OPERATIONS', 'SYSTEM_INIT'),
('70000000-0000-0000-0000-000000000002', 'OperationsOfficer',
 'Operations Officer',
 'Operator role for Operations organization.',
 'OPERATIONS', 'SYSTEM_INIT');

-- Travel agency roles
INSERT INTO roles (id, name, display_name, description, org_type, created_by) VALUES
('20000000-0000-0000-0000-000000000001', 'TravelAgencyAdmin',
 'Travel Agency Administrator',
 'Admin role for Travel Agency operations.',
 'TRAVEL_AGENCY', 'SYSTEM_INIT'),
('20000000-0000-0000-0000-000000000002', 'TravelAgencyManager',
 'Travel Agency Manager',
 'Manager role for Travel Agency operations.',
 'TRAVEL_AGENCY', 'SYSTEM_INIT'),
('20000000-0000-0000-0000-000000000003', 'TravelAgencyStaff',
 'Travel Agency Staff',
 'Staff role for Travel Agency operations.',
 'TRAVEL_AGENCY', 'SYSTEM_INIT');

-- Sales agency roles
INSERT INTO roles (id, name, display_name, description, org_type, created_by) VALUES
('20000000-0000-0000-0000-000000000010', 'SalesAgencyAdmin',
 'Sales Agency Administrator',
 'Admin role for Sales Agency operations.',
 'SALES_AGENCY', 'SYSTEM_INIT'),
('20000000-0000-0000-0000-000000000011', 'SalesAgencyAgent',
 'Sales Agency Agent',
 'Agent role for Sales Agency operations.',
 'SALES_AGENCY', 'SYSTEM_INIT');

-- Rescue centre and rescue company roles
INSERT INTO roles (id, name, display_name, description, org_type, created_by) VALUES
('30000000-0000-0000-0000-000000000004', 'RescueCentreAdmin',
 'Rescue Centre Administrator',
 'Admin role for Rescue Centre operations.',
 'RESCUE_CENTRE', 'SYSTEM_INIT'),
('30000000-0000-0000-0000-000000000003', 'RescueDispatcher',
 'Rescue Dispatcher',
 'Dispatcher role for Rescue Centre operations.',
 'RESCUE_CENTRE', 'SYSTEM_INIT'),
('30000000-0000-0000-0000-000000000001', 'RescueCompanyAdmin',
 'Rescue Company Administrator',
 'Admin role for Rescue Company operations.',
 'RESCUE_COMPANY', 'SYSTEM_INIT'),
('30000000-0000-0000-0000-000000000002', 'RescueOperator',
 'Rescue Operator',
 'Operator role for Rescue Company operations.',
 'RESCUE_COMPANY', 'SYSTEM_INIT');

-- Insurance company roles
INSERT INTO roles (id, name, display_name, description, org_type, created_by) VALUES
('40000000-0000-0000-0000-000000000001', 'InsuranceCompanyAdmin',
 'Insurance Company Administrator',
 'Admin role for Insurance Company operations.',
 'INSURANCE_COMPANY', 'SYSTEM_INIT'),
('40000000-0000-0000-0000-000000000002', 'InsuranceReviewer',
 'Insurance Reviewer',
 'Reviewer role for Insurance Company claim workflows.',
 'INSURANCE_COMPANY', 'SYSTEM_INIT');

-- Hospital roles
INSERT INTO roles (id, name, display_name, description, org_type, created_by) VALUES
('50000000-0000-0000-0000-000000000001', 'HospitalAdmin',
 'Hospital Administrator',
 'Admin role for Hospital operations.',
 'HOSPITAL', 'SYSTEM_INIT'),
('50000000-0000-0000-0000-000000000002', 'HospitalOperator',
 'Hospital Operator',
 'Operator role for Hospital operations.',
 'HOSPITAL', 'SYSTEM_INIT');

-- Service provider roles
INSERT INTO roles (id, name, display_name, description, org_type, created_by) VALUES
('80000000-0000-0000-0000-000000000001', 'ServiceProviderAdmin',
 'Service Provider Administrator',
 'Admin role for Service Provider operations.',
 'SERVICE_PROVIDER', 'SYSTEM_INIT'),
('80000000-0000-0000-0000-000000000002', 'ServiceProviderOperator',
 'Service Provider Operator',
 'Operator role for Service Provider operations.',
 'SERVICE_PROVIDER', 'SYSTEM_INIT');

-- Government body organization roles
INSERT INTO roles (id, name, display_name, description, org_type, created_by) VALUES
('60000000-0000-0000-0000-000000000010', 'GovernmentBodyAdmin',
 'Government Body Administrator',
 'Admin role for Government Body workflows.',
 'GOVERNMENT_BODY', 'SYSTEM_INIT'),
('60000000-0000-0000-0000-000000000011', 'GovernmentBodyAnalyst',
 'Government Body Analyst',
 'Analyst role for Government Body reporting.',
 'GOVERNMENT_BODY', 'SYSTEM_INIT');


-- ============================================================================
-- ROLE <-> PERMISSION MAPPINGS
-- ============================================================================

-- SuperAdmin -> all permissions
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

-- AccessAdmin
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

-- SecurityAdmin
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

-- AuditViewer
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '10000000-0000-0000-0000-000000000005', id, 'SYSTEM_INIT'
FROM permissions
WHERE is_deprecated = false
  AND (action = 'read' OR key = 'platform.analytics.view');

-- OperationsAdmin (central)
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '10000000-0000-0000-0000-000000000006', id, 'SYSTEM_INIT'
FROM permissions
WHERE is_deprecated = false
  AND key IN (
      'order.order.read', 'order.order.update', 'order.order.approve',
      'payment.transaction.read', 'payment.transaction.approve', 'payment.transaction.refund',
      'document.file.read', 'document.file.download',
      'notification.message.read', 'notification.message.send',
      'rescue.sos.read', 'rescue.sos.respond',
      'organization.member.read', 'user.profile.read'
  );

-- GovernmentOversight (system)
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '10000000-0000-0000-0000-000000000007', id, 'SYSTEM_INIT'
FROM permissions
WHERE is_deprecated = false
  AND (
      (domain IN ('organization', 'user', 'order', 'payment', 'insurance', 'rescue', 'document', 'notification')
       AND action = 'read')
      OR key = 'platform.analytics.view'
  );

-- OperationsOrgAdmin
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '70000000-0000-0000-0000-000000000001', id, 'SYSTEM_INIT'
FROM permissions
WHERE is_deprecated = false
  AND (
      domain IN ('organization', 'user', 'order', 'payment', 'document', 'notification')
      OR key IN ('rescue.sos.read', 'rescue.sos.respond')
  );

-- OperationsOfficer
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '70000000-0000-0000-0000-000000000002', id, 'SYSTEM_INIT'
FROM permissions
WHERE is_deprecated = false
  AND key IN (
      'order.order.read', 'order.order.update',
      'payment.transaction.read',
      'document.file.read', 'document.file.download',
      'notification.message.read', 'notification.message.send',
      'rescue.sos.read',
      'organization.member.read'
  );

-- TravelAgencyAdmin
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '20000000-0000-0000-0000-000000000001', id, 'SYSTEM_INIT'
FROM permissions
WHERE is_deprecated = false
  AND key IN (
      'order.order.create', 'order.order.read', 'order.order.update', 'order.order.approve',
      'order.item.create', 'order.item.read', 'order.item.update',
      'order.group.create', 'order.group.read', 'order.group.update',
      'payment.transaction.initiate', 'payment.transaction.read',
      'payment.invoice.create', 'payment.invoice.read', 'payment.invoice.update',
      'document.file.upload', 'document.file.read', 'document.file.download', 'document.file.export',
      'notification.message.send', 'notification.message.read',
      'user.profile.read', 'user.profile.update',
      'organization.member.read'
  );

-- TravelAgencyManager
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '20000000-0000-0000-0000-000000000002', id, 'SYSTEM_INIT'
FROM permissions
WHERE is_deprecated = false
  AND key IN (
      'order.order.create', 'order.order.read', 'order.order.update', 'order.order.approve',
      'order.item.read', 'order.group.read',
      'payment.transaction.read', 'payment.invoice.read',
      'document.file.upload', 'document.file.read', 'document.file.download',
      'notification.message.send', 'notification.message.read',
      'user.profile.read'
  );

-- TravelAgencyStaff
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '20000000-0000-0000-0000-000000000003', id, 'SYSTEM_INIT'
FROM permissions
WHERE is_deprecated = false
  AND key IN (
      'order.order.create', 'order.order.read',
      'order.item.create', 'order.item.read',
      'document.file.upload', 'document.file.read',
      'notification.message.send', 'notification.message.read',
      'user.profile.read'
  );

-- SalesAgencyAdmin
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '20000000-0000-0000-0000-000000000010', id, 'SYSTEM_INIT'
FROM permissions
WHERE is_deprecated = false
  AND key IN (
      'order.order.create', 'order.order.read', 'order.order.update', 'order.order.approve',
      'order.item.create', 'order.item.read',
      'payment.transaction.initiate', 'payment.transaction.read', 'payment.invoice.read',
      'notification.message.send', 'notification.message.read',
      'document.file.upload', 'document.file.read',
      'user.profile.read'
  );

-- SalesAgencyAgent
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '20000000-0000-0000-0000-000000000011', id, 'SYSTEM_INIT'
FROM permissions
WHERE is_deprecated = false
  AND key IN (
      'order.order.create', 'order.order.read',
      'order.item.read',
      'payment.transaction.read',
      'notification.message.send', 'notification.message.read',
      'user.profile.read'
  );

-- RescueCentreAdmin
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '30000000-0000-0000-0000-000000000004', id, 'SYSTEM_INIT'
FROM permissions
WHERE is_deprecated = false
  AND (
      domain = 'rescue'
      OR key IN ('document.file.read', 'document.file.upload', 'notification.message.send', 'notification.message.read', 'user.profile.read')
  );

-- RescueDispatcher
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '30000000-0000-0000-0000-000000000003', id, 'SYSTEM_INIT'
FROM permissions
WHERE is_deprecated = false
  AND key IN (
      'rescue.sos.read', 'rescue.sos.respond', 'rescue.sos.escalate',
      'rescue.dispatch.create', 'rescue.dispatch.read', 'rescue.dispatch.update',
      'rescue.mission.read', 'rescue.mission.update',
      'notification.message.send', 'notification.message.read',
      'user.profile.read'
  );

-- RescueCompanyAdmin
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '30000000-0000-0000-0000-000000000001', id, 'SYSTEM_INIT'
FROM permissions
WHERE is_deprecated = false
  AND key IN (
      'rescue.mission.create', 'rescue.mission.read', 'rescue.mission.update', 'rescue.mission.close',
      'rescue.dispatch.create', 'rescue.dispatch.read', 'rescue.dispatch.update',
      'rescue.sos.read', 'rescue.sos.respond',
      'document.file.read', 'document.file.upload',
      'user.profile.read'
  );

-- RescueOperator
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '30000000-0000-0000-0000-000000000002', id, 'SYSTEM_INIT'
FROM permissions
WHERE is_deprecated = false
  AND key IN (
      'rescue.mission.read', 'rescue.mission.update',
      'rescue.dispatch.read', 'rescue.dispatch.update',
      'rescue.sos.read', 'rescue.sos.respond',
      'user.profile.read'
  );

-- InsuranceCompanyAdmin
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '40000000-0000-0000-0000-000000000001', id, 'SYSTEM_INIT'
FROM permissions
WHERE is_deprecated = false
  AND (
      domain = 'insurance'
      OR key IN (
          'payment.transaction.read', 'payment.transaction.refund',
          'document.file.read', 'document.file.upload',
          'notification.message.send', 'notification.message.read',
          'user.profile.read'
      )
  );

-- InsuranceReviewer
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '40000000-0000-0000-0000-000000000002', id, 'SYSTEM_INIT'
FROM permissions
WHERE is_deprecated = false
  AND key IN (
      'insurance.claim.read', 'insurance.claim.approve', 'insurance.claim.reject', 'insurance.claim.settle',
      'insurance.policy.read',
      'document.file.read',
      'user.profile.read'
  );

-- HospitalAdmin
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '50000000-0000-0000-0000-000000000001', id, 'SYSTEM_INIT'
FROM permissions
WHERE is_deprecated = false
  AND key IN (
      'user.profile.read', 'user.profile.update',
      'document.file.read', 'document.file.upload', 'document.file.download',
      'rescue.sos.read', 'rescue.sos.respond',
      'notification.message.send', 'notification.message.read'
  );

-- HospitalOperator
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '50000000-0000-0000-0000-000000000002', id, 'SYSTEM_INIT'
FROM permissions
WHERE is_deprecated = false
  AND key IN (
      'user.profile.read',
      'document.file.read', 'document.file.upload',
      'rescue.sos.read',
      'notification.message.read'
  );

-- ServiceProviderAdmin
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '80000000-0000-0000-0000-000000000001', id, 'SYSTEM_INIT'
FROM permissions
WHERE is_deprecated = false
  AND key IN (
      'document.file.upload', 'document.file.read', 'document.file.update', 'document.file.delete', 'document.file.download', 'document.file.export',
      'document.template.create', 'document.template.read', 'document.template.update', 'document.template.delete',
      'notification.campaign.create', 'notification.campaign.read', 'notification.campaign.update', 'notification.campaign.schedule', 'notification.campaign.send',
      'notification.message.send', 'notification.message.read', 'notification.message.retry',
      'order.order.read',
      'payment.invoice.read'
  );

-- ServiceProviderOperator
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '80000000-0000-0000-0000-000000000002', id, 'SYSTEM_INIT'
FROM permissions
WHERE is_deprecated = false
  AND key IN (
      'document.file.upload', 'document.file.read', 'document.file.download',
      'notification.message.send', 'notification.message.read',
      'order.order.read'
  );

-- GovernmentBodyAdmin
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '60000000-0000-0000-0000-000000000010', id, 'SYSTEM_INIT'
FROM permissions
WHERE is_deprecated = false
  AND key IN (
      'organization.organization.read', 'organization.member.read',
      'user.profile.read', 'user.account.read',
      'order.report.read',
      'payment.report.read',
      'insurance.claim.read',
      'rescue.mission.read',
      'document.file.read',
      'notification.campaign.read',
      'platform.analytics.view'
  );

-- GovernmentBodyAnalyst
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '60000000-0000-0000-0000-000000000011', id, 'SYSTEM_INIT'
FROM permissions
WHERE is_deprecated = false
  AND key IN (
      'organization.organization.read',
      'user.profile.read',
      'order.report.read',
      'payment.report.read',
      'insurance.claim.read',
      'rescue.mission.read',
      'document.file.read',
      'notification.campaign.read'
  );
