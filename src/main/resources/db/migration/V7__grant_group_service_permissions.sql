-- ============================================================================
-- V7 — First-class permission keys for resource grants, groups, and services.
-- These features were previously gated by @PreAuthorize("hasRole('SuperAdmin')")
-- (or bare authenticated), so the console could not gate their nav/buttons on a
-- permission and showed them to everyone. Give each a read + manage key so the
-- UI follows the same rule as every other area: nav on .read, actions on .manage.
--
-- NOTE: SuperAdmin's grant in V4 was a point-in-time snapshot
-- (WHERE is_deprecated = false at that migration), so permissions added later
-- must be granted to SuperAdmin explicitly here.
-- ============================================================================

INSERT INTO permissions (key, domain, resource, action, description, created_by) VALUES
('platform.resource_grant.read',   'platform', 'resource_grant', 'read',   'Read resource grants',   'SYSTEM_INIT'),
('platform.resource_grant.manage', 'platform', 'resource_grant', 'manage', 'Create/revoke resource grants', 'SYSTEM_INIT'),
('platform.group.read',            'platform', 'group',          'read',   'Read subject groups',    'SYSTEM_INIT'),
('platform.group.manage',          'platform', 'group',          'manage', 'Manage subject groups and members', 'SYSTEM_INIT'),
('platform.service.read',          'platform', 'service',        'read',   'Read the service registry', 'SYSTEM_INIT'),
('platform.service.manage',        'platform', 'service',        'manage', 'Register services and sync manifests', 'SYSTEM_INIT')
ON CONFLICT (key) DO NOTHING;

-- SuperAdmin (10000000-...0001): everything.
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '10000000-0000-0000-0000-000000000001', id, 'SYSTEM_INIT'
FROM permissions
WHERE key IN ('platform.resource_grant.read', 'platform.resource_grant.manage',
              'platform.group.read', 'platform.group.manage',
              'platform.service.read', 'platform.service.manage')
ON CONFLICT DO NOTHING;

-- AccessAdmin (10000000-...0003): manages access objects — grants and groups
-- (read + manage) and may view the service registry, but not register services.
INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '10000000-0000-0000-0000-000000000003', id, 'SYSTEM_INIT'
FROM permissions
WHERE key IN ('platform.resource_grant.read', 'platform.resource_grant.manage',
              'platform.group.read', 'platform.group.manage',
              'platform.service.read')
ON CONFLICT DO NOTHING;
