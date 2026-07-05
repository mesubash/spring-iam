-- ============================================================================
-- V6 — AccessAdmin needs platform.identity.read.
-- The admin console's user picker (assignments, deny rules, grants, groups)
-- lists identities; AccessAdmin manages all of those objects, so it must be
-- able to resolve subjects by email instead of typing raw UUIDs.
-- ============================================================================

INSERT INTO role_permissions (role_id, permission_id, granted_by)
SELECT '10000000-0000-0000-0000-000000000003', p.id, 'SYSTEM_INIT'
FROM permissions p
WHERE p.key = 'platform.identity.read'
ON CONFLICT DO NOTHING;
