-- Grants a resource server makes through /api/v1/internal/provisioning get their own origin, so
-- the provisioning API lists and revokes exactly those and never a seeded or admin-made grant
-- (the bootstrap SuperAdmin grant is MIGRATION).
ALTER TABLE assignments DROP CONSTRAINT assignments_origin_check;
ALTER TABLE assignments ADD CONSTRAINT assignments_origin_check
    CHECK (origin IN ('STANDARD', 'BREAK_GLASS', 'MIGRATION', 'PROVISIONED'));
