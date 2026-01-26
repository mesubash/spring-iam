# Project Status

Last updated: 2026-01-25

## Implemented

- Core authorization engine (RBAC + scope containment + DENY overrides)
- Scoped DENY rule evaluation using scope_closure containment
- ABAC condition evaluation (time window, IP ranges, MFA flag, ownership checks, subject-match fields)
- Role hierarchy support (effective permissions include inherited roles + management endpoints)
- Permission groups (CRUD + membership management endpoints)
- Audit logging with immutable entity and response auditId
- Automated audit partition creation (monthly, scheduled)
- Policy engine (ABAC/ReBAC) with JSON conditions + policy management endpoints
- JWT admin security with role-based endpoint protection
- Audit retention automation (drop/detach old partitions)
- Redis caching for permissions, deny rules, scope containment, role permissions
- Health/metrics endpoints with Micrometer
- Optional API key security filter for internal access
- Flyway migrations added (schema moved to db/migration)

## Partially Implemented

- ReBAC/ownership policies: supported via conditions + resource metadata; policy engine available but needs policy definitions

## Planned / Not Implemented

- Policy DSL or external policy engine (e.g., OPA-style rules)
- External archival pipeline for audit partitions (off-DB storage)
- UI/admin console for permission groups, roles, scopes
- Advanced analytics dashboards for audit logs

## Notes

- If `iam.security.internal-api-key` is empty, API key checks are disabled.
- Conditional assignments skip permission caching for correctness.
