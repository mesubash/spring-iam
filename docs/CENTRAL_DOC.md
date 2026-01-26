# Spring IAM - Centralized Documentation

Last updated: 2026-01-25

## 1) What this service does

This is a centralized authorization service. Every other service asks it one question:

"Can subject S perform permission P on resource R right now?"

The service answers by checking:
1) DENY rules (hard override)
2) Role + scope (RBAC + hierarchy)
3) Assignment conditions (ABAC in assignments)
4) Policies (optional ABAC/ReBAC rules)
5) Audit log (every decision)

If any check fails, the request is denied and logged.

## 2) End-to-end authorization flow (real life)

Example: Sita wants to approve Order #123 inside Everest Travels.

1) DENY rules:
   - If Sita has an active deny rule (e.g., order.order.approve), it is blocked immediately.
2) Roles + scopes:
   - If Sita has TravelAgencyAdmin at Everest Travels, she can approve orders inside that org.
3) Assignment conditions:
   - If her assignment has a time window (09:00-17:00), IP restriction, or ownership constraint, those must pass.
4) Policies:
   - If a policy says "cannot approve own created" or "only assigned operator," it is evaluated here.
5) Audit:
   - The decision is saved to authorization_audit.

## 3) Security model

Two ways to authenticate calls:
- API key (internal services)
  - Header: X-Internal-Api-Key: <key>
  - Or Authorization: ApiKey <key>
- JWT (admin or service calls)
  - Header: Authorization: Bearer <token>
  - Role-based access:
    - ROLE_IAM_ADMIN: admin endpoints
    - ROLE_INTERNAL / ROLE_IAM_CLIENT / ROLE_IAM_ADMIN: /authorize

Public endpoints:
- /api/v1/health/**
- /actuator/**
- /swagger-ui/**, /api-docs/**

## 4) Data model (core tables)

- permissions
  Immutable list of all permissions (domain.resource.action)

- roles, role_permissions
  Roles bundle permissions

- scopes, scope_closure
  Hierarchical org tree (GLOBAL -> REGION -> COUNTRY -> ...)
  scope_closure = precomputed hierarchy for fast contains checks

- assignments
  Subject -> role + scope + optional conditions

- deny_rules
  Explicit deny overrides (can be scoped)

- authorization_audit
  Immutable log of every authorization decision

- permission_groups (optional)
  Logical grouping of permissions for UI

- role_hierarchy (optional)
  Role inheritance (child inherits parent permissions)

- policies (optional)
  ABAC/ReBAC rules evaluated after RBAC

## 5) Controllers and endpoints

Authorization
- POST /api/v1/authorize
- POST /api/v1/authorize/batch

Permissions
- GET /api/v1/permissions?domain=order
- GET /api/v1/permissions/{id}
- POST /api/v1/permissions

Roles
- GET /api/v1/roles?orgType=TRAVEL_AGENCY
- GET /api/v1/roles/{id}
- GET /api/v1/roles/{id}/permissions
- POST /api/v1/roles
- PUT /api/v1/roles/{id}/permissions

Scopes
- GET /api/v1/scopes?type=ORG
- GET /api/v1/scopes/{id}
- GET /api/v1/scopes/{id}/descendants
- POST /api/v1/scopes

Assignments
- GET /api/v1/assignments?subjectId=user_ram
- POST /api/v1/assignments
- DELETE /api/v1/assignments/{id}?revokedBy=admin&reason=policy

Deny Rules
- GET /api/v1/deny-rules?subjectId=user_ram
- POST /api/v1/deny-rules
- DELETE /api/v1/deny-rules/{id}

Audit
- GET /api/v1/audit/subject/{subjectId}?limit=100
- GET /api/v1/audit/resource/{resourceType}/{resourceId}?limit=100
- GET /api/v1/audit/statistics/{subjectId}?sinceDaysAgo=7

Health
- GET /api/v1/health/cache-stats
- GET /api/v1/health/metrics

Permission Groups
- GET /api/v1/permission-groups
- GET /api/v1/permission-groups/{id}
- POST /api/v1/permission-groups
- GET /api/v1/permission-groups/{id}/permissions
- PUT /api/v1/permission-groups/{id}/permissions

Role Hierarchy
- GET /api/v1/role-hierarchy/parents/{roleId}
- GET /api/v1/role-hierarchy/children/{roleId}
- POST /api/v1/role-hierarchy
- DELETE /api/v1/role-hierarchy?parentRoleId=...&childRoleId=...

Policies
- GET /api/v1/policies
- GET /api/v1/policies/{id}
- POST /api/v1/policies
- PUT /api/v1/policies/{id}
- DELETE /api/v1/policies/{id}

## 6) Assignment conditions (ABAC inside assignments)

Supported keys (jsonb):
- time_window / timeWindow: "HH:mm-HH:mm" (e.g., "09:00-17:00")
- timezone / timeZone: "Asia/Kathmandu" (default UTC)
- ip_ranges / ipRanges: ["103.0.0.0/8", "192.168.1.0/24"]
- require_mfa / requireMfa: true
- ownership_required / ownershipRequired: true
- can_only_access_own_created / canOnlyAccessOwnCreated: true
- cannot_approve_own_created / cannotApproveOwnCreated: true
- subject_match_fields / subjectMatchFields: ["ownerId", "assignedOperatorId"]

Ownership checks look in:
- resource.metadata.ownerId / createdBy / created_by
- context.additionalContext.ownerId

## 7) Policy engine (ABAC/ReBAC)

Policies are JSON trees stored in policies.conditions. Example:

{
  "all": [
    {"field": "subject", "op": "neq", "value": "$resource.ownerId"},
    {"field": "context.ipAddress", "op": "in", "value": ["103.0.0.0/8"]}
  ]
}

Supported operators:
- eq, neq, in, not_in, contains, exists
- gt, gte, lt, lte (numbers)
- regex
- before, after (timestamps)

Supported fields:
- subject, permission
- resource.type, resource.id, resource.scopeId
- resource.metadata.<key> or resource.<key>
- context.timestamp, context.ipAddress, context.userAgent, context.sessionId, context.requestId
- context.additional.<key> or context.<key>

Policy matching:
- DENY policy match => immediate deny
- If any ALLOW policies exist, at least one must match

## 8) Caching & performance

Redis caches:
- permissions (per user + scope)
- deny rules
- scope containment
- role permissions
- policy lists

TTL settings are in application.yml (iam.authorization.cache.*)

## 9) Auditing & partitions

Every authorization decision is written to authorization_audit.
Partitions are created monthly automatically.
Retention can drop or detach old partitions.

## 10) Running the service

1) Configure .env or environment variables (see .env.example)
2) Start DB + Redis
3) Run: ./mvnw spring-boot:run

Swagger UI: /swagger-ui.html
Actuator: /actuator/health
