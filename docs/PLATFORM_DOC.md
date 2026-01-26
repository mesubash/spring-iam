# Spring IAM Platform - Comprehensive Documentation

Last updated: 2026-01-25

## 1) Purpose

Spring IAM is a centralized authorization platform. All services call it to answer:

"Can subject S perform permission P on resource R under context C?"

It ensures consistent access control, multi-tenant isolation, auditability, and performance.

## 2) High-level Architecture

- API Service: Spring Boot
- Database: PostgreSQL (schema + partitions + triggers)
- Cache: Redis
- Security: API Key + JWT (role-based)

Request flow:
1) Client/service calls IAM /authorize
2) IAM checks DENY rules
3) IAM checks active assignments + roles + scope containment
4) IAM enforces assignment conditions (ABAC)
5) IAM evaluates policies (ABAC/ReBAC)
6) IAM writes audit log

## 3) Core Authorization Flow (exact order)

Decision pipeline:
1) DENY rules (global or scoped, wildcard supported) -> immediate deny
2) Role permissions + scope containment
3) Assignment conditions (time, IP, ownership, MFA, subject-match)
4) Policies (optional ABAC/ReBAC logic)
5) Audit log written for every decision

If any step fails -> DENY + audit.

## 4) Security Model

Two authentication mechanisms:
- API Key (internal service-to-service)
  - Header: X-Internal-Api-Key: <key>
  - Or Authorization: ApiKey <key>

- JWT (admin/service access)
  - Header: Authorization: Bearer <token>
  - Roles from token:
    - ROLE_IAM_ADMIN -> admin endpoints
    - ROLE_INTERNAL or ROLE_IAM_CLIENT -> /authorize

Public endpoints:
- /api/v1/health/**
- /actuator/**
- /swagger-ui/**, /api-docs/**

## 5) Data Model Summary

permissions
- Immutable registry of all actions (domain.resource.action)

roles
- Named bundles of permissions

role_permissions
- Many-to-many mapping between roles and permissions

role_hierarchy (optional)
- Role inheritance (child inherits parent permissions)

scopes
- Hierarchical organization tree (GLOBAL -> REGION -> COUNTRY -> ORG -> DEPT -> TEAM -> PROJECT)

scope_closure
- Precomputed transitive closure for fast scope containment checks

assignments
- Subject assigned to a role at a specific scope
- Supports conditions (ABAC)

deny_rules
- Explicit overrides (DENY always wins)

permission_groups (optional)
- Logical grouping of permissions for UI

policies (optional)
- ABAC/ReBAC rule definitions

authorization_audit
- Immutable log of every authorization decision

## 6) Assignment Conditions (ABAC inside assignments)

Supported keys (JSON in assignments.conditions):
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

## 7) Policy Engine (ABAC/ReBAC)

Policies are JSON rules stored in policies.conditions. They run after RBAC.

Matching logic:
- DENY policy match -> immediate deny
- If any ALLOW policies exist, at least one must match

JSON structure example:
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

Supported field paths:
- subject, permission
- resource.type, resource.id, resource.scopeId
- resource.metadata.<key> or resource.<key>
- context.timestamp, context.ipAddress, context.userAgent, context.sessionId, context.requestId
- context.additional.<key> or context.<key>

## 8) Caching & Performance

Redis caches:
- permissions per user + scope (5 min)
- deny rules (1 min)
- scope containment (1 hour)
- role permissions (30 min)
- policies (2 min)

## 9) Audit Logging & Retention

- Every /authorize call generates an audit record
- authorization_audit is partitioned monthly
- Partition creation is scheduled
- Retention job drops or detaches old partitions

## 10) Error Response Format

All errors return:
{
  "timestamp": "2026-01-25T10:30:00Z",
  "status": 400,
  "error": "Bad Request",
  "message": "...",
  "path": "/api/v1/...",
  "validationErrors": {
    "field": "message"
  }
}

## 11) API Reference (complete)

### 11.1 Authorization

POST /api/v1/authorize
Auth: ROLE_INTERNAL / ROLE_IAM_CLIENT / ROLE_IAM_ADMIN
Flow:
1) DENY rules
2) RBAC + scope
3) Assignment conditions
4) Policies
5) Audit log

Request:
{
  "subject": "user_ram",
  "permission": "order.order.approve",
  "resource": {
    "type": "ORDER",
    "id": "ORD_123",
    "scopeId": "uuid",
    "metadata": {
      "ownerId": "user_sita"
    }
  },
  "context": {
    "timestamp": "2026-01-25T10:00:00Z",
    "ipAddress": "103.1.2.3",
    "userAgent": "Mozilla/5.0",
    "sessionId": "sess_abc",
    "requestId": "req_1",
    "additionalContext": {
      "mfa": true
    }
  }
}

Response:
{
  "authorized": true,
  "reason": "ALLOW: Permission granted via role assignment",
  "effectivePermissions": ["order.order.approve", "order.order.cancel"],
  "auditId": "uuid",
  "timestamp": "2026-01-25T10:00:00Z",
  "latencyMs": 4
}

POST /api/v1/authorize/batch
Auth: ROLE_INTERNAL / ROLE_IAM_CLIENT / ROLE_IAM_ADMIN
Flow: same as /authorize for each entry
Request: [ AuthorizationRequest, ... ]
Response:
{
  "permission:resourceId": AuthorizationResponse,
  "permission:resourceId": AuthorizationResponse
}

### 11.2 Permissions

GET /api/v1/permissions?domain=order
Auth: ROLE_IAM_ADMIN
Flow: Returns active permissions or domain-filtered permissions

GET /api/v1/permissions/{id}
Auth: ROLE_IAM_ADMIN
Flow: Returns permission by id

POST /api/v1/permissions
Auth: ROLE_IAM_ADMIN
Flow:
1) Validate key format
2) Ensure permission does not exist
3) Insert into permissions
Request:
{
  "key": "order.order.approve",
  "domain": "order",
  "resource": "order",
  "action": "approve",
  "description": "Approve order"
}
Response: Permission entity

### 11.3 Roles

GET /api/v1/roles?orgType=TRAVEL_AGENCY
Auth: ROLE_IAM_ADMIN
Flow: Returns active roles (optionally by orgType)

GET /api/v1/roles/{id}
Auth: ROLE_IAM_ADMIN
Flow: Returns role by id

GET /api/v1/roles/{id}/permissions
Auth: ROLE_IAM_ADMIN
Flow:
1) Resolve role hierarchy
2) Return full permission list (including inherited)

POST /api/v1/roles
Auth: ROLE_IAM_ADMIN
Flow:
1) Validate role name unique
2) Validate permission IDs exist
3) Insert role
4) Insert role_permissions
Request:
{
  "name": "TravelAgencyAdmin",
  "displayName": "Travel Agency Admin",
  "description": "Admin role",
  "orgType": "TRAVEL_AGENCY",
  "permissionIds": ["uuid", "uuid"]
}
Response: Role entity

PUT /api/v1/roles/{id}/permissions
Auth: ROLE_IAM_ADMIN
Flow:
1) Validate role exists and not system role
2) Validate permission IDs
3) Replace role_permissions
4) Invalidate role cache
Request: ["uuid", "uuid"]

### 11.4 Scopes

GET /api/v1/scopes?type=ORG
Auth: ROLE_IAM_ADMIN
Flow: Returns active scopes (optionally by type)

GET /api/v1/scopes/{id}
Auth: ROLE_IAM_ADMIN
Flow: Returns scope by id

GET /api/v1/scopes/{id}/descendants
Auth: ROLE_IAM_ADMIN
Flow: Returns all descendants using ltree path

POST /api/v1/scopes
Auth: ROLE_IAM_ADMIN
Flow:
1) Validate type
2) Validate parent scope
3) Compute depth + path
4) Insert scope
5) Trigger maintains scope_closure
Request:
{
  "type": "ORG",
  "name": "Everest Travels",
  "code": "EVT",
  "parentId": "uuid",
  "metadata": {"orgType": "TRAVEL_AGENCY"}
}
Response: Scope entity

### 11.5 Assignments

GET /api/v1/assignments?subjectId=user_ram
Auth: ROLE_IAM_ADMIN
Flow: Returns active assignments for subject (or all)

POST /api/v1/assignments
Auth: ROLE_IAM_ADMIN
Flow:
1) Validate role exists
2) Validate scope exists
3) Ensure assignment not already active
4) Insert assignment
5) Invalidate caches
Request:
{
  "subjectId": "user_ram",
  "subjectType": "USER",
  "roleId": "uuid",
  "scopeId": "uuid",
  "grantedBy": "admin",
  "expiresAt": "2026-12-31T23:59:59Z",
  "conditions": {
    "timeWindow": "09:00-17:00",
    "ipRanges": ["103.0.0.0/8"],
    "requireMfa": true
  }
}
Response: Assignment entity

DELETE /api/v1/assignments/{id}?revokedBy=admin&reason=policy
Auth: ROLE_IAM_ADMIN
Flow:
1) Mark assignment revoked + inactive
2) Invalidate caches

### 11.6 Deny Rules

GET /api/v1/deny-rules?subjectId=user_ram
Auth: ROLE_IAM_ADMIN
Flow: Returns active deny rules for subject

POST /api/v1/deny-rules
Auth: ROLE_IAM_ADMIN
Flow:
1) Validate permission exists or wildcard format
2) Insert deny rule
3) Invalidate deny cache
Request:
{
  "subjectId": "user_ram",
  "permissionKey": "order.order.approve",
  "scopeId": null,
  "reason": "Investigation",
  "referenceId": "SEC-2026-145",
  "createdBy": "security_admin",
  "expiresAt": "2026-02-28T23:59:59Z"
}
Response: DenyRule entity

DELETE /api/v1/deny-rules/{id}
Auth: ROLE_IAM_ADMIN
Flow:
1) Mark deny rule inactive
2) Invalidate cache

### 11.7 Permission Groups

GET /api/v1/permission-groups
Auth: ROLE_IAM_ADMIN
Flow: Returns all permission groups

GET /api/v1/permission-groups/{id}
Auth: ROLE_IAM_ADMIN
Flow: Returns permission group by id

POST /api/v1/permission-groups
Auth: ROLE_IAM_ADMIN
Flow:
1) Validate name unique
2) Validate parent group (if provided)
3) Insert group
Request:
{
  "name": "Order Management",
  "description": "Order related permissions",
  "parentGroupId": null
}

GET /api/v1/permission-groups/{id}/permissions
Auth: ROLE_IAM_ADMIN
Flow: Returns permissions in group

PUT /api/v1/permission-groups/{id}/permissions
Auth: ROLE_IAM_ADMIN
Flow:
1) Validate permission IDs
2) Replace group membership
Request:
{
  "permissionIds": ["uuid", "uuid"]
}

### 11.8 Role Hierarchy

GET /api/v1/role-hierarchy/parents/{roleId}
Auth: ROLE_IAM_ADMIN
Flow: Returns parent role IDs

GET /api/v1/role-hierarchy/children/{roleId}
Auth: ROLE_IAM_ADMIN
Flow: Returns child role IDs

POST /api/v1/role-hierarchy
Auth: ROLE_IAM_ADMIN
Flow:
1) Validate roles exist
2) Prevent cycles
3) Insert hierarchy
Request:
{
  "parentRoleId": "uuid",
  "childRoleId": "uuid"
}

DELETE /api/v1/role-hierarchy?parentRoleId=...&childRoleId=...
Auth: ROLE_IAM_ADMIN
Flow:
1) Delete hierarchy
2) Invalidate role cache

### 11.9 Policies

GET /api/v1/policies
Auth: ROLE_IAM_ADMIN
Flow: Returns all policies

GET /api/v1/policies/{id}
Auth: ROLE_IAM_ADMIN
Flow: Returns policy by id

POST /api/v1/policies
Auth: ROLE_IAM_ADMIN
Flow:
1) Validate name unique
2) Validate permissionKey if present
3) Insert policy
4) Invalidate policy cache
Request:
{
  "name": "NoSelfApproval",
  "description": "Cannot approve own orders",
  "permissionKey": "order.order.approve",
  "resourceType": "ORDER",
  "scopeId": null,
  "effect": "DENY",
  "priority": 100,
  "conditions": {
    "all": [
      {"field": "subject", "op": "eq", "value": "$resource.ownerId"}
    ]
  },
  "active": true,
  "createdBy": "system"
}

PUT /api/v1/policies/{id}
Auth: ROLE_IAM_ADMIN
Flow:
1) Update policy fields
2) Validate
3) Invalidate cache
Request:
{
  "description": "Update",
  "effect": "ALLOW",
  "priority": 10,
  "conditions": {"any": []},
  "active": true
}

DELETE /api/v1/policies/{id}
Auth: ROLE_IAM_ADMIN
Flow:
1) Mark policy inactive
2) Invalidate cache

### 11.10 Audit

GET /api/v1/audit/subject/{subjectId}?limit=100
Auth: ROLE_IAM_ADMIN
Flow: Returns recent audit logs for subject

GET /api/v1/audit/resource/{resourceType}/{resourceId}?limit=100
Auth: ROLE_IAM_ADMIN
Flow: Returns recent audit logs for resource

GET /api/v1/audit/statistics/{subjectId}?sinceDaysAgo=7
Auth: ROLE_IAM_ADMIN
Flow: Aggregates audit stats (allow/deny counts)

### 11.11 Health & Metrics

GET /api/v1/health/cache-stats
Auth: Public
Flow: Redis cache key counts

GET /api/v1/health/metrics
Auth: Public
Flow: Authz counters + latency metrics

## 12) Running the service

1) Create .env (copy from .env.example)
2) Run DB + Redis (docker-compose.yml)
3) Start service
   - docker compose up --build
   - or ./mvnw spring-boot:run

## 13) Notes

- /authorize returns auditId in every response
- Conditional assignments skip permission caching (correctness)
- Policies and conditions are optional; RBAC works without them
