# IAM Service – Postman Testing Guide

This guide walks you through **testing every API** in Postman, step‑by‑step, with **example requests and responses**, plus the **full flow** needed to validate authorization behavior. IDs and timestamps will differ in your environment.

---

## 0) Postman Environment Setup

Create a Postman environment with these variables:

- `base_url` = `http://localhost:8080`
- `admin_jwt` = `<JWT with role IAM_ADMIN>`
- `internal_api_key` = `dev-internal-key` (from `.env`)

**Headers to use:**
- Admin endpoints: `Authorization: Bearer {{admin_jwt}}`
- Internal authorize endpoints: `X-Internal-Api-Key: {{internal_api_key}}`
- Always set: `Content-Type: application/json`

### JWT requirements (admin endpoints)
Your JWT **must** contain `roles` with `IAM_ADMIN`.
Minimal payload example:
```json
{
  "sub": "admin-user-1",
  "iss": "iam-service",
  "aud": "iam-admin",
  "roles": ["IAM_ADMIN"],
  "iat": 1700000000,
  "exp": 1893456000
}
```
Use **HS256** with the secret in `IAM_JWT_SECRET`.

---

## 1) Health & Metrics (No Auth)

### 1.1 Health (Cache stats)
**GET** `{{base_url}}/api/v1/health/cache-stats`

**Example Response**
```json
{
  "permissionCacheSize": 4,
  "denyRulesCacheSize": 1,
  "scopeCacheSize": 3,
  "roleCacheSize": 2,
  "policyCacheSize": 1
}
```

### 1.2 Metrics
**GET** `{{base_url}}/api/v1/health/metrics`

**Example Response**
```json
{
  "authorization.allow.total": 2,
  "authorization.deny.total": 1,
  "authorization.cache.hit.total": 5,
  "authorization.cache.miss.total": 3,
  "authorization.avg.latency.ms": 2.7,
  "authorization.max.latency.ms": 12.3,
  "authorization.total.checks": 8,
  "cache.stats": {
    "permissionCacheSize": 4,
    "denyRulesCacheSize": 1,
    "scopeCacheSize": 3,
    "roleCacheSize": 2,
    "policyCacheSize": 1
  }
}
```

---

## 2) Create Scopes (Hierarchy)

Scopes are **required** for assignments and authorization.

### 2.0 List scopes
**GET** `{{base_url}}/api/v1/scopes?type=ORG`
**Auth:** Bearer admin token

### 2.1 Get scope by ID
**GET** `{{base_url}}/api/v1/scopes/{{scope_id}}`
**Auth:** Bearer admin token

### 2.2 Create GLOBAL scope
**POST** `{{base_url}}/api/v1/scopes`
**Auth:** Bearer admin token

**Body**
```json
{
  "type": "GLOBAL",
  "name": "Global",
  "code": "GLOBAL"
}
```

**Example Response**
```json
{
  "id": "6b8c23e2-31bd-4f09-8dc0-5ac2f0b1b9e8",
  "type": "GLOBAL",
  "name": "Global",
  "code": "GLOBAL",
  "parentId": null,
  "path": "GLOBAL",
  "depth": 0,
  "metadata": {},
  "active": true,
  "createdAt": "2026-01-25T16:50:00Z",
  "updatedAt": "2026-01-25T16:50:00Z",
  "createdBy": "system"
}
```

### 2.3 Create REGION scope
**POST** `{{base_url}}/api/v1/scopes`
**Auth:** Bearer admin token

**Body**
```json
{
  "type": "REGION",
  "name": "Asia",
  "code": "ASIA",
  "parentId": "6b8c23e2-31bd-4f09-8dc0-5ac2f0b1b9e8",
  "metadata": {
    "regionCode": "ASIA"
  }
}
```

**Example Response**
```json
{
  "id": "c1c3bb34-97fb-4f4f-bc22-6d9e7ad0b3d4",
  "type": "REGION",
  "name": "Asia",
  "code": "ASIA",
  "parentId": "6b8c23e2-31bd-4f09-8dc0-5ac2f0b1b9e8",
  "path": "GLOBAL.ASIA",
  "depth": 1,
  "metadata": {"regionCode": "ASIA"},
  "active": true,
  "createdAt": "2026-01-25T16:51:00Z",
  "updatedAt": "2026-01-25T16:51:00Z",
  "createdBy": "system"
}
```

### 2.4 Create COUNTRY scope
**POST** `{{base_url}}/api/v1/scopes`
**Auth:** Bearer admin token

**Body**
```json
{
  "type": "COUNTRY",
  "name": "Nepal",
  "code": "NP",
  "parentId": "REGION_SCOPE_ID",
  "metadata": {
    "countryCode": "NP"
  }
}
```

### 2.5 Create ORG scope
**POST** `{{base_url}}/api/v1/scopes`
**Auth:** Bearer admin token

**Body**
```json
{
  "type": "ORG",
  "name": "Everest Travels",
  "code": "EVT",
  "parentId": "COUNTRY_SCOPE_ID",
  "metadata": {
    "orgType": "TRAVEL_AGENCY"
  }
}
```

**Note:** Replace `REGION_SCOPE_ID` and `COUNTRY_SCOPE_ID` with the IDs returned from the REGION and COUNTRY scope creation.

### 2.6 Get descendants
**GET** `{{base_url}}/api/v1/scopes/{{scope_id}}/descendants`
**Auth:** Bearer admin token

---

## 3) Create Permissions

### 3.0 List permissions
**GET** `{{base_url}}/api/v1/permissions?domain=booking`
**Auth:** Bearer admin token

### 3.1 Get permission by ID
**GET** `{{base_url}}/api/v1/permissions/{{permission_id}}`
**Auth:** Bearer admin token

### 3.2 Create permission (single)
**POST** `{{base_url}}/api/v1/permissions`
**Auth:** Bearer admin token

**Body**
```json
{
  "key": "booking.reservation.read",
  "domain": "booking",
  "resource": "reservation",
  "action": "read",
  "description": "Read reservation details"
}
```

**Example Response**
```json
{
  "id": "41cfe4cf-f3e4-42f9-aad1-7be79f4bf3c1",
  "key": "booking.reservation.read",
  "domain": "booking",
  "resource": "reservation",
  "action": "read",
  "description": "Read reservation details",
  "isDeprecated": false,
  "createdAt": "2026-01-25T16:52:00Z",
  "createdBy": "system"
}
```

### 3.3 Create permissions (batch)
**POST** `{{base_url}}/api/v1/permissions`
**Auth:** Bearer admin token

**Body**
```json
[
  {
    "key": "booking.reservation.read",
    "domain": "booking",
    "resource": "reservation",
    "action": "read",
    "description": "Read reservation details"
  },
  {
    "key": "booking.reservation.approve",
    "domain": "booking",
    "resource": "reservation",
    "action": "approve",
    "description": "Approve reservation"
  }
]
```

**Example Response**
```json
[
  {
    "id": "41cfe4cf-f3e4-42f9-aad1-7be79f4bf3c1",
    "key": "booking.reservation.read",
    "domain": "booking",
    "resource": "reservation",
    "action": "read",
    "description": "Read reservation details",
    "isDeprecated": false,
    "createdAt": "2026-01-25T16:52:00Z",
    "createdBy": "system"
  },
  {
    "id": "7f8c2f20-3f94-45b9-a5c4-9c1e1250a3cd",
    "key": "booking.reservation.approve",
    "domain": "booking",
    "resource": "reservation",
    "action": "approve",
    "description": "Approve reservation",
    "isDeprecated": false,
    "createdAt": "2026-01-25T16:52:00Z",
    "createdBy": "system"
  }
]
```

**More permissions (optional):**
Create `booking.reservation.approve` and `booking.reservation.cancel` for richer tests.

---

## 4) Create Role + Attach Permissions

### 4.0 List roles
**GET** `{{base_url}}/api/v1/roles?orgType=TRAVEL_AGENCY`
**Auth:** Bearer admin token

### 4.1 Get role by ID
**GET** `{{base_url}}/api/v1/roles/{{role_id}}`
**Auth:** Bearer admin token

### 4.2 Create role with permissions
**POST** `{{base_url}}/api/v1/roles`
**Auth:** Bearer admin token

**Body**
```json
{
  "name": "ReservationAgent",
  "displayName": "Reservation Agent",
  "description": "Can read reservations",
  "orgType": "TRAVEL_AGENCY",
  "permissionIds": ["41cfe4cf-f3e4-42f9-aad1-7be79f4bf3c1"]
}
```

**Example Response**
```json
{
  "id": "b21a6c9a-76da-4f9c-99d0-15fdb7795d88",
  "name": "ReservationAgent",
  "displayName": "Reservation Agent",
  "description": "Can read reservations",
  "isSystemRole": false,
  "orgType": "TRAVEL_AGENCY",
  "active": true,
  "createdAt": "2026-01-25T16:53:00Z",
  "updatedAt": "2026-01-25T16:53:00Z",
  "createdBy": "system"
}
```

### 4.3 View role permissions
**GET** `{{base_url}}/api/v1/roles/{{role_id}}/permissions`
**Auth:** Bearer admin token

**Example Response**
```json
[
  {
    "id": "41cfe4cf-f3e4-42f9-aad1-7be79f4bf3c1",
    "key": "booking.reservation.read",
    "domain": "booking",
    "resource": "reservation",
    "action": "read",
    "description": "Read reservation details",
    "isDeprecated": false,
    "createdAt": "2026-01-25T16:52:00Z",
    "createdBy": "system"
  }
]
```

### 4.4 Replace role permissions
**PUT** `{{base_url}}/api/v1/roles/{{role_id}}/permissions`
**Auth:** Bearer admin token

**Body**
```json
[
  "41cfe4cf-f3e4-42f9-aad1-7be79f4bf3c1"
]
```

---

## 5) Role Hierarchy (Optional)

A child role inherits all permissions from its parent.

### 5.1 Create hierarchy
**POST** `{{base_url}}/api/v1/role-hierarchy`
**Auth:** Bearer admin token

**Body**
```json
{
  "parentRoleId": "parent-role-uuid",
  "childRoleId": "child-role-uuid"
}
```

### 5.2 Get parents/children
**GET** `{{base_url}}/api/v1/role-hierarchy/parents/{{role_id}}`
**GET** `{{base_url}}/api/v1/role-hierarchy/children/{{role_id}}`
**Auth:** Bearer admin token

**Note:** parent and child cannot be the same.

---

## 6) Create Assignment (Attach Role to Subject)

### 6.0 List assignments
**GET** `{{base_url}}/api/v1/assignments?subjectId=user-123`
**Auth:** Bearer admin token

### 6.1 Revoke assignment
**DELETE** `{{base_url}}/api/v1/assignments/{{assignment_id}}?revokedBy=admin-user-1&reason=manual+revoke`
**Auth:** Bearer admin token

### 6.2 Assign role to user
**POST** `{{base_url}}/api/v1/assignments`
**Auth:** Bearer admin token

**Body**
```json
{
  "subjectId": "user-123",
  "subjectType": "USER",
  "roleId": "b21a6c9a-76da-4f9c-99d0-15fdb7795d88",
  "scopeId": "2efb5de7-9b9b-4746-a7b0-3bda1cc1c6b1",
  "grantedBy": "admin-user-1",
  "conditions": {
    "time_window": "09:00-18:00",
    "ip_ranges": ["10.0.0.0/8"],
    "require_mfa": true
  }
}
```

**Example Response**
```json
{
  "id": "7e9b6bc9-88b1-4e9f-9e53-223ce43a6df1",
  "subjectId": "user-123",
  "subjectType": "USER",
  "roleId": "b21a6c9a-76da-4f9c-99d0-15fdb7795d88",
  "scopeId": "2efb5de7-9b9b-4746-a7b0-3bda1cc1c6b1",
  "effect": "ALLOW",
  "grantedBy": "admin-user-1",
  "grantedAt": "2026-01-25T16:55:00Z",
  "expiresAt": null,
  "conditions": {
    "time_window": "09:00-18:00",
    "ip_ranges": ["10.0.0.0/8"],
    "require_mfa": true
  },
  "active": true,
  "revokedAt": null,
  "revokedBy": null,
  "revokeReason": null
}
```

---

## 7) Deny Rules (Explicit Deny)

Deny rules override everything.

### 7.0 List deny rules
**GET** `{{base_url}}/api/v1/deny-rules?subjectId=user-123`
**Auth:** Bearer admin token

### 7.1 Create deny rule
**POST** `{{base_url}}/api/v1/deny-rules`
**Auth:** Bearer admin token

**Body**
```json
{
  "subjectId": "user-123",
  "permissionKey": "booking.reservation.read",
  "scopeId": "2efb5de7-9b9b-4746-a7b0-3bda1cc1c6b1",
  "reason": "Investigation hold",
  "createdBy": "admin-user-1"
}
```

### 7.2 Remove deny rule
**DELETE** `{{base_url}}/api/v1/deny-rules/{{deny_rule_id}}`
**Auth:** Bearer admin token

**Example Response**
```json
{
  "id": "0b66a51c-6f29-4f35-8a92-5d49e4c2ac70",
  "subjectId": "user-123",
  "permissionKey": "booking.reservation.read",
  "scopeId": "2efb5de7-9b9b-4746-a7b0-3bda1cc1c6b1",
  "reason": "Investigation hold",
  "referenceId": null,
  "createdBy": "admin-user-1",
  "createdAt": "2026-01-25T16:56:00Z",
  "expiresAt": null,
  "active": true
}
```

---

## 8) Policy Engine (ABAC / ReBAC)

Policies are optional and **evaluated after role/deny checks**. If any `ALLOW` policy exists, at least one must match.

### 8.0 List policies
**GET** `{{base_url}}/api/v1/policies`
**Auth:** Bearer admin token

### 8.1 Get policy by ID
**GET** `{{base_url}}/api/v1/policies/{{policy_id}}`
**Auth:** Bearer admin token

### 8.2 Create policy
**POST** `{{base_url}}/api/v1/policies`
**Auth:** Bearer admin token

**Body**
```json
{
  "name": "Allow-read-own-reservations",
  "description": "User can read their own reservations",
  "permissionKey": "booking.reservation.read",
  "resourceType": "reservation",
  "scopeId": "2efb5de7-9b9b-4746-a7b0-3bda1cc1c6b1",
  "effect": "ALLOW",
  "priority": 10,
  "conditions": {
    "all": [
      {"field": "subject", "op": "eq", "value": "$resource.metadata.ownerId"}
    ]
  },
  "active": true,
  "createdBy": "admin-user-1"
}
```

### 8.3 Update policy
**PUT** `{{base_url}}/api/v1/policies/{{policy_id}}`
**Auth:** Bearer admin token

**Body**
```json
{
  "description": "Updated description",
  "priority": 5,
  "active": true
}
```

### 8.4 Deactivate policy
**DELETE** `{{base_url}}/api/v1/policies/{{policy_id}}`
**Auth:** Bearer admin token

**Example Response**
```json
{
  "id": "b1f25136-2af1-4f26-8f70-4c3eece8c211",
  "name": "Allow-read-own-reservations",
  "description": "User can read their own reservations",
  "permissionKey": "booking.reservation.read",
  "resourceType": "reservation",
  "scopeId": "2efb5de7-9b9b-4746-a7b0-3bda1cc1c6b1",
  "effect": "ALLOW",
  "priority": 10,
  "conditions": {
    "all": [
      {"field": "subject", "op": "eq", "value": "$resource.metadata.ownerId"}
    ]
  },
  "active": true,
  "createdAt": "2026-01-25T16:57:00Z",
  "updatedAt": "2026-01-25T16:57:00Z",
  "createdBy": "admin-user-1"
}
```

### Policy conditions (operators)
Supported operators:
- `eq`, `neq`, `in`, `not_in`, `contains`, `exists`
- `gt`, `gte`, `lt`, `lte`
- `regex`, `before`, `after`

Supported fields:
- `subject`, `permission`
- `resource.type`, `resource.id`, `resource.scopeId`, `resource.metadata.*`
- `context.timestamp`, `context.ipAddress`, `context.userAgent`, `context.sessionId`, `context.requestId`
- `context.additional.*`

---

## 9) Authorization Check (Core Flow)

This endpoint is used by other services at runtime.

### 9.1 Single authorization
**POST** `{{base_url}}/api/v1/authorize`
**Auth:** `X-Internal-Api-Key: {{internal_api_key}}` (or Bearer token with IAM_ADMIN/IAM_CLIENT)

**Body**
```json
{
  "subject": "user-123",
  "permission": "booking.reservation.read",
  "resource": {
    "type": "reservation",
    "id": "res-999",
    "scopeId": "2efb5de7-9b9b-4746-a7b0-3bda1cc1c6b1",
    "metadata": {
      "ownerId": "user-123"
    }
  },
  "context": {
    "timestamp": "2026-01-25T17:00:00Z",
    "ipAddress": "10.1.2.3",
    "userAgent": "PostmanRuntime/7.39",
    "sessionId": "sess-abc",
    "requestId": "req-123",
    "additionalContext": {
      "mfa": true
    }
  }
}
```

**Example Response (ALLOW)**
```json
{
  "authorized": true,
  "reason": "ALLOW: Permission granted via role assignment",
  "effectivePermissions": ["booking.reservation.read"],
  "auditId": "fa2bd0c0-7052-48b8-99c8-0fd3c4e06264",
  "timestamp": "2026-01-25T17:00:00Z",
  "latencyMs": 3
}
```

**Example Response (DENY: explicit deny rule)**
```json
{
  "authorized": false,
  "reason": "DENY: Explicit deny rule exists",
  "effectivePermissions": [],
  "auditId": "8be0e941-ff50-4de7-a71a-3546f46a4085",
  "timestamp": "2026-01-25T17:00:00Z",
  "latencyMs": 2
}
```

### 9.2 Batch authorization
**POST** `{{base_url}}/api/v1/authorize/batch`
**Auth:** `X-Internal-Api-Key: {{internal_api_key}}`

**Body**
```json
[
  {
    "subject": "user-123",
    "permission": "booking.reservation.read",
    "resource": {"type": "reservation", "id": "res-1", "scopeId": "2efb5de7-9b9b-4746-a7b0-3bda1cc1c6b1"}
  },
  {
    "subject": "user-123",
    "permission": "booking.reservation.cancel",
    "resource": {"type": "reservation", "id": "res-2", "scopeId": "2efb5de7-9b9b-4746-a7b0-3bda1cc1c6b1"}
  }
]
```

**Example Response**
```json
{
  "booking.reservation.read:res-1": {
    "authorized": true,
    "reason": "ALLOW: Permission granted via role assignment",
    "effectivePermissions": ["booking.reservation.read"],
    "auditId": "e6f7a8e2-2f6d-4b93-9a41-2d8c5f9b3e37",
    "timestamp": "2026-01-25T17:01:00Z",
    "latencyMs": 2
  },
  "booking.reservation.cancel:res-2": {
    "authorized": false,
    "reason": "DENY: Permission not granted by any role",
    "effectivePermissions": [],
    "auditId": "4c93d8f8-1e2f-4588-b2a8-8d0f3e6a5a2e",
    "timestamp": "2026-01-25T17:01:00Z",
    "latencyMs": 2
  }
}
```

---

### 9.3 Effective permissions (bootstrap)
**POST** `{{base_url}}/api/v1/effective-permissions`
**Auth:** `X-Internal-Api-Key: {{internal_api_key}}` (or Bearer token with IAM_ADMIN/IAM_CLIENT)

**Body**
```json
{
  "subject": "user-123",
  "scopeId": "2efb5de7-9b9b-4746-a7b0-3bda1cc1c6b1",
  "resource": {
    "type": "reservation"
  },
  "context": {
    "ipAddress": "10.1.2.3",
    "additionalContext": {
      "mfa": true
    }
  },
  "includeDenied": true
}
```

**Example Response**
```json
{
  "subject": "user-123",
  "scopeId": "2efb5de7-9b9b-4746-a7b0-3bda1cc1c6b1",
  "permissions": [
    "booking.reservation.read",
    "booking.reservation.create"
  ],
  "deniedPermissions": [
    "booking.reservation.cancel"
  ]
}
```

**Note:** If you omit `resource` or `context`, permissions that depend on conditions (MFA, ownership, time window) may be excluded.

---

## 10) Audit Logs

### 10.1 Audit by subject
**GET** `{{base_url}}/api/v1/audit/subject/user-123?limit=50`
**Auth:** Bearer admin token

**Example Response**
```json
[
  {
    "id": "fa2bd0c0-7052-48b8-99c8-0fd3c4e06264",
    "subjectId": "user-123",
    "permissionKey": "booking.reservation.read",
    "resourceType": "reservation",
    "resourceId": "res-999",
    "scopeId": "2efb5de7-9b9b-4746-a7b0-3bda1cc1c6b1",
    "decision": true,
    "reason": "ALLOW: Permission granted via role assignment",
    "context": {"mfa": true},
    "requestId": "req-123",
    "ipAddress": "10.1.2.3",
    "userAgent": "PostmanRuntime/7.39",
    "timestamp": "2026-01-25T17:00:00Z"
  }
]
```

### 10.2 Audit by resource
**GET** `{{base_url}}/api/v1/audit/resource/reservation/res-999?limit=50`
**Auth:** Bearer admin token

### 10.3 Audit stats
**GET** `{{base_url}}/api/v1/audit/statistics/user-123?sinceDaysAgo=7`
**Auth:** Bearer admin token

**Example Response**
```json
{
  "total": 12,
  "allowed": 9,
  "denied": 3,
  "allowRate": 0.75,
  "byPermission": {
    "booking.reservation.read": 10,
    "booking.reservation.cancel": 2
  }
}
```

---

## 11) Permission Groups (Optional UI feature)

### 11.0 List permission groups
**GET** `{{base_url}}/api/v1/permission-groups`
**Auth:** Bearer admin token

### 11.1 Get permission group by ID
**GET** `{{base_url}}/api/v1/permission-groups/{{group_id}}`
**Auth:** Bearer admin token

### 11.2 Create group
**POST** `{{base_url}}/api/v1/permission-groups`
**Auth:** Bearer admin token

**Body**
```json
{
  "name": "Reservations",
  "description": "Reservation-related permissions"
}
```

**Example Response**
```json
{
  "id": "cc3a7c3c-2ee0-4ad1-8bb7-0a6e2dff1e2a",
  "name": "Reservations",
  "description": "Reservation-related permissions",
  "parentGroupId": null,
  "createdAt": "2026-01-25T17:10:00Z"
}
```

### 11.3 Update group permissions
**PUT** `{{base_url}}/api/v1/permission-groups/{{group_id}}/permissions`
**Auth:** Bearer admin token

**Body**
```json


```

---

## 12) Error Responses (Validation + Forbidden)

### 12.1 Validation error example
**POST** `{{base_url}}/api/v1/permissions` with missing fields

**Example Response (400)**
```json
{
  "timestamp": "2026-01-25T17:20:00Z",
  "status": 400,
  "error": "Validation Failed",
  "message": "Input validation failed",
  "path": "/api/v1/permissions",
  "validationErrors": {
    "key": "must not be blank",
    "domain": "must not be blank"
  }
}
```

### 12.2 Forbidden error example
**GET** `{{base_url}}/api/v1/roles` without admin token

**Example Response (403)**
```json
{
  "timestamp": "2026-01-25T17:21:00Z",
  "status": 403,
  "error": "Forbidden",
  "message": "Access is denied",
  "path": "/api/v1/roles"
}
```

---

## 13) Full End‑to‑End Flow (Recommended Order)

1. Create GLOBAL scope
2. Create REGION scope under GLOBAL
3. Create COUNTRY scope under REGION
4. Create ORG scope under COUNTRY
5. Create permissions
6. Create role with permissions
7. (Optional) add role hierarchy
8. Create assignment for subject + scope
9. (Optional) create deny rule or policy
10. Call `/authorize`
11. Fetch audit logs and stats

---

## Tips

- **Deny rules override everything** (even policies).
- **Policies**: if any `ALLOW` policy exists for a permission, at least one must match or request is denied.
- **Assignment conditions** are evaluated when permissions are checked; they can block a permission even if role grants it.
- `scopeId` is crucial: assignments are scoped, and scope containment is enforced.
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbi11c2VyLTEiLCJpc3MiOiJpYW0tc2VydmljZSIsImF1ZCI6ImlhbS1hZG1pbiIsInJvbGVzIjpbIklBTV9BRE1JTiJdLCJpYXQiOjE3NjkzNjE1OTUsImV4cCI6MTc3MTk1MzU5NX0.DGZkDZvp3DKEqoCQIAscODXwk3SghzdZcEHY3i5nsgU
