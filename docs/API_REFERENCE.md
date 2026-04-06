# Spring IAM — API Reference

## Authentication

| Mechanism | Header | Granted Role |
|-----------|--------|--------------|
| API Key | `X-Internal-Api-Key: <key>` or `Authorization: ApiKey <key>` | `ROLE_INTERNAL` |
| JWT | `Authorization: Bearer <token>` | Role-based (from token claims) |

**Public endpoints (no auth required):**

| Pattern | Purpose |
|---------|---------|
| `/api/v1/health/**` | Health checks |
| `/actuator/**` | Spring Actuator |
| `/swagger-ui/**` | Swagger UI |
| `/api-docs/**` | OpenAPI docs |

---

## 1. Authorization (Core Runtime)

### POST `/api/v1/authorize`

| Property | Value |
|----------|-------|
| Auth | `ROLE_INTERNAL` / SuperAdmin / CountryAdmin |
| Content-Type | `application/json` |

**Request:**

```json
{
  "subject": "user:550e8400-e29b-41d4-a716-446655440000",
  "permission": "user:read",
  "resource": {
    "type": "USER",
    "id": "resource-uuid",
    "scopeId": "scope-uuid",
    "metadata": {
      "department": "engineering"
    }
  },
  "context": {
    "timestamp": "2026-04-06T10:00:00Z",
    "ipAddress": "192.168.1.1",
    "userAgent": "Mozilla/5.0",
    "sessionId": "session-uuid",
    "requestId": "req-uuid",
    "additionalContext": {
      "source": "admin-portal"
    }
  }
}
```

**Response — ALLOW:**

```json
{
  "authorized": true,
  "reason": "Permission granted via role COUNTRY_ADMIN at scope Nepal",
  "effectivePermissions": ["user:read", "user:write"],
  "auditId": "audit-uuid",
  "timestamp": "2026-04-06T10:00:00.123Z",
  "latencyMs": 4
}
```

**Response — DENY:**

```json
{
  "authorized": false,
  "reason": "Deny rule matched: user:write denied for subject at scope",
  "effectivePermissions": [],
  "auditId": "audit-uuid",
  "timestamp": "2026-04-06T10:00:00.456Z",
  "latencyMs": 3
}
```

---

### POST `/api/v1/authorize/batch`

| Property | Value |
|----------|-------|
| Auth | `ROLE_INTERNAL` / SuperAdmin / CountryAdmin |
| Max Items | 50 |

**Request:**

```json
[
  {
    "subject": "user:550e8400-e29b-41d4-a716-446655440000",
    "permission": "user:read",
    "resource": { "type": "USER", "id": "res-1", "scopeId": "scope-uuid" },
    "context": { "requestId": "req-uuid" }
  },
  {
    "subject": "user:550e8400-e29b-41d4-a716-446655440000",
    "permission": "user:write",
    "resource": { "type": "USER", "id": "res-2", "scopeId": "scope-uuid" },
    "context": { "requestId": "req-uuid" }
  }
]
```

**Response:**

```json
{
  "user:read:res-1": {
    "authorized": true,
    "reason": "Permission granted via role COUNTRY_ADMIN at scope Nepal",
    "effectivePermissions": ["user:read"],
    "auditId": "audit-uuid-1",
    "timestamp": "2026-04-06T10:00:00.123Z",
    "latencyMs": 3
  },
  "user:write:res-2": {
    "authorized": false,
    "reason": "No matching assignment found",
    "effectivePermissions": [],
    "auditId": "audit-uuid-2",
    "timestamp": "2026-04-06T10:00:00.125Z",
    "latencyMs": 2
  }
}
```

---

### POST `/api/v1/effective-permissions`

| Property | Value |
|----------|-------|
| Auth | `ROLE_INTERNAL` / SuperAdmin / CountryAdmin |

**Request:**

```json
{
  "subject": "user:550e8400-e29b-41d4-a716-446655440000",
  "scopeId": "scope-uuid",
  "resource": {
    "type": "USER",
    "id": "resource-uuid"
  },
  "context": {
    "requestId": "req-uuid"
  },
  "includeDenied": true
}
```

**Response:**

```json
{
  "subject": "user:550e8400-e29b-41d4-a716-446655440000",
  "scopeId": "scope-uuid",
  "permissions": [
    "user:read",
    "user:list",
    "report:read"
  ],
  "deniedPermissions": [
    "user:delete",
    "user:write"
  ]
}
```

---

## 2. User-Facing AuthZ

### GET `/api/authz/me/scopes`

| Property | Value |
|----------|-------|
| Auth | Bearer JWT |

**Response:**

```json
[
  {
    "scopeId": "scope-uuid-1",
    "scopeName": "Nepal",
    "scopeType": "COUNTRY",
    "roles": ["COUNTRY_ADMIN"]
  },
  {
    "scopeId": "scope-uuid-2",
    "scopeName": "India",
    "scopeType": "COUNTRY",
    "roles": ["ACCESS_ADMIN"]
  }
]
```

---

### GET `/api/authz/me/permissions?scopeId={id}`

| Property | Value |
|----------|-------|
| Auth | Bearer JWT |
| Query Params | `scopeId` (required) |

**Response:**

```json
{
  "permissions": [
    "user:read",
    "user:write",
    "user:list",
    "role:read",
    "report:read"
  ]
}
```

---

## 3. Permissions Management

### GET `/api/v1/permissions?domain={domain}`

| Property | Value |
|----------|-------|
| Auth | SuperAdmin |
| Query Params | `domain` (optional) |

**Response:**

```json
[
  {
    "id": "perm-uuid",
    "key": "user:read",
    "domain": "USER_MANAGEMENT",
    "resource": "USER",
    "action": "READ",
    "description": "Read user profiles"
  }
]
```

---

### GET `/api/v1/permissions/{id}`

| Property | Value |
|----------|-------|
| Auth | SuperAdmin |

**Response:**

```json
{
  "id": "perm-uuid",
  "key": "user:read",
  "domain": "USER_MANAGEMENT",
  "resource": "USER",
  "action": "READ",
  "description": "Read user profiles"
}
```

---

### POST `/api/v1/permissions`

| Property | Value |
|----------|-------|
| Auth | SuperAdmin |
| Supports Batch | Yes (send array) |

**Request (single):**

```json
{
  "key": "user:read",
  "domain": "USER_MANAGEMENT",
  "resource": "USER",
  "action": "READ",
  "description": "Read user profiles"
}
```

**Request (batch):**

```json
[
  { "key": "user:read", "domain": "USER_MANAGEMENT", "resource": "USER", "action": "READ", "description": "Read user profiles" },
  { "key": "user:write", "domain": "USER_MANAGEMENT", "resource": "USER", "action": "WRITE", "description": "Update user profiles" }
]
```

---

## 4. Roles Management

### GET `/api/v1/roles?orgType={type}`

| Property | Value |
|----------|-------|
| Auth | Authenticated (delegation enforced) |
| Query Params | `orgType` (optional) |

**Response:**

```json
[
  {
    "id": "role-uuid",
    "name": "COUNTRY_ADMIN",
    "displayName": "Country Administrator",
    "description": "Full admin access within a country scope",
    "orgType": "COUNTRY",
    "system": true,
    "permissionIds": ["perm-uuid-1", "perm-uuid-2"]
  }
]
```

---

### GET `/api/v1/roles/{id}`

| Property | Value |
|----------|-------|
| Auth | Authenticated |

---

### GET `/api/v1/roles/{id}/permissions`

| Property | Value |
|----------|-------|
| Auth | Authenticated |

**Response:**

```json
{
  "roleId": "role-uuid",
  "permissions": [
    { "id": "perm-uuid-1", "key": "user:read", "inherited": false },
    { "id": "perm-uuid-2", "key": "report:read", "inherited": true, "inheritedFrom": "parent-role-uuid" }
  ]
}
```

---

### POST `/api/v1/roles`

| Property | Value |
|----------|-------|
| Auth | Authenticated (permission ceiling enforced) |

**Request:**

```json
{
  "name": "REGIONAL_VIEWER",
  "displayName": "Regional Viewer",
  "description": "Read-only access at regional scope",
  "orgType": "REGION",
  "permissionIds": ["perm-uuid-1", "perm-uuid-2"]
}
```

---

### PUT `/api/v1/roles/{id}/permissions`

| Property | Value |
|----------|-------|
| Auth | Authenticated |
| Restriction | Cannot modify system roles |

**Request:**

```json
["perm-uuid-1", "perm-uuid-2", "perm-uuid-3"]
```

---

## 5. Scopes Management

### GET `/api/v1/scopes?type={type}`

| Property | Value |
|----------|-------|
| Auth | SuperAdmin |
| Query Params | `type` (optional) |

**Response:**

```json
[
  {
    "id": "scope-uuid",
    "type": "COUNTRY",
    "name": "Nepal",
    "code": "NP",
    "parentId": "root-scope-uuid",
    "metadata": { "region": "South Asia" }
  }
]
```

---

### GET `/api/v1/scopes/{id}`

| Property | Value |
|----------|-------|
| Auth | SuperAdmin |

---

### GET `/api/v1/scopes/{id}/descendants`

| Property | Value |
|----------|-------|
| Auth | SuperAdmin |

**Response:**

```json
[
  { "id": "child-scope-1", "type": "REGION", "name": "Province 1", "depth": 1 },
  { "id": "child-scope-2", "type": "DISTRICT", "name": "Kathmandu", "depth": 2 }
]
```

---

### POST `/api/v1/scopes`

| Property | Value |
|----------|-------|
| Auth | SuperAdmin |
| Side Effect | Auto-populates `scope_closure` table |

**Request:**

```json
{
  "type": "COUNTRY",
  "name": "Nepal",
  "code": "NP",
  "parentId": "root-scope-uuid",
  "metadata": { "region": "South Asia" }
}
```

---

## 6. Assignments Management

### GET `/api/v1/assignments?subjectId={id}`

| Property | Value |
|----------|-------|
| Auth | Authenticated (delegation enforced) |
| Query Params | `subjectId` (required) |

**Response:**

```json
[
  {
    "id": "assignment-uuid",
    "subjectId": "user-uuid",
    "subjectType": "USER",
    "roleId": "role-uuid",
    "scopeId": "scope-uuid",
    "expiresAt": "2027-01-01T00:00:00Z",
    "conditions": { "maxDelegationDepth": 2 }
  }
]
```

---

### POST `/api/v1/assignments`

| Property | Value |
|----------|-------|
| Auth | Authenticated (scope containment enforced) |

**Request:**

```json
{
  "subjectId": "user-uuid",
  "subjectType": "USER",
  "roleId": "role-uuid",
  "scopeId": "scope-uuid",
  "expiresAt": "2027-01-01T00:00:00Z",
  "conditions": {
    "maxDelegationDepth": 2
  }
}
```

---

### DELETE `/api/v1/assignments/{id}?revokedBy={who}&reason={why}`

| Property | Value |
|----------|-------|
| Auth | Authenticated (scope containment enforced) |
| Query Params | `revokedBy` (required), `reason` (required) |

**Response:**

```json
{
  "revoked": true,
  "assignmentId": "assignment-uuid",
  "revokedBy": "admin-uuid",
  "reason": "Employee offboarded"
}
```

---

## 7. Deny Rules Management

### GET `/api/v1/deny-rules?subjectId={id}`

| Property | Value |
|----------|-------|
| Auth | Authenticated (delegation enforced) |
| Query Params | `subjectId` (required) |

**Response:**

```json
[
  {
    "id": "deny-rule-uuid",
    "subjectId": "user-uuid",
    "permissionKey": "user:delete",
    "scopeId": "scope-uuid",
    "reason": "Restricted pending investigation",
    "referenceId": "ticket-123",
    "expiresAt": "2026-06-01T00:00:00Z"
  }
]
```

---

### POST `/api/v1/deny-rules`

| Property | Value |
|----------|-------|
| Auth | Authenticated (wildcard patterns require SuperAdmin) |

**Request:**

```json
{
  "subjectId": "user-uuid",
  "permissionKey": "user:delete",
  "scopeId": "scope-uuid",
  "reason": "Restricted pending investigation",
  "referenceId": "ticket-123",
  "expiresAt": "2026-06-01T00:00:00Z"
}
```

---

### DELETE `/api/v1/deny-rules/{id}`

| Property | Value |
|----------|-------|
| Auth | Authenticated |

---

## 8. Policies Management

### GET `/api/v1/policies`

| Property | Value |
|----------|-------|
| Auth | SuperAdmin |

**Response:**

```json
[
  {
    "id": "policy-uuid",
    "name": "Restrict PII Access Outside Business Hours",
    "description": "Deny PII read outside 09:00-17:00",
    "permissionKey": "pii:read",
    "resourceType": "USER",
    "scopeId": "scope-uuid",
    "effect": "DENY",
    "priority": 100,
    "conditions": {
      "timeRange": { "start": "17:00", "end": "09:00" }
    },
    "active": true
  }
]
```

---

### GET `/api/v1/policies/{id}`

| Property | Value |
|----------|-------|
| Auth | SuperAdmin |

---

### POST `/api/v1/policies`

| Property | Value |
|----------|-------|
| Auth | SuperAdmin |

**Request:**

```json
{
  "name": "Restrict PII Access Outside Business Hours",
  "description": "Deny PII read outside 09:00-17:00",
  "permissionKey": "pii:read",
  "resourceType": "USER",
  "scopeId": "scope-uuid",
  "effect": "DENY",
  "priority": 100,
  "conditions": {
    "timeRange": { "start": "17:00", "end": "09:00" }
  },
  "active": true
}
```

---

### PUT `/api/v1/policies/{id}`

| Property | Value |
|----------|-------|
| Auth | SuperAdmin |

**Request:** Same shape as POST.

---

### DELETE `/api/v1/policies/{id}`

| Property | Value |
|----------|-------|
| Auth | SuperAdmin |
| Behavior | Deactivates (soft delete) |

---

## 9. Role Hierarchy

### GET `/api/v1/role-hierarchy/parents/{roleId}`

| Property | Value |
|----------|-------|
| Auth | SuperAdmin |

**Response:**

```json
[
  { "roleId": "parent-role-uuid", "roleName": "SUPER_ADMIN", "depth": 1 }
]
```

---

### GET `/api/v1/role-hierarchy/children/{roleId}`

| Property | Value |
|----------|-------|
| Auth | SuperAdmin |

**Response:**

```json
[
  { "roleId": "child-role-uuid", "roleName": "ACCESS_ADMIN", "depth": 1 },
  { "roleId": "grandchild-role-uuid", "roleName": "VIEWER", "depth": 2 }
]
```

---

### POST `/api/v1/role-hierarchy`

| Property | Value |
|----------|-------|
| Auth | SuperAdmin |
| Validation | Prevents cycles |

**Request:**

```json
{
  "parentRoleId": "parent-role-uuid",
  "childRoleId": "child-role-uuid"
}
```

---

### DELETE `/api/v1/role-hierarchy?parentRoleId={id}&childRoleId={id}`

| Property | Value |
|----------|-------|
| Auth | SuperAdmin |

---

## 10. Permission Groups

### GET `/api/v1/permission-groups`

| Property | Value |
|----------|-------|
| Auth | SuperAdmin |

**Response:**

```json
[
  {
    "id": "group-uuid",
    "name": "User Management",
    "description": "All user management permissions",
    "parentGroupId": null
  }
]
```

---

### GET `/api/v1/permission-groups/{id}`

| Property | Value |
|----------|-------|
| Auth | SuperAdmin |

---

### POST `/api/v1/permission-groups`

| Property | Value |
|----------|-------|
| Auth | SuperAdmin |

**Request:**

```json
{
  "name": "User Management",
  "description": "All user management permissions",
  "parentGroupId": null
}
```

---

### GET `/api/v1/permission-groups/{id}/permissions`

| Property | Value |
|----------|-------|
| Auth | SuperAdmin |

**Response:**

```json
[
  { "id": "perm-uuid-1", "key": "user:read" },
  { "id": "perm-uuid-2", "key": "user:write" }
]
```

---

### PUT `/api/v1/permission-groups/{id}/permissions`

| Property | Value |
|----------|-------|
| Auth | SuperAdmin |

**Request:**

```json
["perm-uuid-1", "perm-uuid-2", "perm-uuid-3"]
```

---

## 11. Audit

### GET `/api/v1/audit/subject/{subjectId}?limit=100`

| Property | Value |
|----------|-------|
| Auth | SuperAdmin / CountryAdmin / AccessAdmin / SecurityAdmin / AuditViewer |
| Query Params | `limit` (default 100) |

**Response:**

```json
[
  {
    "auditId": "audit-uuid",
    "subject": "user:user-uuid",
    "permission": "user:read",
    "resourceType": "USER",
    "resourceId": "resource-uuid",
    "scopeId": "scope-uuid",
    "decision": "ALLOW",
    "reason": "Permission granted via role COUNTRY_ADMIN",
    "timestamp": "2026-04-06T10:00:00Z",
    "ipAddress": "192.168.1.1",
    "latencyMs": 4
  }
]
```

---

### GET `/api/v1/audit/resource/{resourceType}/{resourceId}?limit=100`

| Property | Value |
|----------|-------|
| Auth | SuperAdmin / CountryAdmin / AccessAdmin / SecurityAdmin / AuditViewer |
| Query Params | `limit` (default 100) |

---

### GET `/api/v1/audit/statistics/{subjectId}?sinceDaysAgo=7`

| Property | Value |
|----------|-------|
| Auth | SuperAdmin / CountryAdmin / AccessAdmin / SecurityAdmin / AuditViewer |
| Query Params | `sinceDaysAgo` (default 7) |

**Response:**

```json
{
  "total": 1542,
  "allowed": 1500,
  "denied": 42,
  "allowRate": 0.9728,
  "byPermission": {
    "user:read": { "total": 800, "allowed": 798, "denied": 2 },
    "user:write": { "total": 200, "allowed": 180, "denied": 20 },
    "user:delete": { "total": 42, "allowed": 22, "denied": 20 }
  }
}
```

---

## 12. Health & Metrics (Public)

### GET `/api/v1/health/cache-stats`

| Property | Value |
|----------|-------|
| Auth | None |

**Response:**

```json
{
  "authorizationCache": { "size": 1024, "hitRate": 0.87 },
  "permissionCache": { "size": 256, "hitRate": 0.95 },
  "scopeClosureCache": { "size": 128, "hitRate": 0.99 }
}
```

---

### GET `/api/v1/health/metrics`

| Property | Value |
|----------|-------|
| Auth | None |

**Response:**

```json
{
  "totalRequests": 50432,
  "allowCount": 48910,
  "denyCount": 1522,
  "avgLatencyMs": 3.2,
  "p95LatencyMs": 8.1,
  "p99LatencyMs": 15.4,
  "cacheHitRate": 0.89,
  "uptime": "14d 6h 32m"
}
```

---

## 13. Authentication (AuthN)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register a new user |
| POST | `/api/auth/login` | Login with credentials |
| POST | `/api/auth/refresh` | Refresh access token |
| POST | `/api/auth/logout` | Logout current session |
| POST | `/api/auth/logout-all` | Logout all sessions |
| POST | `/api/auth/verify-email` | Verify email address |
| POST | `/api/auth/verify-email-and-setup-password` | Verify email and set initial password |
| POST | `/api/auth/resend-verification` | Resend verification email |
| POST | `/api/auth/forgot-password` | Request password reset |
| POST | `/api/auth/reset-password` | Reset password with token |
| POST | `/api/auth/change-password` | Change password (authenticated) |
| POST | `/api/auth/request-reactivation` | Request account reactivation |
| POST | `/api/auth/verify-reactivation` | Verify reactivation token |
| GET | `/api/auth/me` | Get current user profile |
| PUT | `/api/auth/me` | Update current user profile |
| GET | `/api/auth/oauth/providers` | List available OAuth providers |
| GET | `/api/auth/oauth/login/{provider}` | Initiate OAuth login flow |

---

## Error Response Format

All error responses follow this structure:

```json
{
  "timestamp": "2026-04-06T10:00:00.789Z",
  "status": 403,
  "error": "Forbidden",
  "message": "Scope containment violation: you cannot assign roles outside your administered scopes",
  "path": "/api/v1/assignments",
  "validationErrors": null
}
```

**With validation errors (422):**

```json
{
  "timestamp": "2026-04-06T10:00:00.789Z",
  "status": 422,
  "error": "Unprocessable Entity",
  "message": "Validation failed",
  "path": "/api/v1/roles",
  "validationErrors": {
    "name": "must not be blank",
    "orgType": "must be one of: GLOBAL, COUNTRY, REGION, DISTRICT, MUNICIPALITY"
  }
}
```
