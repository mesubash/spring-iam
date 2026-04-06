# IAM Integration Guide

This document explains how to integrate the IAM authorization service with any backend service or frontend application. IAM handles authorization; your services handle authentication.

---

## 1. Roles of Each System

### Your application service (already has auth)
- Authenticates users with its own auth system (JWT, session, OAuth, SSO).
- Extracts a stable `subjectId` (user UUID or service account ID).
- Calls IAM to check permissions.
- Enforces IAM's ALLOW/DENY decision locally.

### IAM service (this project)
- Stores permissions, roles, scopes, assignments, deny rules, and policies.
- Evaluates authorization requests against those rules.
- Logs an audit trail for every decision.

**Key principle:** IAM does not manage user accounts. It only knows subjectIds and their assignments.

---

## 2. Identity and Subject IDs

### What is subjectId?
A stable UUID used across your system (e.g., user UUID from your auth database). IAM uses this as the lookup key for assignments.

### Does IAM need all users stored?
No. IAM only stores assignments. Users without assignments never appear in IAM. A user with no assignment receives DENY for all permissions.

### Business membership vs authorization roles
Your services may store business membership data (staff type, org membership, invitation state). IAM stores authorization roles and permissions. A provisioning layer maps business roles to IAM assignments.

---

## 3. Authorization Call Flow

Step-by-step:

1. Your service authenticates the user with its own auth system.
2. Your service extracts `subjectId` from the authenticated session/token.
3. Your service calls IAM:

```
POST /api/v1/authorize
X-Internal-Api-Key: <internal-key>
Content-Type: application/json
```

```json
{
  "subject": "user-123",
  "permission": "billing.invoice.approve",
  "resource": {
    "type": "invoice",
    "id": "inv-456",
    "scopeId": "<scope-uuid>",
    "metadata": { "ownerId": "user-789" }
  },
  "context": {
    "ipAddress": "10.1.2.3",
    "requestId": "req-001",
    "additionalContext": { "mfa": true }
  }
}
```

4. IAM evaluates in order: deny rules, assignments + role permissions, scope containment, assignment conditions, optional policies (ABAC/ReBAC).
5. IAM returns ALLOW or DENY with a reason and audit ID.

```json
{
  "authorized": true,
  "reason": "ALLOW: Permission granted via role assignment",
  "effectivePermissions": ["billing.invoice.approve"],
  "auditId": "fa2bd0c0-7052-48b8-99c8-0fd3c4e06264",
  "timestamp": "2026-01-25T17:00:00Z",
  "latencyMs": 3
}
```

6. Your service enforces the decision locally (allow the action or return 403).

---

## 4. Provisioning Assignments

IAM does not auto-discover users. You must push assignments into IAM when users are created or their roles change.

### Recommended: Event-driven sync

1. Your user service emits events: `UserCreated`, `UserRoleChanged`, `UserDeactivated`.
2. An "IAM sync" worker consumes these events and maps local roles to IAM roles.
3. The worker calls IAM admin APIs to create or revoke assignments.

### Alternative: Direct provisioning

Your user service calls IAM directly when users are created or updated:

- `POST /api/v1/assignments` to grant access
- `DELETE /api/v1/assignments/{id}?revokedBy=...&reason=...` to revoke

### ScopeId must be deterministic

IAM assignments require a `scopeId`. Create IAM scopes when organizations are created and store the mapping:

```
org.id -> iam_scope_id
```

Event payloads should include `iamScopeId` directly:

```json
{
  "eventType": "UserCreated",
  "userId": "user-123",
  "iamScopeId": "2efb5de7-...",
  "role": "STAFF"
}
```

If you do not store `iamScopeId`, the worker must resolve it by a stable scope code (e.g., `orgCode -> scopes.code`). Scope codes must be globally unique.

---

## 5. Role Mapping Strategy

If your services already have local roles, you need a mapping layer.

Example:

| Local Role | IAM Role |
|------------|----------|
| `STAFF` | `OrgStaff` |
| `MANAGER` | `OrgManager` |
| `ORG_ADMIN` | `OrgAdmin` |

The mapping can live in a config table, a dedicated mapping service, or a policy document that drives assignment provisioning.

**IAM should remain the final source of truth for permissions.** Local roles are business labels; IAM roles are authorization grants.

---

## 6. Authentication Between Services and IAM

### API Key for /authorize (service-to-service)

- Header: `X-Internal-Api-Key: <key>` (or `Authorization: ApiKey <key>`)
- Grants `ROLE_INTERNAL`
- Only valid for `/authorize` and `/effective-permissions` endpoints

### JWT for admin APIs

- Header: `Authorization: Bearer <token>`
- Must contain role `IAM_ADMIN` (or `SuperAdmin`, `CountryAdmin` as configured)

### Production hardening

- Use per-service API keys (not a single shared key)
- Implement key rotation (quarterly or shorter)
- Apply rate limiting per API key
- Use network allowlist or mTLS
- Include `X-Service-Id` header for caller attribution in audit logs

---

## 7. Frontend Integration

### Core principle

Frontend should be **permission-driven, not role-string-driven**.

Do NOT render UI with:
```js
if (role === "OrgAdmin") { showButton() }
```

Instead, use permission keys:
```js
if (can("billing.invoice.approve")) { showButton() }
```

### Recommended flow

1. User logs in and stores JWT.
2. Call `GET /api/authz/me/scopes` to get the list of scopes (orgs) the user belongs to.
3. User selects an active org/scope (or default to the first one).
4. Call `GET /api/authz/me/permissions?scopeId=<selected>` to get permissions for that scope.
5. Store permissions as a `Set<string>` in frontend state.
6. Render sidebar, routes, and action buttons using a helper:

```ts
type AuthzState = {
  activeScopeId: string | null;
  scopes: Array<{ id: string; name: string; type: string; code: string }>;
  permissions: Set<string>;
  loadedAt: number | null;
};

const can = (perm: string) => authz.permissions.has(perm);
```

### Do not call /authorize per button

The `/api/v1/authorize` endpoint is for backend service-to-service checks. Frontend should fetch permissions once per scope change and cache them locally.

### Cache and refresh guidance

- Cache permissions per `scopeId`.
- Re-fetch when: scope changes, token refreshes, user triggers explicit refresh, or a known assignment update event occurs.

### Backend is final enforcement

Hidden buttons are UX only, not security. Every protected business API must call IAM's `/authorize` endpoint on the backend. A hidden button that a user bypasses via direct API call must still be blocked server-side.

---

## 8. Scope and Multi-Tenancy

Scopes represent organizational hierarchy, enforced by database triggers:

```
GLOBAL (depth 0)
  REGION (depth 1)
    COUNTRY (depth 2)
      ORG (depth 3)
        DEPT (depth 4)
          TEAM (depth 5)
            PROJECT (depth 6)
```

### Key rules

- An assignment at `ORG` scope grants access to that org and all its descendants (DEPT, TEAM, PROJECT).
- IAM checks scope containment before granting permission: the resource's scope must be a descendant of (or equal to) the assignment's scope.
- Sibling scopes are isolated. An admin at "Company A" cannot access "Company B" data -- both are ORG scopes under the same COUNTRY, but siblings do not contain each other.
- For cross-org access (e.g., a regional auditor), assign the user at a higher scope level (COUNTRY or REGION).

---

## 9. Error Handling

When calling IAM from your service, handle these responses:

| Status | Meaning | Action |
|--------|---------|--------|
| `200` with `authorized: true` | Permission granted | Allow the action |
| `200` with `authorized: false` | Permission denied | Return 403 to the end user |
| `401` | Missing or invalid auth to IAM | Check API key or JWT configuration |
| `403` | Authenticated but insufficient role to call this IAM endpoint | Check that your service uses the correct auth method |
| `400` | Validation error in the request body | Fix the request payload |
| `503` | IAM temporarily unavailable | Retry with backoff; optionally fail-closed (deny) |

---

## 10. Minimal Integration Checklist

- [ ] Use a stable `subjectId` (UUID) across all systems
- [ ] Map local membership roles to IAM roles
- [ ] Provision assignments into IAM (with correct `scopeId`)
- [ ] Create IAM scopes alongside org/company creation
- [ ] Call `POST /api/v1/authorize` for permission checks from backend services
- [ ] Enforce IAM decision in your service (allow or reject)
- [ ] Frontend: fetch scopes and permissions via `/api/authz/me/*` endpoints
- [ ] Frontend: render UI based on permission keys, not role strings
- [ ] Monitor audit logs via `/api/v1/audit/*` endpoints
- [ ] Configure per-service API keys with rotation strategy for production
