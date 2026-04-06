# IAM Testing Guide

This guide walks through testing the IAM service using Postman, step by step, with example requests and the full flow needed to validate authorization behavior.

---

## 1. Environment Setup

### Postman variables

Create a Postman environment with these variables:

| Variable | Value |
|----------|-------|
| `base_url` | `http://localhost:8080` |
| `admin_jwt` | JWT with role `IAM_ADMIN` (see below) |
| `internal_api_key` | Value from `.env` `IAM_INTERNAL_API_KEY` (e.g., `dev-internal-key`) |

### JWT requirements (admin endpoints)

Your JWT must contain `roles` with `IAM_ADMIN`. Minimal payload:

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

Sign with **HS256** using the secret from `IAM_JWT_SECRET` in your `.env` file.

### Headers

- Admin endpoints: `Authorization: Bearer {{admin_jwt}}`
- Internal authorize endpoints: `X-Internal-Api-Key: {{internal_api_key}}`
- All requests: `Content-Type: application/json`

---

## 2. Bootstrap Admin

**Option A:** If dev seed data is loaded (e.g., V3 migration), log in with the seeded admin:
- Email: `admin@example.com`
- Password: `Admin@123!`

**Option B:** Generate a JWT manually with `SuperAdmin` or `IAM_ADMIN` role for admin endpoint access. Use jwt.io or a script to sign with your `IAM_JWT_SECRET`.

---

## 3. Recommended Testing Order

Follow this order to build up the data needed for authorization checks:

1. **Health check** (no auth required)
   - `GET {{base_url}}/api/v1/health/cache-stats`
   - `GET {{base_url}}/api/v1/health/metrics`

2. **Create scopes** (hierarchy: GLOBAL > REGION > COUNTRY > ORG)
   - `POST {{base_url}}/api/v1/scopes` -- create GLOBAL first
   - Then REGION with `parentId` = GLOBAL scope ID
   - Then COUNTRY with `parentId` = REGION scope ID
   - Then ORG with `parentId` = COUNTRY scope ID

3. **Create permissions**
   - `POST {{base_url}}/api/v1/permissions` (single or batch)
   - Example: `{"key": "billing.invoice.read", "domain": "billing", "resource": "invoice", "action": "read"}`

4. **Create role with permissions**
   - `POST {{base_url}}/api/v1/roles` with `permissionIds` array

5. **(Optional) Create role hierarchy**
   - `POST {{base_url}}/api/v1/role-hierarchy` to set parent-child role inheritance

6. **Create assignment** (attach role to subject at scope)
   - `POST {{base_url}}/api/v1/assignments` with `subjectId`, `roleId`, `scopeId`

7. **(Optional) Create deny rule or policy**
   - `POST {{base_url}}/api/v1/deny-rules` for explicit deny
   - `POST {{base_url}}/api/v1/policies` for ABAC/ReBAC rules

8. **Call POST /api/v1/authorize** (verify ALLOW)
   - Use `X-Internal-Api-Key` header
   - Expect `authorized: true`

9. **Call POST /api/v1/authorize with deny rule active** (verify DENY)
   - Same request as step 8 but with a deny rule in place
   - Expect `authorized: false` with reason referencing deny rule

10. **Check audit logs**
    - `GET {{base_url}}/api/v1/audit/subject/{subjectId}`
    - `GET {{base_url}}/api/v1/audit/statistics/{subjectId}?sinceDaysAgo=7`

---

## 4. Key Test Scenarios

### ALLOW: user has role at correct scope
- Subject has an assignment with a role that includes the requested permission.
- The assignment scope contains the resource scope.
- Expected: `authorized: true`.

### DENY by missing role
- Subject has no assignment at all (or no assignment with the needed permission).
- Expected: `authorized: false`, reason mentions no matching role.

### DENY by scope mismatch
- Subject has the correct role but at a different scope that does not contain the resource scope.
- Example: user assigned at ORG "Company A", resource scoped to ORG "Company B" (sibling scopes).
- Expected: `authorized: false`, reason mentions scope.

### DENY by deny rule
- Subject has the correct role and scope, but an active deny rule exists for that permission.
- Expected: `authorized: false`, reason mentions explicit deny rule.
- Deny rules override everything.

### DENY by assignment conditions
- Subject has the role, but the assignment has conditions that are not met:
  - `time_window`: request is outside allowed hours
  - `ip_ranges`: request IP is not in allowed ranges
  - `require_mfa`: MFA context is false or missing
  - `ownership_required`: subject is not the resource owner
- Expected: `authorized: false`, reason mentions condition failure.

### DENY by policy
- An ALLOW policy exists for the permission but its conditions do not match.
- Example: policy requires `subject != resource.ownerId` (cannot approve own work), but subject is the owner.
- Expected: `authorized: false`.

### Batch authorization
- `POST /api/v1/authorize/batch` with multiple permission checks.
- Returns a map of results, each independently evaluated.

### Effective permissions
- `POST /api/v1/effective-permissions` with subject and scope.
- Returns the full list of allowed (and optionally denied) permissions for that subject at that scope.

---

## 5. Tips

- **Deny rules override everything**, including policies and role assignments. If an ALLOW test unexpectedly returns DENY, check for active deny rules.
- **Policy evaluation order:** If any ALLOW policies exist for a permission, at least one must match. If none match, the request is denied even if the role grants the permission.
- **scopeId is crucial.** Assignments are scoped, and scope containment is enforced. Double-check that the resource scopeId is a descendant of (or equal to) the assignment scopeId.
- **Conditional assignments skip the permission cache.** If an assignment has conditions (time window, IP, MFA, ownership), the authorization engine evaluates them at request time rather than relying on cached permissions.
- **Audit trail:** Every authorization decision is recorded. Use the audit endpoints to verify that decisions were logged correctly and to debug unexpected results.
- **Order matters during setup.** You cannot create an assignment without first having a scope, role, and permissions. Follow the recommended testing order in section 3.
