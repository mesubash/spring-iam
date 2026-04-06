# IAM Migration Guide

Migrating from a legacy system with embedded auth to a centralized IAM service.

---

## 1. What This Guide Covers

This guide is for teams migrating from a monolith where authorization is hardcoded as role strings on user tables to a centralized IAM service with fine-grained permissions, hierarchical scopes, and audit trails.

It covers the data migration strategy, code changes in business services, frontend changes, and the phased rollout plan.

---

## 2. Common Legacy Patterns

Most legacy systems follow one of these patterns:

**Single role string on the user table:**

```
users.role = 'ADMIN'          -- single string, no scoping
```

**Role within a company/org:**

```
company_users.role = 'MANAGER' -- single string, within one company
```

**Scattered authorization checks:**

```java
if (user.getRole().equals("ADMIN")) { allow }
if (companyUser.getRole().equals("MANAGER") || companyUser.getRole().equals("ADMIN")) { allow }
```

### Problems with this approach

- No permission granularity -- a role is all-or-nothing
- No scope hierarchy -- cannot express "admin of Region X" vs "admin of Org Y"
- No deny override -- cannot block one action without removing the entire role
- No audit trail for access decisions
- Authorization logic scattered across every service
- Adding a new role means changing enum constraints and redeploying

---

## 3. Migration Strategy

### Phase 1: Deploy IAM (parallel to existing system)

Deploy the IAM service alongside your existing system. Both run in parallel.

1. Deploy IAM with empty schema (Flyway runs migrations automatically).
2. Create a `GLOBAL` scope.
3. Create `COUNTRY` scopes under GLOBAL (e.g., `COUNTRY:US`, `COUNTRY:UK`).
4. Seed permissions for your existing domains using the `domain.resource.action` pattern.
5. Seed system roles (`SuperAdmin`, `CountryAdmin`) with appropriate permissions.
6. Seed org-level roles (`OrgAdmin`, `OrgManager`, `OrgStaff`) with appropriate permissions.

### Phase 2: Migrate Identities

For each user in your existing `auth_users` or `users` table:

1. Create an identity record (or map to your existing user UUID as the `subjectId`).
2. Create credentials (password hash, OAuth links).
3. Create a profile record (display name, phone, email, avatar).
4. Store the mapping: `old_user.id -> new_identity.id` (or reuse the same UUID if compatible).

### Phase 3: Create Scopes from Organizations

For each company or organization in your existing database:

1. Create an `ORG` scope under the appropriate `COUNTRY` scope.
2. Store the mapping: `company.id -> scope.id`.
3. Add a `scope_id` column to your company table and backfill it.

```json
POST /api/v1/scopes
{
  "type": "ORG",
  "name": "Acme Corp",
  "code": "ACME",
  "parentId": "<country-scope-uuid>",
  "metadata": { "orgType": "ENTERPRISE", "companyId": "<old-company-id>" }
}
```

### Phase 4: Create Assignments from Existing Roles

For each active user-role relationship in your system:

1. Look up the user's `identity_id` from the Phase 2 mapping.
2. Look up the company's `scope_id` from the Phase 3 mapping.
3. Map the old role string to the corresponding IAM role (see section 4).
4. Create an assignment.

```json
POST /api/v1/assignments
{
  "subjectId": "<identity-id>",
  "subjectType": "USER",
  "roleId": "<iam-role-uuid>",
  "scopeId": "<org-scope-uuid>",
  "grantedBy": "migration-script"
}
```

### Phase 5: Dual-Mode Operation

Run both old and new auth in parallel:

1. Your service validates JWTs from the new auth system.
2. For existing features: old role checks still work (backward compatibility).
3. For new features: use IAM's `POST /api/v1/authorize` endpoint.
4. Gradually migrate old role checks to IAM calls, one endpoint at a time.
5. Track migration progress -- which endpoints still use old checks vs IAM.

### Phase 6: Cleanup

Once all endpoints use IAM:

1. Remove `users.role` column (or rename to `display_role` if needed for UI labels).
2. Remove `company_users.role` column.
3. Remove old auth tables (`auth_users`, `blacklisted_refresh_tokens`) from the business service.
4. Update the `users` table to reference `identity_id` instead of old auth fields.
5. Remove old JWT validation logic and role-checking code.

---

## 4. Role Mapping Example

Map your legacy role strings to IAM roles with appropriate scope levels:

| Old Role String | Old Context | IAM Role | Scope Level |
| --------------- | ----------- | -------- | ----------- |
| `ADMIN` | `users.role` | `SuperAdmin` or `CountryAdmin` | `GLOBAL` or `COUNTRY` |
| `USER` | `users.role` | `BasicUser` (or no assignment) | `GLOBAL` |
| `ADMIN` | `company_users.role` | `OrgAdmin` | `ORG:{company}` |
| `MANAGER` | `company_users.role` | `OrgManager` | `ORG:{company}` |
| `STAFF` | `company_users.role` | `OrgStaff` | `ORG:{company}` |
| `AGENT` | `company_users.role` | `OrgAgent` | `ORG:{company}` |

Key insight: the old `users.role` often mixed two concepts -- "what type of entity is this user" and "what can this user do." In the new system, entity type is business data. Authorization comes from assignments.

---

## 5. Business Service Changes

### Authorization checks

**Before:**

```java
if (user.getRole().equals("ADMIN")) {
    // allow
}
```

**After:**

```java
AuthzResponse response = iamClient.authorize(
    currentUser.getIdentityId(),     // subject
    "project.task.approve",          // permission
    resource.getScopeId()            // scope
);
if (!response.isAuthorized()) {
    throw new ForbiddenException(response.getReason());
}
```

### Company/org registration

**Before:** Create company, create company_user with role ADMIN, done.

**After:**

1. Create company in your database (unchanged).
2. Call IAM: `POST /api/v1/scopes` to create an ORG scope with `parentId` pointing to the country scope.
3. Store the returned `scope_id` on the company record.
4. Call IAM: `POST /api/v1/assignments` to assign the creator as `OrgAdmin` at the new scope.

### Employee addition

**Before:** Create company_user with role STAFF, done.

**After:**

1. Create company_user row in your database (without role, or with a display label).
2. Call IAM: `POST /api/v1/assignments` with the employee's `subjectId`, the appropriate role, and the company's `scopeId`.

### Employee removal

**Before:** Deactivate company_user, done (but the user still had the role string).

**After:**

1. Deactivate company_user in your database.
2. Call IAM: `DELETE /api/v1/assignments/{assignmentId}?revokedBy=admin&reason=employee-removed`.
3. Access is revoked on the next `/authorize` check.
4. For immediate revocation before token expiry: create a deny rule.

---

## 6. Frontend Changes

### Login response no longer includes role

**Before:**

```json
{
  "token": "jwt...",
  "user": { "id": "user-uuid", "name": "Alice", "role": "ADMIN" }
}
```

**After:**

```json
{
  "accessToken": "jwt...",
  "refreshToken": "refresh...",
  "expiresIn": 900,
  "identity": { "id": "identity-uuid", "email": "alice@example.com", "displayName": "Alice" }
}
```

### Post-login flow

1. Login and store tokens.
2. `GET /api/authz/me/scopes` -- get list of orgs the user belongs to.
3. If multiple orgs, show an org switcher.
4. `GET /api/authz/me/permissions?scopeId=<selected-org>` -- get permissions.
5. Cache permissions as `Set<string>` in frontend state.
6. Render UI based on permission keys.

### Permission-based UI rendering

**Before:**

```jsx
{user.role === 'ADMIN' && <button>Approve</button>}
```

**After:**

```jsx
{can('project.task.approve') && <button>Approve</button>}
```

### Org switcher (new capability)

Users with assignments at multiple scopes see an org switcher. On switch:

1. User selects a different org from the dropdown.
2. Frontend calls `GET /api/authz/me/permissions?scopeId=<new-scope>`.
3. New permissions replace old ones in cache.
4. UI re-renders with different buttons visible based on the different role at that scope.

### Token refresh strategy

- Access token: 15-minute expiry.
- Refresh token: 7-day expiry, rotated on each use.
- Frontend sets up auto-refresh before the access token expires.
- On refresh, roles may have changed (if admin modified assignments since last login).
- On 401 with expired token: call refresh endpoint, retry the original request.

---

## 7. Module Boundary Rules

If you are building or extending the IAM service itself, these four rules ensure clean separation between AuthN and AuthZ modules. Following them makes future extraction of AuthZ into a separate service a straightforward refactoring job rather than a rewrite.

**Rule 1: No cross-module imports.**

AuthN and AuthZ modules never import each other's internal classes, repositories, or entities. If AuthN needs something from AuthZ (e.g., role claims during login), it calls through a clean interface defined in a shared module.

```
OK:   authn/ calls shared/AuthzQueryService.getRolesForIdentity(identityId)
BAD:  authn/ imports authz/repository/AssignmentRepository directly
BAD:  authz/ imports authn/entity/Credential directly
```

**Rule 2: Separate table ownership.**

Each module owns its tables exclusively. No module reads or writes another module's tables directly.

- AuthN owns: `identities`, `credentials`, `refresh_tokens`, `security_events`
- AuthZ owns: `permissions`, `roles`, `role_permissions`, `scopes`, `scope_closure`, `assignments`, `deny_rules`, `authorization_audit`
- Shared owns: `identity_profiles`

**Rule 3: Communication through DTOs only.**

Modules exchange data through plain DTOs defined in a shared module. No JPA entities or internal models cross module boundaries.

**Rule 4: The /authorize contract is HTTP-shaped.**

Even when AuthZ is called internally via method call, the request and response DTOs must look exactly like the HTTP request/response would if it were a remote call. No passing of JPA entities, database connections, or request-scoped objects.

```java
// This interface looks identical to what a REST client would call
public interface AuthzQueryService {
    AuthorizationResultDto authorize(AuthorizationRequestDto request);
    RoleClaimsDto getRolesForIdentity(UUID identityId);
    List<String> getEffectivePermissions(UUID identityId, UUID scopeId);
}
```

When extraction day comes, you replace the in-memory implementation with an HTTP client. The calling code does not change.
