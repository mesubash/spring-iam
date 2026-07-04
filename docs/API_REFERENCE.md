# IAM Service — API Reference

Generated from controller source under `io.github.mesubash.iam.{authn,authz}.controller` and
`io.github.mesubash.iam.controller`, cross-checked against
`config/SecurityConfig.java` (path-level rules) and `config/FeatureFlags.java` (module toggles).
Only endpoints that exist in the controllers are documented.

## Base URL & conventions

- **Base URL**: service root, e.g. `https://iam.example.com` (default dev port `8080`). All paths below are absolute from the root.
- **Content type**: `application/json` for request/response bodies unless noted.

### Authentication mechanisms

Filter order is **RateLimit → API key → service JWT → user JWT** (`SecurityConfig.filterChain`). The first that authenticates wins.

| Mechanism | How to send | Resulting authority | Used by |
|-----------|-------------|--------------------|---------|
| **User access token** | `Authorization: Bearer <jwt>` | Business roles: `SuperAdmin`, `CountryAdmin`, `AccessAdmin`, `SecurityAdmin`, `AuditViewer`, `User`, … (Spring `ROLE_<name>`) | End users / admin console |
| **Service (system) JWT** | `Authorization: Bearer <jwt>` | Roles from the token's `roles`/`scope` claims (falls back to `ROLE_USER`) | Trusted services |
| **Internal / service API key** | `X-Internal-Api-Key: <key>` **or** `Authorization: ApiKey <key>` | `ROLE_INTERNAL` (principal `internal-client`, or `service:<name>` when the service-registry flag is on and a per-service key matches) | Service-to-service calls (PDP, introspection, manifest sync) |

- **Access tokens are RS256.** Consumers verify them locally against the public keys at `GET /.well-known/jwks.json` (`kid` in the header selects the key).
- **Service JWTs are HS256** (shared secret `iam.security.jwt.secret`), tried before the user-JWT filter; a `Bearer` value that fails HMAC verification falls through to RS256 user-token verification.
- The **refresh token is an opaque value** (not a JWT). On web it is returned only in a `__Host-Refresh` HttpOnly, Secure, SameSite cookie (encrypted at rest in the cookie); mobile/other clients that cannot use cookies read it from the login/refresh response. `/api/auth/refresh` reads it from the cookie.

### Response envelopes

- **`/api/auth/*`, `/api/auth/sessions/*`, `/api/authz/me/*`, and the OAuth controller** wrap results in a **success envelope**:
  ```json
  { "success": true, "message": "…", "data": { … } }
  ```
  (`data` omitted when null; errors set `success:false`.)
- **All `/api/v1/*` admin & runtime endpoints, JWKS, introspection, revocations, meta, health** return **raw JSON** (the entity/DTO/`Map`/`List` directly), no envelope.

### Permission keys

Permission keys are dotted, lowercase: `domain.<resource-path>.action`, **3–6 segments** (e.g. `billing.invoice.read`, `hr.employee.salary.update`). The manifest-sync validator enforces `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){2,5}$` and requires the first segment (`domain`) to be one the calling service owns. (The admin `POST /api/v1/permissions` DTO uses a stricter 3-segment pattern `^[a-z_]+\.[a-z_]+\.[a-z_]+$`.)

### Subject identifiers

`subject` / `subjectId` throughout the authorization API is the **identity UUID** (the authenticated user's identity id), sent as a string.

### Feature flags (`iam.features.*`, all default `false`)

`resource-grants`, `groups`, `service-registry`, `oauth2`, `break-glass`, `introspection`, `revocation-feed`.
When a flag is off, its endpoints throw `ResourceNotFoundException` → **HTTP 404** (except OAuth endpoints, which simply do not exist unless `oauth2=true` — the whole controller is `@ConditionalOnProperty`). `GET /api/v1/meta/features` reports the live map.

### Rate limiting

The `RateLimitFilter` runs first and may return **429** with `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Retry-After-Seconds`, `Retry-After` headers.

---

## 1. Authentication — `/api/auth/*`

Controller: `AuthController` (envelope responses). Public endpoints per `SecurityConfig`; `logout`, `logout-all`, `change-email`, `change-password` require an authenticated user (`@PreAuthorize("isAuthenticated()")`).

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/api/auth/register` | Public | Create an account; sends email verification (login blocked until verified). |
| POST | `/api/auth/login` | Public | Authenticate; returns access token + sets refresh cookie. |
| POST | `/api/auth/refresh` | Public (needs refresh cookie) | Rotate access token using the `__Host-Refresh` cookie. |
| POST | `/api/auth/logout` | Bearer (authenticated) | Revoke current access token + clear refresh cookie. |
| POST | `/api/auth/logout-all` | Bearer (authenticated) | Revoke all refresh tokens/sessions for the user. |
| POST | `/api/auth/oauth/exchange` | Public | Exchange the one-time OAuth redirect `code` for tokens. |
| POST | `/api/auth/verify-email` | Public | Verify email via `token`. |
| POST | `/api/auth/verify-email-and-setup-password` | Public | Verify an invited user's email and set the initial password (one token). |
| POST | `/api/auth/resend-verification` | Public | Resend the verification email. |
| POST | `/api/auth/forgot-password` | Public | Send a password-reset email. |
| POST | `/api/auth/reset-password` | Public | Reset password using `token` + `newPassword`. |
| POST | `/api/auth/change-password` | Bearer (authenticated) | Change password (requires current password). |
| POST | `/api/auth/change-email` | Bearer (authenticated) | Change login email; verification sent to the new address. |
| POST | `/api/auth/verify-email-change` | Public | Confirm the email change via `token`. |
| POST | `/api/auth/request-reactivation` | Public | Request reactivation email for a deactivated account. |
| POST | `/api/auth/verify-reactivation` | Public | Reactivate an account via `token`. |

> Note: there is **no `/api/auth/me`** endpoint in the code. Login/refresh responses carry the identity summary; use `/api/authz/me/*` (§6) for scopes/permissions.

**Request shapes**
- `register` — body `RegisterRequest`: `{ "email": string, "password": string(min 6) }`
- `login` — body `LoginRequest`: `{ "email": string, "password": string }`
- `refresh` — no body; refresh token read from `__Host-Refresh` cookie.
- `oauth/exchange` — body `{ "code": string }`
- `logout` — no body; requires `Authorization` header.
- `verify-email`, `resend-verification`, `forgot-password`, `request-reactivation` — query param `email` or `token` as applicable.
- `reset-password` — query params `token`, `newPassword`.
- `verify-reactivation`, `verify-email-change` — query param `token`.
- `verify-email-and-setup-password` — body `VerifyEmailAndPasswordRequest`: `{ "token": string, "newPassword": string }`
- `change-password` — body `PasswordChangeRequest`: `{ "currentPassword": string, "newPassword": string(min 8), "confirmPassword": string }`
- `change-email` — body `{ "newEmail": string, "currentPassword": string }`

**`POST /api/auth/login` — example**
```json
// request
{ "email": "jane@example.com", "password": "SecurePass123" }

// 200 response (refresh token delivered via Set-Cookie: __Host-Refresh=…; HttpOnly; Secure)
{
  "success": true,
  "message": "Login successful",
  "data": {
    "accessToken": "eyJhbGciOiJSUzI1Ni…",
    "tokenType": "Bearer",
    "expiresIn": 900,
    "identity": {
      "id": "9f1c…-uuid",
      "email": "jane@example.com",
      "displayName": "Jane Doe",
      "emailVerified": true
    }
  }
}
```
`register` returns **201** with `data: { "message": "…verification email sent…" }`. `refresh` mirrors the login `data` shape. Most other endpoints return `data: { "message": "…" }`.

### Sessions — `/api/auth/sessions`

Controller: `SessionController`, class-level `@PreAuthorize("isAuthenticated()")`, envelope responses.

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/api/auth/sessions` | Bearer (authenticated) | List the current user's active device sessions. |
| DELETE | `/api/auth/sessions/{id}` | Bearer (authenticated) | Revoke one session (404 if not owned by the caller). |

`GET` `data` is a list of `SessionView`: `{ id: uuid, deviceLabel, createdIp, createdAt, lastUsedAt }`.

### OAuth login initiation — `/api/auth/oauth/*` (`OAuthController`)

Present **only when `oauth2=true`** (`@ConditionalOnProperty`); otherwise the paths do not exist. All public. These start the browser redirect flow; the app finishes by calling `POST /api/auth/oauth/exchange` (§ above) with the returned one-time `code`.

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/api/auth/oauth/providers` | Public | List supported providers (`["google"]`) and their login URLs (envelope). |
| GET | `/api/auth/oauth/login/google` | Public | Begin Google OAuth; requires `?redirectUri=` (or `?redirectUrl=`). Redirects to the provider. |
| GET | `/api/auth/oauth/login/{provider}` | Public | Generic provider login initiation; requires `?redirectUri=`. Redirects (400 for unsupported provider or missing redirect). |

---

## 2. Keys & discovery

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/.well-known/jwks.json` | Public | Public RS256 keys for local access-token verification. |
| POST | `/api/v1/keys/rotate` | `SuperAdmin` (`@PreAuthorize`) | Rotate the signing key; new key signs immediately, old key verifies during its grace window. |
| GET | `/api/v1/meta/features` | Authenticated | Live feature-flag map for clients to hide disabled modules. |

- `JWKS` (raw): `{ "keys": [ { "kty":"RSA", "kid":"…", "use":"sig", "alg":"RS256", "n":"…", "e":"AQAB" }, … ] }` (cacheable 5 min).
- `keys/rotate` (raw): `{ "kid": "<new-key-id>" }`.
- `meta/features` (raw): `{ "resource-grants": false, "groups": false, "service-registry": false, "oauth2": false, "break-glass": false, "introspection": false, "revocation-feed": false }`.

---

## 3. Authorization runtime (PDP)

Controller: `AuthorizationController` (`/api/v1`). Raw-JSON responses. This is the hot path — `POST /authorize` is called by every consuming service.

`SecurityConfig` path rules + method security:

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/api/v1/authorize` | `INTERNAL`, `SuperAdmin`, or `CountryAdmin` | Decide if a subject may perform an action on a resource (writes audit). |
| POST | `/api/v1/authorize/batch` | `INTERNAL`, `SuperAdmin`, or `CountryAdmin` | Up to 50 checks in one call. |
| POST | `/api/v1/authorize/explain` | `SuperAdmin`, `CountryAdmin`, `AccessAdmin`, `SecurityAdmin`, or `AuditViewer` | Dry-run decision trace; writes **no** audit record. |
| POST | `/api/v1/authorize/simulate` | `SuperAdmin`, `CountryAdmin`, or `AccessAdmin` | What-if: evaluate with a hypothetical add/remove assignment set. |
| POST | `/api/v1/effective-permissions` | `INTERNAL`, `SuperAdmin`, or `CountryAdmin` | All effective permissions for a subject in a scope. `?asOf=<ISO-8601>` for point-in-time reconstruction. |
| POST | `/api/v1/filter-resources` | `INTERNAL`, `SuperAdmin`, or `CountryAdmin` | Narrow a list of resource ids (≤500) to those the subject may act on. |
| GET | `/api/v1/access-list` | `SuperAdmin`, `CountryAdmin`, `AccessAdmin`, `SecurityAdmin`, or `AuditViewer` | Reverse lookup: who holds permission `P` at scope `S`. Query params `permission`, `scopeId`. |

**`AuthorizationRequest`** (used by authorize / batch item / explain; and nested in simulate):
```json
{
  "subject": "9f1c…-identity-uuid",
  "permission": "billing.invoice.read",
  "resource": {
    "type": "invoice",
    "id": "inv_123",
    "scopeId": "a2b…-scope-uuid",   // required
    "metadata": { "amount": 500 }    // optional
  },
  "context": {                        // optional; server fills ipAddress/userAgent if absent
    "timestamp": "2026-07-04T12:00:00Z",
    "ipAddress": "…", "userAgent": "…",
    "sessionId": "…", "requestId": "…",
    "additionalContext": { }
  }
}
```

**`POST /api/v1/authorize` — response** (`AuthorizationResponse`, raw):
```json
{
  "authorized": true,
  "reason": "ALLOWED",
  "effectivePermissions": ["billing.invoice.read", "billing.invoice.write"],
  "auditId": "…-uuid",
  "timestamp": "2026-07-04T12:00:00.123Z",
  "latencyMs": 3,
  "policyVersion": 42
}
```

**`POST /api/v1/authorize/batch`** — body is a JSON array of `AuthorizationRequest` (max 50). Response is a map keyed by `"<permission>:<resourceId>"` → `AuthorizationResponse`.

**`POST /api/v1/authorize/explain` — response** (`ExplainResponse`, raw):
```json
{
  "allowed": false,
  "reason": "denied by deny-rule",
  "steps": [
    { "name": "deny_rules",      "outcome": "DENY", "detail": "matched deny rule …" },
    { "name": "rbac_scope",      "outcome": "SKIP", "detail": "not evaluated" },
    { "name": "conditions",      "outcome": "SKIP", "detail": "" },
    { "name": "resource_grants", "outcome": "SKIP", "detail": "" },
    { "name": "policies",        "outcome": "SKIP", "detail": "" }
  ]
}
```
`simulate` returns the same `ExplainResponse` shape. Its request body:
```json
{
  "request": { /* an AuthorizationRequest */ },
  "addAssignments": [ { "roleId": "…-uuid", "scopeId": "…-uuid" } ],
  "removeAssignmentIds": [ "…-uuid" ]
}
```

**`POST /api/v1/effective-permissions`** — body `EffectivePermissionsRequest`:
```json
{
  "subject": "9f1c…-uuid",
  "scopeId": "a2b…-uuid",
  "resource": { "type": "invoice", "id": "inv_1", "scopeId": "a2b…-uuid" }, // optional
  "context": { … },      // optional
  "includeDenied": true  // include deniedPermissions in the response
}
```
Response (`EffectivePermissionsResponse`, raw):
```json
{
  "subject": "9f1c…-uuid",
  "scopeId": "a2b…-uuid",
  "permissions": ["billing.invoice.read", "billing.invoice.write"],
  "deniedPermissions": ["billing.invoice.delete"]
}
```
With `?asOf=2026-01-01T00:00:00Z` the service reconstructs permissions from assignment history at that instant (scope taken from `scopeId`, else `resource.scopeId`).

**`POST /api/v1/filter-resources`** — body `FilterResourcesRequest`:
```json
{
  "subjectId": "9f1c…-uuid",
  "permission": "billing.invoice.read",
  "resourceType": "invoice",
  "resourceIds": ["inv_1", "inv_2", "inv_3"],  // ≤ 500
  "scopeId": "a2b…-uuid",   // optional
  "context": { }             // optional
}
```
Response (raw): `{ "allowed": ["inv_1", "inv_3"] }`.

**`GET /api/v1/access-list?permission=…&scopeId=…`** — raw list of `AccessListEntry`:
```json
[ { "subjectId": "9f1c…-uuid", "conditional": false },
  { "subjectId": "0aa…-uuid",  "conditional": true } ]
```
(`conditional:true` = grant carries conditions/policies whose live verdict is context-dependent.)

---

## 4. Authorization admin — `/api/v1/*`

All raw-JSON. Path-level auth from `SecurityConfig`; some controllers add method-level `@PreAuthorize`. Unless noted, `POST` returns **201**, `PUT`/`GET` **200**, `DELETE` **200/204** empty.

### Permissions — `PermissionController` (`/api/v1/permissions`) — **SuperAdmin** (path rule)

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/api/v1/permissions` | SuperAdmin | List active permissions; optional `?domain=`. |
| GET | `/api/v1/permissions/{id}` | SuperAdmin | Get one permission (empty 404 if absent). |
| POST | `/api/v1/permissions` | SuperAdmin | Create one or many (body is an array). |

`POST` body: array of `CreatePermissionRequest` `{ key, domain, resource, action, description? }` (key matches `^[a-z_]+\.[a-z_]+\.[a-z_]+$`). Returns the created `Permission` (single) or `List<Permission>`.

### Permission groups — `PermissionGroupController` (`/api/v1/permission-groups`) — **SuperAdmin**

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/api/v1/permission-groups` | SuperAdmin | List groups. |
| GET | `/api/v1/permission-groups/{id}` | SuperAdmin | Get one group (empty 404 if absent). |
| POST | `/api/v1/permission-groups` | SuperAdmin | Create group. Body `CreatePermissionGroupRequest` `{ name, description?, parentGroupId? }`. |
| GET | `/api/v1/permission-groups/{id}/permissions` | SuperAdmin | List a group's permissions. |
| PUT | `/api/v1/permission-groups/{id}/permissions` | SuperAdmin | Replace the group's permission set. Body `{ permissionIds: uuid[] }`. 200 empty. |

### Roles — `RoleController` (`/api/v1/roles`) — **Authenticated** (path rule; service layer refines)

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/api/v1/roles` | Authenticated | List active roles; optional `?orgType=`. |
| GET | `/api/v1/roles/{id}` | Authenticated | Get one role (empty 404 if absent). |
| GET | `/api/v1/roles/{id}/permissions` | Authenticated | List a role's permissions. |
| POST | `/api/v1/roles` | Authenticated | Create a role. Body `CreateRoleRequest` `{ name, displayName?, description?, orgType?, ownerScopeId?, permissionIds? }` (`ownerScopeId` null = global role). |
| PUT | `/api/v1/roles/{id}/permissions` | Authenticated | Replace a role's permissions. Body is a raw `uuid[]`. 200 empty. |

### Role hierarchy — `RoleHierarchyController` (`/api/v1/role-hierarchy`) — **SuperAdmin**

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/api/v1/role-hierarchy/parents/{roleId}` | SuperAdmin | Parent role ids (`uuid[]`). |
| GET | `/api/v1/role-hierarchy/children/{roleId}` | SuperAdmin | Child role ids (`uuid[]`). |
| POST | `/api/v1/role-hierarchy` | SuperAdmin | Add inheritance link. Body `{ parentRoleId, childRoleId }`. |
| DELETE | `/api/v1/role-hierarchy?parentRoleId=…&childRoleId=…` | SuperAdmin | Remove inheritance link. 200 empty. |

### Scopes — `ScopeController` (`/api/v1/scopes`) — **SuperAdmin**

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/api/v1/scopes` | SuperAdmin | List scopes; optional `?type=`. |
| GET | `/api/v1/scopes/root` | SuperAdmin | The root scope. |
| GET | `/api/v1/scopes/{id}` | SuperAdmin | Get one scope (empty 404 if absent). |
| GET | `/api/v1/scopes/{id}/descendants` | SuperAdmin | List descendant scopes. |
| POST | `/api/v1/scopes` | SuperAdmin | Create scope. Body `CreateScopeRequest` `{ type, name, code?, parentId?, metadata? }` (type ∈ GLOBAL/COUNTRY/REGION/ORG/DEPT/TEAM). |
| POST | `/api/v1/scopes/{id}/move` | SuperAdmin | Reparent a scope. Body `MoveScopeRequest` `{ newParentId }`. |

> There is **no scope-types controller** — omitted deliberately.

### Assignments — `AssignmentController` (`/api/v1/assignments`) — **Authenticated**

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/api/v1/assignments` | Authenticated | List assignments; optional `?subjectId=`. |
| POST | `/api/v1/assignments` | Authenticated | Assign a role to a subject at a scope. Body `CreateAssignmentRequest` `{ subjectId, subjectType="USER", roleId, scopeId, expiresAt?, conditions? }`. |
| DELETE | `/api/v1/assignments/{id}?reason=…` | Authenticated | Revoke an assignment. 200 empty. |

### Deny rules — `DenyRuleController` (`/api/v1/deny-rules`) — **Authenticated**

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/api/v1/deny-rules?subjectId=…` | Authenticated | Deny rules for a subject (empty list if `subjectId` omitted). |
| POST | `/api/v1/deny-rules` | Authenticated | Create a deny rule. Body `CreateDenyRuleRequest` `{ subjectId, subjectType="USER", permissionKey, scopeId?, reason, referenceId?, expiresAt? }`. |
| DELETE | `/api/v1/deny-rules/{id}` | Authenticated | Remove a deny rule. 200 empty. |

### Policies — `PolicyController` (`/api/v1/policies`) — **SuperAdmin**

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/api/v1/policies` | SuperAdmin | List policies. |
| GET | `/api/v1/policies/{id}` | SuperAdmin | Get one policy (empty 404 if absent). |
| POST | `/api/v1/policies` | SuperAdmin | Create policy. Body `CreatePolicyRequest` `{ name, description?, permissionKey?, resourceType?, scopeId?, effect="ALLOW", priority=0, conditions?, active=true, createdBy="system" }`. |
| PUT | `/api/v1/policies/{id}` | SuperAdmin | Update policy. Body `UpdatePolicyRequest` (same fields minus `name`). |
| DELETE | `/api/v1/policies/{id}` | SuperAdmin | Deactivate (soft-delete) policy. 200 empty. |

### Context attributes — `ContextAttributeController` (`/api/v1/context-attributes`)

Path falls under `anyRequest().authenticated()`; method security narrows.

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/api/v1/context-attributes` | `SuperAdmin` or `AccessAdmin` | List context attributes. |
| POST | `/api/v1/context-attributes` | `SuperAdmin` | Create attribute. Body `{ name, valueType="STRING", description? }`. |
| DELETE | `/api/v1/context-attributes/{id}` | `SuperAdmin` | Delete attribute. 204. |

### Audit — `AuditController` (`/api/v1/audit`) — **SuperAdmin, CountryAdmin, AccessAdmin, SecurityAdmin, or AuditViewer**

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/api/v1/audit/subject/{subjectId}?limit=100` | (above roles) | Audit records for a subject. |
| GET | `/api/v1/audit/resource/{resourceType}/{resourceId}?limit=100` | (above roles) | Audit records for a resource. |
| GET | `/api/v1/audit/statistics/{subjectId}?sinceDaysAgo=7` | (above roles) | Decision statistics for a subject (default window 7 days). Returns a `Map`. |

### Resource grants — `ResourceGrantController` (`/api/v1/resource-grants`) — **Authenticated** · flag `resource-grants`

Whole controller is flag-gated: **404** when `resource-grants` is off. Grant creation/revocation authority is enforced in-code (grantor must hold the permission ceiling; wildcard-action keys require a platform admin; only the original grantor or a platform admin may revoke).

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/api/v1/resource-grants` | Authenticated (ceiling-checked) | Create a per-instance grant. Body `CreateGrantRequest` `{ subjectId, subjectType="USER", permissionKey, resourceType, resourceId, scopeId?, expiresAt? }`. |
| GET | `/api/v1/resource-grants` | Authenticated | List active grants by `?subjectId=` **or** by `?resourceType=&resourceId=` (400 if neither). |
| DELETE | `/api/v1/resource-grants/{id}` | Grantor or platform admin | Revoke a grant. 204. |

### Subject groups — `SubjectGroupController` (`/api/v1/groups`) — **SuperAdmin** (class-level) · flag `groups`

Whole controller is flag-gated (**404** when `groups` off) and class-level `@PreAuthorize("hasRole('SuperAdmin')")`.

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/api/v1/groups` | SuperAdmin | List groups. |
| POST | `/api/v1/groups` | SuperAdmin | Create group. Body `{ name, description? }`. |
| GET | `/api/v1/groups/{id}/members` | SuperAdmin | List members. |
| POST | `/api/v1/groups/{id}/members` | SuperAdmin | Add member. Body `{ subjectId }`. 201. |
| DELETE | `/api/v1/groups/{id}/members/{subjectId}` | SuperAdmin | Remove member. 204. |

### Service registry — `ServiceRegistryController` (`/api/v1/services`) · flag `service-registry`

Whole controller is flag-gated (**404** when `service-registry` off).

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/api/v1/services` | `SuperAdmin` | Register a service; returns the API key **once**. |
| GET | `/api/v1/services` | `SuperAdmin` | List registered services. |
| PUT | `/api/v1/services/{name}/permissions` | `INTERNAL` or `SuperAdmin` (path rule); in-code: the service itself (`service:<name>`) or `SuperAdmin` | **Manifest sync** — idempotent upsert of the service's own permission keys. |

`POST /api/v1/services` body `{ name, displayName?, ownedDomains?: string[] }` → `{ id, name, ownedDomains, apiKey }` (apiKey shown once; only its SHA-256 is stored).

**Manifest sync — `PUT /api/v1/services/{name}/permissions`**
```json
// request (ManifestRequest)
{
  "permissions": [
    { "key": "billing.invoice.read",  "description": "View invoices" },
    { "key": "billing.invoice.write", "description": "Edit invoices" }
  ],
  "deprecateMissing": true   // optional; treated as true when omitted
}
```
Each `key` must be 3–6 dot segments and its first segment (domain) must be in the service's `ownedDomains` (else 400). When `deprecateMissing` is true, owned-domain keys absent from the manifest are marked **deprecated** (never deleted). Response (`SyncResult`, raw):
```json
{ "created": 2, "unchanged": 5, "deprecated": 1 }
```

---

## 5. Token & sessions service — `/api/v1/token/*`, break-glass

Controller: `TokenIntrospectionController` (`/api/v1/token`), path rule **`INTERNAL` or `SuperAdmin`**. Raw JSON.

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/api/v1/token/introspect` | INTERNAL or SuperAdmin · flag `introspection` | RFC 7662-style live check (signature + expiry + revocation). **404** when flag off. |
| GET | `/api/v1/token/revocations?since=<ISO-8601>` | INTERNAL or SuperAdmin · flag `revocation-feed` | Sessions revoked since a timestamp, for polling/offline consumers. **404** when flag off. |

**`introspect`** — body `{ "token": "<access-jwt>" }` → `{ "active": true, "sub": "…", "sid": "…", "exp": 1751630400, "roles": [ … ] }` (invalid/unparseable token → `{ "active": false }`).

**`revocations`** — raw list: `[ { "sid": "…", "subject": "…-identity-uuid", "revokedAt": "…", "reason": "LOGOUT" }, … ]`.

### Break-glass — `BreakGlassController` (`/api/v1/break-glass`) — **Authenticated** · flag `break-glass`

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/api/v1/break-glass` | Authenticated | Grant emergency, time-boxed elevation (creates a short-lived `BREAK_GLASS` assignment). **404** when `break-glass` off. |

Body `BreakGlassRequest` `{ subjectId, roleId, scopeId, durationMinutes=60, reason, referenceId? }` → the created `Assignment` (201). `reason` is mandatory.

---

## 6. User-facing authz — `/api/authz/me/*`

Controller: `AuthzMeController`, class-level `@PreAuthorize("isAuthenticated()")`, envelope responses. Drives the org-switcher and permission-based UI for the current user.

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/api/authz/me/scopes` | Bearer (authenticated) | Scopes (orgs/teams) where the caller has active role assignments. |
| GET | `/api/authz/me/permissions?scopeId=…` | Bearer (authenticated) | The caller's effective permissions at the given scope. |

- `scopes` `data`: list of `ScopeSummaryDto` `{ id, type, name, code }`.
- `permissions` `data`: `string[]` of permission keys.

---

## 7. Health — `/api/v1/health/*`

Controller: `HealthController`. Not in the public allowlist → **authenticated** (no specific role). Raw JSON. (Liveness/readiness live separately at the public `/actuator/health`.)

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/api/v1/health/cache-stats` | Authenticated | Authorization cache statistics (`CacheStats`). |
| GET | `/api/v1/health/metrics` | Authenticated | Decision counters, latency timers, and cache stats (`Map`). |

Public infra endpoints (permit-all, not part of these controllers): `/actuator/**`, `/health`, `/swagger-ui/**`, `/v3/api-docs/**`, `/.well-known/**`, `GET /` (redirects to `/actuator/health`).
