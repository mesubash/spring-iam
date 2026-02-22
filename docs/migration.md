# Identity Platform — Migration & Implementation Guide

> **From:** Monolith with embedded auth  
> **To:** Unified Identity Platform (AuthN + AuthZ)  
> **Status:** Implementation reference for development team

---

## 1. What We Had (Old System)

The existing system is a monolith with authentication baked in. Authorization is hardcoded as role strings on user tables.

### Old Tables (AuthN related)

| Table | Purpose |
|-------|---------|
| `auth_users` | Login credentials — email, password_hash, provider, provider_user_id |
| `blacklisted_refresh_tokens` | Revoked tokens stored by hash |
| `users` | Profile + hardcoded role enum (TOURIST, ADMIN, TRAVEL_AGENCY, etc.) |
| `companies` | Company registry with approval workflow |
| `company_types` | Multi-type support per company |
| `company_users` | Staff membership with hardcoded role enum (ADMIN, MANAGER, STAFF, AGENT, etc.) |

### Old Authorization Model

```
users.role = 'TRAVEL_AGENCY'        → single string, no scoping
company_users.role = 'ADMIN'        → single string, within one company
```

Business services enforced access like:

```java
if (user.getRole().equals("ADMIN")) { allow }
        if (companyUser.getRole().equals("MANAGER")) { allow }
```

**Problems:**
- No permission granularity (role = all-or-nothing)
- No scope hierarchy (can't express "admin of Nepal" vs "admin of Everest Travels")
- No deny override (can't block one action without removing entire role)
- No audit trail for access decisions
- Authorization logic scattered across every service
- Adding a new role means changing enum constraints and redeploying

---

## 2. What We're Building (New System)

A single **Identity Platform** service containing two logical modules:

```
identity-platform/
├── authn/          ← login, credentials, tokens, sessions
├── authz/          ← permissions, roles, scopes, assignments, deny rules
├── shared/         ← identity_profiles, common DTOs
└── audit/          ← security_events + authorization_audit
```

Deployed as **one service**. Internally modular with strict boundary rules.

### Module Boundary Rules (Non-Negotiable)

These four rules ensure that extracting AuthZ into a separate service later is a one-week refactoring job, not a rewrite. Violating any of these creates tight coupling that makes future extraction painful.

**Rule 1: No cross-module imports.**

AuthN module and AuthZ module never import each other's internal classes, repositories, or entities. If AuthN needs something from AuthZ (e.g., role claims during login), it calls through a clean interface — a service interface defined in the shared module.

```
✅ authn/ calls shared/AuthzQueryService.getRolesForIdentity(identityId)
❌ authn/ imports authz/repository/AssignmentRepository directly
❌ authz/ imports authn/entity/Credential directly
```

**Rule 2: Separate table ownership.**

Each module owns its tables exclusively. No module reads or writes another module's tables directly.

```
authn/ owns:
  identities, credentials, refresh_tokens, security_events

authz/ owns:
  permissions, roles, role_permissions, scopes, scope_closure,
  assignments, deny_rules, authorization_audit

shared/ owns:
  identity_profiles
```

If AuthZ needs to check `identities.account_status`, it calls a shared interface, not a direct query.

**Rule 3: Communication through DTOs only.**

Modules exchange data through plain DTOs defined in the shared module. No JPA entities or internal models cross module boundaries.

```
shared/
├── dto/
│   ├── IdentitySummaryDto      (id, email, accountStatus)
│   ├── RoleClaimsDto           (roles[], primaryScope)
│   ├── AuthorizationRequestDto
│   ├── AuthorizationResultDto
│   └── ProfileDto
├── service/
│   ├── AuthzQueryService       (interface — implemented by authz/)
│   └── IdentityQueryService    (interface — implemented by authn/)
```

**Rule 4: The /authorize contract is HTTP-shaped.**

Even though AuthZ is called internally via method call right now, the `AuthorizationRequestDto` and `AuthorizationResultDto` must look exactly like the HTTP request/response would if it were a remote call. No passing of JPA entities, database connections, or request-scoped objects.

```java
// This interface looks identical to what a REST client would call
public interface AuthzQueryService {
    AuthorizationResultDto authorize(AuthorizationRequestDto request);
    RoleClaimsDto getRolesForIdentity(UUID identityId);
    List<String> getEffectivePermissions(UUID identityId, UUID scopeId);
}
```

When extraction day comes, you replace the in-memory implementation with an HTTP client. The calling code doesn't change.

### Internal Communication Flow

```
Login flow (AuthN needs AuthZ):
  authn/LoginService
    → calls shared/AuthzQueryService.getRolesForIdentity()
    → authz/AuthzQueryServiceImpl queries assignments + roles
    → returns RoleClaimsDto { roles, primaryScope }
    → authn/LoginService builds JWT with these claims

Authorization flow (business service needs AuthZ):
  External HTTP POST /authz/authorize
    → authz/AuthorizationController
    → authz/AuthorizationEngine evaluates
    → returns AuthorizationResultDto

Token refresh (AuthN needs fresh AuthZ claims):
  authn/TokenService
    → calls shared/AuthzQueryService.getRolesForIdentity()
    → gets fresh roles (may have changed since last login)
    → builds new JWT
```

### Package Structure (Java/Spring Boot)

```
com.yourcompany.identity
├── authn/
│   ├── controller/
│   │   ├── AuthController          (login, register, oauth)
│   │   ├── TokenController         (refresh, logout, sessions)
│   │   └── ProfileController       (me, update profile)
│   ├── service/
│   │   ├── AuthenticationService
│   │   ├── CredentialService
│   │   ├── TokenService
│   │   └── IdentityQueryServiceImpl  (implements shared interface)
│   ├── repository/
│   │   ├── IdentityRepository
│   │   ├── CredentialRepository
│   │   ├── RefreshTokenRepository
│   │   └── SecurityEventRepository
│   └── entity/
│       ├── Identity
│       ├── Credential
│       ├── RefreshToken
│       └── SecurityEvent
│
├── authz/
│   ├── controller/
│   │   ├── AuthorizationController  (/authorize, /authorize/batch)
│   │   ├── RoleController
│   │   ├── ScopeController
│   │   ├── AssignmentController
│   │   ├── DenyRuleController
│   │   └── AuditController
│   ├── service/
│   │   ├── AuthorizationEngine      (the core: deny → role → scope → conditions)
│   │   ├── ScopeService
│   │   ├── RoleService
│   │   ├── AssignmentService
│   │   ├── DenyRuleService
│   │   └── AuthzQueryServiceImpl    (implements shared interface)
│   ├── repository/
│   │   ├── PermissionRepository
│   │   ├── RoleRepository
│   │   ├── ScopeRepository
│   │   ├── ScopeClosureRepository
│   │   ├── AssignmentRepository
│   │   ├── DenyRuleRepository
│   │   └── AuthorizationAuditRepository
│   └── entity/
│       ├── Permission
│       ├── Role
│       ├── Scope
│       ├── ScopeClosure
│       ├── Assignment
│       ├── DenyRule
│       └── AuthorizationAudit
│
├── shared/
│   ├── dto/
│   │   ├── IdentitySummaryDto
│   │   ├── RoleClaimsDto
│   │   ├── ProfileDto
│   │   ├── AuthorizationRequestDto
│   │   ├── AuthorizationResultDto
│   │   └── ErrorResponseDto
│   ├── service/
│   │   ├── AuthzQueryService        (interface)
│   │   └── IdentityQueryService     (interface)
│   ├── security/
│   │   ├── JwtProvider
│   │   ├── JwtFilter
│   │   └── ApiKeyFilter
│   └── entity/
│       └── IdentityProfile
│
└── config/
    ├── SecurityConfig
    ├── RedisConfig
    └── DatabaseConfig
```

### What Extraction Looks Like (Future, When Needed)

If `/authorize` traffic becomes a bottleneck or a separate team takes ownership:

```
1. authz/ package → becomes its own Spring Boot application
2. shared/service/AuthzQueryService → implemented as HTTP client (RestTemplate/WebClient)
3. shared/service/IdentityQueryService → implemented as HTTP client in AuthZ service
4. shared/dto/ → copied to both services (or published as a shared library)
5. authn/ calls AuthzQueryService → now goes over HTTP instead of method call
6. External services call AuthZ directly (same /authorize endpoint, same DTOs)
```

Calling code in AuthN doesn't change. Business service calling code doesn't change. Only the implementation of the interface changes from local method call to HTTP call.

---

## 3. What Changed — Table by Table

### 3.1 Replaced Tables

| Old Table | New Table(s) | What Changed |
|-----------|-------------|--------------|
| `auth_users` | `identities` + `credentials` | Split identity from credentials. One identity can now have multiple login methods (password + Google). `identities.id` becomes the universal subject_id. |
| `blacklisted_refresh_tokens` | `refresh_tokens` | Flipped model. Instead of tracking dead tokens, we track ALL tokens and mark them revoked. Gives us active session visibility. |
| `users` (auth fields) | `identities` + `identity_profiles` | `users.role` → deleted, replaced by `assignments`. `users.status` → `identities.account_status`. Profile fields (name, phone, country, avatar) → `identity_profiles`. |

### 3.2 Fields That Moved

| Old Location | New Location | Notes |
|-------------|-------------|-------|
| `auth_users.email` | `identities.primary_email` | Renamed for clarity |
| `auth_users.password_hash` | `credentials.secret_hash` | Separated into own table |
| `auth_users.provider` | `credentials.credential_type` | Now supports multiple per identity |
| `auth_users.provider_user_id` | `credentials.identifier` | Combined with email lookup |
| `auth_users.is_verified` | `identities.email_verified` | Renamed |
| `auth_users.last_login` | `identities.last_login_at` | Added last_login_ip |
| `users.name` | `identity_profiles.display_name` | Renamed |
| `users.phone` | `identity_profiles.phone` | Same |
| `users.email` | `identity_profiles.email` | Contact email (can differ from login email) |
| `users.country` | `identity_profiles.country` | Same |
| `users.avatar_url` | `identity_profiles.avatar_url` | Same |
| `users.role` | **DELETED** | Replaced by `assignments` table |
| `users.status` | `identities.account_status` | Enum values changed: ACTIVE, LOCKED, SUSPENDED, DEACTIVATED |
| `company_users.role` | **DELETED from auth perspective** | Replaced by `assignments` table. `company_users` table stays in business service for business data. |

### 3.3 Completely New Tables

| Table | Purpose |
|-------|---------|
| `security_events` | AuthN audit trail — login attempts, password changes, lockouts |
| `permissions` | Immutable action dictionary (developer-seeded) |
| `roles` | Named permission bundles |
| `role_permissions` | Role ↔ permission mapping |
| `scopes` | Hierarchical org tree (GLOBAL → COUNTRY → ORG → DEPT) |
| `scope_closure` | Pre-computed hierarchy for O(1) containment checks |
| `assignments` | The core: subject + role + scope = access grant |
| `deny_rules` | Emergency overrides — DENY always wins |
| `authorization_audit` | Immutable log of every /authorize decision |

### 3.4 Tables That Stay Unchanged in Business Service

These tables are NOT touched by this migration. They remain in the business service database:

```
companies              → stays (business registry, approval workflow)
company_types          → stays (multi-type support)
company_users          → stays (commission, territory, agent_code, relationship_type)
                          BUT company_users.role is no longer used for authorization
tourists               → stays
orders                 → stays
order_items            → stays
order_groups           → stays
ctgs                   → stays
insurance_products     → stays
routes                 → stays
devices                → stays
payment_transactions   → stays
documents              → stays
... all other business tables stay
```

**The `users` table in the business service** becomes a lightweight reference. It either:
- Gets replaced by a `user_references` table with just `identity_id` + any business-specific user fields
- Or gets its auth fields removed (role, status) and keeps only business fields, with `auth_id` renamed to `identity_id`

---

## 4. The New Schema (13 Tables)

### AuthN Module (5 tables)

```sql
identities
├── id (UUID) ← THE universal subject_id
├── primary_email (unique)
├── email_verified
├── account_status (ACTIVE/LOCKED/SUSPENDED/DEACTIVATED)
├── failed_login_attempts
├── account_locked_until
├── last_login_at
├── last_login_ip
├── mfa_enabled
├── created_at, updated_at

credentials
├── id (UUID)
├── identity_id → identities
├── credential_type (PASSWORD/GOOGLE/APPLE/MICROSOFT)
├── identifier
├── secret_hash (null for OAuth)
├── is_active
├── last_used_at
├── created_at, updated_at
├── UNIQUE(credential_type, identifier)

refresh_tokens
├── id (UUID)
├── identity_id → identities
├── token_hash
├── ip_address, user_agent
├── expires_at
├── revoked_at, revoke_reason
├── created_at

identity_profiles
├── identity_id (PK + FK → identities, 1:1)
├── display_name, phone, email, country, avatar_url
├── created_at, updated_at

security_events
├── id (UUID)
├── identity_id → identities
├── event_type (LOGIN_SUCCESS/LOGIN_FAILED/PASSWORD_CHANGED/...)
├── ip_address, user_agent
├── metadata (JSONB)
├── created_at
```

### AuthZ Module (8 tables)

```sql
permissions
├── id (UUID)
├── key (unique, format: domain.resource.action)
├── domain, resource, action
├── description
├── is_deprecated
├── created_at

roles
├── id (UUID)
├── name (unique)
├── description
├── is_system_role
├── org_type (nullable hint)
├── created_at, updated_at

role_permissions
├── role_id → roles
├── permission_id → permissions
├── PK(role_id, permission_id)

scopes
├── id (UUID)
├── type (GLOBAL/REGION/COUNTRY/ORG/DEPT/TEAM)
├── name, code (unique)
├── parent_id → scopes
├── path (ltree)
├── metadata (JSONB)
├── active
├── created_at, updated_at

scope_closure
├── ancestor_id → scopes
├── descendant_id → scopes
├── depth
├── PK(ancestor_id, descendant_id)
├── Auto-maintained by trigger

assignments
├── id (UUID)
├── subject_id → identities
├── role_id → roles
├── scope_id → scopes
├── granted_by → identities
├── granted_at, expires_at
├── conditions (JSONB)
├── active
├── revoked_at, revoked_by, revoke_reason

deny_rules
├── id (UUID)
├── subject_id → identities
├── permission_key
├── scope_id → scopes (null = global)
├── reason (required)
├── created_by → identities
├── created_at, expires_at, active

authorization_audit (partitioned by month)
├── id, subject_id, permission_key
├── resource_type, resource_id, scope_id
├── decision (bool), reason
├── ip_address, context (JSONB)
├── created_at
├── IMMUTABLE (no update, no delete)
```

---

## 5. How Old Roles Map to New Assignments

### 5.1 users.role Migration

| Old `users.role` | New Assignment |
|------------------|----------------|
| `ADMIN` | role: `SuperAdmin` or `CountryAdmin` at scope: `GLOBAL` or `COUNTRY:NEPAL` |
| `TRAVEL_AGENCY` | No direct assignment — this was an identity type, not a permission. The user gets assigned a role when linked to a company via `company_users`. |
| `SALES_AGENT` | Same as above — role comes from company assignment. |
| `INSURANCE_COMPANY` | Same — role through company. |
| `RESCUE_COMPANY` | Same — role through company. |
| `RESCUE_CENTRE` | Same — role through company. |
| `HOSPITAL` | Same — role through company. |
| `TOURIST` | Typically no assignment needed. Tourists access their own data. If needed: role: `Tourist` at scope: `GLOBAL`. |
| `USER` | Base role. Typically no assignment or a minimal `BasicUser` role. |

**Key insight:** The old `users.role` was mixing two concepts — "what type of entity is this user" and "what can this user do." In the new system, entity type is business data (stored in `company_types` or user metadata). Authorization comes from assignments.

### 5.2 company_users.role Migration

| Old `company_users.role` | Company Type | New Assignment |
|--------------------------|-------------|----------------|
| `ADMIN` | TRAVEL_AGENCY | role: `TravelAgencyAdmin` at scope: `ORG:{company_scope}` |
| `MANAGER` | TRAVEL_AGENCY | role: `TravelAgencyManager` at scope: `ORG:{company_scope}` |
| `STAFF` | TRAVEL_AGENCY | role: `TravelAgencyStaff` at scope: `ORG:{company_scope}` |
| `AGENT` | SALES_COMPANY | role: `SalesAgent` at scope: `ORG:{company_scope}` |
| `SENIOR_AGENT` | SALES_COMPANY | role: `SeniorSalesAgent` at scope: `ORG:{company_scope}` |
| `ADMIN` | RESCUE_COMPANY | role: `RescueCompanyAdmin` at scope: `ORG:{company_scope}` |
| `STAFF` | RESCUE_COMPANY | role: `RescueOperator` at scope: `ORG:{company_scope}` |
| `ADMIN` | INSURANCE | role: `InsuranceAdmin` at scope: `ORG:{company_scope}` |
| `STAFF` | INSURANCE | role: `InsuranceOperator` at scope: `ORG:{company_scope}` |
| `ADMIN` | HOSPITAL | role: `HospitalAdmin` at scope: `ORG:{company_scope}` |

### 5.3 Scope Creation From Existing Companies

For each company in the `companies` table, create a scope:

```
For company "Everest Travels" (id: company-uuid-1, types: [TRAVEL_AGENCY]):

INSERT INTO scopes:
  type: ORG
  name: "Everest Travels"
  code: "EVEREST_TRAVELS"
  parent_id: nepal-country-scope-uuid
  path: GLOBAL.NEPAL.EVEREST_TRAVELS
  metadata: { "orgType": "TRAVEL_AGENCY", "companyId": "company-uuid-1" }
```

The `metadata.companyId` field links the scope back to the business service's company table.

---

## 6. What Changes in Business Services

### 6.1 User References

The business service currently has a `users` table with auth fields. After migration:

**Option A (recommended):** Keep `users` table but strip auth fields:

```
users (business service — AFTER migration)
├── id (UUID) ← keep as-is for FK compatibility
├── identity_id (UUID) → references Identity Platform's identities.id
├── name, phone, email, country, avatar_url ← cached from identity_profiles
├── search_vector
├── created_at, updated_at, deleted_at
├── created_by_user_id, updated_by_user_id
│
├── REMOVED: auth_id (replaced by identity_id)
├── REMOVED: role (moved to assignments)
├── REMOVED: status (moved to identities.account_status)
```

**Why cache profile fields?** So business service can do JOINs and full-text search without calling Identity Platform on every query. Profile changes are synced via event (webhook/message queue) or periodic refresh.

### 6.2 company_users Changes

```
company_users (business service — AFTER migration)
├── id, company_id, user_id ← unchanged
├── relationship_type ← unchanged (EMPLOYEE, CONTRACTOR, etc.)
├── commission_rate, territory, agent_code ← unchanged
├── is_active, effective_from, effective_to ← unchanged
├── notes, metadata ← unchanged
│
├── REMOVED: role ← moved to Identity Platform assignments
```

The `role` column becomes unnecessary because authorization is handled by assignments. But you might keep it as a **display label** (not used for auth checks). If so, rename it to something like `display_role` or `position_title` to make clear it's not an auth concept.

### 6.3 Authorization Check Changes

**Before (old):**

```java
// Scattered across every service
if (user.getRole().equals("ADMIN")) {
        // allow
        }

        if (companyUser.getRole().equals("MANAGER") || companyUser.getRole().equals("ADMIN")) {
        // allow
        }
```

**After (new) — Simple check:**

```java
// JWT contains roles, service checks locally
@PreAuthorize("hasAuthority('order.order.read')")
@GetMapping("/orders")
public List<Order> getOrders() { ... }
```

**After (new) — Complex check:**

```java
@PostMapping("/orders/{orderId}/approve")
public Order approveOrder(@PathVariable String orderId) {
    Order order = orderService.findById(orderId);

    // Call Identity Platform
    AuthzResponse response = identityClient.authorize(
            currentUser.getIdentityId(),     // subject
            "order.order.approve",            // permission
            order.getOrganizationScopeId()    // scope
    );

    if (!response.isAuthorized()) {
        throw new ForbiddenException(response.getReason());
    }

    // proceed with business logic
    return orderService.approve(order);
}
```

### 6.4 Company Registration Flow Change

**Before:** Create company → create company_user with role ADMIN → done.

**After:**

```
1. Business service creates company in companies table (unchanged)
2. Business service calls Identity Platform:
   POST /authz/scopes
   { type: "ORG", name: "New Company", parentId: "nepal-scope-uuid",
     metadata: { orgType: "TRAVEL_AGENCY", companyId: "company-uuid" } }
3. Identity Platform returns scope_id
4. Business service stores scope_id on company record (new column: scope_id)
5. Business service calls Identity Platform:
   POST /authz/assignments
   { subjectId: admin-identity-uuid, roleId: TravelAgencyAdmin-role-uuid,
     scopeId: new-scope-uuid }
6. Admin user now has access to the new company
```

### 6.5 Employee Addition Flow Change

**Before:** Create company_user with role STAFF → done.

**After:**

```
1. Business service creates company_user row (without role, or with display label)
2. Business service calls Identity Platform:
   POST /authz/assignments
   { subjectId: employee-identity-uuid, roleId: TravelAgencyStaff-role-uuid,
     scopeId: company-scope-uuid }
3. Employee now has scoped access
```

### 6.6 Employee Removal Flow Change

**Before:** Deactivate company_user → done (but user still had the role string).

**After:**

```
1. Business service deactivates company_user
2. Business service calls Identity Platform:
   DELETE /authz/assignments/{assignmentId}
   { reason: "Employee removed from company" }
3. Access immediately revoked on next /authorize check
4. Takes effect on JWT within 15 minutes (next token refresh)
5. For immediate effect: create deny rule
```

---

## 7. Frontend Changes

### 7.1 Login Response Change

**Before:**

```json
{
  "token": "jwt...",
  "user": {
    "id": "user-uuid",
    "name": "Sita",
    "role": "TRAVEL_AGENCY",
    "companyId": "company-uuid"
  }
}
```

**After:**

```json
{
  "accessToken": "jwt...",
  "refreshToken": "refresh...",
  "expiresIn": 900,
  "identity": {
    "id": "identity-uuid",
    "email": "sita@everest.com",
    "displayName": "Sita Sharma"
  }
}
```

No role in login response. Role comes from the next call.

### 7.2 New Post-Login Flow

```
1. Login → get tokens
2. GET /authz/me/scopes → get list of orgs user belongs to
3. If multiple orgs → show org switcher
4. GET /authz/me/permissions?scopeId=<selected-org> → get permissions
5. Cache permissions in memory (React state / Zustand / etc.)
6. Render UI conditionally based on permissions
```

### 7.3 Permission-Based UI Rendering

**Before:**

```jsx
{user.role === 'ADMIN' && <button>Approve</button>}
```

**After:**

```jsx
{permissions.includes('order.order.approve') && <button>Approve</button>}
```

### 7.4 Org Switcher (New Feature)

If a user has assignments at multiple scopes (admin at Company A, staff at Company B), the frontend shows an org switcher. On switch:

```
1. User selects "Himalaya Adventures" from dropdown
2. Frontend calls GET /authz/me/permissions?scopeId=himalaya-scope-uuid
3. New permissions replace old ones in cache
4. UI re-renders — different buttons visible based on different role
```

### 7.5 Token Refresh Change

**Before:** Single token, long-lived or manually managed.

**After:**

```
- Access token: 15 min expiry
- Refresh token: 30 day expiry, rotated on each use
- Frontend sets up auto-refresh before access token expires
- On refresh, roles may change (if admin modified assignments)
- On 401 with expired token: call /auth/refresh, retry original request
```

---

## 8. API Endpoints Summary

### AuthN Endpoints (Identity Platform)

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/auth/register` | None | Create account |
| POST | `/auth/login` | None | Login with password |
| POST | `/auth/oauth` | None | Login with OAuth provider |
| POST | `/auth/refresh` | None (refresh token in body) | Get new token pair |
| POST | `/auth/logout` | Bearer JWT | Revoke refresh token |
| POST | `/auth/logout-all` | Bearer JWT | Revoke all sessions |
| GET | `/auth/sessions` | Bearer JWT | List active sessions |
| DELETE | `/auth/sessions/{id}` | Bearer JWT | Revoke specific session |
| GET | `/auth/me` | Bearer JWT | Get own profile |
| PUT | `/auth/me` | Bearer JWT | Update own profile |
| PUT | `/auth/password` | Bearer JWT | Change password |
| POST | `/auth/password/reset-request` | None | Request reset email |
| POST | `/auth/password/reset-confirm` | None | Set new password |
| GET | `/auth/.well-known/jwks.json` | None (public) | JWT public keys |

### AuthZ Endpoints — User-Facing (Identity Platform)

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/authz/me/scopes` | Bearer JWT | List my scopes (org switcher) |
| GET | `/authz/me/permissions` | Bearer JWT | Get my permissions at a scope |

### AuthZ Endpoints — Service-to-Service (Identity Platform)

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/authz/authorize` | API Key | Check permission (the core endpoint) |
| POST | `/authz/authorize/batch` | API Key | Check multiple permissions at once |

### AuthZ Endpoints — Admin (Identity Platform)

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/authz/permissions` | Admin JWT | List permissions (read-only) |
| GET | `/authz/roles` | Admin JWT | List roles |
| GET | `/authz/roles/{id}` | Admin JWT | Get role with permissions |
| POST | `/authz/roles` | Admin JWT | Create org-level role |
| PUT | `/authz/roles/{id}/permissions` | Admin JWT | Update role permissions |
| GET | `/authz/scopes` | Admin JWT | List/filter scopes |
| GET | `/authz/scopes/{id}/descendants` | Admin JWT | Get scope subtree |
| POST | `/authz/scopes` | Admin JWT | Create scope |
| GET | `/authz/assignments` | Admin JWT | List assignments |
| POST | `/authz/assignments` | Admin JWT | Grant access |
| DELETE | `/authz/assignments/{id}` | Admin JWT | Revoke access |
| GET | `/authz/deny-rules` | Admin JWT | List deny rules |
| POST | `/authz/deny-rules` | Admin JWT | Create deny rule |
| DELETE | `/authz/deny-rules/{id}` | Admin JWT | Remove deny rule |
| GET | `/authz/audit` | Admin JWT | Query audit log |

---

## 9. Data Migration Plan

### Phase 1: Deploy Identity Platform (parallel to monolith)

```
1. Deploy Identity Platform with empty schema
2. Create GLOBAL scope
3. Create COUNTRY:NEPAL scope (and other countries if applicable)
4. Seed permissions for existing domains (tourist, order, insurance, rescue, finance, org)
5. Seed system roles (SuperAdmin, CountryAdmin)
6. Seed org-level roles (TravelAgencyAdmin, TravelAgencyStaff, etc.)
7. Map role → permissions for each role
```

### Phase 2: Migrate Identities

```
For each auth_users row:
  1. Create identities row
     - id: generate new UUID (or reuse auth_users.id if UUIDs are compatible)
     - primary_email: auth_users.email
     - email_verified: auth_users.is_verified
     - account_status: derive from users.status
     - last_login_at: auth_users.last_login

  2. Create credentials row
     - identity_id: new identity id
     - credential_type: auth_users.provider (LOCAL → PASSWORD)
     - identifier: auth_users.email (for PASSWORD) or auth_users.provider_user_id (for OAuth)
     - secret_hash: auth_users.password_hash

  3. Create identity_profiles row
     - identity_id: new identity id
     - display_name: users.name
     - phone: users.phone
     - email: users.email
     - country: users.country
     - avatar_url: users.avatar_url

  4. Store mapping: old users.id ↔ new identities.id
```

### Phase 3: Migrate Company Scopes

```
For each companies row:
  1. Create scopes row
     - type: ORG
     - name: companies.company_name
     - code: companies.company_abbr or generated
     - parent_id: country scope
     - metadata: { orgType: from company_types, companyId: companies.id }

  2. Store mapping: old companies.id ↔ new scopes.id
  3. Add scope_id column to companies table in business service
  4. Backfill scope_id using the mapping
```

### Phase 4: Migrate Assignments

```
For each company_users row WHERE is_active = TRUE:
  1. Look up identity_id from users mapping
  2. Look up scope_id from companies mapping
  3. Determine role from company_users.role + company_types:
     - ADMIN + TRAVEL_AGENCY → TravelAgencyAdmin
     - STAFF + TRAVEL_AGENCY → TravelAgencyStaff
     - etc. (see mapping table in section 5.2)
  4. Create assignments row
     - subject_id: identity_id
     - role_id: mapped role
     - scope_id: company scope
     - granted_by: system migration user
```

### Phase 5: Dual-Mode Operation

```
1. Business service validates JWT from new Identity Platform
2. For existing features: still check old role field (backward compat)
3. For new features: call /authz/authorize
4. Gradually migrate old checks to /authorize calls
5. Once all migrated: remove old role columns
```

### Phase 6: Cleanup

```
1. Remove users.role column
2. Remove company_users.role column (or rename to display_role)
3. Remove auth_users table from business service
4. Remove blacklisted_refresh_tokens from business service
5. Update business service users table to reference identity_id
6. Remove old JWT validation logic
7. All auth goes through Identity Platform
```

---

## 10. Cross-Organization Scenarios

### 10.1 Normal Isolation (Default)

Everest Travels admin cannot see Himalaya Rescue data. Both are ORG scopes under COUNTRY:NEPAL. Scope containment check fails because siblings don't contain each other.

### 10.2 Rescue Handles Travel Agency's Tourist SOS

The rescue dispatcher is assigned at **COUNTRY:NEPAL** scope, not at any specific ORG. The SOS resource is also scoped at COUNTRY level. Scope check passes.

```
Assignment: krishna → RescueDispatcher at COUNTRY:NEPAL
Resource: SOS scoped at COUNTRY:NEPAL
Scope check: NEPAL contains NEPAL → YES
```

### 10.3 Insurance Processes Claims Across Agencies

Insurance reviewer is assigned at COUNTRY:NEPAL scope. Claims from any travel agency's tourist within Nepal are accessible.

```
Assignment: reviewer → InsuranceReviewer at COUNTRY:NEPAL
Resource: Claim scoped at COUNTRY:NEPAL
Scope check: NEPAL contains NEPAL → YES
```

### 10.4 Government Oversight

Government body admin is assigned at COUNTRY:NEPAL scope with read-only oversight role. Can view data across all ORGs but cannot modify.

```
Assignment: gov_admin → GovernmentOversight at COUNTRY:NEPAL
Role contains only: *.*.read permissions + platform.analytics.view
```

### 10.5 Platform Super Admin

Assigned at GLOBAL scope. Can see and manage everything.

```
Assignment: rajesh → SuperAdmin at GLOBAL
Scope check: GLOBAL contains everything → always YES
```

---

## 11. What NOT to Build Yet

These features are designed for but should not be implemented until needed:

| Feature | When to Add |
|---------|------------|
| MFA configuration table | When implementing MFA (mfa_enabled flag is ready) |
| Policy engine (ABAC/ReBAC conditions table) | When assignment conditions JSONB isn't flexible enough |
| Role hierarchy (parent-child roles) | When manually copying permissions between roles becomes painful |
| Permission groups | When admin UI needs to group 100+ permissions for easier management |
| REGION scope level | When expanding beyond Nepal to multiple countries in a region |
| Service accounts (subject_type: SERVICE) | When services need their own identity for service-to-service auth |
| Rate limiting per user on /authorize | When dealing with abuse or very high volume |

---

## 12. Implementation Order

```
Week 1-2: Identity Platform Skeleton
  ├── Database schema deployed
  ├── AuthN module: register, login, refresh, logout
  ├── Token issuance with RS256
  ├── JWKS endpoint
  └── Basic health/metrics endpoints

Week 3: AuthZ Core
  ├── Permission + Role seeding
  ├── Scope management API
  ├── Assignment management API
  ├── /authorize endpoint (deny → role → scope check)
  └── Authorization audit logging

Week 4: Migration
  ├── Identity migration script
  ├── Scope creation for existing companies
  ├── Assignment creation from existing roles
  ├── Business service JWT validation switch
  └── Dual-mode operation (old + new)

Week 5: Integration
  ├── First business service integrated (Order service)
  ├── Frontend login flow updated
  ├── Org switcher + permission-based UI
  ├── Test: admin at Company A cannot see Company B
  └── Test: deny rule blocks specific action

Week 6: Rollout
  ├── Remaining services integrated
  ├── Old role columns removed
  ├── Old auth tables removed from business service
  ├── Performance testing
  └── Production deployment

Week 7+: Iterate
  ├── Add rescue domain permissions
  ├── Add insurance domain permissions
  ├── Deny rule admin UI
  ├── Audit log viewer
  └── Advanced features as needed
```

---

## 13. Key Decisions Summary

| Decision | Choice | Reason |
|----------|--------|--------|
| AuthN + AuthZ deployment | Single service, two modules | Small team, lower operational overhead, extract later if needed |
| Multi-tenancy | No tenant_id — scope hierarchy replaces it | Single platform operator, ORG scope = isolation boundary |
| Permission management | Developer-seeded, no admin API | Permissions are code contracts, admin typos would break things |
| Token strategy | Short-lived JWT (15 min) + rotating refresh (30 days) | Balance between security and UX |
| JWT claims | sub + roles + scopeHint only | Keep token small. Full permissions fetched via /me/permissions |
| Scope hierarchy storage | ltree + closure table | Fast containment checks (O(1) via closure) |
| Authorization audit | Immutable, partitioned by month | Compliance requirement, query performance |
| Deny rules | Separate table, checked first | Emergency override without touching assignments |
| Cross-org access | Assign at higher scope level (COUNTRY) | Clean, no special cross-org link table needed |
| Business service users table | Keep with identity_id reference, cache profile | Avoid cross-service JOINs, enable full-text search |