# Spring IAM -- Architecture & Design

> **Single authoritative architecture reference.**
> Consolidates content from previous design documents into one source of truth.

---

## 1. Overview

Spring IAM is a centralized Identity and Access Management service built on **Spring Boot + PostgreSQL + Redis**. It is a single deployable service composed of two logical modules:

- **AuthN (Authentication):** Login flows, credential management, token lifecycle (JWT + refresh tokens), OAuth2 (Google, Apple, Microsoft), account lockout, and session tracking.
- **AuthZ (Authorization):** Permissions, roles, scopes, assignments, deny rules, ABAC policies, and audit logging.

Every downstream service delegates authorization decisions to a single question:

> **Can subject S perform permission P on resource R under context C?**

The modules are designed with strict boundaries so that AuthZ can be extracted into a standalone microservice later without any redesign.

---

## 2. Core Principles

Eight non-negotiable rules govern the entire system:

| # | Principle | Rationale |
|---|-----------|-----------|
| 1 | **Authorization is centralized** | No service-local auth logic. Every service calls `/authorize`. |
| 2 | **Permissions are immutable contracts** | Once created, a permission key is never renamed or deleted -- only deprecated. |
| 3 | **Explicit DENY always overrides ALLOW** | A deny rule wins regardless of any role, assignment, or policy that grants access. |
| 4 | **Scope defines authority boundaries** | Scopes are hierarchical. An assignment at a parent scope flows down to descendants. |
| 5 | **Every decision is auditable** | Every `/authorize` call produces an immutable audit record. |
| 6 | **Services contain ZERO permission logic** | Consuming services never interpret roles, scopes, or permissions locally. |
| 7 | **Roles never contain scope** | A role says WHAT you can do. Scope is attached separately via assignments. |
| 8 | **Module boundaries are strict** | AuthN and AuthZ never import each other directly. Communication is through shared DTOs only. |

---

## 3. Authorization Model (Hybrid)

Authorization is not a single model -- it is four complementary layers evaluated together.

### 3.1 RBAC (Role-Based Access Control)

Roles bundle permissions. Assignments attach a role to a subject at a specific scope.

```
Subject  ---[assignment]--->  Role  ---[role_permissions]--->  Permission
                |
                v
              Scope
```

Roles support inheritance via `role_hierarchy`: child roles inherit all permissions from their parent roles.

### 3.2 Scope Hierarchy

Seven levels form a strict hierarchy:

```
GLOBAL (0) -> REGION (1) -> COUNTRY (2) -> ORG (3) -> DEPT (4) -> TEAM (5) -> PROJECT (6)
```

- An assignment at COUNTRY scope automatically applies to all ORGs, DEPTs, TEAMs, and PROJECTs within that country.
- Implemented with PostgreSQL `ltree` (materialized path) for fast ancestor/descendant queries and a `scope_closure` table (pre-computed transitive closure) for O(1) containment checks.
- Scope containment is enforced: you cannot grant access at a scope higher than your own assignment scope.

### 3.3 ABAC (Assignment Conditions)

Assignments carry a `conditions` JSONB column supporting context-dependent restrictions:

| Condition | Example |
|-----------|---------|
| `time_window` | Only active 09:00-17:00 UTC weekdays |
| `ip_ranges` | Restrict to office CIDR blocks |
| `require_mfa` | Deny if MFA is not active on the identity |
| `ownership` | Allow only if subject owns the target resource |

These conditions are evaluated at decision time (step 4 of the authorization flow).

### 3.4 DENY Rules

Explicit hard overrides stored in `deny_rules`. Properties:

- Always checked first, before any ALLOW logic.
- Can be global (`scope_id = NULL`) or scoped to a specific scope and its descendants.
- Support wildcard permission keys (e.g., `*.*.*` for full suspension).
- Support expiration (`expires_at`) for temporary suspensions.
- Every deny rule requires a `reason` (audit trail).

### 3.5 Policies (ABAC/ReBAC)

Optional JSON condition trees evaluated after RBAC. Stored in the `policies` table with a `conditions` JSONB column. Policies support:

- **Effect:** `ALLOW` or `DENY` (DENY policies are always evaluated before ALLOW policies).
- **Priority:** Integer ordering for deterministic evaluation.
- **Targeting:** By `permission_key`, `resource_type`, or `scope_id`.

Supported condition operators:

| Operator | Description |
|----------|-------------|
| `eq`, `neq` | Equality / inequality |
| `in`, `not_in` | Set membership |
| `contains` | String/array containment |
| `exists` | Attribute presence |
| `gt`, `gte`, `lt`, `lte` | Numeric/date comparison |
| `regex` | Pattern matching |
| `before`, `after` | Temporal comparison |

---

## 4. Authorization Decision Flow

Every `/authorize` request follows this exact evaluation order. If any step fails, the result is **DENY** and an audit record is written.

```
1. Check DENY rules          (cached 1 min, highest priority)
       |
       v  [if denied -> DENY + audit]
2. Fetch active assignments   -> resolve role hierarchy -> collect permissions
       |                       (cached 5 min per user+scope)
       v  [if no matching permission -> DENY + audit]
3. Check scope containment    (cached 1 hour)
       |
       v  [if scope not contained -> DENY + audit]
4. Evaluate assignment conditions  (time window, IP range, MFA, ownership)
       |
       v  [if condition fails -> DENY + audit]
5. Evaluate policies          (DENY policies first, then ALLOW)
       |
       v  [if policy denies -> DENY + audit]
6. ALLOW  +  log audit record (async)
```

**The formula:**

```
AUTHORIZATION = ROLE x SCOPE x CONTEXT
```

Where CONTEXT encompasses assignment conditions, policies, deny rules, and request attributes (IP, time, MFA status).

---

## 5. Permission Model

Permissions are the atomic units of authorization.

**Format:** `domain.resource.action`

```
platform.role.create
organization.member.remove
user.profile.update
```

**Rules:**

- Immutable: permissions are never renamed or deleted. Deprecated permissions have `is_deprecated = TRUE`.
- Code-owned: seeded via Flyway migrations (`V2__seed_data.sql`), not created at runtime through the API.
- Key format enforced by database CHECK constraint: `^[a-z_]+\.[a-z_]+\.[a-z_]+$`
- The `key` column must equal `domain || '.' || resource || '.' || action` (enforced by CHECK).

**Actions are not limited to CRUD.** Common actions include:

`create`, `read`, `update`, `delete`, `approve`, `reject`, `submit`, `cancel`, `upload`, `export`, `assign`, `dispatch`, `suspend`, `deactivate`, `revoke`, `view`

---

## 6. Scope Hierarchy

### Levels

| Level | Type | Depth | Example |
|-------|------|-------|---------|
| 0 | GLOBAL | 0 | `GLOBAL` |
| 1 | REGION | 1 | `GLOBAL.ASIA_PACIFIC` |
| 2 | COUNTRY | 2 | `GLOBAL.ASIA_PACIFIC.NEPAL` |
| 3 | ORG | 3 | `GLOBAL.ASIA_PACIFIC.NEPAL.ACME_CORP` |
| 4 | DEPT | 4 | `GLOBAL.ASIA_PACIFIC.NEPAL.ACME_CORP.ENGINEERING` |
| 5 | TEAM | 5 | `GLOBAL.ASIA_PACIFIC.NEPAL.ACME_CORP.ENGINEERING.BACKEND` |
| 6 | PROJECT | 6 | `GLOBAL.ASIA_PACIFIC.NEPAL.ACME_CORP.ENGINEERING.BACKEND.IAM_V2` |

### Implementation

- **`ltree` materialized path:** Each scope stores its full path (e.g., `GLOBAL.ASIA_PACIFIC.NEPAL`). PostgreSQL GIST index on `path` enables fast `@>` (ancestor) and `<@` (descendant) queries.
- **`scope_closure` table:** Pre-computed transitive closure of all ancestor-descendant pairs with depth. Provides O(1) containment lookups via `scope_contains(ancestor_id, descendant_id)`.
- **Auto-maintained by trigger:** `trg_scope_closure_insert` fires on every INSERT into `scopes`, populating self-references and all ancestor paths.
- **Parent changes blocked:** `trg_scope_prevent_parent_change` raises an exception if `parent_id` is modified, because re-parenting would corrupt the closure table. Create a new scope instead.
- **Depth validated:** `trg_scopes_validate_depth` ensures the `depth` column matches the expected value for the scope `type` (e.g., COUNTRY must be depth 2).

---

## 7. Database Schema

PostgreSQL 14+ with extensions: `uuid-ossp`, `ltree`.

### AuthN Tables

| Table | Description | Key Columns |
|-------|-------------|-------------|
| `identities` | Core identity anchor. `identities.id` is the universal `subject_id` used in JWTs, assignments, and across all services. | `id` (UUID PK), `primary_email`, `account_status` (ACTIVE/LOCKED/SUSPENDED/DEACTIVATED), `mfa_enabled`, `failed_login_attempts`, `account_locked_until` |
| `credentials` | Login methods per identity. Supports PASSWORD (bcrypt), GOOGLE, APPLE, MICROSOFT. One identity can have multiple credentials. | `identity_id` (FK), `credential_type`, `identifier`, `secret_hash`, `is_active` |
| `refresh_tokens` | Active session tracking with rotation support. Revoked tokens are retained for audit. | `identity_id` (FK), `token_hash`, `ip_address`, `user_agent`, `expires_at`, `revoked_at`, `revoke_reason` |
| `identity_profiles` | 1:1 with identities. Shared user profile readable by any service. | `identity_id` (PK/FK), `display_name`, `phone`, `email`, `country`, `avatar_url` |
| `security_events` | Immutable AuthN audit trail. Tracks logins, password changes, lockouts, MFA changes. | `identity_id` (FK), `event_type`, `ip_address`, `user_agent`, `metadata` (JSONB) |

### AuthZ Tables

| Table | Description | Key Columns |
|-------|-------------|-------------|
| `permissions` | Immutable permission registry. Developer-seeded via migrations. Never deleted, only deprecated. | `id` (UUID PK), `key` (unique, `domain.resource.action`), `domain`, `resource`, `action`, `is_deprecated` |
| `roles` | Named permission bundles. Says WHAT you can do, never WHERE. System roles cannot be deactivated. | `id` (UUID PK), `name` (unique), `is_system_role`, `org_type`, `active` |
| `role_permissions` | Many-to-many join: roles to permissions. DELETE RESTRICT on permissions prevents removing active permissions. | `role_id` (FK), `permission_id` (FK), `granted_by` |
| `scopes` | Hierarchical organizational boundaries. Uses ltree path and depth validation. | `id` (UUID PK), `type`, `name`, `code` (unique), `parent_id` (FK self), `path` (LTREE), `depth`, `metadata` (JSONB) |
| `scope_closure` | Pre-computed transitive closure for O(1) containment checks. Auto-maintained by trigger. | `ancestor_id` (FK), `descendant_id` (FK), `depth` |
| `assignments` | The core join: Subject + Role + Scope = access grant. Supports conditions, expiration, and revocation. | `subject_id`, `subject_type` (USER/SERVICE/GROUP), `role_id` (FK), `scope_id` (FK), `effect` (ALLOW/DENY), `conditions` (JSONB), `expires_at`, `active` |
| `deny_rules` | Explicit denials checked FIRST in every authorization decision. Support wildcards and expiration. | `subject_id`, `permission_key` (supports `*` wildcards), `scope_id` (FK, nullable), `reason`, `expires_at`, `active` |
| `policies` | ABAC/ReBAC policies evaluated after RBAC. Support complex JSON condition trees. | `name` (unique), `permission_key`, `resource_type`, `scope_id` (FK), `effect` (ALLOW/DENY), `priority`, `conditions` (JSONB), `active` |
| `permission_groups` | Logical grouping of permissions for admin UI and bulk management. Supports nesting via `parent_group_id`. | `id` (UUID PK), `name` (unique), `parent_group_id` (FK self) |
| `permission_group_members` | Join table: permission groups to permissions. | `group_id` (FK), `permission_id` (FK) |
| `role_hierarchy` | Role inheritance. Child roles inherit all permissions from parent roles. Self-reference prevented by CHECK. | `parent_role_id` (FK), `child_role_id` (FK) |
| `authorization_audit` | Immutable log of every `/authorize` decision. Partitioned by month. No updates or deletes (enforced by DB rules). | `subject_id`, `permission_key`, `resource_type`, `resource_id`, `scope_id`, `decision` (boolean), `reason`, `context` (JSONB), `ip_address`, `timestamp` |

### Table Growth Estimates

| Table | Expected Size | Growth Rate |
|-------|--------------|-------------|
| `permissions` | ~200-500 rows | Slow (developer-seeded) |
| `roles` | ~20-100 rows | Slow |
| `scopes` | ~1K-10K rows | Medium |
| `scope_closure` | ~10K-100K rows | Auto-computed on scope insert |
| `assignments` | ~1K-100K rows | High |
| `deny_rules` | ~10-100 rows | Low |
| `policies` | ~10-200 rows | Low |
| `authorization_audit` | Millions | Very high (partitioned monthly) |

---

## 8. System Roles

Seven built-in system roles are seeded by `V2__seed_data.sql`. System roles have `is_system_role = TRUE` and cannot be deactivated (enforced by CHECK constraint).

| Role | Typical Scope | Permissions Summary |
|------|--------------|---------------------|
| **SuperAdmin** | GLOBAL | All permissions. Full platform access. |
| **CountryAdmin** | COUNTRY | All `platform.*` and `organization.*` permissions, plus all `read` and `approve` actions across domains. |
| **AccessAdmin** | Any | Manages roles, scopes, assignments, deny rules, and policies. Reads the permission registry. |
| **SecurityAdmin** | Any | Identity lifecycle (`platform.identity.*`), user account/session management, audit read. |
| **AuditViewer** | Any | Read-only: all `*.*.read` permissions plus `platform.analytics.view`. |
| **OperationsAdmin** | Any | Broad read access, organization member read, user profile read. For cross-domain incident response. |
| **GovernmentOversight** | COUNTRY | Read-only across all domains plus analytics. Country-level oversight without write access. |

Org-specific roles (e.g., department managers, project leads) are defined per deployment in separate migration files or created via the API.

---

## 9. Security Model

### Authentication Mechanisms

Two mechanisms protect IAM endpoints:

| Mechanism | Header | Grants | Use Case |
|-----------|--------|--------|----------|
| **API Key** | `X-Internal-Api-Key` | `ROLE_INTERNAL` | Service-to-service `/authorize` calls. Internal network only. |
| **JWT** | `Authorization: Bearer <token>` | Role-based (SuperAdmin, CountryAdmin, etc.) | Admin endpoints (CRUD on roles, scopes, assignments, etc.) |

### Security Details

- **API key comparison is timing-safe** to prevent timing side-channel attacks.
- **JWT tokens:** 15-minute access token expiration, 7-day refresh token expiration. Refresh tokens are stored as hashes, support rotation, and track IP/User-Agent.
- **OAuth2:** Google (and extensible to Apple, Microsoft) via Spring Security OAuth2 client.
- **Account lockout:** After 5 failed login attempts, the account is locked for 30 minutes (configurable).
- **Rate limiting:** 10 requests per IP per endpoint per 60-second sliding window (configurable).

### Delegated Management Guard

When an administrator creates or modifies assignments, two checks are enforced:

1. **Scope containment:** The admin can only assign roles within or below their own scope. A CountryAdmin for Nepal cannot create assignments in Japan.
2. **Permission ceiling:** The admin can only assign permissions they themselves possess. You cannot delegate access you do not have.

---

## 10. Caching Strategy

Redis is used as a shared cache layer. All TTLs are configurable in `application.yml` under `iam.authorization.cache`.

| Cache Key | TTL | Rationale |
|-----------|-----|-----------|
| Permissions per user+scope | 5 min | Balance between freshness and performance for the hot path |
| Deny rules | 1 min | Security-critical; must reflect changes quickly |
| Scope containment | 1 hour | Scope hierarchy changes rarely |
| Role permissions | 30 min | Role-permission mappings are relatively stable |
| Policies | 2 min | Policies can change more frequently than role mappings |

### Cache Invalidation Triggers

Cache entries are evicted when the underlying data changes:

- **Assignment changes** (create, revoke, expire) invalidate the user+scope permissions cache.
- **Role-permission updates** (add/remove permission from role) invalidate the role permissions cache.
- **Deny rule changes** (create, delete, expire) invalidate the deny rules cache.
- **Scope changes** (create, deactivate) invalidate the scope containment cache.

### Redis Configuration

- Connection pool: max-active 10, max-idle 8, min-idle 2
- Connection timeout: 2 seconds
- Lettuce client (non-blocking)
- Null values are not cached (`cache-null-values: false`)

---

## 11. Audit & Compliance

### Authorization Audit

- Every `/authorize` decision is logged to the `authorization_audit` table.
- **Immutable:** Database rules (`no_update_authz_audit`, `no_delete_authz_audit`) prevent any modification or deletion.
- **Async logging:** Audit writes are asynchronous (configurable batch size: 100, flush interval: 5 seconds) to avoid adding latency to authorization decisions.
- **Partitioned monthly:** The table uses PostgreSQL range partitioning on `timestamp`. A scheduled job creates partitions 2 months ahead (daily at 00:15 UTC).

### AuthN Security Events

- Login successes/failures, password changes, account lockouts, MFA changes, and session revocations are logged to `security_events`.
- Separate from authorization audit -- this table is owned by the AuthN module.

### Retention

- Configurable retention period (default: **24 months**).
- A scheduled job runs daily at 01:30 UTC and DROPs partitions older than the retention period.
- Retention action is configurable (`DROP` by default).

### Enrichment

- `ip_address` and `user_agent` are enriched server-side from the HTTP request, not from client-provided data.
- `request_id` provides correlation back to the originating HTTP request for distributed tracing.

---

## 12. Performance Targets

| Metric | Target |
|--------|--------|
| Authorization latency (cached) | < 10ms p95 |
| Authorization latency (uncached) | < 50ms p95 |
| Throughput | 10,000 req/sec |
| Cache hit rate | > 95% |

Supporting infrastructure:

- HikariCP connection pool: 20 max connections, 5 minimum idle.
- Tomcat: 200 max threads, 10 min spare.
- Hibernate batch size: 20 (ordered inserts and updates).
- Prometheus metrics enabled with percentile histograms on `authorization.check.duration`.
- Warning logged if any authorization decision exceeds 50ms (`iam.audit.performance.max-authorization-time-ms`).

---

## 13. Module Boundaries

AuthN and AuthZ are logically separated within the same deployable. Four rules enforce the boundary:

### Rules

1. **No cross-module imports.** Code in `com.hgn.iam.authn` never imports from `com.hgn.iam.authz` and vice versa.
2. **Separate table ownership.** AuthN owns `identities`, `credentials`, `refresh_tokens`, `identity_profiles`, `security_events`. AuthZ owns `permissions`, `roles`, `role_permissions`, `scopes`, `scope_closure`, `assignments`, `deny_rules`, `policies`, `permission_groups`, `permission_group_members`, `role_hierarchy`, `authorization_audit`.
3. **Communication through shared DTOs only.** The `com.hgn.iam.shared` package contains DTOs, entities, exceptions, and utilities used by both modules.
4. **The `/authorize` contract is HTTP-shaped.** The authorization check accepts the same request/response shape whether called in-process or over the network, making extraction to a separate service a deployment change, not a code change.

### Package Structure

```
com.hgn.iam
  |-- authn/
  |     |-- config/
  |     |-- controller/
  |     |-- dto/
  |     |-- entity/
  |     |-- repository/
  |     |-- security/
  |     |     |-- oauth2/
  |     |     |-- token/
  |     |-- service/
  |           |-- impl/
  |-- authz/
  |     |-- controller/
  |     |-- dto/
  |     |-- entity/
  |     |-- repository/
  |     |-- service/
  |-- shared/
  |     |-- dto/
  |     |-- entity/
  |     |-- exception/
  |     |-- repository/
  |     |-- security/
  |     |-- service/
  |     |-- util/
  |-- config/
  |-- controller/
  |-- exception/
  |-- util/
```

---

## 14. Error Handling

All errors return a consistent JSON structure:

```json
{
  "timestamp": "2026-04-06T12:00:00.000Z",
  "status": 400,
  "error": "Validation Failed",
  "message": "Input validation failed",
  "path": "/api/roles",
  "validationErrors": {
    "name": "must not be blank",
    "description": "size must be between 1 and 500"
  }
}
```

The `validationErrors` field is only present for validation failures (400). For all other errors, it is omitted.

### HTTP Status Codes

| Status | Meaning | When Used |
|--------|---------|-----------|
| **400** | Bad Request | Validation errors, malformed JSON, illegal arguments, database constraint violations (duplicate key, FK violation, CHECK constraint) |
| **401** | Unauthorized | Missing or invalid credentials, expired/invalid/reused tokens, bad credentials |
| **403** | Forbidden | Insufficient permissions, email not verified, authorization denied |
| **404** | Not Found | Resource does not exist, no handler for URL |
| **405** | Method Not Allowed | HTTP method not supported for the endpoint |
| **409** | Conflict | Resource state conflict (e.g., duplicate creation) |
| **415** | Unsupported Media Type | Request Content-Type is not `application/json` |
| **500** | Internal Server Error | Unexpected/unhandled exceptions |
| **503** | Service Unavailable | Infrastructure errors (database down, Redis unreachable). This is NOT a security denial -- it means the service cannot evaluate the request. |

**Important:** Infrastructure failures (DB connection errors, Redis timeouts) return **503 Service Unavailable**, not 403. A service that cannot reach its data store cannot make a security decision and must not pretend it has denied access. The `AuthorizationServiceException` handler ensures this distinction.

### Database Error Translation

PostgreSQL constraint violations are translated into human-readable messages. Duplicate keys, foreign key violations, CHECK constraint failures, invalid UUIDs, invalid JSON, and ltree format errors all produce specific, actionable 400 responses instead of raw database error text.
