# Spring IAM — Template Redesign Proposal

> **Status:** PROPOSAL — awaiting approval
> **Date:** 2026-07-04
> **Goal:** Evolve this service into a reusable, any-scale IAM template: a central token issuer (AuthN) plus a deeply granular but *layered/optional* authorization engine (AuthZ), usable by a microservice fleet, a modular monolith, or a set of independent apps.

---

## Table of Contents

1. [Design Philosophy](#1-design-philosophy)
2. [The Layered Authorization Model](#2-the-layered-authorization-model)
3. [Change 1 — Flexible Scope Hierarchy](#3-change-1--flexible-scope-hierarchy)
4. [Change 2 — Token Architecture (Central Issuer)](#4-change-2--token-architecture-central-issuer)
5. [Change 3 — Consumption Modes & Service Registry](#5-change-3--consumption-modes--service-registry)
6. [Change 4 — Resource Grants (ReBAC, Layer 5)](#6-change-4--resource-grants-rebac-layer-5)
7. [Change 5 — Data Model Cleanups](#7-change-5--data-model-cleanups)
8. [Change 6 — Security & Performance Hardening](#8-change-6--security--performance-hardening)
9. [Full Schema Design (Target State)](#9-full-schema-design-target-state)
10. [Decision Pipeline (Target State)](#10-decision-pipeline-target-state)
11. [Configuration Surface](#11-configuration-surface)
12. [API Surface Changes](#12-api-surface-changes)
13. [Execution Plan (Phases)](#13-execution-plan-phases)
14. [Open Decisions](#14-open-decisions)

---

## 1. Design Philosophy

Four rules drive every change in this document:

| # | Rule | Meaning |
|---|------|---------|
| 1 | **Layered granularity** | Authorization is one deny-overrides pipeline. Each capability layer is opt-in. A disabled layer costs zero queries, exposes zero API surface, and adds zero cognitive load. |
| 2 | **Baseline must be trivial** | A new project should get plain RBAC working (roles → permissions → allow/deny) without ever reading about scopes, policies, or ABAC. Sensible defaults, one seeded ROOT scope, done. |
| 3 | **Nothing compile-time** | No enums for roles, no hardcoded hierarchy levels, no per-service code changes to add a permission. All authorization objects are rows, managed via API. |
| 4 | **Issuer, not gatekeeper** | AuthN issues and refreshes tokens. Consuming services verify tokens **locally** via JWKS — no shared secrets, no per-request validation calls. Fine-grained decisions go through the PDP endpoint (`/authorize`) only when the consumer opts into that depth. |

What this service is **not**: a user-profile store, a notification service, a session store for consumer apps, or a gateway. Profile data moves to consuming services.

---

## 2. The Layered Authorization Model

```
Layer  Capability          What it adds                                     Default
─────  ─────────────────   ───────────────────────────────────────────────  ────────
 L0    RBAC                permissions + roles + role hierarchy             ALWAYS ON
                           + assignments (subject × role)
 L1    Scope hierarchy     assignments gain a scope; grants flow down       ON (dormant
                           the tree; flexible, deployment-defined levels    w/ single ROOT)
 L2    Deny rules          explicit overrides; wildcards; expiry;           ON
                           always win
 L3    ABAC conditions     per-assignment context checks: time window,      OFF
                           IP CIDR, MFA, ownership, separation-of-duties
 L4    Policies            JSON condition trees (ALLOW/DENY, priority,      OFF
                           targeting by permission/resource/scope)
 L5    Resource grants     per-instance ReBAC: "subject S may do P on       OFF
                           resource R#id" without any role
```

**Baseline deployment (L0–L2):** the migration seeds one ROOT scope; every assignment silently lands there; the consumer never sees the word "scope". It behaves exactly like a simple roles-and-permissions system with a kill-switch (deny rules).

**Full deployment (L0–L5):** multi-level org tree, contextual conditions, policy engine, per-resource sharing.

The pipeline shape never changes — layers that are off (or have no data) are skipped. The same `POST /authorize` contract serves both extremes.

### Current implementation → layer mapping

| Layer | Current state | Work needed |
|-------|--------------|-------------|
| L0 | ✅ Solid (permissions registry, roles, role_hierarchy BFS, assignments) | Drop vestigial `assignments.effect` column |
| L1 | ⚠️ Works, but 7 level names hardcoded (Java + DB trigger) | De-hardcode (§3) |
| L2 | ✅ Solid (wildcards, scoped/global, expiry, reason) | None |
| L3 | ✅ Implemented (hand-rolled evaluator in AuthorizationService) | Gate behind flag |
| L4 | ✅ Implemented (PolicyEvaluator, whitelisted context) | Gate behind flag |
| L5 | ❌ Missing | New table + pipeline step (§6) |

---

## 3. Change 1 — Flexible Scope Hierarchy

### Problem

Level names `GLOBAL → REGION → COUNTRY → ORG → DEPT → TEAM → PROJECT` are hardcoded in three places:

1. `ScopeService.java:54` — Java whitelist of allowed type strings.
2. `validate_scope_depth()` trigger in `V1__init.sql` — maps each type to one exact depth.
3. CHECK constraints / comments assuming GLOBAL root.

A logistics app wants `PLATFORM → TENANT → WAREHOUSE`. A SaaS wants `PLATFORM → ORG → WORKSPACE → PROJECT`. The engine underneath (ltree paths + closure table) is already level-agnostic — only the validation layer blocks this.

### Design

**`scope_types` — optional, deployment-defined level registry:**

```sql
CREATE TABLE scope_types (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name           VARCHAR(50)  NOT NULL UNIQUE,          -- e.g. 'TENANT'
    display_name   VARCHAR(100) NOT NULL,
    -- which types may be a parent of this type; empty array = may be root
    allowed_parent_types  TEXT[] NOT NULL DEFAULT '{}',
    -- optional strict ordering (lower = closer to root); NULL = unordered
    level_order    INT,
    description    TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

**Validation rules (service layer, replacing the Java whitelist + depth trigger):**

| Registry state | Behavior |
|---------------|----------|
| Empty (default) | **Free-form mode.** Any type label, any nesting, any depth. Only structural rules apply (root has no parent, no cycles — closure trigger already guarantees). |
| Populated | **Strict mode.** `scope.type` must exist in registry; `parent.type` must be in `allowed_parent_types` (or scope must be root if array empty). |

**Depth** is always *derived* (`parent.depth + 1`), never validated against type. The `validate_scope_depth()` trigger is dropped.

**ROOT seeding:** V2 seed creates a single scope `('ROOT', type='ROOT', path='ROOT', depth=0)`. Baseline deployments assign everything at ROOT and never touch this subsystem. `GET /api/v1/scopes/root` returns it so integrators don't hardcode its UUID.

**Path segment fix:** ltree path segments currently derive from `name.toUpperCase().replace(" ","_")` — two siblings named "North Region" and "NORTH REGION" collide. Change: path segment = `code` (new required column, validated slug `^[A-Za-z0-9_]{1,50}$`, unique among siblings).

```sql
ALTER TABLE scopes ADD COLUMN code VARCHAR(50) NOT NULL;
CREATE UNIQUE INDEX uq_scopes_sibling_code ON scopes (parent_id, code) NULLS NOT DISTINCT;
-- path = parent.path || '.' || code
```

**Kept as-is:** `scopes.path LTREE` (+ GiST) for subtree queries, `scope_closure` (+ trigger) for O(1) containment, Redis containment cache.

---

## 4. Change 2 — Token Architecture (Central Issuer)

### Problem

Current signing is HS256 with a shared secret. Every consumer that wants local verification must hold the *signing* key — one compromised consumer can mint tokens. This is the single biggest disqualifier for a fleet-wide template. Secondary issues: the same secret also derives the cookie-encryption AES key and the OAuth cookie HMAC key.

### Design

#### 4.1 Asymmetric signing + JWKS

- Sign with **RS256** (default; ES256 optional via config).
- Publish public keys at **`GET /.well-known/jwks.json`** (public, cacheable, `kid` per key).
- Consumers verify locally with any standard JWT library. Zero shared secrets, zero per-request calls to IAM.

**Key storage & rotation:**

```sql
CREATE TABLE signing_keys (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    kid          VARCHAR(64)  NOT NULL UNIQUE,      -- key id in JWKS/JWT header
    algorithm    VARCHAR(10)  NOT NULL DEFAULT 'RS256',
    public_key   TEXT         NOT NULL,             -- PEM
    private_key  TEXT         NOT NULL,             -- PEM, encrypted at rest (AES-GCM w/ master key from env)
    status       VARCHAR(20)  NOT NULL DEFAULT 'ACTIVE'
                 CHECK (status IN ('ACTIVE','ROTATED','REVOKED')),
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    rotated_at   TIMESTAMPTZ,
    not_after    TIMESTAMPTZ                         -- stop honoring after this
);
```

Rotation flow: generate new key → new tokens signed with it → old key stays in JWKS as `ROTATED` until `not_after` (≥ max access-token TTL) → then removed. Admin endpoint `POST /api/v1/keys/rotate` + optional scheduled rotation. Bootstrap: generate a key pair on first startup if table empty (log the event loudly).

Pluggable `KeySource` interface: `DbKeySource` (default), `EnvPemKeySource` (for K8s-secret-managed keys, table unused).

#### 4.2 Claims modes

Configurable token fatness — how much authorization data rides in the JWT:

```yaml
iam:
  token:
    claims-mode: roles        # minimal | roles | permissions
```

| Mode | Claims added | Use case |
|------|-------------|----------|
| `minimal` | `sub`, `email_verified`, `status`, `type` | Consumers do everything via PDP calls |
| `roles` *(default)* | + `roles: ["OrgAdmin", ...]` | Coarse local checks (`hasRole`) |
| `permissions` | + `perms: ["route.bus.create", ...]`, `scope` | Small apps skip `/authorize` entirely |

Access token TTL stays short (15 min default) — this bounds staleness of embedded claims *and* the revocation window.

#### 4.3 Optional endpoints (flag-gated)

- **Introspection** `POST /api/v1/token/introspect` (RFC 7662-shaped): live check of a token — signature + expiry + blacklist + account status. For high-security paths that can't tolerate the 15-min revocation window.
- **Revocation feed** `GET /api/v1/token/revocations?since=<ts>`: list of revoked token IDs / subject IDs since a timestamp, for offline/edge consumers that poll.

#### 4.4 AuthN slimming

**Keep** (already solid): register, login, refresh rotation with reuse detection (`TokenReuseException` nukes the family), logout / logout-all, account lockout (5 attempts / 30 min), email verification flow, invite flow (`verify-email-and-setup-password`), reactivation flow, security-events audit.

**Remove — profile stack** (profile data belongs to consuming services):

| Delete | Notes |
|--------|-------|
| `shared/entity/IdentityProfile.java` | + `identity_profiles` table |
| `shared/repository/IdentityProfileRepository.java` | |
| `authn/controller/ProfileController.java` | `GET/PUT /api/auth/me` profile parts |
| `ProfileResponse`, `UpdateProfileRequest` DTOs | |
| Profile writes in `AuthServiceImpl.register`, `CustomOAuth2UserService` | `RegisterRequest.fullName` dropped |

`GET /api/auth/me` survives in reduced form: identity id, email, status, email_verified, mfa_enabled, roles. OAuth-provided name/picture are passed through **once** in the registration response / first-token claims, for the consumer app to store — IAM does not persist them.

**OAuth2**: behind `iam.features.oauth2` flag (default off). When off — no OAuth beans, no endpoints, no Swagger entries.

**Email**: introduce a port so flows are actually usable:

```java
public interface NotificationPort {
    void sendEmailVerification(String email, String token);
    void sendPasswordReset(String email, String token);
    void sendReactivation(String email, String token);
}
// Implementations: LogNotificationAdapter (default, dev),
//                  SmtpNotificationAdapter, WebhookNotificationAdapter (POSTs to a configured URL —
//                  lets any deployment plug its own notification service without code changes)
```

---

## 5. Change 3 — Consumption Modes & Service Registry

### 5.1 Three integration modes (documented as first-class recipes)

```
Mode A — CLAIMS ONLY                Mode B — PDP                   Mode C — HYBRID (recommended)
┌─────────┐   JWKS (cached)         ┌─────────┐  POST /authorize   routine reads  → claims
│ Service │◄────────── IAM          │ Service │─────────► IAM      sensitive ops  → PDP
└─────────┘                         └─────────┘  (per-request,     writes/deletes → PDP
verify JWT locally,                 cached decision, <5ms warm)
read roles/perms claims
Latency: 0 network                  Latency: 1 call (Redis-cached)
Revocation: ≤ token TTL             Revocation: ≤ cache TTL (60s deny / 300s perm)
Granularity: coarse                 Granularity: full (all 6 layers)
```

### 5.2 Service registry (optional layer, flag: `iam.features.service-registry`)

Replaces the single shared `IAM_INTERNAL_API_KEY` with per-service identity:

```sql
CREATE TABLE services (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name          VARCHAR(100) NOT NULL UNIQUE,      -- 'route-service'
    display_name  VARCHAR(150) NOT NULL,
    -- permission namespaces this service owns, e.g. {'route','trip'}
    owned_domains TEXT[]       NOT NULL DEFAULT '{}',
    api_key_hash  VARCHAR(255) NOT NULL,             -- bcrypt/SHA-256 of issued key
    active        BOOLEAN      NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_seen_at  TIMESTAMPTZ
);
```

- `ApiKeyAuthFilter` extended: look up key by hash → authenticate as `service:<name>` with `ROLE_INTERNAL`. Flag off → current single-key behavior unchanged.
- Per-service keys are individually revocable; `last_seen_at` gives fleet observability.

### 5.3 Permission manifest sync (the template's killer feature)

Permissions live where they're *used* — in the consumer's codebase — and are pushed to IAM on deploy:

```
PUT /api/v1/services/{name}/permissions          (auth: that service's API key)
{
  "permissions": [
    {"key": "route.bus.create",  "description": "Create bus"},
    {"key": "route.bus.assign",  "description": "Assign bus to route"}
  ],
  "deprecateMissing": true
}
```

Semantics: idempotent upsert; keys present in IAM (within the service's `owned_domains`) but absent from the manifest get `is_deprecated = true` (never deleted — permission keys are immutable contracts). A service may only sync domains it owns. Result: no seed-file drift, no manual permission bookkeeping, CI-friendly.

---

## 6. Change 4 — Resource Grants (ReBAC, Layer 5)

### Problem

Assignments grant at *scope* level. "Share document #123 with user Y" is only expressible today via a policy with a `resource.id eq` condition — unmanageable at scale (policies are admin objects, not user-sharing primitives).

### Design

```sql
CREATE TABLE resource_grants (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    subject_id      VARCHAR(255) NOT NULL,             -- same universal subject_id
    subject_type    VARCHAR(20)  NOT NULL DEFAULT 'USER',
    permission_key  VARCHAR(150) NOT NULL,             -- exact key or 'domain.resource.*'
    resource_type   VARCHAR(100) NOT NULL,             -- 'document'
    resource_id     VARCHAR(255) NOT NULL,             -- '123'
    scope_id        UUID REFERENCES scopes(id),        -- optional: grant valid only within scope
    granted_by      VARCHAR(255) NOT NULL,
    expires_at      TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    revoked_by      VARCHAR(255),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_resource_grant UNIQUE (subject_id, permission_key, resource_type, resource_id)
);
CREATE INDEX idx_rg_subject ON resource_grants (subject_id)
    WHERE revoked_at IS NULL;
CREATE INDEX idx_rg_resource ON resource_grants (resource_type, resource_id)
    WHERE revoked_at IS NULL;
```

**Pipeline placement:** after RBAC (step 3) fails to find the permission — i.e., a grant is an *additional* allow path, evaluated before final deny. Deny rules (L2) still override grants: pipeline order guarantees it.

**API:**

```
POST   /api/v1/resource-grants                 create (caller must hold the permission themselves
                                               at a scope containing the resource — ceiling check
                                               via DelegatedManagementGuard)
DELETE /api/v1/resource-grants/{id}            revoke
GET    /api/v1/resource-grants?subjectId=...   list by subject
GET    /api/v1/resource-grants?resourceType=documents&resourceId=123    list by resource
```

**Caching:** per-subject grant list, TTL 60 s (same class as deny rules — security-relevant, short).

Flag: `iam.features.resource-grants` (default off — table not queried, endpoints 404).

---

## 7. Change 5 — Data Model Cleanups

| Item | Action | Rationale |
|------|--------|-----------|
| `assignments.effect` | **Drop column** | DENY-effect assignments are silently ignored today (`findActiveAssignments` filters `effect='ALLOW'`). One deny mechanism — `deny_rules` — is a clearer contract. |
| `identity_profiles` | **Drop table** | §4.4 — profile data belongs to consumers. |
| `db/schama.sql` | **Delete file** | Stray non-Flyway reference dump (typo'd name), drifts from real migrations. |
| `GlobalExceptionHandler.mapCheckConstraint` | **Reconcile** | References constraint names (`chk_permission_domain_lowercase`, `chk_assignment_expiry_future`, …) that don't exist in V1 — align with actual schema. |
| `validate_scope_depth()` trigger | **Drop** | §3. |
| Permission groups | **Keep** | Admin-UX only, outside the decision path, harmless. |
| Migrations | **Restructure** | `V1` core (identities, credentials, tokens, RBAC), `V2` hierarchy (scopes, closure, scope_types) + ROOT seed, `V3` advanced (policies, deny_rules*, resource_grants, services, signing_keys), `V4` platform permission seed, `V5__example_seed` (delete-for-prod). *deny_rules is L2/on-by-default but ships in V3 with the other optional-surface tables; the table existing while unused costs nothing. |

---

## 8. Change 6 — Security & Performance Hardening

### Security (must-fix before template release)

| # | Issue | Fix |
|---|-------|-----|
| S1 | **OAuth open redirect** — `isAllowedRedirect()` accepts any absolute URI; the real allowlist (`app.frontend.allowed-redirect-uris` + `parseAllowedRedirects()`) is dead code | Wire the allowlist; empty allowlist = same-origin only |
| S2 | **Access token in redirect URL** (`?token=<JWT>`) — leaks via logs/Referer/history | One-time exchange code: redirect with `?code=<random>`, frontend swaps it at `POST /api/auth/oauth/exchange` (code stored in Redis, 60 s TTL, single-use) |
| S3 | **`__Host-` cookie with `secure=false` default** — browsers silently reject it | `app.cookie.secure` default `true`; dev profile overrides to plain cookie name |
| S4 | **Key reuse** — one secret for JWT HMAC + cookie AES + OAuth cookie HMAC | RS256 removes JWT secret entirely; cookie AES and cookie HMAC get separate config keys |
| S5 | **Raw DB messages leak** via exception-handler fallback | Generic message + correlation id; raw detail to logs only |
| S6 | **Silent fail-open paths** — rate limiter and `RedisTokenService` in-memory fallback degrade silently when Redis dies | Make behavior explicit config: `fail-open` (availability) vs `fail-closed` (security), default fail-closed for token store; alarm-level logging either way |

### Performance / correctness

| # | Issue | Fix |
|---|-------|-----|
| P1 | `logAuditAsync` — `@Async`/`@Transactional` on a self-invoked method → **no-op**, audit runs synchronously on the hot path | Extract `AuditWriter` bean, call through proxy; verify with a thread-name assertion test |
| P2 | `redisTemplate.keys(pattern)` for invalidation — O(N) blocking KEYS on prod Redis | Versioned key prefixes: `auth:v{n}:perm:{subject}` — invalidation = increment version counter, O(1), old keys expire by TTL |
| P3 | `getEffectivePermissions` runs one policy evaluation per granted permission | Batch: fetch applicable policies once, evaluate per-permission in memory |
| P4 | Conditional assignments bypass permission cache entirely (full recompute per request) | Cache the permission set + evaluate only the conditions per request (conditions are the only context-dependent part) |

### Tests (template ships with its spec)

- **Decision-engine table-driven suite**: one test file per layer (L0–L5), fixture-based — subject/roles/scopes/denies/policies in, expected decision + reason out. This is the executable specification of §10.
- Security-filter chain slice tests (each of the 4 filters: match, pass-through, reject).
- Flyway migration test against Testcontainers Postgres (ltree/closure triggers actually fire).
- Token lifecycle integration test: login → refresh → reuse-detection → logout → introspection.

---

## 9. Full Schema Design (Target State)

```
── AuthN ────────────────────────────────────────────────────────────
identities            id (UUID, universal subject_id), primary_email UQ,
                      email_verified, account_status, failed_login_attempts,
                      account_locked_until, last_login_*, mfa_enabled
credentials           identity_id FK, credential_type (PASSWORD|GOOGLE|APPLE|MICROSOFT),
                      identifier, secret_hash (bcrypt|NULL), UQ(type, identifier)
refresh_tokens        identity_id FK, token_hash, ip INET, expires_at,
                      revoked_at, revoke_reason
security_events       identity_id FK, event_type, ip, user_agent, metadata JSONB (immutable)
signing_keys          kid UQ, algorithm, public_key PEM, private_key PEM (encrypted),
                      status (ACTIVE|ROTATED|REVOKED), not_after            [NEW]

── AuthZ core (L0) ──────────────────────────────────────────────────
permissions           key UQ = domain.resource.action (CHECK regex),
                      is_deprecated (never deleted)
roles                 name UQ, display_name, is_system_role, active
role_permissions      role_id × permission_id (UQ), ON DELETE RESTRICT
role_hierarchy        parent_role_id × child_role_id (no self-ref)
assignments           subject_id, subject_type, role_id, scope_id,
                      conditions JSONB (L3), expires_at, revoke fields
                      [REMOVED: effect column]

── Hierarchy (L1) ───────────────────────────────────────────────────
scope_types           name UQ, allowed_parent_types TEXT[], level_order?   [NEW]
scopes                type (free-form or registry-validated), parent_id,
                      code (slug, UQ per sibling) [NEW], path LTREE (GiST),
                      depth (derived), metadata JSONB (GIN)
                      [REMOVED: validate_scope_depth trigger]
scope_closure         ancestor × descendant × depth (trigger-maintained)

── Overrides & context (L2–L4) ─────────────────────────────────────
deny_rules            subject_id, permission_key (wildcards), scope_id?,
                      reason NOT NULL, expires_at, active
policies              name UQ, permission_key/resource_type/scope_id targeting,
                      effect (ALLOW|DENY), priority, conditions JSONB, active

── ReBAC (L5) ───────────────────────────────────────────────────────
resource_grants       subject_id, permission_key, resource_type, resource_id,
                      scope_id?, granted_by, expires_at, revoked_at,
                      UQ(subject, permission, resource_type, resource_id)    [NEW]

── Fleet (optional) ─────────────────────────────────────────────────
services              name UQ, owned_domains TEXT[], api_key_hash, active,
                      last_seen_at                                          [NEW]

── Audit ────────────────────────────────────────────────────────────
authorization_audit   PARTITIONED BY RANGE(timestamp) monthly, immutable
                      (UPDATE/DELETE rules), decision, reason, context JSONB

── Removed ──────────────────────────────────────────────────────────
identity_profiles     (profile data → consuming services)
db/schama.sql         (stray reference file)
```

---

## 10. Decision Pipeline (Target State)

```
POST /api/v1/authorize  { subjectId, permission, resourceType?, resourceId?, scopeId?, context? }
        │
        ▼
① DENY RULES (L2)                     cache 60s
   wildcard match + scope containment → match ⇒ DENY("explicit_deny")
        │
        ▼
② RBAC (L0) + SCOPE (L1)              cache 300s (perm sets), 3600s (containment)
   active assignments → scope_closure containment
   → role_hierarchy BFS → permission set
        │
        ├─ permission found ──────────────────────────────┐
        │                                                 ▼
        ├─ not found & L5 on                    ③ ABAC CONDITIONS (L3)   [flag]
        │       ▼                                  time / IP / MFA / ownership / SoD
        │  ②b RESOURCE GRANTS (L5)  cache 60s      fail ⇒ try next assignment;
        │     exact/wildcard grant for              all fail ⇒ DENY("condition_failed")
        │     (subject, permission,                       │
        │      resourceType, resourceId)                  ▼
        │     found ⇒ continue to ③/④           ④ POLICIES (L4)          [flag]
        │     not found ⇒ DENY("no_permission")    applicable policies (cache 120s)
        │                                          DENY policies first — any match ⇒ DENY
        │                                          ALLOW policies exist ⇒ ≥1 must match
        ▼                                                 │
   DENY("no_permission")                                  ▼
                                                   ⑤ ALLOW + async audit
Disabled layer ⇒ step skipped entirely (no query, no cache lookup).
Infra failure ⇒ 503 AuthorizationServiceException (fail-closed, never fake DENY/ALLOW).
Every terminal outcome ⇒ audit record (async, separate AuditWriter bean).
```

---

## 11. Configuration Surface

```yaml
iam:
  features:                      # the layer/module switches
    oauth2: false                # Google/Apple/Microsoft login
    abac-conditions: false       # L3 assignment conditions
    policies: false              # L4 policy engine
    resource-grants: false       # L5 ReBAC
    service-registry: false      # per-service API keys + manifest sync
    introspection: false         # POST /token/introspect
    revocation-feed: false       # GET /token/revocations
    strict-scope-types: auto     # auto = strict iff scope_types has rows

  token:
    algorithm: RS256             # RS256 | ES256
    claims-mode: roles           # minimal | roles | permissions
    access-ttl: 15m
    refresh-ttl: 7d
    key-source: db               # db | env-pem
    rotation-cron: ""            # empty = manual rotation only

  authorization:
    cache:
      permissions-ttl: 300
      deny-rules-ttl: 60
      resource-grants-ttl: 60
      scope-ttl: 3600
      policy-ttl: 120
    fail-mode: closed            # closed (503 on infra error) | open

  security:
    cookie-encryption-key: ${IAM_COOKIE_KEY}     # separate from signing keys
    allowed-redirect-uris: ${IAM_ALLOWED_REDIRECTS:}  # empty = same-origin only
```

Every flag defaults to the **baseline** (simple) side. A consumer scales up by flipping flags — never by forking code.

---

## 12. API Surface Changes

### New

| Endpoint | Purpose | Flag |
|----------|---------|------|
| `GET /.well-known/jwks.json` | Public keys for local JWT verification | always |
| `POST /api/v1/keys/rotate` | Rotate signing key (SuperAdmin) | always |
| `GET /api/v1/scopes/root` | The seeded ROOT scope | always |
| `GET/POST/DELETE /api/v1/scope-types` | Manage level registry | always |
| `POST /api/auth/oauth/exchange` | One-time code → tokens (replaces `?token=` redirect) | oauth2 |
| `POST /api/v1/token/introspect` | Live token check | introspection |
| `GET /api/v1/token/revocations?since=` | Revocation feed for polling consumers | revocation-feed |
| `CRUD /api/v1/resource-grants` | Per-resource sharing | resource-grants |
| `CRUD /api/v1/services` + `PUT /api/v1/services/{name}/permissions` | Registry + manifest sync | service-registry |

### Changed

| Endpoint | Change |
|----------|--------|
| `GET /api/auth/me` | Slimmed: identity + status + roles only (no profile fields) |
| `POST /api/auth/register` | `fullName` removed from request |
| `POST /api/v1/scopes` | Requires `code`; type validated against registry only in strict mode |

### Removed

| Endpoint | Replacement |
|----------|-------------|
| `PUT /api/auth/me` (profile update) | Consuming services own profile data |

Unchanged: `/authorize`, `/authorize/batch`, `/effective-permissions`, all role/permission/assignment/deny-rule/policy/audit admin APIs, `/api/authz/me/*`.

---

## 13. Execution Plan (Phases)

Each phase is independently shippable; the template is usable after Phase 2.

### Phase 1 — Core flexibility *(foundation)*
1. `scope_types` table + strict/free-form validation; drop Java whitelist + depth trigger
2. `scopes.code` column + path-generation fix; ROOT scope seeding + `/scopes/root`
3. Drop profile stack (5 files, 2 DTOs, table, service touches)
4. Drop `assignments.effect`; reconcile exception-handler constraint names; delete `schama.sql`
5. Migration restructure (V1–V5 layout per §7)

### Phase 2 — Token architecture *(the issuer)*
1. `signing_keys` + RS256 signing + JWKS endpoint + `kid` rotation (+ `KeySource` port)
2. Claims modes (minimal/roles/permissions)
3. Cookie key separation (S4); OAuth exchange code (S2); redirect allowlist (S1); `__Host-` secure default (S3)
4. `NotificationPort` + log/SMTP/webhook adapters
5. Introspection + revocation-feed endpoints (flag-gated)

### Phase 3 — Layered features *(the template promise)*
1. `iam.features.*` flag wiring — conditional beans, endpoint gating, pipeline step skipping
2. `resource_grants` table + pipeline step ②b + CRUD + ceiling checks
3. `services` registry + per-service API keys + permission manifest sync
4. OAuth2 behind flag

### Phase 4 — Hardening & spec *(release quality)*
1. P1–P4 performance fixes (async audit bean, versioned cache keys, batch policy eval)
2. S5–S6 (error message hygiene, explicit fail-mode)
3. Decision-engine table-driven test suite + filter-chain + migration + token-lifecycle tests
4. Docs rewrite: per-mode integration guides (claims / PDP / hybrid), template-adoption checklist

---

## 14. Open Decisions

| # | Question | Recommendation |
|---|----------|----------------|
| 1 | ES256 vs RS256 default | RS256 (broadest library support); ES256 available via config |
| 2 | Should `deny_rules` be flag-gated like L3–L5? | No — keep always-on. It's the security kill-switch; cost when unused is one cached empty lookup |
| 3 | Multi-tenancy: is `domain` namespacing + scope subtrees enough, or add a hard `tenant_id` column across authz tables? | Start with namespacing + subtrees (ships in this design); hard tenancy is a later, additive migration if a deployment needs cryptographic-grade isolation |
| 4 | MFA: `mfa_enabled` field exists with zero logic | Out of scope for this redesign; L3 `require_mfa` condition reads the claim if an upstream IdP/step-up flow sets it. Native TOTP could be a future flag |

---

*End of proposal.*
