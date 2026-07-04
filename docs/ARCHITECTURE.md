# Architecture

> Current-state overview of Spring IAM. For the deep specs see
> [`AUTHZ_DESIGN.md`](AUTHZ_DESIGN.md) (authorization engine) and
> [`AUTHN_DESIGN.md`](AUTHN_DESIGN.md) (authentication / token issuer).

---

## 1. What it is

A single deployable service that answers two questions for a whole fleet of apps:

- **AuthN** — *Who is this?* Issues and rotates tokens; it is a central **token
  issuer**, not a gatekeeper. Consumers verify tokens locally.
- **AuthZ** — *May subject S do permission P on resource R at scope C under
  context X?* A layered, deny-overrides decision engine.

One PostgreSQL database, one Redis, one JVM. AuthN and AuthZ are separate
modules that talk only through shared interfaces, so AuthZ can be split into
its own service later without redesign.

```
                    ┌────────────────────────────────────────┐
   browsers /       │              Spring IAM                 │
   mobile apps ───► │  ┌──────────┐        ┌───────────────┐  │
                    │  │  AuthN    │        │    AuthZ      │  │
   consuming    ───►│  │ issuer +  │ shared │  decision     │  │
   services         │  │ sessions  │  DTOs  │  engine       │  │
                    │  └────┬─────┘         └──────┬────────┘  │
                    └───────┼──────────────────────┼──────────┘
                            │                       │
                     PostgreSQL 16            Redis (cache +
                  (ltree, closure,          sessions blacklist +
                   partitions, Flyway)        rate limit + OTT)
```

---

## 2. Authentication

- **Access tokens**: RS256 JWT, 15 min. Signed with a private key from the
  `signing_keys` table; consumers verify against **`GET /.well-known/jwks.json`**
  — no shared secrets. Keys rotate (`kid` header, grace window). Claims carry
  `sub` (identity UUID = universal subject id), `sid` (session), `jti`
  (revocation handle), and — per `claims-mode` — `roles` or `perms`.
- **Refresh tokens**: opaque 256-bit values, stored SHA-256-hashed, one rotation
  chain per **session**. One session = one device. Rotation on every use;
  replaying a rotated token outside a 60 s grace window kills the whole session
  (theft detection). A 60 s retry grace absorbs lost-response races.
- **Sessions**: multi-device (cap 10, LRU eviction), listable and revocable by
  the user (`/api/auth/sessions`).
- **Credentials**: password (bcrypt-12) and OAuth2 (Google, flag-gated) coexist
  per identity. OAuth completes via a single-use exchange code — tokens never
  ride in a URL.
- **Lifecycle**: register → email-verify → active; lockout after 5 fails / 30 min;
  suspend / deactivate / reactivate; password + email change flows.
- Identity holds only what an issuer needs (email, status, flags). **Profile data
  lives in consuming services**, not here.

## 3. Authorization

A single **deny-overrides pipeline** of six opt-in layers. A disabled layer costs
zero queries and exposes zero API surface.

| Layer | Question | Default |
|---|---|---|
| RBAC | Does one of S's roles grant P? | always on |
| Scope | Does the grant's scope contain the resource's scope? | on (dormant with a single ROOT) |
| Deny rules | Is S explicitly forbidden here? (wildcards, always win) | on |
| ABAC conditions | Do per-assignment conditions hold (time, IP, MFA, ownership)? | flag |
| Policies | Do attribute rules (JSON trees, ENFORCE/SHADOW) allow/deny? | flag |
| Resource grants | Was S granted P on this specific instance (no role)? | flag |

**Pipeline order:** scope-validity → deny rules → RBAC×scope → conditions →
resource-grant fallback → policies → allow. Deny always wins; infra failure
returns **503** (fail-closed), never a fake decision. Every terminal outcome is
written to an immutable, monthly-partitioned `authorization_audit` (async, off
the hot path).

**Scopes** are a flexible tree: levels are deployment-defined via the
`scope_types` registry (empty = free-form). Materialized `ltree` paths serve
subtree queries; a trigger-maintained `scope_closure` table gives O(1)
containment. Re-parenting is a managed transactional operation
(`POST /scopes/{id}/move`).

**Tenanting** comes from two places: permission `domain` namespaces services
(`invoice.*` vs `route.*`), and `roles.owner_scope_id` scopes a role to a
subtree so tenants can define same-named roles without collision.

## 4. Request-time security

Filter chain (all before Spring's `UsernamePasswordAuthenticationFilter`):

```
RateLimit → ApiKey → JwtAuth (service token) → JwtAuthentication (user token)
```

Each filter passes through on non-match so the next can try. Three ways to
authenticate a call:

- **User JWT** (Bearer) — end users, verified via JWKS.
- **Internal API key** (`X-Internal-Api-Key`) — service→PDP calls. Either a
  single shared key or, with the service registry on, per-service keys
  (SHA-256-stored, principal `service:<name>`).
- **Service JWT** — inter-service tokens with `roles`/`scope` claims.

## 5. Consumption modes

Consumers pick their depth:

- **Claims** — verify the JWT locally, read `roles`/`perms`. Zero latency,
  staleness bounded by the 15 min TTL.
- **PDP** — call `POST /api/v1/authorize` per decision. Full granularity,
  Redis-cached. Batch and `filter-resources` variants for lists.
- **Hybrid** (recommended) — claims for routine reads, PDP for sensitive
  writes.

## 6. Caching & invalidation

Redis, versioned key prefixes: invalidation is a single `INCR` on a version
counter (per-subject, plus global epoch/role/scope/policy) — no `KEYS`/`SCAN`.
Tiered TTLs (deny 60 s, permissions 5 min, scope 1 h). Every authorize response
carries a `policyVersion` consistency token.

## 7. Operational surfaces

- **Metrics**: Micrometer → `/actuator/prometheus` (decision counters, latency
  histogram, cache hits).
- **Audit partitions**: scheduled create-ahead + retention jobs.
- **Integrity**: startup validator (one root, no dangling refs, non-hollow
  system roles, closure sanity) + optional nightly closure/ltree drift check.
- **Feature flags**: `iam.features.*` — resource-grants, groups,
  service-registry, oauth2, break-glass, introspection, revocation-feed. Discover
  live via `GET /api/v1/meta/features`.

---

## 8. Tech stack

| Component | Choice |
|---|---|
| Framework | Spring Boot 4 / Java 21 |
| Database | PostgreSQL 16 (`ltree`, `uuid-ossp`, `pgcrypto`) |
| Cache / sessions | Redis (Lettuce) |
| Migrations | Flyway (`V1` core → `V5` example seed) |
| Tokens | RS256 JWT (jjwt) + opaque refresh + OAuth2 |
| API docs | springdoc / Swagger UI at `/api-docs` |
| Metrics | Micrometer + Prometheus |

See [`CONFIGURATION.md`](CONFIGURATION.md) for every setting and
[`INTEGRATION_GUIDE.md`](INTEGRATION_GUIDE.md) for how to consume it.
