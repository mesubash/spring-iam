# Spring IAM

Centralized **Identity & Access Management** (AuthN + AuthZ) as a reusable
template. Deploy it once as the authentication and authorization backbone for a
microservice fleet, a modular monolith, or a set of independent apps.

Every service asks IAM one question — **"Can subject S do permission P on
resource R at scope C under context X?"** — and IAM is the single source of
truth for the answer.

---

## What it does

**Authentication** — a central token issuer, not a gatekeeper.
- Password + OAuth2 (Google) login, email verification, account lockout,
  password/email change, reactivation.
- **RS256** access tokens (15 min) verified locally by consumers via
  **JWKS** — no shared secrets. Opaque rotating refresh tokens with per-device
  sessions and theft detection.
- Multi-device session management (list / revoke).

**Authorization** — a layered, deny-overrides decision engine.
- Permissions (`domain.resource.action`), roles + role hierarchy, and a
  **flexible scope tree** (levels are deployment-defined, not hardcoded).
- Deny rules (always win), ABAC assignment conditions, ABAC policies
  (ENFORCE/SHADOW), and per-instance resource grants (ReBAC).
- Every layer is **opt-in** via feature flags — the baseline is plain RBAC.
- Immutable, partitioned audit of every decision; Redis-cached for low latency.

---

## Quick start

```bash
# 1. Configure
cp .env.example .env          # edit secrets; defaults work for local dev

# 2. Start Postgres + Redis (+ the service)
docker compose up -d

# 3. Or run the service against local infra
./mvnw spring-boot:run

# 4. Explore
#    Swagger UI:  http://localhost:8080/api-docs
#    JWKS:        http://localhost:8080/.well-known/jwks.json
#    Health:      http://localhost:8080/actuator/health
```

Dev seed admin (from `V5__example_seed.sql`): `admin@example.com` /
`Admin@123!`. **Replace V5 for production.**

---

## Core concepts

| Concept | Meaning |
|---|---|
| **Permission** | Immutable key `domain.<resource-path>.action` (3–6 segments) |
| **Role** | Named bundle of permissions; says *what*, never *where* |
| **Scope** | Node in a deployment-defined org tree; grants flow down |
| **Assignment** | subject × role × scope (+ optional conditions/expiry) |
| **Deny rule** | Explicit override; always wins; wildcards + expiry |
| **Policy** | ABAC condition tree (ALLOW/DENY, ENFORCE or SHADOW) |
| **Resource grant** | Per-instance permission — "share X with Y", no role |

---

## Using it as a template

1. Keep migrations `V1`–`V4` (core schema + platform permissions + system roles).
2. Replace `V5__example_seed.sql` with your scopes, permissions, roles, and admin.
3. Configure `.env` (see [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md)).
4. Turn on only the feature flags you need — everything defaults to the simple
   baseline.
5. Integrate services per [`docs/INTEGRATION_GUIDE.md`](docs/INTEGRATION_GUIDE.md).

---

## Documentation

| Document | What's in it |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Current-state overview of both modules |
| [docs/API_REFERENCE.md](docs/API_REFERENCE.md) | Every endpoint, auth, request/response |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | All env vars and feature flags |
| [docs/INTEGRATION_GUIDE.md](docs/INTEGRATION_GUIDE.md) | How to consume IAM (claims / PDP / hybrid) |
| [docs/AUTHZ_DESIGN.md](docs/AUTHZ_DESIGN.md) | Authorization engine — deep design spec |
| [docs/AUTHN_DESIGN.md](docs/AUTHN_DESIGN.md) | Token issuer — deep design spec |
| [docs/UI_PLAN.md](docs/UI_PLAN.md) | Admin console + frontend SDK plan |
| [docs/FUTURE_ENHANCEMENTS.md](docs/FUTURE_ENHANCEMENTS.md) | Deferred features with trigger conditions |

---

## Tech stack

Spring Boot 4 · Java 21 · PostgreSQL 16 (ltree/closure/partitions) · Redis ·
Flyway · RS256 JWT + JWKS · OpenAPI/Swagger · Micrometer/Prometheus · Maven.

## License

Private / internal use.
