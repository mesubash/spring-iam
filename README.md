# Spring IAM

Centralized Identity & Access Management (AuthN + AuthZ) service built as a **template repository**. Deploy it as your authentication and authorization backbone for any project.

## What This Service Does

**Authentication (AuthN):**
- User registration with email verification
- Login with password or OAuth2 (Google, Apple, Microsoft)
- JWT access tokens (15 min) + rotating refresh tokens (7 days)
- Account lockout after failed attempts
- Password reset and change flows
- Session management (logout, logout-all)
- Security event audit trail

**Authorization (AuthZ):**
- Centralized permission checks for all services
- Scoped RBAC + ABAC + DENY rules + optional policies
- Hierarchical scope model (GLOBAL > REGION > COUNTRY > ORG > DEPT > TEAM > PROJECT)
- Low-latency decisions with Redis caching
- Immutable audit log of every authorization decision

Every service asks one question: **"Can subject S perform permission P on resource R?"**

---

## Quick Start

```bash
# 1. Configure environment
cp .env.example .env    # Edit with your DB/Redis/JWT settings

# 2. Start PostgreSQL + Redis
docker-compose up -d

# 3. Run the service
./mvnw spring-boot:run

# 4. Access
# Swagger UI:  http://localhost:8080/api-docs
# Health:      http://localhost:8080/actuator/health
```

Default admin credentials (from example seed): `admin@example.com` / `Admin@123!`

---

## Core Concepts

| Concept | Description |
|---------|-------------|
| **Permission** | Immutable key: `domain.resource.action` (e.g., `platform.role.create`) |
| **Role** | Named bundle of permissions (e.g., SuperAdmin, OrgAdmin) |
| **Scope** | Hierarchical org boundary (GLOBAL > REGION > COUNTRY > ORG > ...) |
| **Assignment** | Subject + Role + Scope = access grant. Supports conditions (time, IP, MFA). |
| **Deny Rule** | Explicit override. DENY always wins regardless of roles. |
| **Policy** | Optional ABAC/ReBAC rules evaluated after RBAC. |

---

## Authorization Decision Flow

```
Request -> 1. DENY rules (cached 1 min)
        -> 2. Role assignments + scope containment (cached 5 min)
        -> 3. Assignment conditions (time, IP, MFA, ownership)
        -> 4. Policy evaluation (DENY first, then ALLOW)
        -> 5. Audit log (async)
        -> ALLOW / DENY
```

---

## API Surface

### Authentication
| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/api/auth/register` | Public | Register |
| POST | `/api/auth/login` | Public | Login |
| POST | `/api/auth/refresh` | Cookie | Refresh tokens |
| POST | `/api/auth/logout` | Bearer | Logout |
| GET/PUT | `/api/auth/me` | Bearer | Profile |

### Authorization (Runtime)
| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/api/v1/authorize` | API Key | Check permission |
| POST | `/api/v1/authorize/batch` | API Key | Batch check (max 50) |
| POST | `/api/v1/effective-permissions` | API Key | Get all permissions at scope |

### Authorization (User-Facing)
| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/api/authz/me/scopes` | Bearer | My accessible scopes |
| GET | `/api/authz/me/permissions` | Bearer | My permissions at scope |

### Admin APIs
Permissions, Roles, Scopes, Assignments, Deny Rules, Policies, Role Hierarchy, Permission Groups, Audit — all under `/api/v1/`. See [API Reference](docs/API_REFERENCE.md) for details.

---

## Technology Stack

| Component | Technology |
|-----------|------------|
| Framework | Spring Boot 4.0 / Java 21 |
| Database | PostgreSQL 14+ (ltree, uuid-ossp) |
| Cache | Redis (Lettuce) |
| Auth | JWT (HMAC-SHA) + API Key + OAuth2 |
| Migrations | Flyway |
| API Docs | OpenAPI 3 / Swagger UI |
| Metrics | Micrometer + Prometheus |
| Build | Maven |

---

## Project Structure

```
src/main/java/com/hgn/iam/
  authn/              # Authentication module
    controller/       #   Login, register, OAuth, profile
    service/          #   Auth logic, token management
    security/         #   JWT provider, OAuth2 handlers
    entity/           #   Identity, Credential, RefreshToken
    repository/       #   JPA repositories
    dto/              #   Request/response objects

  authz/              # Authorization module
    controller/       #   Authorize, roles, scopes, assignments, etc.
    service/          #   Authorization engine, policy evaluator, cache
    entity/           #   Permission, Role, Scope, Assignment, DenyRule, Policy
    repository/       #   JPA repositories
    dto/              #   Authorization request/response

  shared/             # Shared between modules
    security/         #   SecurityConfig, ApiKeyAuthFilter, JwtAuthFilter
    service/          #   AuthzQueryService, IdentityQueryService
    entity/           #   IdentityProfile
    dto/              #   ApiResponse, ErrorResponse
    exception/        #   Custom exceptions

src/main/resources/
  application.yml     # All configuration
  db/migration/       # Flyway migrations
    V1__init.sql      #   Core schema (tables, triggers, functions)
    V2__seed_data.sql  #  Platform permissions + system roles
    V3__example_seed.sql # Example dev setup (replace for your project)
  db/schama.sql       # Reference schema (documentation only)
```

---

## Using as a Template

1. **Keep V1 and V2** migrations as-is (core schema + system roles)
2. **Replace V3** with your project's seed data:
   - Your scope hierarchy (regions, countries, orgs)
   - Your domain permissions (`myapp.resource.create`, etc.)
   - Your org-specific roles
   - Your bootstrap admin user
3. **Configure** `.env` with your database, Redis, JWT secret, and OAuth credentials
4. **Integrate** your services using the [Integration Guide](docs/INTEGRATION_GUIDE.md)

---

## System Roles (Built-in)

| Role | Scope | Purpose |
|------|-------|---------|
| SuperAdmin | GLOBAL | Full platform access |
| CountryAdmin | COUNTRY | Country-level governance |
| AccessAdmin | Any | Manage roles, assignments, policies |
| SecurityAdmin | Any | Identity lifecycle, security controls |
| AuditViewer | Any | Read-only audit + analytics |
| OperationsAdmin | Any | Cross-domain operations |
| GovernmentOversight | COUNTRY | Read-only oversight |

---

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/ARCHITECTURE.md) | Authorization model, decision flow, schema, caching |
| [API Reference](docs/API_REFERENCE.md) | Complete endpoint reference with request/response examples |
| [Integration Guide](docs/INTEGRATION_GUIDE.md) | How to integrate services and frontend |
| [Testing Guide](docs/TESTING_GUIDE.md) | Postman testing setup and scenarios |
| [Migration Guide](docs/MIGRATION_GUIDE.md) | Migrating from legacy auth systems |

---

## Configuration

Key settings in `application.yml`:

```yaml
iam:
  authorization:
    cache:
      permissions-ttl: 300    # 5 minutes (seconds)
      deny-rules-ttl: 60      # 1 minute
      scope-ttl: 3600         # 1 hour
      role-ttl: 1800          # 30 minutes
      policy-ttl: 120         # 2 minutes
  security:
    internal-api-key: ${IAM_INTERNAL_API_KEY:}
app:
  jwt:
    secret: ${APP_JWT_SECRET:}
    expiration: 900000         # 15 min access token
    refresh-expiration: 604800000  # 7 day refresh token
```

---

## Production Checklist

- [ ] Set strong JWT secret and API key
- [ ] Configure PostgreSQL with `ltree` and `uuid-ossp` extensions
- [ ] Configure Redis for caching
- [ ] Set up Flyway migrations
- [ ] Create your scope hierarchy
- [ ] Seed your domain permissions and roles
- [ ] Create initial SuperAdmin assignment
- [ ] Configure audit partition retention
- [ ] Enable monitoring via `/actuator/prometheus`
- [ ] Set up log aggregation

---

## License

Private / Internal use.
