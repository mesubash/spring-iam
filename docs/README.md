# Spring IAM Documentation

## What is Spring IAM?

Spring IAM is a centralized Identity and Access Management service providing authentication (AuthN) and authorization (AuthZ) for any project that needs access control. It acts as a single source of truth: every other service asks IAM one question -- "Can subject S perform permission P on resource R right now?" -- and enforces the answer locally.

Use it as a template for any greenfield project or as a migration target for legacy systems with scattered auth logic.

## Quick Start

1. Copy `.env.example` to `.env` and configure database, Redis, and JWT secret.
2. Start PostgreSQL 14+ (with `ltree` and `uuid-ossp` extensions) and Redis.
3. Run the service:
   ```bash
   ./mvnw spring-boot:run
   ```
4. Open Swagger UI at `http://localhost:8080/swagger-ui.html` (or `/api-docs` for raw OpenAPI spec).
5. Use the seed admin credentials (see TESTING_GUIDE.md) or generate a JWT with `IAM_ADMIN` role to access admin endpoints.

## Core Concepts

- **Permissions** -- Structured as `domain.resource.action` (e.g., `billing.invoice.approve`). Immutable action dictionary seeded by developers.
- **Roles** -- Named bundles of permissions (e.g., `OrgAdmin` bundles 20 permissions). Assigned to subjects at specific scopes.
- **Scopes** -- Hierarchical org tree: `GLOBAL > REGION > COUNTRY > ORG > DEPT > TEAM`. An assignment at ORG grants access to that org and all descendants.
- **Assignments** -- The core access grant: subject + role + scope. Optionally includes conditions (time window, IP range, MFA requirement).
- **Deny Rules** -- Emergency overrides that block specific permissions for a subject. Deny always wins, evaluated before everything else.
- **Policies** -- Optional ABAC/ReBAC rules evaluated after RBAC (e.g., "user can only approve resources they did not create").

## Documentation Index

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](DESIGN.md) | Authorization model, decision flow, database schema, caching strategy |
| [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md) | How backend services and frontends integrate with IAM |
| [TESTING_GUIDE.md](TESTING_GUIDE.md) | Postman testing guide with step-by-step flow |
| [MIGRATION_GUIDE.md](MIGRATION_GUIDE.md) | Migrating from legacy embedded auth to centralized IAM |
| [CENTRAL_DOC.md](CENTRAL_DOC.md) | Consolidated reference: endpoints, data model, policy engine, caching |

## Technology Stack

| Component | Technology |
|-----------|------------|
| Framework | Spring Boot 4, Java 21 |
| Database | PostgreSQL 14+ (ltree, uuid-ossp extensions) |
| Cache | Redis |
| Auth | JWT (HS256) + API Key for service-to-service |
| Migrations | Flyway |
| API Docs | OpenAPI 3 / Swagger UI |
| Build | Maven Wrapper (`./mvnw`) |
