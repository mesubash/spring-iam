# spring-iam

Production‑grade Authorization (AuthZ) service with scoped RBAC + ABAC policies, explicit deny rules, and full audit logging. Services authenticate users themselves (AuthN) and call this service for authorization decisions.

---

## 1) What this service does (and doesn’t)

**Does:**
- Centralized authorization decisions for many services
- Scoped RBAC + ABAC policies
- Explicit deny overrides
- Audit logging and metrics
- Low‑latency checks with caching

**Does NOT:**
- Authenticate users
- Store user profiles or passwords

**Input to IAM:** stable `subjectId` from your AuthN system.

---

## 2) Core approach (production model)

- Each product/service keeps its own AuthN (user DB + login + tokens)
- IAM is the **single source of truth for permissions/roles/scopes**
- Services send `subjectId` and resource context to IAM
- IAM returns ALLOW/DENY and audits the decision

This is a standard **AuthZ-as-a-service** model.

---

## 3) Scope hierarchy (what “GLOBAL, COUNTRY, REGION, ORG” mean)

Scopes represent a **hierarchical org tree**. Depth is enforced in the DB schema:

- `GLOBAL` = depth 0
- `COUNTRY` = depth 1
- `REGION` = depth 2
- `ORG` = depth 3
- `DEPT` = depth 4
- `TEAM` = depth 5
- `PROJECT` = depth 6

Example:

```
GLOBAL
└── COUNTRY (Nepal)
    └── REGION (Bagmati)
        └── ORG (Everest Travels)
```

Path example: `GLOBAL.NEPAL.BAGMATI.EVEREST_TRAVELS`

Only **GLOBAL** is seeded by migration. All other scopes are created at runtime.

---

## 4) Core entities

- **Permission**: immutable key `domain.resource.action` (e.g. `booking.reservation.read`)
- **Role**: bundle of permissions
- **Assignment**: subject ↔ role ↔ scope (+ optional conditions)
- **Deny Rule**: explicit deny (global or scoped)
- **Policy**: ABAC rule (ALLOW/DENY + conditions)

---

## 5) Runtime authorization flow

1. **Deny rules** (cached) → immediate deny if matched
2. **Assignments + scope containment** (RBAC)
3. **Assignment conditions** (MFA, IP range, time window, ownership, etc.)
4. **Policy evaluation** (ABAC)
5. **Audit log** of the decision

---

## 6) Authorization request model

All ABAC fields are provided by the **caller** in the request (IAM does not fetch resource metadata).

```json
POST /api/v1/authorize
{
  "subject": "user-123",
  "permission": "booking.reservation.read",
  "resource": {
    "type": "reservation",
    "id": "res-999",
    "scopeId": "2efb5de7-9b9b-4746-a7b0-3bda1cc1c6b1",
    "metadata": {
      "ownerId": "user-123"
    }
  },
  "context": {
    "timestamp": "2026-01-25T17:00:00Z",
    "ipAddress": "10.1.2.3",
    "userAgent": "PostmanRuntime/7.39",
    "requestId": "req-123",
    "additionalContext": {
      "mfa": true
    }
  }
}
```

---

## 7) ABAC policy syntax

Condition tree with `all` / `any` / `not`:

```json
{
  "all": [
    {"field": "subject", "op": "eq", "value": "$resource.metadata.ownerId"}
  ]
}
```

Supported operators:
- `eq`, `neq`, `in`, `not_in`, `contains`, `exists`
- `gt`, `gte`, `lt`, `lte`
- `regex`, `before`, `after`

Supported fields:
- `subject`, `permission`
- `resource.type`, `resource.id`, `resource.scopeId`, `resource.metadata.*`
- `context.timestamp`, `context.ipAddress`, `context.userAgent`, `context.sessionId`, `context.requestId`
- `context.additional.*`

---

## 8) Assignment condition keys

Assignments can include a `conditions` JSON. Supported keys include:
- `time_window` (e.g. `"09:00-18:00"`)
- `ip_ranges` (CIDR list)
- `require_mfa` (boolean)
- `ownership_required` / `can_only_access_own_created`
- `cannot_approve_own_created`
- `subject_match_fields` (list of metadata/context field names)

---

## 9) Effective permissions (bootstrap)

Use when a UI/service wants a full “capabilities” list for a subject/scope.

```
POST /api/v1/effective-permissions
```

Returns permissions after deny + conditions + policy evaluation.

---

## 10) API surface

### Admin APIs (Bearer JWT with `IAM_ADMIN`)
- `/api/v1/scopes`
- `/api/v1/permissions`
- `/api/v1/roles`
- `/api/v1/role-hierarchy`
- `/api/v1/assignments`
- `/api/v1/deny-rules`
- `/api/v1/policies`
- `/api/v1/audit`

### Runtime APIs (internal)
- `/api/v1/authorize`
- `/api/v1/authorize/batch`
- `/api/v1/effective-permissions`

### Docs & health
- Swagger UI: `/api-docs`
- OpenAPI JSON: `/api-docs/openapi.json`
- Health: `/api/v1/health` and `/actuator/**`

---

## 11) IAM authentication

- **Admin APIs**: Bearer JWT (`IAM_ADMIN`)
- **Runtime APIs**: `X-Internal-Api-Key`

Production hardening recommendations:
- per‑service keys, rotation, and auditing
- mTLS or OAuth client‑credentials in higher security environments
- include `X-Service-Id` (audited) for caller attribution

---

## 12) Audit logging

Every decision is stored in `authorization_audit`:
- subjectId, permissionKey, resourceType/id, scopeId
- decision + reason
- requestId, userAgent, ipAddress
- context JSON

Audit table is partitioned by month.

---

## 13) Caching + invalidation

Caches:
- permissions (subject + scope)
- deny rules
- scope containment
- role permissions
- policy candidates

Invalidation occurs on:
- assignment create/revoke
- role permission update
- role hierarchy update
- deny rule create/revoke
- policy create/update/deactivate
- scope create/update

---

## 14) First‑time setup (minimal)

1. Start DB + service (Docker Compose)
2. Create required scopes (GLOBAL already exists)
   - COUNTRY → REGION → ORG
3. Register permissions
4. Create roles and attach permissions
5. Create assignments for subjects
6. Run `/authorize` and verify audit logs

For full step‑by‑step, use `docs/POSTMAN_TESTING_GUIDE.md`.

---

## 15) Production checklist (ops)

- Ensure DB migrations are applied (Flyway)
- Ensure `ltree` extension is available
- Set internal API key or service‑to‑service auth (mTLS/CC tokens)
- Configure audit partition retention policy
- Enable monitoring/metrics from `/actuator`
- Configure log aggregation for audit failures
- Define cache invalidation strategy for cross‑service changes
- Backup/replication for audit tables
- Add service caller identity in audit context

---

## 16) File structure (high‑level)

```
.
├─ docs/
│  ├─ INFO.md
│  ├─ DESIGN.md
│  ├─ CENTRAL_DOC.md
│  ├─ PLATFORM_DOC.md
│  ├─ INTEGRATION_GUIDE.md
│  └─ POSTMAN_TESTING_GUIDE.md
├─ src/
│  ├─ main/java/com/hgn/iam/
│  │  ├─ config/          # Cache, Flyway, OpenAPI, scheduler
│  │  ├─ controller/      # REST endpoints
│  │  ├─ dto/             # Request/response objects
│  │  ├─ entity/          # JPA entities
│  │  ├─ exception/       # API error handling
│  │  ├─ repository/      # Spring Data repos
│  │  ├─ security/        # API key + JWT security
│  │  ├─ service/         # Business logic (authorization engine)
│  │  └─ util/            # helpers (IP matching, etc.)
│  └─ main/resources/
│     ├─ application.yml
│     └─ db/migration/    # Flyway migrations
├─ docker-compose.yml
├─ Dockerfile
├─ pom.xml
└─ README.md
```

---

## 17) Code map (key classes)

- `AuthorizationService` — core authorization engine
- `PolicyEvaluator` — ABAC condition evaluation
- `ScopeService` — scope creation/validation
- `AssignmentService` — create/revoke assignments
- `DenyRuleService` — deny rule management
- `RoleService` + `RoleHierarchyService` — role/permission logic
- `AuditService` + `AuditPartitionService` — audit logging
- `ApiKeyAuthFilter` / `JwtAuthFilter` — security filters
- `GlobalExceptionHandler` — consistent error responses

---

## 18) Docs

- `docs/INFO.md` — DB schema and constraints
- `docs/DESIGN.md` — architecture + flows
- `docs/CENTRAL_DOC.md` — system summary
- `docs/PLATFORM_DOC.md` — platform overview
- `docs/INTEGRATION_GUIDE.md` — integration patterns
- `docs/POSTMAN_TESTING_GUIDE.md` — end‑to‑end API testing

---

## 19) Quick links

- Swagger UI: `/api-docs`
- OpenAPI JSON: `/api-docs/openapi.json`
- Health: `/api/v1/health`

---

## 20) License

Internal / private use.
