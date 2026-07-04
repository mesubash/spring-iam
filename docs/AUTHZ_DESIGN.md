# Authorization (AuthZ) — Complete Design

> Authorization module design (AuthN covered separately in `AUTHN_DESIGN.md`).
> **Date:** 2026-07-04
> **Scope of this document:** the full authorization model, current schema, proposed schema, decision pipeline, condition languages, caching, delegation, APIs, and worked examples for every concept.

---

## Table of Contents

1. [Model Overview — The Six Layers](#1-model-overview--the-six-layers)
2. [Core Concepts & Vocabulary](#2-core-concepts--vocabulary)
3. [Current Schema (as implemented in V1)](#3-current-schema-as-implemented-in-v1)
4. [Proposed Schema — Table by Table](#4-proposed-schema--table-by-table)
   - 4.1 [permissions](#41-permissions--unchanged)
   - 4.2 [roles / role_permissions / role_hierarchy](#42-roles-changed--role_permissions--role_hierarchy)
   - 4.3 [scope_types (NEW)](#43-scope_types-new--deployment-defined-levels)
   - 4.4 [scopes (CHANGED)](#44-scopes-changed--flexible-levels)
   - 4.5 [scope_closure](#45-scope_closure--unchanged)
   - 4.6 [assignments (CHANGED)](#46-assignments-changed--drop-effect)
   - 4.7 [subject_groups (NEW, optional)](#47-subject_groups--subject_group_members-new-optional)
   - 4.8 [deny_rules](#48-deny_rules--changed-minor)
   - 4.9 [policies](#49-policies--changed-minor)
   - 4.10 [resource_grants (NEW)](#410-resource_grants-new--rebac)
   - 4.11 [services (NEW, optional)](#411-services-new-optional--registry--manifest-sync)
   - 4.12 [permission_groups](#412-permission_groups--unchanged)
   - 4.13 [authorization_audit](#413-authorization_audit--unchanged)
   - 4.14 [context_attributes (NEW)](#414-context_attributes-new--policy-vocabulary-registry)
5. [The Decision Pipeline](#5-the-decision-pipeline)
6. [Worked Decision Examples (A–E)](#6-worked-decision-examples)
7. [Assignment Condition Language (L3)](#7-assignment-condition-language-l3)
8. [Policy Condition Language (L4)](#8-policy-condition-language-l4)
9. [Caching Design](#9-caching-design)
10. [Delegated Administration](#10-delegated-administration)
11. [API Surface](#11-api-surface)
12. [Configuration](#12-configuration)
13. [Migration Diff Summary (Current → Proposed)](#13-migration-diff-summary-current--proposed)
14. [Example Deployment Profiles](#14-example-deployment-profiles)
15. [Architect Review — Resolved Findings & Known Boundaries](#15-architect-review--resolved-findings--known-boundaries)

---

## 1. Model Overview — The Six Layers

Authorization answers one question:

> **Can subject S perform permission P on resource R (type + id) at scope C, given request context X?**

The answer is produced by a single **deny-overrides pipeline** built from six capability layers. Each layer is opt-in. A disabled layer is skipped entirely — no query, no cache lookup, no API surface.

```
Layer  Capability          Question it answers                              Default
─────  ─────────────────   ───────────────────────────────────────────────  ─────────
 L0    RBAC                Does any of S's roles grant P?                   ALWAYS ON
 L1    Scope hierarchy     Does the grant's scope contain the resource's    ON (dormant
                           scope? (grants flow down the tree)               with 1 root)
 L2    Deny rules          Is S explicitly forbidden from P here?           ON
 L3    ABAC conditions     Does the grant only apply under context          OFF
                           conditions (time / IP / MFA / ownership)?
 L4    Policies            Do attribute rules (JSON condition trees)        OFF
                           allow or deny this specific request?
 L5    Resource grants     Was S directly granted P on THIS resource        OFF
                           instance, without any role?
```

**Baseline deployment (L0–L2):** one auto-seeded ROOT scope; every assignment lands there implicitly; the integrator sees plain roles-and-permissions plus a kill switch (deny rules). Zero hierarchy knowledge required.

**Full deployment (L0–L5):** arbitrary org tree, contextual conditions, a policy engine, and per-resource sharing — Google-Zanzibar-lite without the operational cost.

The `POST /authorize` contract is identical at every level.

---

## 2. Core Concepts & Vocabulary

| Concept | Definition | Example |
|---|---|---|
| **Subject** | The actor asking for access. Any string ID — a user UUID, a service name, a group ID. IAM does not require the subject to be a local identity. | `"c3d9…-uuid"` (user), `"svc:billing"` (service) |
| **Permission** | Immutable capability key `domain.resource.action`. Never renamed/deleted, only deprecated. | `invoice.invoice.approve` |
| **Role** | Named bundle of permissions. Says WHAT you can do, never WHERE. | `InvoiceManager` = {`invoice.invoice.create`, `invoice.invoice.approve`} |
| **Scope** | Node in the org tree. Says WHERE authority applies. Grants at a scope flow down to all descendants. | `ROOT.ACME.FINANCE` |
| **Assignment** | Subject × Role × Scope — the actual grant. Optionally carries ABAC conditions and expiry. | "Alice is InvoiceManager at ACME.FINANCE until 2026-12-31, office IPs only" |
| **Deny rule** | Explicit override. Always wins over every allow path. | "Bob: `**` denied everywhere — investigation #4711" |
| **Policy** | Attribute rule (JSON condition tree) targeted at a permission/resource-type/scope. ALLOW or DENY. | "DENY `invoice.invoice.approve` when `resource.metadata.amount > 10000`" |
| **Resource grant** | Direct per-instance permission — no role involved. | "Carol may `doc.file.read` on document #123" |
| **Decision** | `ALLOW` or `DENY` + machine-readable reason + audit record. Infra failure ⇒ HTTP 503, never a fake decision. | `{"allowed": false, "reason": "explicit_deny"}` |

---

## 3. Current Schema (as implemented in V1)

Authoritative source: `src/main/resources/db/migration/V1__init.sql`. AuthZ tables only, condensed to the essentials; ✅ = kept as-is in the proposal, ⚠️ = changed, ❌ = removed.

```sql
-- ✅ permissions — immutable registry
CREATE TABLE permissions (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key           VARCHAR(100) UNIQUE NOT NULL,      -- domain.resource.action
    domain        VARCHAR(50) NOT NULL,
    resource      VARCHAR(50) NOT NULL,
    action        VARCHAR(50) NOT NULL,
    description   TEXT,
    is_deprecated BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by    VARCHAR(100),
    CHECK (key ~ '^[a-z_]+\.[a-z_]+\.[a-z_]+$'),
    CHECK (key = domain || '.' || resource || '.' || action)
);

-- ⚠️ roles — gains owner_scope_id (tenant-scoped roles, §4.2)
CREATE TABLE roles (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name           VARCHAR(100) UNIQUE NOT NULL,     -- ^[A-Za-z][A-Za-z0-9_]*$
    display_name   VARCHAR(200),
    description    TEXT,
    is_system_role BOOLEAN NOT NULL DEFAULT FALSE,   -- CHECK: system role can't deactivate
    org_type       VARCHAR(50),                      -- free-form UI hint
    active         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at / updated_at / created_by
);

-- ✅ role_permissions — M:N, ON DELETE RESTRICT on permission side
CREATE TABLE role_permissions (
    id UUID PK, role_id UUID FK CASCADE, permission_id UUID FK RESTRICT,
    granted_at, granted_by, UNIQUE (role_id, permission_id)
);

-- ✅ role_hierarchy — child inherits parent permissions
CREATE TABLE role_hierarchy (
    parent_role_id UUID FK CASCADE, child_role_id UUID FK CASCADE,
    PRIMARY KEY (parent_role_id, child_role_id),
    CHECK (parent_role_id != child_role_id)
);

-- ⚠️ scopes — hierarchy tree; LEVELS CURRENTLY HARDCODED
CREATE TABLE scopes (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    type       VARCHAR(20) NOT NULL
        CHECK (type IN ('GLOBAL','REGION','COUNTRY','ORG','DEPT','TEAM','PROJECT')),  -- ❌ drop
    name       VARCHAR(200) NOT NULL,
    code       VARCHAR(50) UNIQUE,                   -- nullable today; path built from *name* (bug)
    parent_id  UUID REFERENCES scopes(id) ON DELETE RESTRICT,
    path       LTREE NOT NULL,                       -- GiST-indexed materialized path
    depth      INT NOT NULL DEFAULT 0,
    metadata   JSONB NOT NULL DEFAULT '{}',          -- GIN-indexed
    active     BOOLEAN NOT NULL DEFAULT TRUE,
    CHECK (type != 'GLOBAL' OR parent_id IS NULL),   -- ❌ replaced by generic root rule
    CHECK (type =  'GLOBAL' OR parent_id IS NOT NULL)
);
-- ❌ trigger validate_scope_depth(): maps each type to one fixed depth (GLOBAL=0 … PROJECT=6)
-- ✅ trigger maintain_scope_closure(): closure rows on INSERT
-- ✅ trigger prevent_scope_parent_change(): re-parenting forbidden (closure integrity)
-- seed: GLOBAL root at fixed UUID 00000000-0000-0000-0000-000000000001

-- ✅ scope_closure — transitive closure, O(1) containment
CREATE TABLE scope_closure (
    ancestor_id UUID FK CASCADE, descendant_id UUID FK CASCADE,
    depth INT NOT NULL CHECK (depth >= 0),
    PRIMARY KEY (ancestor_id, descendant_id)
);
-- + SQL function scope_contains(ancestor, descendant) → EXISTS lookup

-- ⚠️ assignments — the grant tuple
CREATE TABLE assignments (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    subject_id    VARCHAR(100) NOT NULL,
    subject_type  VARCHAR(20) NOT NULL DEFAULT 'USER'
        CHECK (subject_type IN ('USER','SERVICE','GROUP')),
    role_id       UUID NOT NULL FK RESTRICT,
    scope_id      UUID NOT NULL FK RESTRICT,
    effect        VARCHAR(10) NOT NULL DEFAULT 'ALLOW'
        CHECK (effect IN ('ALLOW','DENY')),          -- ❌ drop: DENY silently ignored by engine
    granted_by / granted_at,
    expires_at    TIMESTAMPTZ,                       -- temporary grants
    conditions    JSONB NOT NULL DEFAULT '{}',       -- L3 ABAC conditions
    active        BOOLEAN NOT NULL DEFAULT TRUE,
    revoked_at / revoked_by / revoke_reason,
    CHECK (expires_at IS NULL OR expires_at > granted_at),
    CHECK (revoked_at/revoked_by consistency)
);
-- ✅ trigger auto_deactivate_on_revoke(): sets active=false when revoked_at set

-- ✅ deny_rules — explicit overrides, checked first
CREATE TABLE deny_rules (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    subject_id     VARCHAR(100) NOT NULL,
    permission_key VARCHAR(100) NOT NULL
        CHECK (permission_key ~ '^[a-z_*]+\.[a-z_*]+\.[a-z_*]+$'),  -- wildcards allowed
    scope_id       UUID FK CASCADE,                  -- NULL = everywhere
    reason         TEXT NOT NULL CHECK (LENGTH(TRIM(reason)) > 0),
    reference_id   VARCHAR(100),                     -- ticket / case number
    created_by / created_at,
    expires_at     TIMESTAMPTZ,                      -- temporary suspensions
    active         BOOLEAN NOT NULL DEFAULT TRUE
);

-- ✅ policies — ABAC rules
CREATE TABLE policies (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name           VARCHAR(120) UNIQUE NOT NULL,
    description    TEXT,
    permission_key VARCHAR(100),                     -- targeting (NULL = any)
    resource_type  VARCHAR(100),                     -- targeting (NULL = any)
    scope_id       UUID FK CASCADE,                  -- targeting (NULL = any)
    effect         VARCHAR(10) NOT NULL DEFAULT 'ALLOW' CHECK (effect IN ('ALLOW','DENY')),
    priority       INT NOT NULL DEFAULT 0,
    conditions     JSONB NOT NULL DEFAULT '{}',      -- condition tree (§8)
    active         BOOLEAN NOT NULL DEFAULT TRUE
);

-- ✅ permission_groups + permission_group_members — admin-UI grouping only
CREATE TABLE permission_groups (id UUID PK, name UNIQUE, description,
    parent_group_id UUID self-FK, created_at);
CREATE TABLE permission_group_members (group_id FK CASCADE, permission_id FK CASCADE,
    PRIMARY KEY (group_id, permission_id));

-- ✅ authorization_audit — immutable, monthly range-partitioned
CREATE TABLE authorization_audit (
    id UUID, subject_id, permission_key, resource_type, resource_id, scope_id,
    decision BOOLEAN NOT NULL, reason TEXT NOT NULL, context JSONB,
    request_id, ip_address INET, user_agent, timestamp TIMESTAMPTZ,
    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);
-- default partition + RULEs: UPDATE/DELETE DO INSTEAD NOTHING (immutable)
-- monthly partitions pre-created by scheduled AuditPartitionService; retention job drops old ones
```

### What is wrong with the current schema (summary)

| # | Problem | Where | Fix |
|---|---------|-------|-----|
| 1 | Hierarchy levels hardcoded — 7 fixed type names, fixed depth per type | `scopes` CHECK + `validate_scope_depth()` trigger + `ScopeService.java:54` whitelist | §4.3–4.4: `scope_types` registry, free-form default, depth derived |
| 2 | ltree path built from `name.toUpperCase().replace(" ","_")` — sibling collision possible; `code` column exists but unused for paths | `ScopeService` | §4.4: `code` becomes NOT NULL, path segment = code |
| 3 | `assignments.effect='DENY'` accepted by API but **silently ignored** by the engine (only ALLOW rows are fetched) | `assignments` + `AssignmentRepository` | §4.6: drop the column; deny = `deny_rules`, one mechanism |
| 4 | No per-resource-instance grants — "share X with Y" needs a policy hack | — | §4.10: `resource_grants` |
| 5 | No consumer identity — one shared API key for every calling service | — | §4.11: `services` registry |
| 6 | `subject_type` GROUP declared but nothing resolves group membership | `assignments` | §4.7: optional `subject_groups` |

---

## 4. Proposed Schema — Table by Table

Each section: **DDL** → **rationale** → **example**.

### 4.1 `permissions` — UNCHANGED

```sql
CREATE TABLE permissions (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key           VARCHAR(150) UNIQUE NOT NULL,      -- 3–6 dot-separated segments
    domain        VARCHAR(50)  NOT NULL,             -- first segment (namespace)
    resource      VARCHAR(100) NOT NULL,             -- middle segment(s), may contain dots
    action        VARCHAR(50)  NOT NULL,             -- last segment
    description   TEXT,
    is_deprecated BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_by    VARCHAR(100),
    CONSTRAINT chk_permission_key_format
        CHECK (key ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){2,5}$'),   -- 3..6 segments
    CONSTRAINT chk_permission_key_matches CHECK (key = domain || '.' || resource || '.' || action)
);
```

*(Format changes vs current: segments admit digits — `s3.bucket.read`, `oauth2.client.create` valid; and key depth is **variable, 3–6 segments**, not fixed at 3.)*

**Key depth.** The shape is `domain.<resource-path>.action` — first segment is always the namespace, last is always the action, everything between is the resource path:

| Key | domain | resource | action |
|---|---|---|---|
| `order.order.create` | order | order | create |
| `hgn.order.insurance.create` | hgn | order.insurance | insurance-object create |
| `hgn.order.shipment.item.update` | hgn | order.shipment.item | update |

The engine never parses the middle: RBAC/grant checks are **exact string membership** in a permission set, so a 6-segment key costs exactly what a 3-segment key costs. Depth only matters to wildcard matching (deny rules/policies — see §4.8) and to manifest-sync ownership (first segment = owning namespace). Guidance: prefer flat 3-segment keys; add segments only when the resource genuinely nests (`order.insurance` is a real sub-resource, not a naming fashion).

**Rationale.** The three-segment key is the atomic authorization unit and an *immutable contract*: once a consumer codes `if (authorize("invoice.invoice.approve"))`, that string may never change meaning. Deprecation instead of deletion keeps old audit rows interpretable. `domain` doubles as the namespace for multi-service deployments (`invoice.*` owned by the invoice service, `route.*` by the route service) — this is what makes one IAM serve many apps without collision.

**Example rows**

| key | domain | resource | action | description |
|---|---|---|---|---|
| `invoice.invoice.create` | invoice | invoice | create | Create an invoice |
| `invoice.invoice.approve` | invoice | invoice | approve | Approve an invoice |
| `platform.role.create` | platform | role | create | (IAM's own admin permission) |
| `doc.file.read` | doc | file | read | Read a document |

---

### 4.2 `roles` (CHANGED) / `role_permissions` / `role_hierarchy`

DDL as in §3, plus one addition — **tenant-scoped roles**:

```sql
ALTER TABLE roles ADD COLUMN owner_scope_id UUID REFERENCES scopes(id) ON DELETE RESTRICT;
-- NULL  = global role: assignable anywhere (template default, today's behavior)
-- set   = role belongs to that subtree: visible to and assignable only within it
```

**Why.** Without this, roles are one global namespace. The day tenant #2 wants a custom role named `Manager`, it collides with tenant #1's `Manager` — or worse, tenant #1's role definition silently leaks into tenant #2's admin UI. With `owner_scope_id`:

- A role owned by `ROOT.ACME` can only be used in assignments whose scope is inside `ROOT.ACME` (containment check at assignment creation).
- Role name uniqueness becomes `UNIQUE (owner_scope_id, name)` (global roles keep effective global uniqueness via NULL owner) — Acme's `Manager` and Globex's `Manager` coexist.
- `GET /api/v1/roles?scopeId=…` returns global roles + roles owned by any ancestor of that scope — tenant admins see exactly their vocabulary.
- Delegated admins (§10) may create roles only with `owner_scope_id` inside their own subtree — and the permission ceiling still applies to what they put in them.

**Example.** Acme's admin creates `{name: "Manager", owner_scope_id: s1}` with acme-relevant permissions. Globex creates its own `Manager` under `s4`. Neither sees the other's. `SuperAdmin`'s global roles (owner NULL) remain visible everywhere.

Three deliberate properties (unchanged):

1. **Roles never contain scope.** `InvoiceManager` means the same set of capabilities whether assigned at ROOT or at one team. WHERE is the assignment's job. This is what lets one role definition serve every org unit.
2. **`role_hierarchy` is a DAG, not a tree** — a child role may inherit from several parents. Resolution is a BFS up the parent edges collecting permissions (already implemented, batch queries per frontier level). Cycle prevention is enforced in the service layer at edge-creation time (walk from proposed parent up; reject if child encountered).
3. **`is_system_role`** protects template-shipped roles (e.g. `SuperAdmin`) from deactivation; the DB CHECK backs the service check.

**Example** — role inheritance:

```
roles:            InvoiceViewer          InvoiceManager
role_permissions: invoice.invoice.read   invoice.invoice.create
                                         invoice.invoice.approve
role_hierarchy:   (parent=InvoiceViewer, child=InvoiceManager)
```

Effective permissions of `InvoiceManager` = own + inherited =
`{invoice.invoice.read, invoice.invoice.create, invoice.invoice.approve}`.

---

### 4.3 `scope_types` (NEW) — deployment-defined levels

```sql
CREATE TABLE scope_types (
    id                   UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                 VARCHAR(50)  NOT NULL UNIQUE,   -- 'TENANT', 'WAREHOUSE', …
    display_name         VARCHAR(100) NOT NULL,
    allowed_parent_types TEXT[]       NOT NULL DEFAULT '{}',  -- empty = may only sit under ROOT
    level_order          INT,                            -- optional cosmetic ordering
    description          TEXT,
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
```

**Rationale.** The engine (ltree + closure) never cared about level *names* — only the validation layer did. Moving level definitions into data makes the hierarchy a per-deployment choice instead of a fork-the-code choice.

**Two validation modes** (service layer; the old `validate_scope_depth()` trigger is dropped):

| `scope_types` table | Mode | Behavior on `POST /scopes` |
|---|---|---|
| empty (default) | **free-form** | any `type` label accepted, any nesting, any depth |
| has rows | **strict** | `type` must exist; parent's type must be listed in `allowed_parent_types` (or parent must be ROOT if the array is empty) |

**Example A — SaaS deployment seeds:**

```sql
INSERT INTO scope_types (name, display_name, allowed_parent_types, level_order) VALUES
('ORG',       'Organization', '{}',            1),   -- under ROOT only
('WORKSPACE', 'Workspace',    '{ORG}',         2),
('PROJECT',   'Project',      '{WORKSPACE}',   3);
```

**Example B — logistics deployment:**

```sql
INSERT INTO scope_types (name, display_name, allowed_parent_types, level_order) VALUES
('TENANT',    'Tenant',    '{}',                1),
('REGION',    'Region',    '{TENANT}',          2),
('WAREHOUSE', 'Warehouse', '{REGION,TENANT}',   3);   -- warehouse may sit under region OR directly under tenant
```

**Example C — baseline app:** table stays empty; the integrator never creates a scope at all and every assignment defaults to ROOT.

---

### 4.4 `scopes` (CHANGED) — flexible levels

```sql
CREATE TABLE scopes (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    type       VARCHAR(50)  NOT NULL,               -- free-form or registry-validated (no CHECK list)
    name       VARCHAR(200) NOT NULL,               -- human label, mutable
    code       VARCHAR(50)  NOT NULL,               -- slug; THE ltree path segment (sibling-unique, see below)
    parent_id  UUID REFERENCES scopes(id) ON DELETE RESTRICT,
    path       LTREE NOT NULL,                      -- parent.path || '.' || code
    depth      INT   NOT NULL,                      -- derived: parent.depth + 1 (root = 0)
    metadata   JSONB NOT NULL DEFAULT '{}',
    active     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at / updated_at / created_by,

    CONSTRAINT chk_scope_code_format CHECK (code ~ '^[A-Za-z0-9_]{1,50}$'),
    CONSTRAINT chk_scope_root_depth  CHECK ((parent_id IS NULL) = (depth = 0))
);
CREATE UNIQUE INDEX uq_scopes_single_root ON scopes ((1)) WHERE parent_id IS NULL;  -- exactly one root
CREATE UNIQUE INDEX uq_scopes_sibling_code ON scopes (parent_id, code);             -- sibling-unique, NOT global
CREATE INDEX idx_scopes_path     ON scopes USING GIST (path);
CREATE INDEX idx_scopes_parent   ON scopes (parent_id);
CREATE INDEX idx_scopes_metadata ON scopes USING GIN (metadata);
```

**Changes vs current**

| Change | Why |
|---|---|
| `type` CHECK list removed | levels come from `scope_types` (or free-form) |
| `validate_scope_depth()` trigger dropped | depth is derived from the parent, not implied by the type |
| `code` NOT NULL + path segment = `code` | today the path uses normalized `name` — "North Region" and "NORTH_REGION" siblings collide |
| `code` uniqueness: global → **sibling-only** `UNIQUE(parent_id, code)` | global uniqueness breaks multi-tenant flexibility: if Acme has workspace `FIN`, Globex could never create its own `FIN`. Sibling uniqueness is exactly what ltree path uniqueness requires — nothing more. Lookup-by-code becomes lookup-by-path (`ROOT.GLOBEX.FIN`) |
| GLOBAL-specific CHECKs → generic root rule + single-root partial index | template ships one seeded ROOT (`id = 00000000-0000-0000-0000-000000000001`, `code = 'ROOT'`); multi-app deployments hang each app under ROOT |

**Kept:** `maintain_scope_closure()` trigger (closure rows on insert).

**Changed — re-parenting becomes a managed operation instead of a ban.** The current `prevent_scope_parent_change()` trigger forbids moves entirely; real organizations reorganize, and "create a new subtree, migrate assignments" breaks `scope_id` references stored in consumer databases and loses assignment history. Replacement:

```
POST /api/v1/scopes/{id}/move   { "newParentId": "…" }        (SuperAdmin only)
```

Semantics — single transaction under an advisory lock on the scopes table:
1. Reject if the new parent is inside the moving subtree (cycle) or violates `scope_types` rules in strict mode.
2. Delete closure rows linking the subtree to its old ancestors; re-insert rows for the new ancestor chain (`old-ancestor × subtree` out, `new-ancestor × subtree` in — bounded: |ancestors| × |subtree|).
3. Rebuild `path` and `depth` for the subtree (`UPDATE … SET path = new_prefix || subpath(path, nlevel(old_prefix))`).
4. Version-bump the scope-containment cache family (§9) and write an audit record.

Direct `UPDATE scopes SET parent_id` remains trigger-blocked — the move endpoint is the only path, so closure/path/cache can never silently drift.

**Example tree** (SaaS profile from §4.3-A):

```
id     type       name            code       path                        depth
s0     ROOT       Root            ROOT       ROOT                        0
s1     ORG        Acme Corp       ACME       ROOT.ACME                   1
s2     WORKSPACE  Acme Finance    FIN        ROOT.ACME.FIN               2
s3     PROJECT    Q3 Audit        Q3AUDIT    ROOT.ACME.FIN.Q3AUDIT       3
s4     ORG        Globex          GLOBEX     ROOT.GLOBEX                 1
```

Subtree query (admin UI): `SELECT * FROM scopes WHERE path <@ 'ROOT.ACME'` → s1, s2, s3 (GiST-indexed).

---

### 4.5 `scope_closure` — UNCHANGED

```sql
CREATE TABLE scope_closure (
    ancestor_id   UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    descendant_id UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    depth         INT  NOT NULL CHECK (depth >= 0),
    PRIMARY KEY (ancestor_id, descendant_id)
);
```

**Rationale.** Two hierarchy representations on purpose:

- **`scopes.path` (ltree)** — set queries: "all descendants of X" for admin UIs, effective-permission trees. GiST-indexed.
- **`scope_closure`** — point queries: "does X contain Y?" — the hot-path check inside every authorization decision. One PK lookup, O(1), and trivially cacheable.

The closure is populated by trigger on scope insert: a self-row `(new, new, 0)` plus one row per ancestor.

**Example** — closure rows for the tree above (s2 = ROOT.ACME.FIN):

| ancestor | descendant | depth |
|---|---|---|
| s0 | s2 | 2 |
| s1 | s2 | 1 |
| s2 | s2 | 0 |

Containment check "does an assignment at s1 (ACME) cover a resource at s3 (Q3AUDIT)?" → `EXISTS (ancestor=s1, descendant=s3)` → **yes**.

---

### 4.6 `assignments` (CHANGED) — drop `effect`

```sql
CREATE TABLE assignments (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    subject_id    VARCHAR(100) NOT NULL,
    subject_type  VARCHAR(20)  NOT NULL DEFAULT 'USER'
                  CHECK (subject_type IN ('USER','SERVICE','GROUP')),
    role_id       UUID NOT NULL REFERENCES roles(id)  ON DELETE RESTRICT,
    scope_id      UUID NOT NULL REFERENCES scopes(id) ON DELETE RESTRICT,
    -- ❌ effect column REMOVED
    granted_by    VARCHAR(100) NOT NULL,
    granted_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ,
    conditions    JSONB        NOT NULL DEFAULT '{}',   -- L3, see §7
    origin        VARCHAR(20)  NOT NULL DEFAULT 'STANDARD'
                  CHECK (origin IN ('STANDARD','BREAK_GLASS','MIGRATION')),
    active        BOOLEAN      NOT NULL DEFAULT TRUE,
    revoked_at    TIMESTAMPTZ,
    revoked_by    VARCHAR(100),
    revoke_reason TEXT,
    CONSTRAINT chk_assignment_expiry CHECK (expires_at IS NULL OR expires_at > granted_at),
    CONSTRAINT chk_assignment_revoke_consistency
        CHECK ((revoked_at IS NULL AND revoked_by IS NULL) OR
               (revoked_at IS NOT NULL AND revoked_by IS NOT NULL))
);
```

**Why drop `effect`?** The engine only ever loads `effect='ALLOW'` rows, so a DENY assignment is accepted by the API and then silently ignored — worse than not existing, because an admin believes they denied something. One deny mechanism (`deny_rules`, §4.8) with its mandatory `reason` field is the honest contract.

**Example rows**

```jsonc
// Permanent grant: Alice is InvoiceManager for all of Acme
{ "subject_id": "alice-uuid", "role_id": "<InvoiceManager>", "scope_id": "s1",
  "granted_by": "root-admin", "conditions": {} }

// Temporary contractor, office-hours + office-network only (L3)
{ "subject_id": "bob-uuid", "role_id": "<InvoiceViewer>", "scope_id": "s2",
  "expires_at": "2026-09-30T23:59:59Z",
  "conditions": {
      "time_window": "09:00-17:00", "timezone": "Asia/Kathmandu",
      "ip_ranges": ["203.0.113.0/24"]
  } }

// Baseline app (never created a scope): everything at ROOT
{ "subject_id": "carol-uuid", "role_id": "<Admin>", "scope_id": "s0" }
```

Lifecycle: revocation sets `revoked_at/revoked_by/revoke_reason`; the `auto_deactivate_on_revoke()` trigger (kept) flips `active=false` atomically. Expired assignments are filtered at query time (`expires_at IS NULL OR expires_at > NOW()`).

**Temporal guarantee (as-of queries).** Assignments, deny rules, and resource grants are **never hard-deleted** — revocation is the only removal, and it preserves the row with its full validity interval (`granted_at → revoked_at|expires_at`). This makes point-in-time reconstruction a pure query: `GET /effective-permissions?asOf=2026-06-01T00:00:00Z` evaluates L0–L2 against rows whose interval covers that instant — "what could Alice do on June 1" for incident forensics and compliance audits, at zero storage cost beyond what revocation already keeps. There are no DELETE endpoints for these tables, by contract.

**Break-glass (`origin='BREAK_GLASS'`).** Emergency elevated access as a first-class flow:

```
POST /api/v1/break-glass     (flag: iam.features.break-glass)
{ "subjectId": "oncall-eng", "roleId": "<IncidentResponder>", "scopeId": "s1",
  "durationMinutes": 120,            // hard cap: 240
  "reason": "prod outage — order pipeline down", "referenceId": "INC-2291" }
```

Semantics: creates a normal assignment with mandatory short `expires_at`, `origin='BREAK_GLASS'`, mandatory reason/reference; emits a dedicated audit event and a webhook notification the moment it's created **and** when it expires. It rides the standard pipeline (deny rules still override it), auto-dies, and is trivially reportable (`WHERE origin='BREAK_GLASS'`) for post-incident review.

---

### 4.7 `subject_groups` + `subject_group_members` (NEW, optional)

Flag: `iam.features.groups` (default **off**). Makes the existing `subject_type='GROUP'` placeholder real.

```sql
CREATE TABLE subject_groups (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    active      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by  VARCHAR(100)
);

CREATE TABLE subject_group_members (
    group_id   UUID NOT NULL REFERENCES subject_groups(id) ON DELETE CASCADE,
    subject_id VARCHAR(100) NOT NULL,
    added_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    added_by   VARCHAR(100),
    PRIMARY KEY (group_id, subject_id)
);
CREATE INDEX idx_sgm_subject ON subject_group_members (subject_id);
```

**Semantics.** When the flag is on, assignment resolution for subject S becomes: assignments where `subject_id = S` **∪** assignments where `subject_type='GROUP' AND subject_id IN (S's group ids)`. Group membership list is cached per subject (300 s). No group nesting in v1 — flat membership keeps resolution one query and prevents cycle headaches.

**Example.** Put 40 support agents in group `support-l1`; one assignment `(support-l1, GROUP, SupportAgent, ROOT.ACME)` instead of 40 rows. New hire = one membership row.

---

### 4.8 `deny_rules` — CHANGED (minor)

DDL as in §3, with two adjustments:

```sql
ALTER TABLE deny_rules ADD COLUMN subject_type VARCHAR(20) NOT NULL DEFAULT 'USER'
    CHECK (subject_type IN ('USER','SERVICE','GROUP'));
-- permission_key: dot-separated segments; each segment = name or '*';
-- optionally ONE trailing '**'. Validated in service layer + CHECK regex.
```

`subject_type='GROUP'` (with the groups flag on) denies every member of a group in one rule — "suspend the whole contractor pool" without enumerating subjects. Deny resolution for subject S loads rules for S ∪ S's groups.

Behavior spec:

- **Checked first** in the pipeline; a match ends the decision immediately (`explicit_deny`).
- `permission_key` wildcard semantics (variable-depth keys, §4.1):
  - `*` matches **exactly one** segment: `invoice.*.approve` matches `invoice.order.approve`, not `invoice.order.item.approve`.
  - Trailing `**` matches **one or more** remaining segments: `hgn.order.**` matches `hgn.order.insurance.create` and `hgn.order.shipment.item.update`; `**` alone = everything (full suspension).
  - No `**` present ⇒ segment counts must be equal (exact-arity match).
- `scope_id = NULL` → applies everywhere; non-null → applies at that scope **and all its descendants** (closure check).
- `expires_at` → temporary suspension that lifts itself.
- `reason` mandatory — a deny with no explanation is an incident, not a control.

**Examples**

```jsonc
// Full account suspension pending investigation, auto-lifts in 7 days
{ "subject_id": "bob-uuid", "permission_key": "**", "scope_id": null,
  "reason": "Security investigation", "reference_id": "SEC-4711",
  "expires_at": "2026-07-11T00:00:00Z" }

// Bob keeps all other rights, but may not approve invoices inside Acme Finance subtree
{ "subject_id": "bob-uuid", "permission_key": "invoice.invoice.approve",
  "scope_id": "s2", "reason": "Separation of duties — Bob creates invoices here" }
```

---

### 4.9 `policies` — CHANGED (minor)

DDL as in §3, plus **shadow mode**:

```sql
ALTER TABLE policies ADD COLUMN enforcement_mode VARCHAR(10) NOT NULL DEFAULT 'ENFORCE'
    CHECK (enforcement_mode IN ('ENFORCE','SHADOW'));
```

A `SHADOW` policy runs through the full pipeline but its verdict never affects the decision — the would-be outcome is recorded in the audit row (`context.shadowResults: [{policy, wouldDeny}]`). Authoring flow: create in SHADOW (console default) → observe "would have denied N requests" for a few days → promote to ENFORCE with one update. Kills the "typo'd policy bricks production" failure mode. See `UI_PLAN.md` §5.

Behavior spec (flag: `iam.features.policies`, default off):

- **Targeting** decides which policies are *candidates* for a request: `permission_key` (exact or wildcard), `resource_type`, `scope_id` (containment, not equality) — all nullable, NULL = matches any.
- **Combining mode** — explicit config, because the two sane semantics differ sharply:

  ```yaml
  iam.authorization.policy-mode: deny-only   # deny-only (default) | required-allow
  ```

  | Mode | Semantics | When to use |
  |---|---|---|
  | `deny-only` *(default)* | Only DENY policies are evaluated: any candidate whose conditions match ⇒ DENY. ALLOW-effect policies are ignored (validation warns on save). Policies are pure guard-rails on top of RBAC. | Almost always. Predictable: adding a policy can only *restrict*. |
  | `required-allow` | DENY policies first (as above). Then, **if any ALLOW candidates exist, at least one must match** — else DENY (`no_matching_allow_policy`). | Positive gating ("prod deploys only from CI"). **Sharp edge:** creating one targeted ALLOW policy flips its target to default-deny — requests that passed on pure RBAC start failing. Opt-in for that reason. |

  No candidates at all ⇒ policies are neutral, pipeline continues (both modes).
- `priority` orders evaluation within the same effect bucket (higher first) — relevant for audit readability and short-circuiting, never for overriding DENY.
- Condition language: §8.

**Examples**

```jsonc
// Guard-rail: big invoices need a step-up — deny approve above 10k unless MFA
{ "name": "invoice-approve-limit",
  "permission_key": "invoice.invoice.approve", "resource_type": "invoice",
  "effect": "DENY", "priority": 100,
  "conditions": {
    "all": [
      { "field": "resource.metadata.amount", "op": "gt", "value": 10000 },
      { "not": { "field": "context.additional.mfa", "op": "eq", "value": true } }
    ]
  } }

// Environment fence: production deploys only from CI
// (ALLOW effect ⇒ needs policy-mode: required-allow. In deny-only mode express the
//  same rule negatively: DENY when environment=production AND channel != ci.)
{ "name": "prod-deploy-ci-only",
  "permission_key": "platform.deploy.execute",
  "effect": "ALLOW",
  "conditions": {
    "all": [
      { "field": "context.additional.environment", "op": "eq", "value": "production" },
      { "field": "context.additional.channel",     "op": "eq", "value": "ci" }
    ]
  } }
```

---

### 4.10 `resource_grants` (NEW) — ReBAC

Flag: `iam.features.resource-grants` (default **off**).

```sql
CREATE TABLE resource_grants (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    subject_id      VARCHAR(100) NOT NULL,
    subject_type    VARCHAR(20)  NOT NULL DEFAULT 'USER'
                    CHECK (subject_type IN ('USER','SERVICE','GROUP')),
    permission_key  VARCHAR(100) NOT NULL
                    CHECK (permission_key ~ '^[a-z_]+\.[a-z_]+\.[a-z_*]+$'),  -- wildcard on action only
    resource_type   VARCHAR(100) NOT NULL,
    resource_id     VARCHAR(100) NOT NULL,
    scope_id        UUID REFERENCES scopes(id) ON DELETE CASCADE,  -- optional extra fence
    granted_by      VARCHAR(100) NOT NULL,
    granted_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    revoked_by      VARCHAR(100),
    CONSTRAINT uq_resource_grant
        UNIQUE (subject_id, permission_key, resource_type, resource_id)
);
CREATE INDEX idx_rg_subject  ON resource_grants (subject_id)                 WHERE revoked_at IS NULL;
CREATE INDEX idx_rg_resource ON resource_grants (resource_type, resource_id) WHERE revoked_at IS NULL;
```

**Rationale.** Assignments answer "what can S do *in this part of the org*". They cannot say "S may read *this one document*". Today that requires a policy with a `resource.id eq` condition — a global admin object per share, unusable as a user-level sharing primitive. `resource_grants` is that primitive: cheap rows, self-service creation (guarded, §10), independently revocable and expirable.

**Design choices**
- **Additional allow path, not an override.** Evaluated only when RBAC found no permission. Deny rules (checked earlier) still beat any grant — suspending a user kills their shares too, automatically.
- **Wildcard only on the action segment** (`doc.file.*` = every action on that file). Domain/resource wildcards on an instance grant would be meaningless.
- `scope_id` optional: if set, the grant only fires when the request's resource scope is inside it (e.g. a grant that dies if the document moves out of the workspace).

**Examples**

```jsonc
// Share one document, read-only, expires in 30 days
{ "subject_id": "carol-uuid", "permission_key": "doc.file.read",
  "resource_type": "document", "resource_id": "123",
  "granted_by": "alice-uuid", "expires_at": "2026-08-03T00:00:00Z" }

// Full control of one specific device handed to a field technician
{ "subject_id": "tech-7-uuid", "permission_key": "fleet.device.*",
  "resource_type": "device", "resource_id": "DEV-889" }
```

---

### 4.11 `services` (NEW, optional) — registry + manifest sync

Flag: `iam.features.service-registry` (default **off**; when off, the single shared API key behaves exactly as today).

```sql
CREATE TABLE services (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name          VARCHAR(100) NOT NULL UNIQUE,       -- 'invoice-service'
    display_name  VARCHAR(150) NOT NULL,
    owned_domains TEXT[]       NOT NULL DEFAULT '{}', -- permission namespaces it owns
    api_key_hash  VARCHAR(128) NOT NULL,              -- SHA-256 of the issued key
    active        BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_seen_at  TIMESTAMPTZ
);
```

**Two jobs:**

1. **Per-service PDP credentials.** Each consumer gets its own API key (only the SHA-256 stored). Key lookup authenticates the caller as `service:<name>` with `ROLE_INTERNAL`. Individually revocable; `last_seen_at` shows which services actually call.
2. **Permission manifest sync** — permissions live in the consumer's codebase and are pushed on deploy:

```
PUT /api/v1/services/invoice-service/permissions        (auth: invoice-service's key)
{
  "permissions": [
    { "key": "invoice.invoice.create",  "description": "Create invoice" },
    { "key": "invoice.invoice.approve", "description": "Approve invoice" }
  ],
  "deprecateMissing": true
}
→ 200 { "created": 1, "unchanged": 1, "deprecated": 1 }
```

Rules: idempotent upsert; a service may only touch domains in its `owned_domains`; keys missing from the manifest get `is_deprecated=true` (never deleted — immutability contract). Result: zero seed-file drift, permission changes ride the consumer's normal deploy.

---

### 4.12 `permission_groups` — UNCHANGED

Admin-UI convenience only ("Billing permissions", "User management"); **never consulted by the decision pipeline**. Kept because bulk role editing needs it and it costs nothing.

---

### 4.13 `authorization_audit` — UNCHANGED

DDL as in §3 (monthly range partitions, immutability RULEs, default partition, scheduled partition-ahead creation + retention drop).

**Example record**

```jsonc
{ "subject_id": "bob-uuid", "permission_key": "invoice.invoice.approve",
  "resource_type": "invoice", "resource_id": "INV-2026-0042", "scope_id": "s2",
  "decision": false, "reason": "explicit_deny",
  "context": { "denyRuleId": "…", "referenceId": "SEC-4711" },
  "request_id": "req-9f3a", "ip_address": "203.0.113.7",
  "timestamp": "2026-07-04T11:32:09Z" }
```

Reason vocabulary (machine-readable, stable): `explicit_deny`, `no_permission`, `scope_not_contained`, `scope_inactive`, `condition_failed`, `policy_deny`, `no_matching_allow_policy`, `resource_grant`, `allowed`.

---

### 4.14 `context_attributes` (NEW) — policy vocabulary registry

```sql
CREATE TABLE context_attributes (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        VARCHAR(50)  NOT NULL UNIQUE,       -- key under context.additional.*
    value_type  VARCHAR(20)  NOT NULL DEFAULT 'STRING'
                CHECK (value_type IN ('STRING','NUMBER','BOOLEAN','TIMESTAMP')),
    description TEXT,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_by  VARCHAR(100)
);
```

**Why.** The `context.additional.*` whitelist (which extra attributes callers may feed into policy evaluation — `mfa`, `department`, `region`, …) is hardcoded Java today. That whitelist is a *security control* (§8): without it callers invent attributes to steer policies. But its *content* is deployment vocabulary — a hospital wants `ward` and `shift`; a bank wants `desk` and `clearance`. Registry table = deployments extend vocabulary via API, code fork never required. Template seeds the current defaults (`mfa`, `department`, `region`, `environment`, `deviceType`, `channel`).

Rules: unregistered attribute in a request ⇒ resolves to null + warning (unchanged behavior); policy referencing an unregistered attribute ⇒ **rejected at policy-save time** (fail-fast — typo'd policies die at authoring, not silently at runtime). `value_type` powers save-time operator checking (`gt` on BOOLEAN ⇒ rejected). Cached 10 min, version-bumped on change.

---

## 5. The Decision Pipeline

```
POST /api/v1/authorize
{ subjectId, permission, resourceType?, resourceId?, scopeId?, context? }
  │  (scopeId omitted ⇒ ROOT — baseline apps never send it)
  ▼
⓪ SCOPE VALIDITY
   request.scope must exist and be active ⇒ else DENY "scope_inactive"
  ▼
① DENY RULES (L2)                                          cache 60 s / subject
   all active deny rules for subject (∪ subject's groups if groups on)
   → wildcard match on permission
   AND (rule.scope IS NULL OR closure-contains(rule.scope, request.scope))
   match ⇒ DENY "explicit_deny"
  ▼
② RBAC (L0) × SCOPE (L1)                                   cache 300 s / subject+scope
   active, unexpired assignments (subject ∪ groups) at ACTIVE scopes
   → keep those whose scope closure-contains request.scope
   → resolve role_hierarchy (BFS) → union of permission keys
   permission present ──── yes ──▶ ③        absent ──▶ ④
  ▼
③ ASSIGNMENT CONDITIONS (L3, if enabled)                   evaluated per request, uncached
   for each assignment that contributed the permission: evaluate conditions (§7)
   ≥1 assignment passes ⇒ role path holds ──▶ ⑤
   all fail ⇒ fall through to ④  (a resource grant may still allow —
              the grant path is independent of the role path)
  ▼
④ RESOURCE GRANTS (L5, if enabled)                         cache 60 s / subject
   unrevoked, unexpired grant matching (subject ∪ groups, permission or
   action-wildcard, resourceType, resourceId) AND optional grant.scope containment
   found ⇒ ⑤ (reason "resource_grant")
   not found ⇒ DENY — "no_permission" if ② found nothing,
                      "condition_failed" if ③ failed
  ▼
⑤ POLICIES (L4, if enabled)                                candidates cached 120 s
   candidates by targeting (permission / resourceType / scope containment)
   deny-only mode:      DENY candidates — any condition match ⇒ DENY "policy_deny"
   required-allow mode: + if ALLOW candidates exist, ≥1 must match
                          else DENY "no_matching_allow_policy"
  ▼
⑥ ALLOW  →  async audit write (dedicated AuditWriter bean, auditExecutor)

Disabled layer ⇒ step skipped (no query, no cache lookup).
Infra failure  ⇒ HTTP 503 AuthorizationServiceException — fail-closed, never a fake decision.
Every terminal outcome (⓪–⑥) ⇒ one immutable audit row.
```

Batch endpoint runs the same pipeline per item (max 50), sharing the per-subject caches across items.

---

## 6. Worked Decision Examples

Setup used by all examples — SaaS tree from §4.4, roles from §4.2, plus:

```
assignments:
  A1: alice  InvoiceManager  @ s1 (ROOT.ACME)                    conditions: {}
  A2: bob    InvoiceViewer   @ s2 (ROOT.ACME.FIN)                conditions: { "time_window": "09:00-17:00", "timezone": "UTC" }
deny_rules:
  D1: bob    invoice.invoice.approve  @ s2   reason "SoD"
resource_grants:
  G1: carol  doc.file.read  document/123   expires 2026-08-03
policies:
  P1: invoice-approve-limit (DENY approve if amount>10000 and no MFA)   [§4.9]
```

### Example A — plain RBAC allow (baseline, L0+L1 only)

```
Request:  { subjectId: "alice", permission: "invoice.invoice.approve",
            resourceType: "invoice", resourceId: "INV-7", scopeId: "s3" }   // Q3 Audit project
① no deny rules for alice                        → pass
② A1 active; closure(s1 ⊇ s3)? row (s1,s3) exists → in scope
   InvoiceManager ∪ inherited(InvoiceViewer) = {read, create, approve}
   "invoice.invoice.approve" present              → pass
③ A1.conditions = {}                              → pass (vacuously); role path holds
④ resource grants                                 → not consulted (role path already held)
⑤ policies disabled in this deployment           → skipped
⑥ ALLOW  { "allowed": true, "reason": "allowed" }
```

Grant at ORG level covered a PROJECT three levels down — that is L1 inheritance, one closure lookup.

### Example B — deny rule overrides a valid role (L2)

```
Request:  { subjectId: "bob", permission: "invoice.invoice.approve", scopeId: "s3" }
① D1 matches: permission equal, closure(s2 ⊇ s3) true
→ DENY { "allowed": false, "reason": "explicit_deny",
         "context": { "reference": "SoD" } }
```

Pipeline never reached RBAC — even if Bob had `InvoiceManager` at ROOT, the deny wins.

### Example C — ABAC condition failure (L3)

```
Request:  { subjectId: "bob", permission: "invoice.invoice.read", scopeId: "s2",
            context: { timestamp: "2026-07-04T22:30:00Z" } }
① D1 targets approve, not read                    → pass
② A2 in scope; InvoiceViewer grants read          → pass
③ A2.time_window "09:00-17:00" UTC vs 22:30      → FAIL; no other assignment grants read
④ resource grants: none for bob on this resource  → nothing rescues
→ DENY { "allowed": false, "reason": "condition_failed",
         "context": { "failedCondition": "time_window" } }
```

Same request at 14:00 UTC → ALLOW. And note the ④ fallback: had Bob held a resource grant
for this exact document, the failed time-window on his *role* would not block the *grant* —
the two allow paths are independent.

### Example D — policy deny on attributes (L4)

```
Request:  { subjectId: "alice", permission: "invoice.invoice.approve",
            resourceType: "invoice", resourceId: "INV-9", scopeId: "s2",
            context: { additional: { mfa: false },
                       resourceMetadata: { amount: 25000 } } }
①–③ pass (as Example A)
④ P1 is a candidate (permission+resourceType match)
   conditions: amount 25000 > 10000 ✓ AND NOT(mfa=true) ✓  → DENY policy matches
→ DENY { "allowed": false, "reason": "policy_deny", "context": { "policy": "invoice-approve-limit" } }
```

Same request with `mfa: true` → P1's condition fails → no DENY match → no ALLOW candidates exist → ALLOW.

### Example E — resource grant with no role at all (L5)

```
Request:  { subjectId: "carol", permission: "doc.file.read",
            resourceType: "document", resourceId: "123" }        // scopeId omitted ⇒ ROOT
① no deny rules                                   → pass
② carol has zero assignments → permission absent  → ④
④ G1 matches (subject, permission, type, id), unexpired → grant path
⑤ no candidate policies                           → neutral
⑥ ALLOW { "allowed": true, "reason": "resource_grant" }

Same request for resourceId "124" → ④ finds nothing → DENY "no_permission".
```

---

## 7. Assignment Condition Language (L3)

`assignments.conditions` is a flat JSONB object; **every present key must pass** (implicit AND). Evaluated per contributing assignment; one passing assignment is enough (§5-③). Unknown keys are rejected at assignment-creation time (fail-fast, no silent typo-conditions).

| Key | Value | Semantics | Example |
|---|---|---|---|
| `time_window` | `"HH:mm-HH:mm"` | Request time inside window. Wraparound supported (`"22:00-06:00"`); start == end means 24 h. | `"09:00-17:00"` |
| `timezone` | IANA zone | Zone for `time_window` (falls back to `context.timezone`, then UTC). | `"Asia/Kathmandu"` |
| `days_of_week` | array | Request day ∈ list (in `timezone`). | `["MON","TUE","WED","THU","FRI"]` |
| `ip_ranges` | array of CIDR | `context.ipAddress` inside any range (IPv4/IPv6). | `["203.0.113.0/24","2001:db8::/32"]` |
| `require_mfa` | `true` | `context.additional.mfa` (or `mfaVerified`) must be true. | step-up for admin roles |
| `ownership_required` | `true` | `subjectId` == resource owner (`resourceMetadata.ownerId` / `createdBy`). | "edit own drafts only" |
| `cannot_approve_own_created` | `true` | Separation of duties: DENY if subject **is** the owner. | four-eyes approval |
| `subject_match_fields` | array of field names | `subjectId` must equal each named resource/context field. | `["assigneeId"]` |

**Full example — contractor assignment:**

```json
{
  "time_window": "08:00-18:00",
  "timezone": "Europe/Berlin",
  "days_of_week": ["MON","TUE","WED","THU","FRI"],
  "ip_ranges": ["198.51.100.0/22"],
  "require_mfa": true
}
```

All five must hold at request time, on top of the role/scope match — otherwise this assignment contributes nothing (and if no other assignment grants the permission, the decision is `condition_failed`).

---

## 8. Policy Condition Language (L4)

`policies.conditions` is a **recursive condition tree**.

### Structure

```jsonc
// Boolean nodes — arbitrary nesting
{ "all": [ <node>, … ] }     // AND
{ "any": [ <node>, … ] }     // OR
{ "not": <node> }            // negation

// Leaf node
{ "field": "<path>", "op": "<operator>", "value": <json> }
```

### Operators (each with example)

| Op | Meaning | Example leaf |
|---|---|---|
| `eq` / `neq` | equality | `{"field":"context.additional.environment","op":"eq","value":"production"}` |
| `in` / `not_in` | set membership | `{"field":"subject","op":"in","value":["alice","carol"]}` |
| `contains` | string/array containment | `{"field":"resource.metadata.tags","op":"contains","value":"confidential"}` |
| `exists` | attribute present & non-null | `{"field":"context.additional.deviceType","op":"exists"}` |
| `gt` `gte` `lt` `lte` | numeric compare | `{"field":"resource.metadata.amount","op":"gt","value":10000}` |
| `regex` | pattern match | `{"field":"resource.id","op":"regex","value":"^INV-2026-"}` |
| `before` / `after` | temporal compare (ISO-8601, LocalDate, epoch-millis all parsed) | `{"field":"context.timestamp","op":"before","value":"2026-12-31T23:59:59Z"}` |

### Field resolution

| Prefix | Resolves to |
|---|---|
| `subject` | the requesting subject id |
| `permission` | the requested permission key |
| `resource.type` / `resource.id` / `resource.scopeId` | request resource fields |
| `resource.metadata.<k>` | caller-supplied resource metadata |
| `context.timestamp` / `ipAddress` / `userAgent` / `sessionId` / `requestId` | request context |
| `context.additional.<k>` | extra context — **registered keys only** (§4.14 `context_attributes` registry; template seeds `mfa`, `department`, `region`, `environment`, `deviceType`, `channel`). Unregistered keys resolve to null + warning — callers cannot invent attributes to steer policies. |

**`$` indirection:** a `value` starting with `$` is resolved as another field — field-to-field comparison:

```json
{ "field": "subject", "op": "eq", "value": "$resource.metadata.ownerId" }
```

= "subject must own the resource", expressed inside a policy.

### Complete policy example

"External-channel writes to confidential resources are denied outside the EU region":

```json
{
  "name": "confidential-eu-fence",
  "resource_type": "document",
  "effect": "DENY",
  "priority": 90,
  "conditions": {
    "all": [
      { "field": "resource.metadata.classification", "op": "eq", "value": "confidential" },
      { "field": "permission", "op": "regex", "value": "\\.(update|delete)$" },
      { "any": [
          { "field": "context.additional.channel", "op": "eq", "value": "external-api" },
          { "not": { "field": "context.additional.region", "op": "eq", "value": "eu" } }
      ]}
    ]
  }
}
```

---

## 9. Caching Design

All caches Redis, JSON-serialized, null-caching off.

| Cache | Key shape | TTL | Invalidation |
|---|---|---|---|
| Deny rules / subject | `authz:v{n}:deny:{subject}` | 60 s | TTL + version bump on deny CRUD |
| Permission set / subject+scope | `authz:v{n}:perm:{subject}:{scope}` | 300 s | version bump on assignment/role change for subject |
| Scope containment | `authz:v{n}:sc:{anc}:{desc}` | 3600 s | effectively immutable (no re-parenting) |
| Role → permissions | `authz:v{n}:roleperm:{role}` | 1800 s | version bump on role_permissions change |
| Policy candidates | `authz:v{n}:pol:{perm}:{rtype}` | 120 s | TTL + version bump on policy CRUD |
| Resource grants / subject | `authz:v{n}:rg:{subject}` | 60 s | TTL + version bump on grant CRUD |
| Group memberships / subject | `authz:v{n}:grp:{subject}` | 300 s | version bump on membership change |

**Versioned-prefix invalidation (replaces current `KEYS` scans):** `{n}` is a per-family counter in Redis. Invalidation = `INCR` the counter — O(1), no `KEYS`/`SCAN`, stale entries die by TTL. Per-subject counters for the subject-keyed families keep blast radius minimal.

**Version-bump triggers:** assignment create/revoke → subject counter; deny CRUD → subject counter; role_permissions change → role family; scope deactivate or **move** (§4.4) → global scope-containment family (rare, admin ops); group membership change → that member's counter. Group-*assignment* changes affect all members — rather than iterating members, the permission-set cache key incorporates the versions of the subject's groups (`authz:v{n}:perm:{subject}:{scope}:g{maxGroupVer}`), so one group-level `INCR` invalidates every member lazily.

**Revocation propagation guarantees (worst case, warm caches):** deny rule → ≤ 0 s (version bump, instant); assignment revoke → ≤ 0 s (bump); role permission removal → ≤ 0 s (bump); *nothing relies on TTL expiry alone* — TTLs are the backstop, bumps are the mechanism.

**Consistency token.** Every decision response carries `policyVersion` — the max of the version counters involved. A consumer that just performed a write ("revoke then re-check") may send `X-Min-Policy-Version: <n>`; if the cached entry predates it, IAM bypasses cache for that request. Zanzibar-zookie-lite: read-after-write consistency on demand, zero cost when unused.

**Integrity guards.**
- *Startup validator:* on boot, verify — no dangling `scope_id`/`role_id` references, system roles non-hollow (≥1 permission), closure row count consistent with scope count, exactly one root. Failures log at ERROR with a repair hint; `iam.integrity.fail-on-error: true` refuses to start (recommended for prod).
- *Nightly reconciliation job:* recompute closure from `parent_id` chains and ltree paths from codes; diff against stored — any drift (manual SQL, partial migration) is reported before it becomes mystery denies. Runs read-only; repair is an explicit admin action.

**Deliberate non-caches:** L3 condition evaluation (context-dependent by definition — the cached artifact is the permission set + attached conditions; conditions re-evaluate per request). This also fixes today's behavior where any conditional assignment disabled the permission cache entirely.

Latency budget (warm caches): deny lookup + perm-set lookup + closure lookup ≈ 3 Redis GETs → target p99 < 5 ms; alert threshold 50 ms (existing `authorization.check.duration` histogram).

---

## 10. Delegated Administration

Management APIs are themselves authorized — by IAM's own permissions (`platform.role.create`, `platform.assignment.create`, …) plus two structural rules enforced in `DelegatedManagementGuard` on every write:

| Rule | Meaning | Example |
|---|---|---|
| **Scope containment** | You can only create/revoke grants at or below a scope where you yourself hold a management assignment. | Org-admin of `ROOT.ACME` can assign roles inside Acme, never at `ROOT.GLOBEX` or `ROOT`. |
| **Permission ceiling** | You cannot hand out a permission you do not hold (through any of your roles, hierarchy-resolved, **including group-derived assignments** when groups are enabled) at that scope. | A delegated admin whose roles lack `invoice.invoice.approve` cannot create an assignment/grant conferring it — no privilege escalation by role-crafting. |

`SuperAdmin` (system role) bypasses both. Resource-grant creation applies the same two rules: grantor must hold the granted permission at a scope containing the resource.

**Worked example.** Dave holds `AccessAdmin` (can manage assignments) + `InvoiceViewer` at `s1 (ACME)`:
- ✅ assign `InvoiceViewer` to a colleague at `s2` — inside his scope, permission he holds
- ❌ assign `InvoiceManager` at `s2` — ceiling: he lacks `invoice.invoice.approve`/`create`
- ❌ assign anything at `s4 (GLOBEX)` — containment: outside his subtree

---

## 11. API Surface

### Runtime (PDP) — called by services

```
POST /api/v1/authorize                  single decision
POST /api/v1/authorize/batch            ≤ 50 decisions
POST /api/v1/authorize/explain          dry-run: full decision trace (which deny/assignment/
                                        condition/policy fired at each step), NO audit write,
                                        admin-only — the "why was this denied?" debugger    [NEW]
POST /api/v1/authorize/simulate         what-if: evaluate with hypothetical assignment set
                                        ({add:[…], remove:[…]}) → decision + effective-
                                        permission diff; nothing persisted, no audit;
                                        admin-only — answers "what happens if I grant X"
                                        BEFORE granting                                     [NEW]
POST /api/v1/filter-resources           list filtering: {subjectId, permission, resourceType,
                                        resourceIds[≤500]} → allowed subset. One permission-
                                        set evaluation + per-resource grant/policy pass —
                                        replaces N× /authorize loops on every list endpoint  [NEW]
POST /api/v1/effective-permissions      all permissions of subject at scope
                                        (+ ?asOf=<timestamp> — point-in-time reconstruction
                                        from revocation history, L0–L2)                     [NEW: asOf]
GET  /api/v1/access-list                reverse lookup: who holds permission P at scope S?
                                        (subjects via assignments+groups+grants; paginated;
                                        admin/audit-role only — powers "members with access"
                                        UIs and access reviews)                             [NEW]
POST /api/v1/break-glass                emergency time-boxed elevated assignment (§4.6)     [NEW, flag]
```

*`effective-permissions` and `access-list` reflect L0–L2 truth; L3/L4 verdicts are context-dependent and only decidable per request — responses carry `"conditional": true` markers on entries that have attached conditions/policies.*

**Request / response**

```jsonc
POST /api/v1/authorize
{ "subjectId": "alice-uuid",
  "permission": "invoice.invoice.approve",
  "resourceType": "invoice",              // optional
  "resourceId": "INV-7",                  // optional
  "scopeId": "s3-uuid",                   // optional, default ROOT
  "context": {                            // optional
     "ipAddress": "203.0.113.7",
     "additional": { "mfa": true },
     "resourceMetadata": { "amount": 25000, "ownerId": "bob-uuid" } } }

→ 200
{ "allowed": true,
  "reason": "allowed",                    // stable vocabulary, §4.13
  "evaluatedAt": "2026-07-04T11:32:09Z",
  "policyVersion": 4172,                  // consistency token, §9
  "context": { "matchedAssignment": "A1-uuid" } }   // diagnostic detail
```

### Event stream + client SDK (flag: `iam.features.event-stream`)

For fleets that want local decision caching with instant revocation:

```
Events published (Redis pub/sub `iam:events`, plus optional webhook fan-out):
  assignment.created|revoked      deny_rule.created|expired|removed
  role.permissions_changed        resource_grant.created|revoked
  scope.moved|deactivated         policy.changed
Payload: { type, subjectId?, roleId?, scopeId?, policyVersion, ts }   — ids only, no PII
```

Companion **client SDK** (Java first, TS second; thin, optional): verifies JWTs via JWKS, caches `/authorize` decisions locally keyed by `policyVersion`, subscribes to the event stream and drops affected entries on arrival, falls back to remote PDP on miss or stream outage (with the §9 TTLs as backstop). Converts the central-PDP latency boundary (§15) into: local-cache hit ≈ 0 network, revocation propagation ≈ event latency (ms). Consumers that skip the SDK lose nothing — plain REST remains the contract.

### User-facing

```
GET /api/authz/me/scopes                     scopes where I hold assignments (org switcher)
GET /api/authz/me/permissions?scopeId=…      my effective permissions at a scope
```

### Management (all guarded per §10)

```
Permissions        GET /api/v1/permissions[?domain=…] · GET /{id} · POST (batch)
Roles              GET /api/v1/roles[?orgType=…] · GET /{id} · POST · GET/{id}/permissions · PUT /{id}/permissions
Role hierarchy     GET /api/v1/role-hierarchy/parents/{id} · /children/{id} · POST · DELETE
Scopes             GET /api/v1/scopes[?type=…] · GET /{id} · GET /{id}/descendants · POST · GET /root · POST /{id}/move   [NEW: /root, /move]
Scope types        GET/POST/DELETE /api/v1/scope-types                                                     [NEW]
Assignments        GET /api/v1/assignments[?subjectId=…] · POST · DELETE /{id}?reason=…
Deny rules         GET /api/v1/deny-rules?subjectId=… · POST · DELETE /{id}
Policies           GET/POST /api/v1/policies · GET/PUT/DELETE /{id}
Resource grants    GET /api/v1/resource-grants?subjectId=…|resourceType=…&resourceId=… · POST · DELETE /{id}   [NEW, flag]
Groups             CRUD /api/v1/groups · POST/DELETE /{id}/members                                          [NEW, flag]
Services           CRUD /api/v1/services · PUT /{name}/permissions (manifest sync)                          [NEW, flag]
Permission groups  CRUD /api/v1/permission-groups (UI only)
Audit              GET /api/v1/audit/subject/{id} · /resource/{type}/{id} · /statistics/{id}
```

Removed: `assignments.effect` from create-assignment request. Everything else backward-compatible.

All list endpoints are paginated (`?page=&size=`, size ≤ 200, stable sort) — unbounded lists don't survive real deployments.

---

## 12. Configuration

```yaml
iam:
  features:                       # authz layer switches
    abac-conditions: false        # L3
    policies: false               # L4
    resource-grants: false        # L5
    groups: false                 # subject groups
    service-registry: false       # per-service keys + manifest sync
    strict-scope-types: auto      # auto = strict iff scope_types has rows | strict | free-form
    break-glass: false            # emergency time-boxed elevation (§4.6)
    event-stream: false           # authz event publishing for SDK/local caches (§11)

  authorization:
    policy-mode: deny-only        # deny-only | required-allow (§4.9 — sharp edge documented there)
    cache:
      deny-rules-ttl: 60
      permissions-ttl: 300
      scope-ttl: 3600
      role-ttl: 1800
      policy-ttl: 120
      resource-grants-ttl: 60
      groups-ttl: 300
    fail-mode: closed             # infra error ⇒ 503 (closed) | best-effort continue (open)
    audit:
      async: true
      batch-size: 100
    performance:
      max-authorization-time-ms: 50

  integrity:
    fail-on-error: true           # startup validator refuses boot on broken invariants (§9)
    reconciliation-cron: "0 0 3 * * *"   # nightly closure/ltree drift check; empty = off
```

Every default sits on the **simple** side; scaling up = flipping flags, never forking code.

---

## 13. Migration Diff Summary (Current → Proposed)

| Object | Action |
|---|---|
| `scope_types` | **CREATE** (empty by default → free-form mode) |
| `scopes.type` CHECK list | **DROP** constraint |
| `scopes` GLOBAL-specific CHECKs | **REPLACE** with `chk_scope_root_depth` + single-root partial unique index |
| `scopes.code` | **ALTER** to NOT NULL (backfill from existing code/name), path segments rebuilt from code; uniqueness relaxed global → sibling (`UNIQUE(parent_id, code)`) |
| `validate_scope_depth()` + trigger | **DROP** |
| GLOBAL seed scope | **KEEP** row (fixed UUID), re-labeled `code='ROOT'`, `type='ROOT'` |
| `assignments.effect` | **DROP** column (verify no DENY rows exist first; migrate any found to `deny_rules` with reason `'migrated from DENY assignment'`) |
| `permissions` key format CHECKs | **RELAX** — segments admit digits (`[a-z][a-z0-9_]*`) and key depth becomes variable 3–6 segments (`domain.<resource-path>.action`); `deny_rules` wildcards gain trailing `**` (any remaining depth) |
| `deny_rules.subject_type` | **ADD** column (DEFAULT 'USER') — enables group-level denies |
| `subject_id` / `resource_id` columns | **WIDEN** to VARCHAR(255) across assignments, deny_rules, resource_grants, authorization_audit — URN-style external ids don't fit 100 |
| Scope move | **ADD** managed `POST /scopes/{id}/move` (closure + path rebuild in one transaction); direct `parent_id` UPDATE stays trigger-blocked |
| `roles.owner_scope_id` | **ADD** column (NULL = global); name uniqueness becomes `UNIQUE(owner_scope_id, name)` — tenant-scoped roles (§4.2) |
| `assignments.origin` | **ADD** column (STANDARD / BREAK_GLASS / MIGRATION) — §4.6 |
| `policies.enforcement_mode` | **ADD** column (ENFORCE / SHADOW) — §4.9, UI_PLAN §5 |
| `resource_grants` | **CREATE** |
| `subject_groups`, `subject_group_members` | **CREATE** |
| `services` | **CREATE** |
| `context_attributes` | **CREATE** + seed current whitelist defaults (§4.14) |
| `role_permissions`, `role_hierarchy`, `scope_closure`, `permission_groups` | **UNCHANGED** |
| Closure/parent-change/auto-deactivate triggers, `scope_contains()` | **UNCHANGED** |

Code-side: `ScopeService` whitelist → registry validation; assignment DTOs lose `effect`; pipeline gains steps ②b (grants) and group resolution; cache layer moves to versioned prefixes.

---

## 14. Example Deployment Profiles

### Profile 1 — Simple app (baseline: L0–L2)

Everything default. Integrator does:

```
1. PUT  permissions        (or plain POST /api/v1/permissions at setup)
2. POST /api/v1/roles      { name: "Admin",  permissionIds: [...] }
                           { name: "Member", permissionIds: [...] }
3. POST /api/v1/assignments { subjectId: <user>, roleId: <Admin> }   // scopeId omitted → ROOT
4. POST /api/v1/authorize   from the backend on each protected action
```

Never sees: scopes, conditions, policies, grants. Deny rules available as the ban hammer.

### Profile 2 — Multi-tenant SaaS (L0–L3 + grants)

```
scope_types: ORG > WORKSPACE > PROJECT        (strict mode kicks in automatically)
scopes:      one ORG node per customer under ROOT
flags:       abac-conditions=true, resource-grants=true
usage:       customer admins get AccessAdmin @ their ORG (delegation, §10)
             document sharing via resource_grants
             contractor access via assignment expiry + time_window/ip conditions
```

Tenant isolation = scope containment: a grant inside `ROOT.ACME` can never authorize anything under `ROOT.GLOBEX` — the closure table has no such row.

### Profile 3 — Microservice fleet (all layers)

```
flags:       service-registry=true, policies=true, groups=true (+ L3, L5 as needed)
services:    each microservice registered, owns its permission domains,
             pushes manifest on deploy, holds its own PDP API key
scope tree:  whatever the business is — regions, business units, or one ROOT
policies:    global guard-rails (amount limits, environment fences, SoD)
audit:       partition-ahead + retention jobs on; Prometheus histogram on decision latency
```

---

## 15. Architect Review — Resolved Findings & Known Boundaries

Adversarial self-review performed 2026-07-04. Findings and their resolutions (all applied above):

| # | Finding | Resolution |
|---|---------|-----------|
| D1 | `scopes.code` global uniqueness made tenant-chosen codes collide across subtrees (Acme's `FIN` blocks Globex's `FIN`) | Sibling-unique `UNIQUE(parent_id, code)` — §4.4 |
| D2 | Pipeline starved resource grants: role found + all conditions failed ⇒ terminal deny, valid grant never consulted | Condition failure falls through to the grant step; role path and grant path are independent — §5 ③→④ |
| E1 | Policy-combining cliff: one targeted ALLOW policy silently flipped its target to default-deny | Explicit `policy-mode`: `deny-only` default (policies can only restrict), `required-allow` opt-in with the edge documented — §4.9 |
| E2 | `scopes.active` had no defined pipeline semantics (deactivated scope still authorized) | Step ⓪ `scope_inactive` + assignments at inactive scopes excluded — §5 |
| F2 | Re-parenting ban too harsh for reorganizing enterprises | Managed `POST /scopes/{id}/move` with transactional closure/path rebuild — §4.4 |
| G1 | No "why denied?" debugging tool | `POST /authorize/explain` dry-run trace — §11 |
| G2 | No reverse lookup (who has P at S?) for access reviews / UIs | `GET /api/v1/access-list`, paginated — §11 |
| G3 | Group-assignment changes needed per-member cache invalidation | Group version folded into the permission-set cache key — §9 |
| G4 | Permission segments rejected digits; ID columns too narrow for URNs | Regex relaxed, VARCHAR(255) widening — §4.1, §13 |

**Known boundaries — deliberate non-goals, with the supported pattern:**

| Boundary | Status | Pattern for deployments that need it |
|---|---|---|
| **Multi-dimensional scoping** (matrix orgs: resource in "Nepal" AND "Payments BU") | One tree, one scope per request — by design. Two trees would double closure complexity and make containment ambiguous. | Primary dimension = scope tree; secondary dimension = `resource.metadata` attribute + policies (`region eq nepal`). Works today; first-class multi-scope is a possible v2 if real demand appears. |
| **Resource hierarchy inheritance** (folder→file: "viewer of folder sees files") | Grants are flat per-instance; no Zanzibar relation graph. | Hierarchical containers map to *scopes* (folder = scope, grant at folder scope covers files via L1), or the consuming app resolves the parent before calling `/authorize`. |
| **PDP centralization latency** for cross-region consumers | Largely addressed: event stream + client SDK (§11) give local-cache hits with ms-level revocation propagation. | Claims/hybrid mode for coarse checks; `/filter-resources` and batch for list workloads; SDK for hot paths; plain REST always available. |
| **Point-in-time consistency tokens** (Zanzibar "zookies") | Not provided; staleness bounded by §9 guarantees (bumps instant, TTLs backstop). | Deployments needing read-after-write authorization consistency call `/authorize` with cache-bypass header (admin/test only). |

---

*End of authorization design.*
