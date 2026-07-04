# UI Plan — Admin Console, Frontend SDK & Sample Applications

> **Status:** PLAN — approved direction, implementation later (after backend Phase 3 API freeze)
> **Date:** 2026-07-04
> Companions: `AUTHZ_DESIGN.md` (engine), `ARCHITECTURE.md` (overview), `FUTURE_ENHANCEMENTS.md` (deferred items)

---

## 1. The Three Artifacts

One phase, three deliverables, strictly separated:

| Artifact | What | Ships as | Audience |
|---|---|---|---|
| **iam-console** | one app for admins AND users | **standalone** React SPA in `web/` — own Docker image (nginx), deployed independently of the Java service | platform admins, tenant admins, end users |
| **Frontend SDK** (`authz-sdk`) | permission-driven-UI toolkit | published TS package (framework-agnostic core + React bindings) | consumer-app developers |
| **Sample pair** | reference consumer app: `sample-service` + `sample-ui` | `examples/` folder, own containers | template adopters + CI e2e |

Rule of thumb: **SDK is product, console is dogfood, sample is documentation-that-runs.**

**Deployment boundary (decided):** the console is a pure black-box REST consumer.
It is **not** served from the Spring Boot jar and is **not** part of the Maven /
Java Docker build (`.dockerignore` excludes `web/`). It builds and ships on its
own image and talks to IAM only via `VITE_API_BASE_URL` / runtime `API_BASE_URL`.
The root `docker-compose.yml` (Postgres + Redis + IAM) does not include it;
`web/docker-compose.web.yml` runs the frontend alone.

---

## 2. Core Principles (apply to all three)

1. **Permission-driven rendering, never role-driven.** No `if (role === 'ADMIN')` anywhere — nav, routes, pages, buttons all derive from permission keys. Roles stay invisible to every frontend.
2. **UI gating is UX, not security.** Server re-checks every call. Frontend checks only decide what to *show*.
3. **Button ↔ permission key 1:1.** The key a button checks is the key the backend endpoint checks. No frontend-invented names, no mapping layers.
4. **Graceful 403 is a normal flow**, not an error page: entries marked `conditional: true` (time-window / policy-dependent) render enabled; a 403 shows a friendly "not available right now" and triggers a permission-set refetch (self-heal).
5. **Black-box consumption.** Every UI talks to IAM exclusively through the public HTTP APIs with the user's own bearer token. No privileged endpoints, no internal imports, no shared DB.

---

## 3. Admin Console

### 3.1 Placement & auth

- **Standalone** React app in `web/` (name `iam-console`), served by its own nginx image — NOT bundled into the jar, NOT in the Java build. Runtime API base URL via `API_BASE_URL` (nginx entrypoint writes `env-config.js`).
- Logs in through IAM's own AuthN (`/api/auth/login`, OAuth if enabled); operates with the operator's bearer token and IAM's own `platform.*` permissions.
- **Dogfooding contract:** the console is the first consumer of the SDK and of permission-driven rendering. Every screen and button is gated via `<Can permission="platform.…">`. If the pattern is awkward here, we fix the pattern — before adopters feel it.
- Console discovers enabled features via `GET /api/v1/meta/features` (small new endpoint — returns active `iam.features.*` flags) and hides panels for disabled ones.

### 3.2 Screens (priority order)

| # | Screen | Backing APIs | Notes |
|---|---|---|---|
| 1 | **Assignments & access view** | `/assignments`, `/access-list`, `/effective-permissions` | "who has what, where" — the daily-driver screen; grant/revoke with reason |
| 2 | **Scope tree browser** | `/scopes`, `/scopes/{id}/descendants`, `/scopes/{id}/move`, `/scope-types` | tree view; drag-to-move behind confirmation (move is heavy); create with type validation |
| 3 | **Role editor** | `/roles`, `/roles/{id}/permissions`, `/role-hierarchy`, `/permission-groups` | tenant-scoped visibility built in (`owner_scope_id`); permission picker grouped by permission_groups |
| 4 | **Deny hammer** | `/deny-rules` | deliberately prominent; reason + reference forced; expiry presets (24h / 7d / permanent) |
| 5 | **Explain debugger** | `/authorize/explain`, `/authorize/simulate` | the killer screen: paste/build a request, watch pipeline steps ⓪–⑥ light up with the firing rule highlighted; simulate tab for what-if grants |
| 6 | **Policy studio** | `/policies`, `/context-attributes` | see §5 — templates, builder, shadow dashboard |
| 7 | **Audit browser** | `/audit/*` | filter by subject/resource/decision/time; decision drill-down links to explain |
| 8 | **Break-glass console** | `/break-glass`, audit | active break-glass grants ticker + post-incident report view |
| 9 | Housekeeping | `/services`, `/groups`, `/permissions`, keys | registry, groups, permission catalog, key rotation |

### 3.3 Backend prerequisites created by this plan

| Item | Where specified |
|---|---|
| `GET /api/v1/meta/features` (flag discovery) | this doc |
| `policies.enforcement_mode` ENFORCE/SHADOW + `shadowResults` in audit | AUTHZ_DESIGN §4.9 (added) |
| everything else (explain, simulate, access-list, move, context-attributes) | already in AUTHZ_DESIGN |

---

## 4. Frontend SDK (`authz-sdk`)

Small by contract (~a few hundred lines, zero runtime deps):

**Core (framework-agnostic TS):**
- permission-set store: bootstrap from `GET /api/authz/me/permissions?scopeId=…`, refetch on scope switch / any 403 / TTL (default 5 min)
- `can(key)`, `canAny([...])`, `canAll([...])`, `conditional(key)` lookups
- scope switcher backed by `GET /api/authz/me/scopes`
- `filterResources()` helper wrapping `POST /api/v1/filter-resources` for list pages
- fetch wrapper: attaches token, intercepts 403 → self-heal refetch + typed `NotPermittedError`

**React bindings:**
- `<AuthzProvider>` (token source + scope), `useAuthz()`, `useScopes()`
- `<Can permission="…">`, `<Can permission="…" fallback="disabled">`, route-guard helper for TanStack Router

Vue/Angular bindings: not now — core is framework-free precisely so they can be added without rewrite (future-doc territory).

---

## 5. Policy Authoring UX (Policy Studio)

Three layers, because raw JSON condition trees are unusable for humans:

- **Layer A — Templates.** Parameterized recipes; admin fills 2–3 typed fields, never sees JSON: *Amount limit* · *Time fence* · *IP fence* · *Environment fence* · *Separation of duties* · *Owner only*. Hardcoded in console v1; `policy_templates` table only if deployments demand custom recipes (future doc).
- **Layer B — Visual builder.** all/any/not blocks + leaf rows of three dropdowns: field (fed by `context_attributes` registry + resource-metadata keys), operator (filtered by the attribute's `value_type`), typed value input. Live JSON preview pane. Save hits the §4.14 fail-fast validation — unknown fields and type-mismatched operators rejected at authoring time.
- **Layer C — Shadow mode.** New policies default to `enforcement_mode: SHADOW`: they run in the pipeline, their would-be verdicts land in audit (`shadowResults`), decisions are unaffected. Studio dashboard: "this policy would have denied 14 requests this week — inspect them", one click to promote to ENFORCE. Test-before-save panel embeds `/authorize/explain` + `/simulate`.

(Optional LLM natural-language → draft-policy assistant = F11 in FUTURE_ENHANCEMENTS; console must never require it.)

---

## 6. Sample Pair (`examples/`)

```
examples/
  sample-service/              Spring Boot 4 consumer — own pom, NOT a module of IAM's build
  sample-ui/                   React app consuming authz-sdk
  docker-compose.example.yml   iam + postgres + redis + sample pair; one command up
```

**sample-service** (one domain — invoices; ~10 classes hard cap):
- registers via service-registry, pushes permission manifest on startup
- verifies user JWTs locally via `/.well-known/jwks.json` — no shared secrets
- hybrid enforcement: claims for reads, `POST /authorize` for approve, `/filter-resources` for lists

**sample-ui**: login → scope switcher → invoice list (filtered) → create/approve buttons gated by `<Can>` → graceful-403 on the shadow/time-window case.

**Demo seed** (replaces V3-example philosophy): two users (manager, clerk), two roles, five permissions, one deny rule, one SHADOW policy — every layer visibly fires in a 5-minute walkthrough.

**Black-box enforcement (CI-checked):**
- sample never imports `io.github.mesubash.iam` (grep gate in CI)
- own build files, no parent-pom inheritance from IAM
- talks HTTP only; own container; only shared artifact = published `authz-sdk`

**Scope discipline:** sample demonstrates the golden path ONLY. Groups, break-glass, ReBAC, event stream get doc snippets, not sample code.

---

## 7. Stack (decided)

| Layer | Choice |
|---|---|
| UI framework | React 19 + TypeScript, Vite build |
| Server state / routing / tables | TanStack Query · TanStack Router (typed, permission-guarded routes) · TanStack Table |
| Styling / components | Tailwind v4 + shadcn/ui (copied-in components — no versioned UI-lib lock-in) |
| Forms | react-hook-form + zod |
| API client | generated from springdoc OpenAPI (`orval` / `openapi-typescript`) — DTO drift dies at compile time |
| Sample backend | Spring Boot 4 / Java 21 (same as IAM — adopters are Spring shops; polyglot proof lives in Postman/curl docs) |
| e2e | Playwright — UI flows AND API-level negative security tests (tampered JWT → 401, revoked assignment → 403, expired API key → rejected) in one tool |
| Workspace | pnpm workspaces (`admin-ui`, `sample-ui`, `authz-sdk`), Node 22 LTS |

Explicit non-choices: no Next.js (no SSR need), no Redux (Query covers it), no CRA (dead), no versioned component library (3-year buildability).

---

## 8. Execution Order & Gates

The backend (AuthN + AuthZ) is complete; the UI track is the remaining work. Phases:

| Phase | Deliverable | Gate to start |
|---|---|---|
| **5a** | `authz-sdk` core + React bindings + OpenAPI codegen pipeline | backend Phase 3 done (API freeze) |
| **5b** | Admin Console screens 1–5 (assignments, scopes, roles, deny, explain) | 5a |
| **5c** | Policy Studio (templates → builder → shadow dashboard) | 5b + shadow mode implemented backend-side |
| **6** | Sample pair + demo seed + Playwright e2e wired into CI | 5a (runs parallel to 5b/5c) |
| — | Console screens 7–9, polish, docs walkthrough | after 6 |

Pre-Phase-1 (backend) actions already extracted from this plan:
1. `policies.enforcement_mode` column → in AUTHZ_DESIGN schema (done).
2. `GET /api/v1/meta/features` → trivial endpoint, lands with the feature-flag wiring in backend Phase 3.

**Definition of done for the whole UI track:** `git clone && docker compose -f examples/docker-compose.example.yml up` → working login, working sample app with permission-gated buttons, working admin console — in under 5 minutes, with Playwright green in CI.

---

*End of UI plan.*
