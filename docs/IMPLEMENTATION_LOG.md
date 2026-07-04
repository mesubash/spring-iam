# Implementation Log

> Running log of implementation work. Newest entries at the bottom of each phase.
> Spec references: `AUTHZ_DESIGN.md`, `AUTHN_DESIGN.md`, `TEMPLATE_REDESIGN_PROPOSAL.md`, `UI_PLAN.md`.

---

## Phase 6 — Claims modes, OAuth gating, feed/token/webhook polish

| Date | Block | What was done | Commit |
|------|-------|---------------|--------|
| 2026-07-04 | claims | `app.jwt.claims-mode` (minimal/roles/permissions) in JwtTokenProvider; permissions mode adds effective perms at ROOT + scope claim (optional AuthzQueryService dep) | Phase 6 commit |
| 2026-07-04 | oauth | OAuth2 now truly flag-gated: 4 beans + OAuthController `@ConditionalOnProperty(iam.features.oauth2)`, SecurityConfig wires oauth2Login only when present, static google registration removed from yml (supply via env when enabling). App boots clean with zero OAuth props — dummy test props removed | Phase 6 commit |
| 2026-07-04 | polish | `policyVersion` consistency token on authorize responses; revocation feed `GET /token/revocations?since=` (flag); nightly `ScopeReconciliationJob` (closure/self-row drift, cron-disabled default); break-glass fire-and-forget webhook (JDK HttpClient); rate-limiter explicit `fail-mode` (open/closed). Suite 45/45 | Phase 6 commit |

## Phase 5 — PDP extras, AuthN extras, integrity, registry

| Date | Block | What was done | Commit |
|------|-------|---------------|--------|
| 2026-07-04 | PDP | `POST /authorize/explain` (dry-run pipeline trace, no audit), `POST /authorize/simulate` (hypothetical assignment set), `POST /filter-resources` (≤500 ids → allowed subset), `GET /access-list` (reverse lookup via closure), `?asOf=` on effective-permissions (assignment-history reconstruction). `fetchUserPermissions` refactored into reusable `computePermissions`; `decideNoAudit` shared by filter/simulate | Phase 5 commit |
| 2026-07-04 | AuthN | Client ip/ua threaded into password-login sessions; email-change flow (`change-email` + `verify-email-change`, re-auth + verify-new + notify, EMAIL_CHANGE token type); introspection endpoint (flag, INTERNAL-only); break-glass endpoint (flag, `AssignmentService.createBreakGlass`, ≤4h cap, origin BREAK_GLASS). SecurityEventType enum synced with V1 (SESSION_EVICTED/REUSE_DETECTED/OAUTH_LINKED/EMAIL_CHANGED) | Phase 5 commit |
| 2026-07-04 | Registry/guards | `context_attributes` entity+repo+CRUD; PolicyService save-time validation rejects unregistered `context.additional.*` fields; PolicyEvaluator runtime whitelist widened by the registry (60s cache, optional dep so unit tests keep no-arg ctor). Startup `IntegrityValidator` (one root, no dangling refs, non-hollow system roles, closure ≥ scope count; `iam.integrity.fail-on-error` refuses boot). Feature flags + meta extended (break-glass, introspection) | Phase 5 commit |
| 2026-07-04 | tests | Decision suite → 32 (explain trace, filter-resources). Suite 45/45. **Backend complete except pagination** (deferred: broad list pagination conflicts with the array UI contract; add as opt-in later) | Phase 5 commit |

## Phase 4 — Hardening

| Date | Block | What was done | Commit |
|------|-------|---------------|--------|
| 2026-07-04 | all | Audit writes moved to dedicated `AuditWriter` bean — `@Async` now actually fires (self-invocation made it a silent no-op on the hot path). CacheService rewritten to versioned key prefixes: invalidation = one INCR, zero `KEYS`/`SCAN`; per-subject counters + global epoch/role/scope/policy counters; bug found & fixed — cached `PolicySnapshot` dropped `enforcement_mode`, turning SHADOW policies into ENFORCE on cache hits. `getEffectivePermissions` policy loop now evaluates against one cached all-active fetch. `GlobalExceptionHandler` no longer returns raw DB messages (logs + generic); dead scope-depth mapping removed. One-time tokens stored SHA-256-hashed, single-purpose slim `TokenService`, in-memory Redis fallback deleted (fail loud). `NotificationPort` + dev log adapter wired into register/reset/resend/reactivation — all notification TODOs gone. Suite 42/42 green | Phase 4 commit |

## Phase 3 — Feature flags & fleet

| Date | Block | What was done | Commit |
|------|-------|---------------|--------|
| 2026-07-04 | all | `iam.features.*` flags (`FeatureFlags` + `GET /api/v1/meta/features`; disabled feature endpoints 404). Resource grants live: entity/repo, pipeline lookup (action-wildcard matching, optional scope fence, independent of role-condition failures), CRUD w/ ceiling guard (wildcard grants = SuperAdmin only, revoke = grantor or SuperAdmin). Subject groups live: entities/repos, pipeline resolves subject ∪ groups for deny rules + assignments (perm cache bypassed when groups on — invalidation counters don't cover groups yet), SuperAdmin CRUD. Service registry live: `services` entity, per-service API keys (SHA-256 lookup in ApiKeyAuthFilter → principal `service:<name>`, last_seen stamped), registration returns key once, manifest sync (`PUT /api/v1/services/{name}/permissions` — owned-domain enforcement, idempotent upsert, deprecate-missing). Decision suite → 29 tests (grants/groups paths). Suite 42/42. Carried: grants/groups Redis caching, group-aware invalidation counters | Phase 3 commit |

## Phase 2 — AuthN token core

| Date | Block | What was done | Commit |
|------|-------|---------------|--------|
| 2026-07-04 | A1 | Schema (V1 rewrite): `sessions` + rotation-chain `refresh_tokens` (SHA-256 at rest) + `signing_keys` | Phase 2 commit |
| 2026-07-04 | A2 | RS256 everywhere: SigningKeyService (bootstrap RSA-2048 keygen, AES-GCM private-key encryption when IAM_KEY_ENCRYPTION_KEY set, rotation w/ 1h verify grace), JwtTokenProvider rewritten (kid header, jti/sid/typ/email_verified/roles claims, kid-resolving parser), `GET /.well-known/jwks.json` + `POST /api/v1/keys/rotate` | Phase 2 commit |
| 2026-07-04 | A3 | Sessions: multi-device (cap 10, LRU evict), opaque refresh + rotation + 60s retry-grace (encrypted successor cache) + reuse⇒session-death (`noRollbackFor` so revocation survives the throw), jti/sid blacklist service (fail-closed), sessions API (list/revoke device). AuthServiceImpl login/refresh/logout/logout-all rewired; dual-store blacklist + refresh-as-JWT + `validateAndRefreshToken` deleted | Phase 2 commit |
| 2026-07-04 | A4 | OAuth: single-use 60s exchange code replaces `?token=` redirect (`POST /api/auth/oauth/exchange`), redirect allowlist enforced (empty ⇒ frontend origin only), linking matrix (auto-link only on provider-verified email). Cookie: `__Host-Refresh`, secure default true, dedicated IAM_COOKIE_KEY (legacy fallback warns) | Phase 2 commit |
| 2026-07-04 | A5 | Session lifecycle integration tests (rotate/grace-retry/reuse/logout-all/cap) against real Postgres+Redis. Suite 37/37. **Phase 2 core complete.** Carried: NotificationPort (emails still logged), introspection + revocation-feed endpoints, claims modes config, email-change flow, OTT hashing + in-memory fallback removal in RedisTokenService, client ip/ua into password-login sessions | Phase 2 commit |

## Phase 1 — AuthZ schema & engine

**Plan (blocks):**
- B0 — decision-engine test suite against CURRENT engine (green baseline before any change)
- B1 — Flyway migration restructure (V1 core / V2 hierarchy / V3 advanced / V4 platform seed / V5 example seed); delete `db/schama.sql`
- B2 — schema + entity changes (scope_types, scopes code/path, assignments effect→origin, roles.owner_scope_id, deny_rules.subject_type, policies.enforcement_mode, permissions variable-depth; new DDL-only tables: resource_grants, subject_groups, services, context_attributes)
- B3 — engine changes (pipeline reorder w/ grant fallback + scope_inactive, policy modes + shadow, scope registry validation, /scopes/root, /scopes/{id}/move)
- B4 — API & delegation updates (DTO changes, tenant-role visibility, guard ceiling, pagination)
- B5 — verify (full suite, Testcontainers migration test, worked examples A–E as tests)

| Date | Block | What was done | Commit |
|------|-------|---------------|--------|
| 2026-07-04 | — | Log created; Phase 1 started | — |
| 2026-07-04 | pre | Package rename `com.hgn` → `io.github.mesubash` (dirs moved, 165 files rewritten, pom groupId, docs) | rename commit |
| 2026-07-04 | B0 | Decision-engine baseline suite: 19 unit tests pinning current pipeline (L0–L4 + failure modes), all green | B0 commit |
| 2026-07-04 | B3 | Engine: step-0 scope validity (cached active flag), resource-grant fallback seam (flag, default off — grant path independent of failed role conditions), policy modes (`deny-only` default / `required-allow`), SHADOW policy evaluation → audit `shadowResults`, `**` wildcard matching. ScopeService rewritten: registry/free-form validation via scope_types, path from code, `GET /scopes/root`, transactional `POST /scopes/{id}/move` (closure + ltree + depth rebuild under GUC-gated trigger). Dev-cruft comments removed. Suite 33/33 green | B3 commit |
| 2026-07-04 | B4 | Tenant roles wired through API: CreateRoleRequest.ownerScopeId, per-owner uniqueness, guard check on owning subtree, tenant role only assignable inside its subtree. Deny rules: subjectType passthrough, wildcard grammar updated (digits + trailing `**`). Layer-label comments stripped from code/migrations. 33/33 green. Deferred to Phase 4 (logged): pagination, machine-readable reason codes, role listing filtered by scope | B4 commit |
| 2026-07-04 | B5 | Scope-move integration test against real Postgres (subtree closure rebuild, ltree path rewrite, depth delta, GUC trigger, cycle rejection). Suite 34/34 green. **Phase 1 complete.** Carried to later phases: resource-grant lookup implementation (flag seam ready), pagination, machine-readable reason codes, scope-filtered role listing, `iam.features.*` endpoint gating | B5 commit |
| 2026-07-04 | B1+B2 | Migrations rewritten V1 core / V2 hierarchy / V3 advanced / V4 platform seed / V5 example (deleted old V1–V3 + schama.sql). Target schema baked in: scope_types, flexible scopes (code sibling-unique, single ROOT), assignments effect→origin, roles.owner_scope_id, deny_rules.subject_type + ** wildcards, policies.enforcement_mode, variable-depth permission keys, new tables (resource_grants, subject_groups, services, context_attributes). Profile stack deleted (5 files + table + touches). Entities aligned. Compose images → alpine. Full suite 28/28 green incl. fresh-DB Flyway run | B1+B2 commit |
