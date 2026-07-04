# Implementation Log

> Running log of implementation work. Newest entries at the bottom of each phase.
> Spec references: `AUTHZ_DESIGN.md`, `AUTHN_DESIGN.md`, `TEMPLATE_REDESIGN_PROPOSAL.md`, `UI_PLAN.md`.

---

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
| 2026-07-04 | B1+B2 | Migrations rewritten V1 core / V2 hierarchy / V3 advanced / V4 platform seed / V5 example (deleted old V1–V3 + schama.sql). Target schema baked in: scope_types, flexible scopes (code sibling-unique, single ROOT), assignments effect→origin, roles.owner_scope_id, deny_rules.subject_type + ** wildcards, policies.enforcement_mode, variable-depth permission keys, new tables (resource_grants, subject_groups, services, context_attributes). Profile stack deleted (5 files + table + touches). Entities aligned. Compose images → alpine. Full suite 28/28 green incl. fresh-DB Flyway run | B1+B2 commit |
