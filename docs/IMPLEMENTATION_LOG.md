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
