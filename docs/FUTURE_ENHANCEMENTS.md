# Future Enhancements — Deferred by Design

> Companion to `AUTHZ_DESIGN.md` (authorization) and `ARCHITECTURE.md` (overview).
> Everything here was consciously **deferred**, not forgotten. Each entry records: what it is, why it waits, a design sketch so future-us doesn't restart from zero, and the **trigger** — the observable condition that says "build it now."
> Date: 2026-07-04

---

## How to use this document

Before adding anything to the core design, check it against the trigger column. Building ahead of the trigger is speculation; building at the trigger is engineering. Entries are ordered by how likely their trigger is to fire.

| # | Enhancement | Effort | Trigger |
|---|-------------|--------|---------|
| F1 | Signed decision tokens | M | Service chains re-checking the same decision ≥2× per request |
| F2 | Dual-control (four-eyes) approvals | M | First enterprise security review that demands it |
| F3 | Permission implications graph | M | Roles routinely carry 30+ permissions in triplets (read/write/admin) |
| F4 | Admin UI module | L | Second real adopter of the template |
| F5 | OpenTelemetry tracing | S | First production deployment (do during implementation) |
| F6 | Anomaly signals | S | First security-operations consumer |
| F7 | Multi-dimensional scoping | XL | A deployment needs matrix-org enforcement that metadata+policies can't express |
| F8 | Resource hierarchy inheritance (Zanzibar-lite) | XL | Per-resource sharing at >10⁶ grants or nested-container semantics as core product |
| F9 | Access reviews / attestation campaigns | M | Compliance regime requiring periodic re-certification (SOX/ISO 27001) |
| F10 | Native MFA (TOTP/WebAuthn) in AuthN | M | Deployments without an upstream IdP that can assert MFA |
| F11 | LLM policy assistant (NL → draft policy) | S | Policy Studio shipped and template/builder still leaves authoring friction |

---

## F1 — Signed decision tokens

**What.** `/authorize` optionally returns a short-lived JWT (~30 s, signed with the platform key) attesting `{subject, permission, resource, decision, policyVersion}`. Service A calls B and passes the token; B verifies via JWKS and trusts the decision without its own PDP call.

**Why deferred.** Only pays off in multi-hop service chains; adds a token format to version and revocation semantics to explain (a 30 s attestation window ≈ the existing cache staleness, but it *looks* scarier in review).

**Sketch.** `POST /authorize {…, "attest": true}` → `decisionToken` claim set `{sub, perm, rtype, rid, scope, allowed, pv, iat, exp}`. Verification is standard JWKS. No storage, no revocation (expiry-only, hence the short TTL). Audit rows flag `attested: true`.

**Trigger.** Traces show the same (subject, permission, resource) checked ≥2× inside one request chain.

---

## F2 — Dual-control (four-eyes) approvals

**What.** Flag-gated: designated critical operations — SuperAdmin assignment, `**` deny-rule removal, signing-key rotation, system-role permission edits — don't execute directly; they create a `pending_changes` row a *second* admin must approve.

**Why deferred.** Real workflow complexity (expiry of pending items, self-approval prevention, notification), and small deployments hate it. Baseline stays single-actor.

**Sketch.**
```sql
CREATE TABLE pending_changes (
    id UUID PK, operation VARCHAR(50), payload JSONB,
    requested_by VARCHAR(100), requested_at TIMESTAMPTZ,
    status VARCHAR(20) CHECK (status IN ('PENDING','APPROVED','REJECTED','EXPIRED')),
    decided_by VARCHAR(100), decided_at TIMESTAMPTZ,
    CONSTRAINT chk_no_self_approval CHECK (decided_by IS NULL OR decided_by != requested_by)
);
```
Config lists guarded operations: `iam.dual-control.operations: [assignment.superadmin, deny.wildcard-remove, keys.rotate]`. Executor replays `payload` through the normal service path on approval (so all guards re-run at execution time). Pending items expire in 72 h.

**Trigger.** First enterprise security questionnaire with a four-eyes requirement — historically arrives with the first bank/government prospect.

---

## F3 — Permission implications graph

**What.** `doc.file.admin ⇒ doc.file.write ⇒ doc.file.read`: granting the stronger key implies the weaker ones. Roles shrink; "admin can obviously also read" stops being a per-role bookkeeping chore.

**Why deferred.** Implicit grants are the classic audit complaint ("why does Alice have read? — nothing grants it explicitly"). Explain/explain-tooling must resolve chains. Cycle prevention needed. The explicit-triplet annoyance is real but survivable at baseline scale.

**Sketch.**
```sql
CREATE TABLE permission_implications (
    permission_id UUID FK, implies_permission_id UUID FK,
    PRIMARY KEY (permission_id, implies_permission_id)
);
```
DAG, cycle-checked on write (same walk as role_hierarchy). Resolution happens once at permission-set build (§9 role-permission cache) — closure over implications, cached, so the hot path cost is zero. `/authorize/explain` must render the implication chain. Manifest sync gains an `implies: []` field per permission.

**Trigger.** Role definitions in a real deployment average >30 permissions with obvious read/write/admin triplet duplication.

---

## F4 — Admin UI module

**What.** Optional SPA shipped with the template: scope-tree browser, role/assignment editors, deny hammer with reason prompt, audit browser, `/authorize/explain` visual debugger, break-glass console.

**Why deferred.** Largest single work item on the list; API surface must stabilize first or the UI churns with it. `permission_groups` and `/access-list` already exist to serve it.

**Sketch.** Static SPA (React/Vite) served from the jar under `/admin`, talking only to the public management APIs with the operator's own bearer token — no privileged backdoor endpoints. Feature-flag detection: UI hides panels whose flags are off (reads `GET /api/v1/meta/features`, a new tiny endpoint). The explain debugger is the killer screen: paste a request, see the §5 pipeline with the firing rule highlighted per step.

**Trigger.** Second real adopter — first adopter validates the API shape, second one proves the template market and justifies the spend.

---

## F5 — OpenTelemetry tracing

**What.** Span per pipeline step (`authz.deny-check`, `authz.rbac`, `authz.conditions`, `authz.policies`, `authz.grants`), decision attributes on the root span, trace-id written into `authorization_audit.request_id`.

**Why deferred.** Not deferred far — do it during Phase 4 implementation. Kept out of the design doc only because it changes no contracts.

**Sketch.** Micrometer Observation API (already on classpath via Boot) → OTLP exporter config. Audit correlation: `request_id = current traceId` when present.

**Trigger.** First production deployment.

---

## F6 — Anomaly signals

**What.** Deterministic security telemetry — explicitly **not** ML: deny-spike per subject (N denies / M minutes), first-seen IP per subject, `explain`-endpoint usage by non-admins, break-glass frequency. Exported as Prometheus metrics + optional webhook per rule.

**Why deferred.** Consumer of these signals (SIEM/on-call) must exist first; without one it's dashboard decoration.

**Sketch.** Counter table or Redis sliding windows on the audit write path (async, off the decision hot path). Config: `iam.signals.rules: [{type: deny-spike, threshold: 20, window: 5m, webhook: …}]`.

**Trigger.** First deployment with a security-operations team consuming events.

---

## F7 — Multi-dimensional scoping (matrix orgs)

**What.** Resource simultaneously under "Nepal" (geo tree) and "Payments" (business-unit tree); authorization requires containment in *both*. Today: one tree, second dimension via `resource.metadata` + policies (documented pattern, §15 of AUTHZ_DESIGN).

**Why deferred.** Doubles the core complexity: N closure tables or a labeled-forest closure, multi-scope requests, ambiguous containment semantics (AND vs OR across dimensions), cache keys explode. The metadata+policy pattern covers the observed 90 % case.

**Sketch (if triggered).** `scope_trees (id, name)` table; `scopes.tree_id`; closure per tree (same table, tree-scoped); request carries `scopeIds: {geo:…, bu: …}`; assignment carries one scope per tree it constrains; pipeline requires containment in every dimension the assignment declares. Policies unchanged. Migration: existing tree becomes tree #1.

**Trigger.** A real deployment where the second dimension needs *delegated administration* or *inheritance* (the two things metadata-policies can't fake), not just filtering.

---

## F8 — Resource hierarchy inheritance (Zanzibar-lite)

**What.** "Viewer of folder sees all files, recursively" as engine-level semantics; relation tuples between resources.

**Why deferred.** This is the step that turns a template into an infrastructure product: tuple storage growth, recursive evaluation with memoization, consistency tokens become mandatory rather than optional. Current answers: containers-as-scopes (L1 covers it) or app-side parent resolution.

**Sketch (if triggered).** `resource_edges (parent_type, parent_id, child_type, child_id)` + bounded-depth upward walk (≤5) during ④ grant check, memoized per request; grants gain `inherit: true`. Do NOT build general relation algebra — single `parent-of` edge type only, or adopt an actual Zanzibar implementation (SpiceDB/OpenFGA) beside IAM and delegate L5 to it.

**Trigger.** Grant table crossing ~10⁶ live rows with nested-container product semantics, or product asks for recursive sharing UX.

---

## F9 — Access reviews / attestation campaigns

**What.** Periodic re-certification: "manager M, confirm these 14 grants are still needed" — IGA-lite. Rows not confirmed by deadline get flagged (or auto-revoked, config).

**Why deferred.** Workflow + notification machinery; meaningless without an org that runs reviews. The primitives already exist (as-of queries, access-list, expiring assignments).

**Sketch.** `review_campaigns (id, scope_id, filter, due_at, action_on_timeout)` + `review_items (campaign, assignment_id, reviewer, status)`. Generation = access-list snapshot; completion = revoke or re-stamp `expires_at`. Everything else is notification plumbing via the existing webhook port.

**Trigger.** SOX / ISO 27001 / SOC 2 audit requiring documented periodic access review.

---

## F10 — Native MFA in AuthN

**What.** TOTP enrollment/verification (and later WebAuthn) inside IAM itself, setting the `mfa` context attribute authoritatively instead of trusting the caller's claim.

**Why deferred.** AuthN scope was deliberately slimmed to issuer-only in this redesign round; MFA touches enrollment UX, recovery codes, rate limiting — a self-contained project. `Identity.mfa_enabled` column and `require_mfa` condition (L3) already form the seam.

**Sketch.** `mfa_factors (identity_id, type, secret_encrypted, confirmed_at)`; login flow gains a second step when enabled; access token gains `amr: ["pwd","otp"]` claim; the L3 `require_mfa` condition and policies read `amr` from the *token* (server-truth) instead of `context.additional.mfa` (caller-truth) when native MFA is on.

**Trigger.** A deployment without an upstream IdP (Google/AD) that can assert MFA — i.e., IAM is the only identity authority and compliance demands MFA.

---

## F11 — LLM policy assistant

**What.** Policy Studio panel: admin types "deny invoice approval above 10k without MFA", an LLM drafts the condition tree, admin reviews it in the visual builder, saves into SHADOW mode as usual.

**Why deferred.** Studio's templates + builder + shadow mode must exist first — the assistant only *drafts into* that pipeline; it never bypasses validation or shadow. Console must never *require* an LLM (template stays air-gap friendly).

**Sketch.** Console-side call to a configurable endpoint (`iam.console.assistant-url`, off by default) with the `context_attributes` registry + permission catalog as grounding; output constrained to the policy JSON schema; always lands in SHADOW with the builder open for review. No backend changes — pure console feature.

**Trigger.** Policy Studio in production and users still report authoring friction beyond what templates cover.

---

*End of future enhancements.*
