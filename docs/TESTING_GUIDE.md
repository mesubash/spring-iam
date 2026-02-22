# IAM Testing Guide

This guide explains how to use the two Postman collections in this repo and how they differ.

## 1) Collections and Purpose

### A) `postman/HGN_IAM_AuthZ_Focus.postman_collection.json`
Use this as the primary, deterministic authorization test suite for the current implementation.

What it validates:
- Core admin login and sanity checks
- Org-by-org login (`admin` + secondary user)
- `/api/authz/me/permissions` behavior per scope
- `/api/v1/authorize` behavior using `X-Internal-Api-Key`
- Positive + negative authorization outcomes per org role pair

### B) `postman/HGN_IAM_Platform.postman_collection.json`
Use this as a broad platform/regression playground.

What it covers:
- Larger endpoint surface (permissions, scopes, roles, policies, assignments, deny rules, audit)
- Runtime authz checks
- Access-denied scenarios
- Delegation-style scenarios (org admin management), some of which are aspirational vs current enforcement

## 2) Current Backend Enforcement (Important)

Current security rules in code:
- `/api/v1/authorize/**` and `/api/v1/effective-permissions` -> `INTERNAL`, `SuperAdmin`, `CountryAdmin`
- `/api/v1/permissions/**`, `/roles/**`, `/scopes/**`, `/assignments/**`, `/deny-rules/**`, `/permission-groups/**`, `/role-hierarchy/**`, `/policies/**`, `/audit/**` -> `SuperAdmin`, `CountryAdmin`

Reference:
- `src/main/java/com/hgn/iam/config/SecurityConfig.java:156`
- `src/main/java/com/hgn/iam/config/SecurityConfig.java:169`

Implication:
- Org admins (TravelAdmin, OperationsAdmin, RescueCentreAdmin, etc.) are not allowed to call admin management endpoints in the current code.

## 3) Which Collection to Use for What

| Goal | Use | Notes |
|------|-----|-------|
| Validate current authz correctness end-to-end | `HGN_IAM_AuthZ_Focus` | Best signal, aligned with current seeds and auth gates |
| Explore full API surface manually | `HGN_IAM_Platform` | Good for exploration; not all assertions represent current enforcement |
| CI pass/fail gate | `HGN_IAM_AuthZ_Focus` | Recommended |
| Future delegated-admin behavior spec | `HGN_IAM_Platform` (selected sections) | Treat parts as target-state tests |

## 4) Key Differences Between the Two

1. Scope of testing
- `AuthZ_Focus`: compact and role/scope behavior-focused.
- `Platform`: much wider API coverage and scenario breadth.

2. Stability
- `AuthZ_Focus`: expected to be mostly green against current code and seed data.
- `Platform`: includes expectation sets that can fail under current security config.

3. Runtime authorize usage
- Both use `X-Internal-Api-Key` for `/api/v1/authorize` checks.
- This is correct for service-to-service style authorization checks.

4. Delegation assumptions
- `AuthZ_Focus`: does not rely on org-admin delegated management for admin APIs.
- `Platform`: includes delegated management assumptions for org admins.

## 5) Known Mismatches in `HGN_IAM_Platform` (Current Code)

These examples conflict with current security config and will fail if executed as strict assertions:

- CountryAdmin expected `403` on admin endpoints, but current code allows CountryAdmin:
  - `postman/HGN_IAM_Platform.postman_collection.json:1617`
  - `postman/HGN_IAM_Platform.postman_collection.json:2091`
  - `postman/HGN_IAM_Platform.postman_collection.json:2914`

- TravelAdmin expected to list/create roles via admin APIs:
  - `postman/HGN_IAM_Platform.postman_collection.json:2962`
  - `postman/HGN_IAM_Platform.postman_collection.json:3151`

- TravelAdmin expected to create assignments and deny rules:
  - `postman/HGN_IAM_Platform.postman_collection.json:3364`
  - `postman/HGN_IAM_Platform.postman_collection.json:4201`

- Delegated folder description states org-admin role management is allowed, but backend gate currently does not allow this:
  - `postman/HGN_IAM_Platform.postman_collection.json:2958`

## 6) Recommended Execution Strategy

### For reliable verification (today)
1. Run `HGN_IAM_AuthZ_Focus` fully.
2. Treat failures there as real regressions (seed/authz/runtime issues).

### For platform exploration
1. Run `HGN_IAM_Platform` selectively.
2. Use it for manual exploration and future-behavior planning.
3. Do not treat all current red tests there as engine bugs; some are expectation-model mismatches.

## 7) Seed Credentials Used by Current Collections

Core users:
- `superadmin@hgn.com` / `Admin@123!`
- `nepal.admin@hgn.com` / `Nepal@123!`
- `access.admin@hgn.com` / `Access@123!`
- `security.admin@hgn.com` / `Security@123!`

Org users use:
- admin account password: `OrgAdmin@123!`
- secondary account password: `OrgUser@123!`

These align with:
- `src/main/resources/db/migration/V3__dev_users.sql`
- `src/main/resources/db/migration/V4__dev_orgs.sql`

## 8) Practical Rule of Thumb

- If you want truth for current system behavior: run `HGN_IAM_AuthZ_Focus`.
- If you want broad coverage plus future delegated scenarios: use `HGN_IAM_Platform`, but separate current-pass checks from target-state checks.

