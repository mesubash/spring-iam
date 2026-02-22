# IAM Domain, Role, Scope, and Permission Clarity

## Purpose
This document captures the intended IAM model discussed in this chat:
- your target business domains,
- what permissions should look like,
- centralized system roles,
- org-level roles and scope usage,
- frontend integration pattern,
- and answers to the main confusion points.

---

## 1. Target Domains
The authorization model should support these domains:

1. `platform` (IAM administration and governance)
2. `order` (create/manage orders)
3. `payment` (payment lifecycle)
4. `user` (business user operations)
5. `insurance` (external insurance provider workflows)
6. `rescue` (SOS and rescue operations)
7. `document` (document upload/access/export)
8. `notification` (message/campaign dispatch)

---

## 2. Permission Model

### 2.1 Naming Format
Permission keys must follow:

`domain.resource.action`

Examples:
- `order.order.create`
- `order.order.approve`
- `payment.transaction.refund`
- `insurance.claim.approve`
- `rescue.sos.respond`
- `document.file.upload`
- `notification.campaign.send`

### 2.2 Actions Are Not Only CRUD
Permissions should include CRUD and business workflow actions.

Recommended action categories:
1. Core: `create`, `read`, `update`, `delete`
2. Workflow: `approve`, `reject`, `submit`, `cancel`, `close`, `reopen`
3. Operations: `assign`, `revoke`, `dispatch`, `respond`
4. File/data: `upload`, `download`, `export`, `import`
5. Finance/comms: `refund`, `settle`, `send`, `retry`, `schedule`

### 2.3 Ownership of Permissions
Permissions are code-owned (migrations), not API-created at runtime.
- Global/Country admins can map permissions to roles.
- Admins should not create new permission keys from UI/API.

---

## 3. Scope Model

### 3.1 Scope Hierarchy
Primary hierarchy:

`GLOBAL -> REGION -> COUNTRY -> ORG -> DEPT -> TEAM -> PROJECT`

For your current setup:
- country root example: `NEPAL`
- org nodes under Nepal:
  - Operations
  - Super User (it is not an organization but is a super user)
  - Travel Agency
  - Sales Agency
  - Rescue Centre
  - Rescue Company
  - Insurance Company
  - Hospital
  - Service Provider
  - Government Bodies

### 3.2 Scope Principle
Assignments are scoped:

`subject + role + scope = access grant`

Cross-org access should be explicit:
- assign higher-scope roles at `COUNTRY` (or above),
- do not rely on sibling-org access.

---

## 4. Centralized System Roles
Recommended global/country-level roles:

1. `SuperAdmin` (GLOBAL)
2. `CountryAdmin` (COUNTRY)
3. `AccessAdmin` (roles, assignments, deny-rules, policies)
4. `SecurityAdmin` (identity/account security operations)
5. `AuditViewer` (audit/compliance read-only)
6. `OperationsAdmin` (cross-org operations as needed)
7. `GovernmentOversight` (country-level read-only oversight)
These are different from org-level business roles.

---

## 5. Organization-Level Roles
Each org type should have role templates, for example:

1. `OrgAdmin`
2. `OrgManager`
3. `OrgOperator` / `OrgStaff`
4. domain-specific roles:
   - `RescueDispatcher`
   - `InsuranceReviewer`
   - `HospitalOperator`
   - `TravelAgencyManager`

Template idea:
- same role names can exist as distinct IAM roles per org-type or use a shared naming strategy.
- all access still enforced via scope-specific assignments.

---

## 6. Policy Usage (ABAC/ReBAC)
Policies are for conditional logic, not baseline permission design.

Use policies when needed for rules like:
- ownership (`subject == resource.owner`)
- time windows
- IP/network restrictions
- MFA required
- contextual allow/deny logic

Baseline access should remain role + scope based.

---

## 7. Frontend Integration Pattern
Frontend should be permission-driven (not role-string-driven).

After login:
1. `GET /api/authz/me/scopes`
2. User selects active scope (org/country context)
3. `GET /api/authz/me/permissions?scopeId=<selected>`
4. Cache permissions as a set in frontend state
5. Render UI with capability checks, e.g. `can('order.order.create')`

Important:
- Do not call authorize endpoint for every button.
- Fetch permissions once per active scope (refetch on scope switch/token refresh).
- Backend remains final enforcement point for every protected API.

---

## 8. Answers to Key Confusions

### Q1: Are permissions only CRUD?
No. They should include workflow and operational actions (`approve`, `upload`, `export`, `respond`, etc.) in addition to CRUD.

### Q2: How hard is adding an organization or role?
- Adding a new organization instance under a country: usually easy (new scope + assignments).
- Adding a new role using existing permissions: easy.
- Adding new permission keys: medium (migration + mapping updates).

### Q3: How hard is changing hierarchy (insert/remove middle level)?
With the current strict scope/depth design, this is hard in live systems.
- Additive changes are easier than restructuring existing parent-child trees.
- Plan hierarchy carefully early to avoid disruptive migrations later.

---

## 9. Recommended Operating Rules
1. Keep permission keys stable and version-controlled.
2. Treat scopes as tenancy boundaries.
3. Keep centralized roles minimal and clear.
4. Use org roles for day-to-day business operations.
5. Use policies sparingly for exceptions and context-aware controls.
6. Keep frontend capability checks cached per scope; enforce on backend always.
