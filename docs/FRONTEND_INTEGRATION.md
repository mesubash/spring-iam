# Frontend Integration

How a browser SPA (like the `web/` admin console) consumes Spring IAM: the
response envelopes, the token lifecycle, and — most importantly — how to render
the UI **dynamically from permissions and feature flags** instead of hardcoding
what each user can see. This is the contract; if the backend changes it, update
this doc.

> Companion to [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md) (service-to-service).
> That doc is about verifying tokens and calling the PDP. This one is about a
> logged-in human clicking around a UI.

---

## 1. Response shapes — there are three, know which is which

A frontend HTTP client MUST handle all three. Mixing them up is the single most
common integration bug.

| Family | Endpoints | Body |
|---|---|---|
| **Success envelope** | `/api/auth/*`, `/api/authz/*` | `{ "success": true, "message": "...", "data": <T> }` |
| **Error envelope** | any endpoint, on failure | `{ "timestamp", "status": <int>, "error", "message", "path", "validationErrors" }` |
| **Raw entity** | `/api/v1/*` (admin) and `/api/v1/meta/features` | the object/array directly, no wrapper |

Rules for a generic client:

- **Unwrap the success envelope to `data`** when the body is an object that has a
  `data` field *and* a `success` (or `status`) marker. Do **not** key only on
  `status` — the success envelope uses `success`; only the *error* envelope uses
  a numeric `status`. (This exact mismatch once made `me/scopes` return the whole
  envelope and the console did `scopes.map(...)` on an object and crashed.)
- **`/api/v1/*` returns raw JSON** — no envelope. `GET /api/v1/roles` is a bare
  `Role[]`. Don't try to unwrap it.
- On a non-2xx, read `message` from the error envelope for the toast; fall back to
  the status line.

```ts
function unwrap<T>(body: unknown): T {
  if (body && typeof body === "object" && "data" in body &&
      ("success" in body || "status" in body)) {
    return (body as { data: T }).data;
  }
  return body as T; // raw /api/v1/* entity
}
```

---

## 2. Token lifecycle

- **Access token** — RS256 JWT, 15 min. Keep it **in memory only** (never
  `localStorage`). Send as `Authorization: Bearer <token>`.
- **Refresh token** — opaque, delivered as a `__Host-Refresh` **HttpOnly cookie**.
  The browser sends it automatically; JS never reads it. All requests use
  `credentials: "include"`.
- **Identity** — `/api/auth/login` and `/api/auth/refresh` both return
  `data.identity` (`{ id, email, displayName, emailVerified }`). The JWT itself
  carries only `sub`, `roles`, `email_verified` — **not** email/displayName — so
  the refresh response is how the UI restores the header (email) on reload
  without a separate `/me` call. This is intentional; don't strip it.

### The refresh flow (and the one rule that bites)

```
login → access token in memory + refresh cookie set
any 401 (token expired) → POST /api/auth/refresh → new access token → retry once
on reload → POST /api/auth/refresh with the cookie → silent session restore
```

**Refresh tokens rotate on every use.** The backend detects reuse: if a rotated
(already-spent) refresh token is presented again, it treats the session as
compromised and **revokes it**. Consequence for the client:

> **Refresh must be a single in-flight request.** If bootstrap-on-load and a
> 401-retry (or React StrictMode's double-invoke, or several parallel 401s) each
> fire their own `/refresh`, the second replays a spent cookie → session
> revoked → user bounced to login. Share one promise:

```ts
let inFlight: Promise<Result> | null = null;
function refresh() {
  if (!inFlight) inFlight = doRefresh().finally(() => (inFlight = null));
  return inFlight;
}
```

This is correct backend behavior — do not ask for it to be relaxed. Fix it on the
client with the single-flight guard above.

---

## 3. Dynamic rendering — permissions, never role names

The UI must be driven by **what the user can do**, resolved per scope, never by
branching on role names. Roles are an implementation detail of the grant; the
same screen may be reachable by three different roles.

### Bootstrap the authz context (once, after auth)

| Call | Returns | Use for |
|---|---|---|
| `GET /api/authz/me/scopes` | `ScopeSummary[]` the user has any grant in | the scope switcher |
| `GET /api/authz/me/permissions?scopeId=<id>` | `string[]` permission keys at that scope | `can()` |
| `GET /api/v1/meta/features` | `{ "<flag>": bool }` (raw, no envelope) | feature gating |

Build a `Set<string>` of permission keys and expose:

```ts
can(key)        => permissions.has(key)
canAny(keys)    => keys.some(can)
```

**Re-fetch permissions when the active scope changes** — a user can be an admin at
one scope and read-only at another. Cache-key your permission query by `scopeId`.

### Gate three things with it

1. **Navigation** — only render a nav item if its backing permission (or feature
   flag) is present. Hidden, not disabled.
2. **Actions** — wrap create/edit/delete buttons in a `can(...)` check so a
   read-only user sees data but no mutators.
3. **Routes** — guard each page with the permission it needs; on direct URL
   access without it, show a neutral "not available for your access level"
   instead of a hard error.

### Defense in depth, not a security boundary

Client permission checks are **UX only**. The server re-authorizes every call.
A user who forges `can()` still gets a `403` from the API. So:

- Treat a `403` as expected, not exceptional: show a quiet toast, optionally
  refetch permissions (they may have changed), do **not** crash the page.
- Never assume a hidden button means a safe endpoint.

---

## 4. Feature flags

`GET /api/v1/meta/features` reflects the server's `iam.features.*` config
([CONFIGURATION.md](CONFIGURATION.md)). Flag-gated capabilities are **absent from
the API entirely** when off (the endpoints 404 / "not enabled"), so the UI must
hide their nav + actions when the flag is false — independent of permissions.

| Flag | Gates |
|---|---|
| `resource-grants` | per-resource (ReBAC) grants UI + `/api/v1/resource-grants` |
| `groups` | subject groups UI + `/api/v1/groups` |
| `service-registry` | service clients UI + `/api/v1/services` |
| `break-glass` | emergency elevation action + `/api/v1/break-glass` |
| `oauth2` | social login (also needs a client registration, not flag-only) |
| `revocation-feed`, `introspection` | token revocation feed / introspection |

A page can require **both** a permission and a flag (e.g. Resource Grants needs
the flag on *and* the user's grant-read permission).

---

## 5. Endpoint quirks the UI must know

These are non-obvious contracts that a frontend will get wrong without warning:

- **Deny rules** — `GET /api/v1/deny-rules` returns `[]` unless you pass
  `?subjectId=<id>`. It is a per-subject lookup, not a global list. Build the UI
  around "enter a subject, then view/manage their deny rules."
- **Resource grants** — same: filter by `subjectId` (or `resourceType`+
  `resourceId`). No unfiltered global list.
- **Audit** — there is **no** global "recent decisions" feed. Query by subject
  (`/api/v1/audit/subject/{id}`), by resource
  (`/api/v1/audit/resource/{type}/{id}`), or stats
  (`/api/v1/audit/statistics/{subjectId}`). A dashboard "recent activity" widget
  should query the logged-in user's own subject id.
- **Role permissions** — a `Role` object does **not** embed its permission ids.
  Fetch them separately with `GET /api/v1/roles/{id}/permissions` when opening a
  role editor.
- **Permissions create** — `POST /api/v1/permissions` takes an **array**, even for
  one permission.
- **Context attributes** — `GET` is allowed for admin-tier roles, but **create /
  delete are `SuperAdmin`-only** and gated by *role*, not a permission key. There
  is no `platform.context_attribute.*` permission. If you gate the create button
  on a normal read permission, non-super admins will see it and get a `403`. Gate
  it on a permission only `SuperAdmin` holds (e.g. `platform.permission.create`)
  as a proxy, or accept the 403-toast.
- **Key rotation** — `POST /api/v1/keys/rotate` is `SuperAdmin`-only (role-gated),
  same proxy-gating caveat as above.
- **Subjects are UUIDs, not emails** — assignments, deny-rules, grants, groups,
  audit and explain all key on the identity UUID (`sub`). Don't make operators
  type it: resolve users by email through `GET /api/v1/identities?query=` (needs
  `platform.identity.read`) and store the id. Raw-UUID paste must still work so
  service/group subjects stay addressable. The console's `SubjectPicker`
  component does exactly this (with a plain-input fallback when the caller lacks
  identity read).
- **Admin user management** — `POST /api/v1/identities` creates a user and
  returns `{ identity, temporaryPassword }`; `temporaryPassword` is non-null
  only when the server generated one — show it once, it is never retrievable
  again. Same one-time-secret pattern on `PUT /{id}/password`. Status changes
  (`PUT /{id}/status`) revoke sessions on SUSPEND/DEACTIVATE.
- **CORS** — dev origins are set via `cors.allowed-origins`
  (`CORS_ALLOWED_ORIGINS`); it already includes `http://localhost:5173` (Vite) and
  `3000`. `credentials: include` requires an explicit origin match — a wildcard
  will not work with cookies.

---

## 6. Permission → screen map (reference)

The seeded platform permission keys and the nav they light up. Your own domains
add their own keys; the pattern is the same.

| Permission (read) | Console area |
|---|---|
| `platform.identity.read` | Users (+ the subject picker everywhere) |
| `platform.scope.read` | Scopes |
| `platform.role.read` | Roles |
| `platform.assignment.read` | Assignments |
| `platform.deny_rule.read` | Deny Rules |
| `platform.policy.read` | Policies, Context Attributes |
| `platform.permission.read` | Permissions catalog |
| `platform.audit.read` | Audit, Explain |

Create/update/delete variants (`.create`, `.update`, `.delete`, `.revoke`,
`.move`) gate the corresponding action buttons. See
[AUTHZ_DESIGN.md](AUTHZ_DESIGN.md) for the full key catalog and the seed role
grants.

---

## 7. Reference implementation

`web/` (the `iam-console` React app) implements all of the above:

- `src/api/client.ts` — envelope unwrap, in-memory token, single-flight refresh,
  401→refresh→retry, 403 handler.
- `src/context/AuthContext.tsx` — silent restore, login/logout.
- `src/context/AuthzContext.tsx` — scopes, per-scope permissions, `can()`/
  `canAny()`, feature flags.
- `src/components/iam/AppLayout.tsx` — permission/flag-gated navigation.

It talks to the backend **only** over this REST contract — no shared code, no DB
access — so it doubles as the executable spec for a new frontend.
