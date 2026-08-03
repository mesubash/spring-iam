# iam-console

Standalone web console for the Spring IAM service — one React app serving **both**
audiences from a single build:

- **Administrators** manage users, scopes, roles, assignments, deny rules,
  policies, context attributes, grants, groups, services, and audit.
- **Regular users** see their own access, sessions, and security settings.

No separate admin build. What a user sees is decided entirely by their
**permissions** (from the API), never by role-name branching.

> **This README is the app cookbook** (how it's wired, how to add things). The
> cross-client **contract** — response envelopes, token rules, the permission
> model spec — lives in [`../docs/FRONTEND_INTEGRATION.md`](../docs/FRONTEND_INTEGRATION.md).
> Read that once; use this to build.

---

## Hard boundary: black-box REST consumer

- Talks to IAM **only** over the public HTTP API (`VITE_API_BASE_URL`).
- Never imports Java, never touches the DB, holds no secrets.
- **Not** part of the Maven build, **not** served from the jar. Builds and
  deploys on its own; the root `.dockerignore` keeps it out of the Java image.

## Stack

React 19 + TypeScript · Vite · TanStack Router (file-based) + Query · Tailwind v4
+ shadcn/ui · react-hook-form + zod · sonner. Package manager: **bun**.

## Develop

```bash
cp .env.example .env        # VITE_API_BASE_URL (default http://localhost:8080)
bun install
bun run dev                 # Vite on http://localhost:5173
```

The Java service must be running. Its CORS already allows `http://localhost:5173`.

```bash
bun run build               # → dist/ (static; regenerates src/routeTree.gen.ts)
```

Deploy `dist/` on any static host. The repo's `docker-compose.yml` intentionally
excludes this app — backend and frontend deploy independently.

---

## Architecture map

```
src/
  api/
    client.ts        fetch wrapper: envelope unwrap, in-memory token,
                     single-flight refresh, 401→refresh→retry, 403 handler
    resources.ts     one object per domain (authApi, authzApi, rolesApi, …)
    types.ts         REST types, mirror the backend exactly
  context/
    AuthContext      identity, login/logout, silent bootstrap on load
    AuthzContext     can()/canAny(), permissions, features, scopes, scopeId
  components/iam/
    Can                  gate a button/action on a permission
    PermissionGuardedPage gate a whole page (deep-link safe)
    SubjectPicker        pick a user by email, store the subject UUID
    AppLayout            sidebar nav (permission/feature gated) + scope switcher
    DataTable, PageHeader, ConfirmDialog, badges
  routes/            file-based routes; _authenticated.* require a session
```

## How the client works (`api/client.ts`)

- **Access token** in memory only. `Authorization: Bearer` added automatically.
- **Envelope unwrap** — `{ success|status, message, data }` is unwrapped to
  `data`; raw `/api/v1/*` entities pass through.
- **Refresh** — a single shared in-flight promise (refresh tokens rotate; two
  concurrent refreshes = reuse → session revoked). A `401` triggers one
  refresh-then-retry.
- **Bootstrap** — on login/reload, `authzApi.bootstrap()` returns identity +
  scopes + permissions + features in one call and **primes the query cache**, so
  the AuthzContext hooks resolve without extra requests.
- **403** — `setForbiddenHandler` shows a quiet toast; never crash the page. A
  403 is expected (the server is the real guard; client checks are UX only).

## Permission model (how gating works here)

`const { can, canAny, permissions, features, scopeId, setScopeId } = useAuthz()`

```tsx
can("platform.role.create")            // does the user hold this key at scopeId?
canAny(["a.b.read", "a.b.manage"])     // any of

<Can permission="platform.role.create">      // gate a button/action
  <Button>New role</Button>
</Can>

<PermissionGuardedPage permission="platform.role.read">  // gate a page (route)
  <RolesPage />
</PermissionGuardedPage>
```

**The rule, no exceptions:**

| UI thing | Gate |
|---|---|
| nav item | `.read` **AND** its feature flag (if any) — never flag alone |
| page route | `.read` (via `PermissionGuardedPage`) |
| action button | the exact `.action` (`.create/.update/.delete/.revoke/.manage`) |

Nav is data in `AppLayout.tsx` → `adminItems[]`: `{ to, label, permission?, featureFlag? }`. Both must pass to render.

## Scopes

A user can be admin at one scope, read-only at another. The header scope switcher
(`setScopeId`) drives a **per-scope** permission refetch. `SubjectPicker` resolves
a user by email and stores their subject **UUID** (what assignments/grants/deny
rules key on) — with a raw-UUID fallback so service/group subjects still work.

---

## Worked example: from API to a rendered button

End to end — how a permission key becomes (or doesn't become) a visible button.

**1. Backend produces the list.** `GET /api/authz/me/permissions?scopeId=<ROOT>`
resolves the caller's role assignments effective at that scope and returns the
union of those roles' permission keys (see [`../docs/AUTHZ_DESIGN.md`](../docs/AUTHZ_DESIGN.md)
for the deny/grant pipeline). On load it's folded into `/me/bootstrap`.

```jsonc
// SuperAdmin at ROOT
{ "success": true, "data": ["platform.role.read","platform.role.create",
                            "platform.role.update","platform.role.delete", …] }
// AuditViewer at ROOT
{ "success": true, "data": ["platform.role.read", …only .read keys] }
```

**2. Context turns the list into `can()`.** `AuthzContext` keeps the array as a
`Set` and re-fetches it per scope:

```ts
const permsQ = useQuery({ queryKey: ["authz", "perms", scopeId],
                          queryFn: () => authzApi.myPermissions(scopeId!),
                          enabled: isAuthenticated && !!scopeId });
const permissions = new Set(permsQ.data ?? []);
const can = (key: string) => permissions.has(key);   // O(1) membership test
```

**3. `<Can>` reads `can()`.** The whole component is this — render children or a
fallback:

```tsx
export function Can({ permission, anyOf, children, fallback = null }) {
  const { can, canAny } = useAuthz();
  const ok = permission ? can(permission) : anyOf ? canAny(anyOf) : false;
  return <>{ok ? children : fallback}</>;
}
```

**4. A page uses it.** Same JSX for everyone:

```tsx
<PageHeader title="Roles"
  actions={<Can permission="platform.role.create"><Button>New role</Button></Can>}
/>
<DataTable columns={cols} rows={roles} />   // rows visible to anyone with .read
```

**5. What each user renders** — identical code, different output because the
`Set` differs:

```
SuperAdmin  →  Roles page + [New role] button + row [edit][delete]
AuditViewer →  Roles page, read-only        (New role hidden: no .create key)
plain user  →  no "Roles" in the sidebar     (no .read key → nav item filtered)
```

**Why it's dynamic (reactive):** `permissions` is a React Query result. When it
changes — scope switch (`setScopeId` → refetch for the new scope) or a `403`
(handler invalidates `["authz","perms"]` → refetch) — the `Set` changes, context
re-renders, and every `<Can>` / nav item / `PermissionGuardedPage` re-evaluates
automatically. You never manually toggle a button; you change the data and the UI
follows.

> `<Can>` is **UX, not security.** A user who un-hides the button still gets a
> `403` from the server. Client gating only decides what to *show*.

---

## Recipe: add an admin page

1. **Route** — `src/routes/_authenticated.admin.<name>.tsx`:
   ```tsx
   export const Route = createFileRoute("/_authenticated/admin/<name>")({
     component: () => (
       <PermissionGuardedPage permission="platform.<res>.read">
         <ThingPage />
       </PermissionGuardedPage>
     ),
   });
   ```
2. **API** — add a module in `api/resources.ts` (`thingApi = { list, create, … }`)
   and its types in `api/types.ts` (match the backend response exactly).
3. **Nav** — one line in `AppLayout.tsx` `adminItems[]` with its `permission`
   (and `featureFlag` if the backend gates it behind one).
4. **Page** — `PageHeader` + `DataTable`; wrap every mutator in
   `<Can permission="platform.<res>.<action>">`.
5. **Build** — `bun run build` regenerates `routeTree.gen.ts` (commit it).

That's the whole loop. Everything else (auth, refresh, scope, 403) is already
handled by the client + contexts.
