# Integration Guide

How a consuming service or frontend integrates with Spring IAM. Pick the
consumption mode that fits your latency and freshness needs, then wire the
minimal pieces below.

---

## 1. Concepts you must hold

- **subject id** = the identity's UUID (`sub` claim). It is the universal key in
  assignments, deny rules, grants, and audit. Your service stores this, not the
  email.
- **permission key** = `domain.<resource-path>.action`, 3–6 segments
  (`invoice.invoice.approve`, `hgn.order.insurance.create`). Your service owns
  its `domain`(s) and defines the keys.
- **scope** = where authority applies. If you don't use a hierarchy, everything
  lives at the seeded ROOT scope and you never think about it.
- **access token** = RS256 JWT, 15 min, verified locally via JWKS.
- **refresh token** = opaque; a `__Host-Refresh` cookie (web) or a body field
  (mobile). Never inspect it.

---

## 2. Choose a consumption mode

| Mode | How | Latency | Freshness | Use for |
|---|---|---|---|---|
| **Claims** | verify JWT, read `roles`/`perms` | 0 network | ≤ 15 min (TTL) | coarse gates, high-volume reads |
| **PDP** | `POST /api/v1/authorize` | 1 cached call | ≤ cache TTL | fine-grained, sensitive ops |
| **Hybrid** *(recommended)* | claims for reads, PDP for writes | mixed | mixed | most services |

---

## 3. Verify tokens locally (all modes)

Fetch the public keys once and cache them; re-fetch on an unknown `kid`.

```
GET {IAM}/.well-known/jwks.json   →   { "keys": [ { kty, kid, n, e, alg:"RS256" } ] }
```

Verify each incoming `Authorization: Bearer <token>`:

1. Resolve the key by the token header `kid`.
2. Verify RS256 signature, `exp`, and `typ == "access"`.
3. Read `sub` (subject id), `sid` (session), and `roles` / `perms` per your mode.

Any standard JWT library does this — no IAM SDK required, no shared secret.
Set `APP_JWT_CLAIMS_MODE=permissions` on IAM if you want `perms` embedded and
want to skip PDP calls entirely for simple apps.

**Revocation window:** local verification trusts the token until it expires
(≤ 15 min). If you need tighter revocation, call introspection (§6) or poll the
revocation feed on sensitive paths.

---

## 4. PDP calls (fine-grained decisions)

Authenticate service→IAM calls with the internal API key
(`X-Internal-Api-Key: <key>`), or a per-service key if the service registry is
enabled.

```jsonc
POST {IAM}/api/v1/authorize
{
  "subjectId": "c3d9…",                    // from the user's token `sub`
  "permission": "invoice.invoice.approve",
  "resourceType": "invoice",               // optional
  "resourceId": "INV-7",                    // optional
  "scopeId": "…",                           // optional, defaults to ROOT
  "context": { "additional": { "mfa": true },
               "resourceMetadata": { "amount": 9000 } } }

→ { "authorized": true, "reason": "allowed", "policyVersion": 4172, "auditId": "…" }
```

- **Lists**: `POST /api/v1/filter-resources { subjectId, permission,
  resourceType, resourceIds[≤500] }` → `{ allowed: [...] }`. One call instead of
  N.
- **Batch**: `POST /api/v1/authorize/batch` (≤ 50 items).
- **Bootstrap a UI**: `POST /api/v1/effective-permissions { subject, scopeId }`
  → the user's full permission set at a scope.
- **Debug**: `POST /api/v1/authorize/explain` returns the full pipeline trace
  (no audit written).

---

## 5. Register your permissions (service registry, optional)

With `iam.features.service-registry=true`, permissions live in your codebase and
sync on deploy — no manual seeding:

```jsonc
PUT {IAM}/api/v1/services/{yourServiceName}/permissions   // auth: your service API key
{ "permissions": [
    { "key": "invoice.invoice.create",  "description": "Create invoice" },
    { "key": "invoice.invoice.approve", "description": "Approve invoice" } ],
  "deprecateMissing": true }
→ { "created": 1, "unchanged": 1, "deprecated": 0 }
```

You may only sync domains your service owns. Keys are immutable — missing ones
get deprecated, never deleted.

---

## 6. Live token state (optional, flagged)

- `POST /api/v1/token/introspect { token }` → `{ active, sub, sid, exp, roles }`
  (internal callers) — for paths that can't tolerate the TTL revocation window.
- `GET /api/v1/token/revocations?since=<ISO>` → revoked session ids since a
  timestamp — for offline/edge consumers that poll and cache decisions locally.

---

## 7. Frontend integration

The end-user login flow:

1. `POST /api/auth/login {email, password}` → `{ data: { accessToken, expiresIn,
   identity } }`. The refresh token arrives as an HttpOnly cookie automatically.
2. Keep `accessToken` **in memory only** (never localStorage).
3. On any 401: `POST /api/auth/refresh` (no body; the cookie does the work) →
   new access token; retry the original request once; on failure, redirect to
   login.
4. Bootstrap capabilities: `GET /api/authz/me/scopes` (org switcher) and
   `GET /api/authz/me/permissions?scopeId=…` → drive nav/buttons off permission
   keys, **never** off role names.
5. Treat a 403 as a normal outcome: show a quiet notice and refetch the
   permission set.

OAuth login (when enabled) redirects back with `?code=…`; exchange it once:
`POST /api/auth/oauth/exchange { code }` → tokens. Tokens never appear in a URL.

See [`UI_PLAN.md`](UI_PLAN.md) for the admin-console and permission-driven-UI
design.

---

## 8. Worked example — a service protecting an endpoint (hybrid)

```
// 1. On every request: verify the Bearer token via JWKS → get subjectId + roles.
// 2. Cheap read? gate locally on a role/perm claim.
// 3. Sensitive write? call the PDP:

if (method == GET) {
    require(tokenClaims.roles.contains("InvoiceViewer"));      // claims mode
} else if (action == "approve") {
    val d = iam.authorize(subjectId, "invoice.invoice.approve", // PDP mode
                          "invoice", invoiceId, scopeId, context);
    require(d.authorized);
}
```

Nothing in your service interprets scopes, hierarchy, or policies — IAM owns
all of it. Your code only knows permission-key strings.
