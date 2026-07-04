# Configuration

Every setting, its env var, and its default. Settings live in
`src/main/resources/application.yml`; override via environment variables
(docker-compose reads `.env`).

---

## Infrastructure

| Env var | Default | Purpose |
|---|---|---|
| `DB_HOST` | `localhost` | PostgreSQL host (compose overrides to `postgres`) |
| `DB_PORT` | `5432` | PostgreSQL port |
| `DB_NAME` | `iam_db` | database name |
| `DB_USERNAME` / `DB_PASSWORD` | `postgres` / `postgres` | credentials |
| `JPA_DDL_AUTO` | `none` | Flyway owns the schema; `validate` to check entities in CI |
| `REDIS_HOST` | `localhost` | Redis host (compose overrides to `redis`) |
| `REDIS_PORT` | `6379` | Redis port |
| `REDIS_PASSWORD` | *(empty)* | Redis auth |
| `SERVER_PORT` | `8080` | HTTP port |

PostgreSQL needs the `uuid-ossp`, `ltree`, and `pgcrypto` extensions — the
migrations create them.

---

## Keys & tokens (AuthN)

| Key (env) | Default | Purpose |
|---|---|---|
| `APP_JWT_SECRET` | dev placeholder | **Legacy** — only feeds the cookie-key fallback now. Access tokens are RS256 from `signing_keys`, not this secret. |
| `IAM_KEY_ENCRYPTION_KEY` | *(empty)* | AES-GCM-encrypts signing private keys at rest. **Set in production** — unset stores them plaintext (logged loudly). |
| `IAM_COOKIE_KEY` | *(falls back to `APP_JWT_SECRET`)* | Independent key for refresh-cookie encryption. Set it to decouple from the JWT secret. |
| `app.jwt.expiration` | `900000` (15 min) | access-token TTL (ms) |
| `app.jwt.refresh-expiration` | `604800000` (7 d) | session lifetime (ms) |
| `APP_JWT_CLAIMS_MODE` | `roles` | `minimal` \| `roles` \| `permissions` — how much authz data rides in the token |
| `iam.authn.session.max-per-identity` | `10` | active sessions per user before LRU eviction |
| `iam.authn.session.rotation-grace-seconds` | `60` | refresh retry window before a replay is treated as theft |

**Signing keys bootstrap themselves** on first start (an RSA-2048 key pair is
generated and stored). Rotate via `POST /api/v1/keys/rotate` (SuperAdmin).

---

## Cookies & CORS

| Env var | Default | Purpose |
|---|---|---|
| `app.jwt.refresh-token-cookie-name` | `__Host-Refresh` | refresh cookie name |
| `APP_COOKIE_SECURE` | `true` | `__Host-` cookies require Secure; set `false` only for plain-HTTP local dev (and rename the cookie) |
| `APP_COOKIE_DOMAIN` | *(empty)* | cookie domain (ignored for `__Host-` cookies) |
| `APP_JWT_ENCRYPT_COOKIES` | `true` | AES-GCM-encrypt the cookie value |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:3000,http://localhost:8080` | allowed origins |
| `APP_FRONTEND_URL` | `http://localhost:3000` | default OAuth redirect origin |
| `APP_ALLOWED_REDIRECT_URIS` | *(empty)* | OAuth redirect allowlist (empty ⇒ frontend origin only) |

---

## Service-to-service auth

| Env var | Default | Purpose |
|---|---|---|
| `IAM_INTERNAL_API_KEY` | *(empty)* | shared internal key for PDP calls; empty disables the single-key path |
| `IAM_JWT_SECRET` / `IAM_JWT_ISSUER` / `IAM_JWT_AUDIENCE` | *(empty)* | service-JWT verification (optional) |

With the service registry flag on, each service gets its own API key instead of
the shared one.

---

## Authorization engine

| Key | Default | Purpose |
|---|---|---|
| `iam.authorization.policy-mode` | `deny-only` | `deny-only` (ALLOW policies inert — policies only restrict) \| `required-allow` (positive gating; sharp edge — see AUTHZ_DESIGN §4.9) |
| `iam.authorization.cache.deny-rules-ttl` | `60` | deny cache seconds |
| `iam.authorization.cache.permissions-ttl` | `300` | permission-set cache seconds |
| `iam.authorization.cache.scope-ttl` | `3600` | scope containment cache seconds |
| `iam.authorization.cache.role-ttl` | `1800` | role-permission cache seconds |
| `iam.authorization.cache.policy-ttl` | `120` | policy candidate cache seconds |

---

## Feature flags (`iam.features.*`)

All default **false** — the baseline is plain RBAC + scopes + deny rules.
Discover live state at `GET /api/v1/meta/features`. Disabled features 404.

| Flag | Enables |
|---|---|
| `resource-grants` | per-instance ReBAC grants + `/api/v1/resource-grants` |
| `groups` | subject groups + `/api/v1/groups`; deny/assignments resolve subject ∪ groups |
| `service-registry` | per-service API keys + manifest sync (`/api/v1/services`) |
| `oauth2` | social login beans + endpoints (also requires an OAuth registration, see below) |
| `break-glass` | `/api/v1/break-glass` emergency elevation |
| `introspection` | `POST /api/v1/token/introspect` |
| `revocation-feed` | `GET /api/v1/token/revocations` |

### Enabling OAuth2

No client registration ships by default (so the app boots with zero OAuth
credentials). To turn it on: set `iam.features.oauth2=true` **and** provide a
registration via env — Google's provider endpoints are built in, so only the
client id/secret are needed:

```
SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENT_ID=...
SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GOOGLE_CLIENT_SECRET=...
```

---

## Account, rate limiting, integrity, audit

| Key | Default | Purpose |
|---|---|---|
| `iam.account.lockout.max-attempts` | `5` | failed logins before lockout |
| `iam.account.lockout.lockout-duration-minutes` | `30` | lockout duration |
| `iam.rate-limit.max-requests` | `10` | requests per IP per auth endpoint per window |
| `iam.rate-limit.window-seconds` | `60` | rate-limit window |
| `iam.rate-limit.fail-mode` | `open` | `open` (allow when Redis down) \| `closed` (reject) |
| `iam.integrity.fail-on-error` | `false` | refuse startup on broken invariants |
| `iam.integrity.reconciliation-cron` | `-` | nightly closure/ltree drift check (`-` disables) |
| `iam.break-glass.webhook-url` (`IAM_BREAK_GLASS_WEBHOOK`) | *(empty)* | optional alert POST on break-glass grant |
| `iam.audit.partitioning.*` / `iam.audit.retention.*` | see yml | monthly partition create-ahead + retention |

---

## Production checklist

- [ ] Set `IAM_KEY_ENCRYPTION_KEY` (encrypts signing keys at rest)
- [ ] Set `IAM_COOKIE_KEY` (independent from any JWT secret)
- [ ] Set a strong `IAM_INTERNAL_API_KEY` (or enable the service registry)
- [ ] `APP_COOKIE_SECURE=true` (default) behind HTTPS
- [ ] `iam.integrity.fail-on-error=true`
- [ ] Configure `APP_ALLOWED_REDIRECT_URIS` if using OAuth
- [ ] Enable audit partition + retention jobs; scrape `/actuator/prometheus`
- [ ] Replace `V5__example_seed.sql` with your own scopes/roles/admin
