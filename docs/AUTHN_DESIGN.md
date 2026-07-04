# Authentication (AuthN) — Complete Design

> **Status:** PROPOSAL — authentication module only
> **Date:** 2026-07-04
> Companions: `AUTHZ_DESIGN.md` (authorization engine), `ARCHITECTURE.md` (overview), `UI_PLAN.md` (frontend track), `FUTURE_ENHANCEMENTS.md` (deferred items)
> **Scope of this document:** identity & credential model, token architecture (issuing, rotation, revocation), session management, OAuth2, account lifecycle, Redis keyspace, security spec, APIs, migration diff — with worked examples.

---

## Table of Contents

1. [Role & Boundaries — Issuer, Not Gatekeeper](#1-role--boundaries--issuer-not-gatekeeper)
2. [Core Concepts & Vocabulary](#2-core-concepts--vocabulary)
3. [Current State (as implemented)](#3-current-state-as-implemented)
4. [Proposed Schema — Table by Table](#4-proposed-schema--table-by-table)
   - 4.1 [identities](#41-identities--unchanged)
   - 4.2 [credentials](#42-credentials--unchanged)
   - 4.3 [sessions (NEW) + refresh_tokens (CHANGED)](#43-sessions-new--refresh_tokens-changed)
   - 4.4 [signing_keys (NEW)](#44-signing_keys-new)
   - 4.5 [security_events](#45-security_events--unchanged)
   - 4.6 [identity_profiles (REMOVED)](#46-identity_profiles--removed)
5. [Token Architecture](#5-token-architecture)
6. [Redis Keyspace](#6-redis-keyspace)
7. [Account Lifecycle](#7-account-lifecycle)
8. [OAuth2 / Social Login](#8-oauth2--social-login)
9. [Worked Flows (A–H)](#9-worked-flows)
10. [Security Specification](#10-security-specification)
11. [API Surface](#11-api-surface)
12. [Configuration](#12-configuration)
13. [Migration Diff Summary (Current → Proposed)](#13-migration-diff-summary-current--proposed)
14. [Integration Profiles](#14-integration-profiles)
15. [Known Boundaries](#15-known-boundaries)

---

## 1. Role & Boundaries — Issuer, Not Gatekeeper

AuthN answers exactly one question:

> **Who is this, and can I prove it to everyone else?**

It is a **central token issuer**: it verifies credentials, mints short-lived asymmetric-signed access tokens, manages refresh/session lifecycle, and publishes public keys so every consuming service verifies tokens **locally** — no shared secrets, no per-request validation calls.

**In scope:** registration, email verification, login (password + OAuth2), token issuing/refresh/revocation, session management, account lockout & lifecycle, password flows, security-event audit.

**Explicitly out of scope:**

| Not AuthN's job | Where it lives |
|---|---|
| User profile data (name, phone, avatar) | consuming services (§4.6) |
| What the user may DO | AuthZ module (`AUTHZ_DESIGN.md`) |
| Sending emails | `NotificationPort` — deployment plugs its own channel (§12) |
| MFA enrollment/verification | deferred, seam prepared — F10 |
| Being a certified OIDC Provider for third parties | boundary — §15 |

---

## 2. Core Concepts & Vocabulary

| Concept | Definition | Example |
|---|---|---|
| **Identity** | The anchor. `identities.id` (UUID) = THE universal `subject_id` in JWTs, assignments, audit — everywhere. | `c3d9…` |
| **Credential** | One way to prove an identity. Many per identity: password + Google + Apple coexist. | PASSWORD credential with bcrypt hash |
| **Access token** | Short-lived (15 min) RS256 JWT. Verified locally by services via JWKS. Never stored server-side; revocation via jti blacklist for the remaining TTL. | `eyJ…` with `kid`, `sub`, `sid`, `roles` |
| **Refresh token** | Opaque 256-bit random string (NOT a JWT). Stored hashed. Single-use: every refresh rotates it. | `Zk3…` (43 chars, base64url) |
| **Session** | One login on one device = one session = one refresh-token *family*. Rotation replaces tokens within the family; reuse of a replaced token kills the whole family. | "Chrome on macOS, since Jul 1" |
| **One-time token** | Email-verification / password-reset / reactivation tokens. Redis-only, hashed, single-use, typed TTLs. | reset token, 15 min |
| **Claims mode** | How much authorization data rides in the access token: `minimal` / `roles` / `permissions`. | §5.3 |

---

## 3. Current State (as implemented)

### 3.1 Current schema (V1, AuthN tables)

```sql
-- ✅ identities — keep as-is
CREATE TABLE identities (
    id                    UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    primary_email         VARCHAR(150) UNIQUE NOT NULL,
    email_verified        BOOLEAN NOT NULL DEFAULT FALSE,
    account_status        VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
        CHECK (account_status IN ('ACTIVE','LOCKED','SUSPENDED','DEACTIVATED')),
    failed_login_attempts INT NOT NULL DEFAULT 0,
    account_locked_until  TIMESTAMPTZ,
    last_login_at         TIMESTAMPTZ,
    last_login_ip         INET,
    mfa_enabled           BOOLEAN NOT NULL DEFAULT FALSE,
    created_at / updated_at
);

-- ✅ credentials — keep as-is
CREATE TABLE credentials (
    id              UUID PRIMARY KEY,
    identity_id     UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    credential_type VARCHAR(30) CHECK (IN ('PASSWORD','GOOGLE','APPLE','MICROSOFT')),
    identifier      VARCHAR(200) NOT NULL,     -- email (PASSWORD) or provider user-id (OAuth)
    secret_hash     TEXT,                      -- bcrypt; NULL for OAuth
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    last_used_at, created_at, updated_at,
    UNIQUE (credential_type, identifier)
);

-- ⚠️ refresh_tokens — restructured (§4.3)
CREATE TABLE refresh_tokens (
    id UUID PK, identity_id FK CASCADE,
    token_hash VARCHAR(128), ip_address INET, user_agent TEXT,
    expires_at, revoked_at, revoke_reason CHECK (IN ('LOGOUT','ROTATION','ADMIN','SECURITY','EXPIRED'))
);

-- ❌ identity_profiles — removed (§4.6)
-- ✅ security_events — keep as-is (11 event types, JSONB metadata, immutable)
```

### 3.2 Current runtime design (from code)

- **JWT: HS256, shared secret** (`app.jwt.secret`), issued by `JwtTokenProvider`. Same secret also derives the cookie AES key (SHA-256) and the OAuth-cookie HMAC key.
- **Refresh token is itself a JWT**, tracked in Redis by `RedisTokenService` (`@Primary`): forward key `refresh:token:{userId}`, reverse key `{TokenType}{token}` → userId. Rotation + reuse detection (`rotate()` throws `TokenReuseException`, deletes everything).
- **DB `refresh_tokens` is a second, parallel blacklist** (`RefreshTokenBlacklistServiceImpl`, SHA-256 hashes) — refresh flow checks *both* stores.
- **In-memory `ConcurrentHashMap` fallback** inside `RedisTokenService` if Redis is down — silent, per-instance, lost on restart.
- **Single active refresh per user**: login and OAuth success call `revokeAll` then `store` — a second device logs the first one out silently (despite a separate `logout-all` endpoint existing).
- One-time tokens (verify/reset/reactivation) stored **raw** in Redis with typed TTLs (reset 15 min, verify 24 h, reactivation 7 d).
- Email sending is `// TODO` — tokens only logged.
- OAuth2: Google wired; success handler redirects with **`?token=<JWT>` in the URL**; redirect validation accepts **any absolute URI** (allowlist code exists but is dead); custom CSRF `state` is generated but never verified (Spring's own state does the real work).
- Cookie: `__Host-Session-Id` with `secure=false` default — browsers reject the cookie in that combination.

### 3.3 What is wrong (summary)

| # | Problem | Fix |
|---|---------|-----|
| 1 | HS256 shared secret — every verifier can mint; no rotation | RS256 + JWKS + `kid` rotation (§4.4, §5.1) |
| 2 | Two parallel refresh stores (Redis primary + DB blacklist), divergent semantics | DB = source of truth, Redis = cache + jti blacklist only (§4.3, §6) |
| 3 | Silent in-memory fallback when Redis dies | Removed — fail-closed; availability is Redis HA's job, not a per-instance map (§10-T8) |
| 4 | Single active session per user (login kills other devices) | First-class multi-session with families (§4.3) |
| 5 | Refresh token is a JWT — needless claims surface, alg confusion risk, revocation still needs a store anyway | Opaque 256-bit random, hashed at rest (§5.2) |
| 6 | One secret drives JWT + cookie AES + OAuth HMAC | Independent keys; JWT secret disappears entirely (§10-T6) |
| 7 | OAuth: token in redirect URL, open redirect, dead allowlist code | One-time exchange code + enforced allowlist (§8) |
| 8 | `__Host-` cookie broken by insecure default | `secure=true` default; dev profile uses plain cookie name (§10-T7) |
| 9 | One-time tokens stored raw in Redis | Store SHA-256(token), compare on hash (§6) |
| 10 | Email sending unimplemented | `NotificationPort` + adapters (§12) |
| 11 | Dead code: `JwtTokenProvider.rotateRefreshToken/validateRefreshToken`, unverified custom OAuth state | Deleted with the redesign |
| 12 | `identity_profiles` in an issuer-only service | Removed (§4.6) |

---

## 4. Proposed Schema — Table by Table

### 4.1 `identities` — UNCHANGED

DDL as in §3.1. Rationale for what it does and doesn't contain:

- `primary_email` is the only human identifier the issuer needs — it is the login handle and the notification address. Everything else about the human lives in consumer services.
- `account_status` is the master switch (§7). `email_verified` gates login. `mfa_enabled` + the `amr` claim (§5.3) form the seam F10 will plug into — column stays even though native MFA is deferred.
- Lockout counters live here (not in Redis) because they must survive restarts and be visible to admins.

**Example row**

```jsonc
{ "id": "c3d9…", "primary_email": "alice@acme.com", "email_verified": true,
  "account_status": "ACTIVE", "failed_login_attempts": 0, "mfa_enabled": false }
```

### 4.2 `credentials` — UNCHANGED

DDL as in §3.1. Properties worth restating:

- **N credentials per identity**: Alice may hold PASSWORD + GOOGLE simultaneously; `UNIQUE(credential_type, identifier)` prevents the same Google account linking to two identities.
- PASSWORD: `identifier` = email, `secret_hash` = bcrypt (strength 12). OAuth types: `identifier` = provider's stable user-id (`sub` from Google), `secret_hash` NULL.
- Linking rules are a security decision — §8.3.

### 4.3 `sessions` (NEW) + `refresh_tokens` (CHANGED)

The centerpiece change. One login = one **session**; rotation happens *inside* a session; reuse detection kills the session, not the user's whole world.

```sql
CREATE TABLE sessions (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identity_id   UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    created_ip    INET,
    user_agent    TEXT,
    device_label  VARCHAR(100),                -- best-effort parse: "Chrome · macOS"
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ NOT NULL,        -- absolute session lifetime (default 7 d, sliding optional)
    revoked_at    TIMESTAMPTZ,
    revoke_reason VARCHAR(30)
        CHECK (revoke_reason IN ('LOGOUT','LOGOUT_ALL','ADMIN','SECURITY','REUSE_DETECTED','EXPIRED','EVICTED'))
);
CREATE INDEX idx_sessions_identity ON sessions (identity_id) WHERE revoked_at IS NULL;

CREATE TABLE refresh_tokens (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id    UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    token_hash    VARCHAR(64) NOT NULL UNIQUE,       -- SHA-256 of the opaque token
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ NOT NULL,
    replaced_by   UUID REFERENCES refresh_tokens(id), -- rotation chain; NULL = current head
    replaced_at   TIMESTAMPTZ,                        -- for the retry-grace window
    revoked_at    TIMESTAMPTZ
);
CREATE INDEX idx_rt_session ON refresh_tokens (session_id);
```

**Semantics**

| Event | Effect |
|---|---|
| Login | new `sessions` row + first `refresh_tokens` row. Other sessions untouched — **multi-device works**. |
| Refresh | present token → look up by hash → must be the chain head (`replaced_by IS NULL`, not revoked/expired, session alive) → issue new token row, set old row's `replaced_by` + `replaced_at` → new access token. |
| **Retry grace (reuse interval)** | presented token has `replaced_by NOT NULL` but `now - replaced_at ≤ rotation-grace` (default 60 s) ⇒ this is a **network retry, not theft**: lost response, or two SPA tabs racing. Return the already-issued successor pair idempotently (cached 60 s in Redis, §6). Without this, every mobile-network blip kills a legitimate session. |
| **Reuse detected** | presented token has `replaced_by NOT NULL` and grace exceeded ⇒ replay of a rotated token (theft indicator). Revoke the **whole session** (`REUSE_DETECTED`), blacklist its live access jti, emit `TOKEN_REVOKED` security event. Other sessions survive. |
| Logout | revoke this session + blacklist current access jti. |
| Logout-all | revoke all sessions of the identity. |
| Session cap | max active sessions per identity (default 10); 11th login evicts the least-recently-used (`EVICTED`). |

**Why DB as source of truth (not Redis):** refresh events are rare (one per ~15 min per device) — DB write cost is irrelevant; in exchange: reuse detection survives restarts and works across instances, sessions are queryable (`GET /api/auth/sessions` — "your devices" screen, UI_PLAN), audit is natural, and the in-memory-fallback hazard disappears. Redis remains a *read-through cache* for hot lookups + the access-token jti blacklist (§6).

**Example** — Alice, two devices:

```
sessions:        S1 (laptop, created Jul 1)      S2 (phone, created Jul 3)
refresh_tokens:  S1: t1 → t2 → t3(head)          S2: t4(head)
```
Attacker replays `t2` (stolen) → `t2.replaced_by = t3` ⇒ reuse ⇒ S1 revoked, S1's access jti blacklisted. Alice's phone (S2) keeps working; laptop must re-login.

### 4.4 `signing_keys` (NEW)

```sql
CREATE TABLE signing_keys (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    kid          VARCHAR(64)  NOT NULL UNIQUE,
    algorithm    VARCHAR(10)  NOT NULL DEFAULT 'RS256' CHECK (algorithm IN ('RS256','ES256')),
    public_key   TEXT NOT NULL,                -- PEM
    private_key  TEXT NOT NULL,                -- PEM, AES-GCM-encrypted with IAM_KEY_ENCRYPTION_KEY (env)
    status       VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
                 CHECK (status IN ('ACTIVE','ROTATED','REVOKED')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rotated_at   TIMESTAMPTZ,
    not_after    TIMESTAMPTZ                   -- drop from JWKS after this
);
```

- Exactly one `ACTIVE` key signs new tokens; `ROTATED` keys stay in JWKS until `not_after` (≥ max access TTL) so in-flight tokens verify; `REVOKED` = compromised, removed immediately (accepting that its unexpired tokens die — that's the point).
- Rotation: `POST /api/v1/keys/rotate` (SuperAdmin, dual-control candidate — F2) + optional cron. Bootstrap: generate on first startup if empty, log loudly.
- `KeySource` port: `db` (default) | `env-pem` (K8s-secret-managed; table unused).
- Published at `GET /.well-known/jwks.json` — public, `Cache-Control: max-age=300`.

### 4.5 `security_events` — UNCHANGED

DDL as in §3.1. Event types gain three: `SESSION_EVICTED`, `REUSE_DETECTED`, `OAUTH_LINKED`. Immutable, JSONB metadata, indexed by identity+time. This is AuthN's audit trail (AuthZ has its own partitioned `authorization_audit`).

**Example row**

```jsonc
{ "identity_id": "c3d9…", "event_type": "REUSE_DETECTED",
  "ip_address": "198.51.100.7",
  "metadata": { "sessionId": "S1", "tokenId": "t2", "action": "session_revoked" } }
```

### 4.6 `identity_profiles` — REMOVED

Dropped with the table: `IdentityProfile` entity, repository, `ProfileController` (`GET/PUT /api/auth/me` profile fields), `ProfileResponse`/`UpdateProfileRequest` DTOs, profile writes in `AuthServiceImpl.register` and `CustomOAuth2UserService`, `RegisterRequest.fullName`.

`GET /api/auth/me` survives, slimmed: `{id, email, emailVerified, status, mfaEnabled, roles}`. OAuth-provided name/picture are returned **once** in the login/registration response for the consumer app to store — IAM never persists them.

---

## 5. Token Architecture

### 5.1 Access token — RS256 JWT

```jsonc
// header
{ "alg": "RS256", "kid": "2026-07-a", "typ": "JWT" }
// payload
{
  "iss": "https://iam.example.com",
  "sub": "c3d9…",                        // identities.id — universal subject_id
  "aud": "example-platform",             // config; consumers SHOULD verify
  "exp": 1751629929, "iat": 1751629029,  // 15 min
  "jti": "7f2c…",                        // blacklist key on logout/revoke
  "sid": "S1-uuid",                      // session id — audit correlation + session-level revoke
  "typ": "access",
  "email_verified": true, "status": "ACTIVE",
  "amr": ["pwd"],                        // auth methods: pwd | google | apple | … (+ "otp" when F10 lands)
  // claims-mode additions:
  "roles": ["OrgAdmin"],                 // mode: roles (default)
  "perms": ["invoice.invoice.read", …],  // mode: permissions
  "scope": "s1-uuid"                     //   └ scope those perms were computed at
}
```

Verification contract for consumers: JWKS fetch (cached, re-fetch on unknown `kid`) → verify signature, `iss`, `aud`, `exp`, `typ=access`. Blacklist checking is IAM-internal (introspection endpoint exists for consumers that need live state — flag-gated).

### 5.2 Refresh token — opaque, hashed, rotated

- 256-bit `SecureRandom` → base64url (43 chars). **Not a JWT** — it carries no claims, needs server-side state anyway (rotation chain), and an opaque string eliminates algorithm/parsing attack surface entirely.
- At rest: SHA-256 hash only (`refresh_tokens.token_hash`). A DB dump yields nothing replayable.
- Transport to browsers: `__Host-`-prefixed HttpOnly Secure SameSite=Lax cookie, AES-GCM-encrypted with a dedicated cookie key. Transport to mobile/native: response body field (they store it in the platform keystore) — §14.
- Rotation on every use; reuse ⇒ session death (§4.3).

### 5.3 Claims modes

| Mode | Adds | Trade-off |
|---|---|---|
| `minimal` | nothing beyond identity claims | every check goes to the PDP — maximal freshness |
| `roles` *(default)* | `roles` | coarse local gates (`hasRole`); 15-min staleness bound |
| `permissions` | `perms` + `scope` | small apps skip `/authorize` entirely; token grows; staleness bound applies to permissions themselves |

Staleness in every mode is capped by access TTL (15 min). Deployments needing tighter revocation use introspection or the event stream (AUTHZ §11).

### 5.4 One-time tokens (verify / reset / reactivation)

Redis-only (they're ephemeral by nature), **stored hashed**, single-use (`GETDEL`), typed TTLs: reset 15 min · verification 24 h · reactivation 7 d. Uniform response semantics to prevent account enumeration (§10-T4).

---

## 6. Redis Keyspace

Redis is cache + ephemeral store — **never the source of truth for sessions**.

| Key | Value | TTL | Purpose |
|---|---|---|---|
| `authn:bl:jti:{jti}` | "1" | remaining access-token TTL | access-token blacklist (logout, session/reuse revoke) |
| `authn:rt:{sha256}` | `{sessionId, identityId, head:true}` | refresh TTL | read-through cache of chain-head lookup (miss ⇒ DB) |
| `authn:ott:{type}:{sha256}` | identityId | typed (15 m / 24 h / 7 d) | one-time tokens, `GETDEL` on consume |
| `authn:oauth:xchg:{code}` | `{identityId, sid}` | 60 s | OAuth one-time exchange code (§8.2) |
| `authn:rt:retry:{oldSha256}` | AES-GCM-encrypted successor pair (access + refresh) | `rotation-grace` (60 s) | idempotent retry response for the grace window (§4.3) — encrypted with the cookie key, single-window lifetime |
| `authn:rl:{path}:{ip}` | counter | window (60 s) | rate-limit windows (existing filter) |

Failure mode: Redis down ⇒ **fail closed** for blacklist-dependent operations (introspection, logout) and fall through to DB for refresh (correctness preserved, latency degrades); no in-memory fallback anywhere. `authn.fail-mode` config mirrors AuthZ's (§12).

---

## 7. Account Lifecycle

```
                 register            verify-email
   (nothing) ──────────────▶ ACTIVE(email_verified=false) ──────────▶ ACTIVE
                                                                        │
        5 failed logins (config) ──────────────────────────────────────┤
                 ▼                                                      │
              LOCKED ── auto-unlock after 30 min / admin unlock ───────▶│
                                                                        │
        admin action ──────▶ SUSPENDED ── admin restore ───────────────▶│
                                                                        │
        user/admin ────────▶ DEACTIVATED ── request-reactivation +      │
                                            verify-reactivation ───────▶ ACTIVE
```

- Login requires: `email_verified = true` AND status `ACTIVE` (LOCKED auto-heals if `account_locked_until` passed).
- LOCKED affects **login only** — existing sessions keep refreshing (config `lockout.revoke-sessions: false` default; flip for stricter posture).
- SUSPENDED/DEACTIVATED: all sessions revoked (`ADMIN`), refresh refused, access tokens blacklisted-by-sid on transition.
- Invite flow kept: `verify-email-and-setup-password` — admin-created identity, user sets first password through the verification token.

---

## 8. OAuth2 / Social Login

### 8.1 Providers

Google wired now; Apple/Microsoft = same `OAuth2UserInfo` seam, config-only additions. Whole subsystem behind `iam.features.oauth2` (default off — beans, endpoints, Swagger entries all absent when off).

### 8.2 Callback → tokens: one-time exchange code (replaces `?token=` redirect)

```
1. Browser →  GET /oauth2/authorization/google?redirect_uri=<app>
              redirect_uri MUST match iam.security.allowed-redirect-uris
              (exact-prefix match; empty list ⇒ same-origin only). 400 otherwise.
2. Google round-trip (Spring's state handling; custom state code deleted)
3. Success handler: find-or-create identity → create session →
   code = SecureRandom(128 bit); Redis authn:oauth:xchg:{code} = {identityId, sid}, TTL 60 s
   → 302 <redirect_uri>?code=<code>              ← code in URL, never a token
4. App: POST /api/auth/oauth/exchange {code}
   → GETDEL (single-use) → access token + refresh cookie (or body for mobile)
```

URL/history/Referer/logs now only ever see a dead 60-second single-use code.

### 8.3 Account linking rules (anti-takeover)

| Situation | Action |
|---|---|
| Provider `sub` already linked | login as that identity |
| Email matches existing identity AND provider asserts `email_verified: true` | **link** credential to the identity, `OAUTH_LINKED` security event |
| Email matches but provider does NOT assert verified email | **refuse auto-link** — create nothing, return explicit "sign in with your password, then link in settings" error. (Auto-linking on unverified provider email = account takeover: attacker registers `victim@corp.com` at a lax provider and inherits the victim's identity.) |
| No match | create identity (`email_verified` = provider's assertion), create credential, create session |

Current code auto-links + force-sets `email_verified=true` unconditionally — that's finding #7's silent cousin, fixed by the table above.

---

## 9. Worked Flows

### A — Login (password)

```
POST /api/auth/login { email, password }
① rate-limit gate (IP+path) ② identity lookup → lockout auto-heal check
③ bcrypt verify → fail: counter++, 5th ⇒ LOCKED+30min, event LOGIN_FAILED; uniform error body
④ email_verified? status ACTIVE? ⑤ create session (cap-check, evict LRU if >10)
⑥ mint access (RS256, active kid, claims mode) + opaque refresh
⑦ reset counter, stamp last_login, event LOGIN_SUCCESS
→ 200 { accessToken, expiresIn: 900 } + Set-Cookie: __Host-Refresh=<AES-GCM(refresh)>
   (mobile: { …, refreshToken } instead of cookie — §14)
```

### B — Refresh (rotation)

```
POST /api/auth/refresh   (cookie or body)
① decrypt cookie → token ② SHA-256 → Redis authn:rt cache → miss ⇒ DB by token_hash
③ checks: is chain head, not expired, session alive, identity ACTIVE
④ new refresh row (old.replaced_by = new), new access token (fresh roles from AuthZ)
→ 200 new access + rotated cookie
```

### C — Retry vs reuse

```
Case 1 — honest retry (grace window):
POST /api/auth/refresh with t2, 4 s after rotation (response was lost on mobile network)
⇒ t2.replaced_by = t3, replaced_at 4 s ago ≤ 60 s grace
⇒ return cached successor pair idempotently (same t3 + its access token). Session fine.

Case 2 — replay attack:
POST /api/auth/refresh with t2, 2 days after rotation
⇒ grace exceeded ⇒ session S1 revoked (REUSE_DETECTED), S1's access jti blacklisted,
  security event emitted, 401 {"error":"invalid_token"}
Legitimate laptop's next refresh (t3) now also 401 (session dead) → re-login.
Phone session S2: untouched.
```

### D — Logout / Logout-all

```
POST /api/auth/logout      → revoke sid (from access token), blacklist jti, clear cookie
POST /api/auth/logout-all  → revoke all sessions, blacklist current jti
                             (other devices' access tokens die at ≤15 min; introspection
                              consumers see revocation instantly via sid check)
```

### E — Register + verify

```
POST /api/auth/register { email, password }
→ identity (email_verified=false) + PASSWORD credential
→ one-time token (hashed) TTL 24 h → NotificationPort.sendEmailVerification
→ 200 uniform body (same shape whether email existed or not — §10-T4)
POST /api/auth/verify-email { token } → GETDEL, email_verified=true
```

### F — Password reset

```
POST /api/auth/forgot-password { email }   → uniform 200 always; token only if identity exists
POST /api/auth/reset-password { token, newPassword }
→ GETDEL, bcrypt update, ALL sessions revoked (SECURITY), event PASSWORD_RESET
```

### G — OAuth login

§8.2 flow; sessions/cookies identical to password login from step ⑤ on.

### H — Email change (login handle rotation)

```
POST /api/auth/change-email { newEmail, currentPassword }     (Bearer)
① re-authenticate (password or recent-login check for OAuth-only identities)
② uniqueness check on newEmail (uniform response — no enumeration)
③ one-time token (hashed) TTL 24 h → NotificationPort to the NEW address
④ notification to the OLD address ("email change requested — not you? contact support")
POST /api/auth/verify-email-change { token }
⑤ swap primary_email + PASSWORD credential identifier, event EMAIL_CHANGED,
   sessions kept (re-auth already proved possession)
```

Login handle changes are a top account-takeover target — hence re-auth + verify-new + notify-old, all three.

---

## 10. Security Specification

| # | Threat | Control |
|---|---|---|
| T1 | Token forgery | RS256; private key AES-GCM-encrypted at rest; verifiers hold public keys only |
| T2 | Stolen refresh token | rotation + reuse detection ⇒ session death (§4.3); hashed at rest; HttpOnly+Secure+`__Host-` cookie; AES-GCM cookie encryption |
| T3 | Stolen access token | 15-min TTL; jti blacklist on logout/revoke; `sid` enables session-level kill; introspection for high-security consumers |
| T4 | Account enumeration | register / forgot-password / resend-verification / change-email return uniform bodies; login runs a **dummy bcrypt compare when the user doesn't exist** (identical work ⇒ identical timing) and never distinguishes "no user" from "bad password" |
| T5 | Brute force | per-IP+path rate limit (Redis window) + per-account lockout (5 / 30 min) — two independent layers |
| T6 | Key-reuse blast radius | three independent keys: signing keypair (DB, encrypted), cookie AES key (`IAM_COOKIE_KEY`), key-encryption key (`IAM_KEY_ENCRYPTION_KEY`); losing one ≠ losing all |
| T7 | Cookie theft / CSRF | `__Host-` + Secure (default ON) + HttpOnly + SameSite=Lax; refresh endpoint accepts cookie only from same site; state-changing endpoints are Bearer-authenticated (no cookie-auth for APIs ⇒ CSRF surface ≈ refresh only, which returns tokens to the caller's JS context, useless cross-site) |
| T8 | Redis outage degradation | no silent fallbacks: blacklist checks fail closed; refresh falls through to DB (correct, slower); loud alerts. `fail-mode` config, default closed |
| T9 | OAuth redirect abuse | enforced allowlist (exact-prefix, empty ⇒ same-origin); one-time 60 s exchange code; no tokens in URLs ever |
| T10 | OAuth account takeover | linking matrix §8.3 — no auto-link on unverified provider email |
| T11 | Timing attacks on token compare | all one-time/refresh comparisons via SHA-256-then-lookup (no string compare of secrets); API-key check keeps `MessageDigest.isEqual` |
| T12 | Session fixation | session id minted server-side at login only; never accepted from client input |

---

## 11. API Surface

```
Public (rate-limited):
  POST /api/auth/register                { email, password }
  POST /api/auth/login                   { email, password }
  POST /api/auth/refresh                 cookie (web) or { refreshToken } (mobile)
  POST /api/auth/verify-email            { token }
  POST /api/auth/verify-email-and-setup-password   { token, password }   (invite flow)
  POST /api/auth/resend-verification     { email }
  POST /api/auth/forgot-password         { email }
  POST /api/auth/reset-password          { token, newPassword }
  POST /api/auth/request-reactivation    { email }
  POST /api/auth/verify-reactivation     { token }
  GET  /.well-known/jwks.json            public keys                         [NEW]
  POST /api/auth/oauth/exchange          { code } → tokens                   [NEW, flag oauth2]
  GET  /api/auth/oauth/login/{provider}  entry redirect                      [flag oauth2]

Authenticated (Bearer):
  GET  /api/auth/me                      slim identity (§4.6)
  POST /api/auth/change-password         { currentPassword, newPassword }    (revokes other sessions)
  POST /api/auth/change-email            { newEmail, currentPassword }       [NEW — flow H]
  POST /api/auth/verify-email-change     { token }                           [NEW — flow H]
  POST /api/auth/logout
  POST /api/auth/logout-all
  GET  /api/auth/sessions                my devices: [{id, deviceLabel, createdIp,
                                         lastUsedAt, current}]               [NEW]
  DELETE /api/auth/sessions/{id}         revoke one device                   [NEW]

Service/admin:
  POST /api/v1/keys/rotate               SuperAdmin (F2 dual-control candidate) [NEW]
  POST /api/v1/token/introspect          { token } → active/claims/sid state  [NEW, flag]
                                         (caller auth: service API key / ROLE_INTERNAL — never public)
  GET  /api/v1/token/revocations?since=  revoked sids/jtis feed               [NEW, flag]

Removed: PUT /api/auth/me (profile) — consumer services own profile data.
```

---

## 12. Configuration

```yaml
iam:
  authn:
    token:
      algorithm: RS256               # RS256 | ES256
      claims-mode: roles             # minimal | roles | permissions
      access-ttl: 15m
      refresh-ttl: 7d                # session absolute lifetime
      rotation-grace: 60s            # retry window before rotated-token reuse = theft (§4.3)
      key-source: db                 # db | env-pem
      rotation-cron: ""              # empty = manual only
    session:
      max-per-identity: 10           # LRU eviction beyond this
      sliding-expiry: false          # true = refresh extends expires_at
    lockout:
      max-attempts: 5
      duration: 30m
      revoke-sessions: false         # LOCKED also kills sessions if true
    cookie:
      name: __Host-Refresh
      secure: true                   # DEFAULT TRUE (dev profile overrides w/ plain name)
      same-site: Lax
      encryption-key: ${IAM_COOKIE_KEY}          # independent key
    keys:
      encryption-key: ${IAM_KEY_ENCRYPTION_KEY}  # encrypts private_key at rest
    security:
      allowed-redirect-uris: ${IAM_ALLOWED_REDIRECTS:}   # empty ⇒ same-origin only
      fail-mode: closed
    rate-limit:
      max-requests: 10
      window: 60s

  features:
    oauth2: false
    introspection: false
    revocation-feed: false

notification:
  adapter: log                       # log | smtp | webhook
  webhook-url: ${IAM_NOTIFY_WEBHOOK:}
```

`NotificationPort`: `sendEmailVerification / sendPasswordReset / sendReactivation`. Adapters: `log` (dev default), `smtp`, `webhook` (POST to deployment's own notification service — zero code changes for custom channels).

---

## 13. Migration Diff Summary (Current → Proposed)

| Object | Action |
|---|---|
| `sessions` | **CREATE** |
| `refresh_tokens` | **REBUILD** — becomes rotation-chain table under sessions (`session_id`, `replaced_by`); old rows not migrated (all users re-login once — acceptable for a template; deployments in flight can run both flows during a grace window) |
| `signing_keys` | **CREATE** + bootstrap keygen on first start |
| `identity_profiles` | **DROP** (+ entity, repository, controller, 2 DTOs, service touches) |
| `identities`, `credentials` | **UNCHANGED** |
| `security_events` | event-type CHECK extended (+`SESSION_EVICTED`, `REUSE_DETECTED`, `OAUTH_LINKED`, `EMAIL_CHANGED`) |
| Redis keyspace | **REPLACE** `RedisTokenService` scheme with §6 keys; in-memory fallback deleted; one-time tokens stored hashed |
| Code deletions | `RefreshTokenBlacklistServiceImpl` (DB is now primary — merged into session service), `JwtTokenProvider` dead methods, custom OAuth state code, `TokenEncryptionUtil` key-derivation-from-JWT-secret (replaced by dedicated key) |
| JWT | HS256 shared secret → RS256 + JWKS; refresh JWT → opaque |

This shipped after the AuthZ schema flexibility work; the two modules are independent.

---

## 14. Integration Profiles

| Profile | Access token | Refresh transport | Notes |
|---|---|---|---|
| **SPA (web)** | memory only (never localStorage) | `__Host-` cookie, auto-sent to `/api/auth/refresh` only | XSS steals at most one 15-min token; CSRF bounded per T7 |
| **Mobile / native** | memory | response body → platform keystore (Keychain/Keystore) | send in `refresh` body; no cookies involved |
| **Machine-to-machine** | service JWT via API key or client-credentials-style issuance against `services` registry (AUTHZ §4.11) | n/a — no refresh; mint per need, short TTL | subjects look like `service:billing` |
| **Consumer service (verifier)** | verify via JWKS locally; optional introspection for sensitive ops | n/a | never holds signing material |

---

## 15. Known Boundaries

| Boundary | Status | Pattern |
|---|---|---|
| **Not a certified OIDC Provider** — IAM issues tokens for *your* fleet; it does not implement the full OIDC/OAuth2 AS spec (discovery doc, all grant types, consent screens) for arbitrary third-party clients | deliberate — full OIDC AS is a product in itself (Keycloak/Ory exist) | third-party federation need ⇒ front IAM with a real OIDC AS, or future enhancement if demand is real |
| **Native MFA** | deferred — F10; seam ready (`mfa_enabled`, `amr` claim, L3 `require_mfa` condition) | upstream IdP asserts MFA via OAuth `amr` meanwhile |
| **SCIM / directory sync** | not planned until an enterprise adopter needs AD/Okta user provisioning | manifest-style sync could extend to identities; future-doc entry when triggered |
| **Passwordless (magic links / passkeys)** | not in v1 | magic-link ≈ one-time-token flow already 80 % built; passkeys ride F10's WebAuthn work |
| **Refresh-token client binding (DPoP / mTLS)** | not in v1 — a refresh token stolen *from the device keystore itself* is usable elsewhere until reuse detection fires | rotation + reuse detection bounds the damage window; DPoP is the standards-track answer if a deployment's threat model requires possession proof — future-doc candidate |

---

*End of authentication design.*
