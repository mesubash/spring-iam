# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/) (pre-1.0: minor versions may change behaviour).

## [0.2.0] - 2026-11-16

A security release. Upgrading is recommended for every deployment.

### Upgrade notes

- **Behaviour changes.** Read these before upgrading:
  - Access tokens now carry `iss` (`APP_JWT_ISSUER`, default `spring-iam`) and
    tokens without it are rejected. Tokens issued before the upgrade stop
    working, so users sign in again once (access tokens last 15 minutes anyway).
  - Rate limiting now **fails closed** when Redis is unreachable. Set
    `IAM_RATELIMIT_FAIL_MODE=open` for the old behaviour.
  - `APP_JWT_SECRET` no longer has a built-in default. If you relied on it, set
    it explicitly; otherwise a random secret is generated on each boot (fine for
    a single instance, but OAuth state cookies won't survive a restart).
  - `resend-verification` and `request-reactivation` return success for unknown
    or ineligible accounts instead of 404/400.
  - The client IP is now the **rightmost** `X-Forwarded-For` hop. Run exactly one
    trusted reverse proxy in front of the service.
  - The OAuth state cookies honour `APP_COOKIE_SECURE` (default `true`) and
    `APP_COOKIE_DOMAIN`. Local plain-HTTP OAuth needs `APP_COOKIE_SECURE=false`.
- **New migration:** `V8__last_failed_login_at.sql` (one nullable column).
- **NotificationPort** gained `sendAccountLocked(email)` as a default no-op
  method. Custom adapters keep compiling; override it to email the user.

### Security

- Role names could be spoofed into authorities. A tenant admin could create a
  role named `SuperAdmin` (or any built-in name) in their own subtree, assign it
  to themselves and pass every `@PreAuthorize` check for the built-in role. Only
  the built-in roles now contribute built-in names.
- `SuperAdmin` assigned at a scope other than ROOT became a global authority. It
  now only counts at ROOT, and such grants are refused.
- Lower administrators (SecurityAdmin, CountryAdmin) could set a SuperAdmin's
  password or change its status, which amounted to a takeover. Both now require
  a SuperAdmin caller when the target is a SuperAdmin.
- Cached permissions kept authorizing after a timed grant's `expires_at`. Timed
  grants now bypass the permission cache.
- The client IP was taken from the leftmost (client-controlled)
  `X-Forwarded-For` entry, which let callers dodge per-IP rate limits and forge
  audit IPs.
- `app.jwt.secret` defaulted to a constant published in this repository. That
  constant signed OAuth state cookies and, without `IAM_COOKIE_KEY`, keyed
  cookie encryption.
- The OAuth state cookies were never `Secure` (they read config keys that did
  not exist).
- The OAuth redirect allowlist matched paths as raw prefixes, so `/cb` also
  allowed `/cb-anything` and `/cb/../anything`. Paths are now normalized and
  matched on whole segments.
- `/actuator/health` exposed database and Redis component details to anonymous
  callers.
- `X-Content-Type-Options: nosniff` was disabled. It is back on, and the CSP no
  longer allows `unsafe-eval` or inline scripts.
- `resend-verification` and `request-reactivation` revealed whether an account
  existed and what state it was in.

### Fixed

- Replicas starting together on an empty database could each generate a signing
  key. Key bootstrap now holds a Postgres advisory lock.
- After a key rotation, other replicas kept signing with the old key and their
  tokens failed once its grace window ended. The active key is re-checked every
  60 seconds.
- A bracketed IPv6 address, a port suffix or junk in the client IP could abort
  the login transaction. IPs are normalized before every `inet` write.
- The failed-login counter never decayed, so failures spread over days still
  caused a lockout. Lockout now uses a sliding window
  (`iam.account.lockout.window-minutes`, default 15).

### Added

- Automatic signing-key rotation (`IAM_KEY_ROTATION_DAYS`, default 90; `0`
  disables).
- Optional `aud` claim on access tokens (`APP_JWT_AUDIENCE`), enforced when set.
- Refresh-token reuse and session eviction are recorded as security events.
- Account-locked notification hook on `NotificationPort`.

## [0.1.0] - 2026-08-19

First public release.

[0.2.0]: https://github.com/mesubash/spring-iam/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/mesubash/spring-iam/releases/tag/v0.1.0
