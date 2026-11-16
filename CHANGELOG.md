# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/) (pre-1.0: minor versions may change behaviour).

## [0.3.1] - 2026-11-16

### Security

- A global role created after install (no owner scope, not a system role)
  could be shadowed by a tenant role with the same name, which then carried the
  same `ROLE_<name>` authority. A global role's name now only counts when it
  comes from that global role.
- A redirect allowlist entry without a port accepted the same host on any port.
  It now means the scheme's default port (443 / 80).

## [0.3.0] - 2026-11-16

Multi-factor authentication, single sign-on across apps, admin audit and a
stricter password policy.

### Upgrade notes

- **Login responses changed shape** for MFA users. `POST /api/auth/login` and
  `POST /api/auth/oauth/exchange` return tokens as before, or
  `{status: "MFA_REQUIRED", challenge}` / `{status: "MFA_ENROLLMENT_REQUIRED",
  enrollmentToken}`. Clients that only read `accessToken` keep working for
  users without MFA; handle the two statuses before anyone enables it.
- **Password policy:** every path that sets a password now requires 8–72
  characters with at least one letter and one digit (register was 6, reset and
  invite setup had no rule).
- **Password reset and change end every session** of the account, including
  the caller's. A completed reset also marks the email verified.
- **`reset-password` takes a JSON body** `{token, newPassword}`. Query
  parameters still work but are deprecated (they end up in access logs).
- **Mail adapters run asynchronously.** `NotificationPort` calls no longer
  block the request; a failing adapter must log its own errors.
- `PUT /api/v1/identities/{id}/status` had no route in 0.2.0 (a misplaced
  annotation) and works again. Status, email-verified and display-name can no
  longer be changed on a SuperAdmin by anyone else.
- OAuth exchange codes issued by 0.2.0 (60-second lifetime) are not accepted
  after the upgrade.
- **New migrations:** `V9__mfa.sql`, `V10__admin_audit.sql`,
  `V11__identity_display_name.sql`, `V12__security_event_email_verified.sql`.

### Added

- **MFA:** TOTP (RFC 6238) with ten single-use recovery codes —
  `/api/auth/mfa/setup|enable|disable|recovery-codes` and the second login step
  `/api/auth/mfa/verify`. `IAM_MFA_REQUIRED_ROLES` forces enrollment for the
  listed roles. Admin reset for a lost device: `DELETE /api/v1/identities/{id}/mfa`.
- **`amr` claim** on access tokens (`pwd`, the OAuth provider, plus `otp` and
  `mfa` after a second factor), kept across refreshes.
- **Single sign-on:** `GET /api/auth/sso/authorize` gives an allowlisted app a
  one-time code from the user's existing IAM session (`prompt=none` for silent
  checks, optional per-app consent via `iam.sso.consent-url`). The app exchanges
  it at `/api/auth/oauth/exchange` and gets its own session with the same `amr`.
- **Admin audit:** every successful admin write under `/api/v1/*` is recorded
  (`GET /api/v1/audit/admin-actions`), and the security event log is readable
  (`GET /api/v1/audit/security-events`).
- **Identity admin:** credentials view, mark email verified, display names
  (captured at registration, editable by admins, returned in `/me/bootstrap`),
  and role delete (`DELETE /api/v1/roles/{id}`).
- **Paging:** identities, assignments and audit listings accept page
  parameters; new paged endpoints return `{content, totalElements, totalPages,
  number, size}`.
- Optional breached-password check (`IAM_PASSWORD_BREACH_CHECK`, off by
  default; k-anonymity, fails open).
- Clear message for an expired or already-used verification link.
- **Console:** MFA sign-in step, forced enrollment and a two-factor card;
  permission tree and full-page role editor; roles on the scope tree; catalog
  pickers instead of pasted ids; selective session logout; user detail with
  diagnostics; admin audit page; role delete; display names; follows the SSO
  `continue` link after sign-in.

### Security

- Social login cannot skip the second factor; SSO codes are only minted from a
  session that passed it, and the check runs again at authorize time.
- Brute-force limits on every code-checking endpoint: per-IP rate limit, 5
  wrong codes per challenge, 10 per account per 15 minutes, no TOTP step
  replay, no re-enrollment over an active authenticator.

### Fixed

- Adding your own `NotificationPort` could leave two candidates and stop the app
  from starting; the built-in log adapter is now a true fallback.
- The console's refresh-and-retry skipped `/api/auth/sessions`, so an expired
  token there never refreshed.
- The console no longer depends on `zod` directly; the copy pulled in by the
  router build plugin is pinned to 4.6.6+ (memory-exhaustion advisory).

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

[0.3.1]: https://github.com/mesubash/spring-iam/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/mesubash/spring-iam/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/mesubash/spring-iam/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/mesubash/spring-iam/releases/tag/v0.1.0
