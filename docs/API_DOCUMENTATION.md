# Spring IAM — API Documentation

> **Version:** 1.0.0
> **Base URL:** `http://localhost:8080`
> **Content-Type:** `application/json`
>
> This document is the single source of truth for all Spring IAM APIs.
> Update this document whenever an API changes.

---

## Table of Contents

1. [Authentication](#authentication)
2. [Authentication (AuthN) APIs](#1-authentication-authn-apis)
3. [Authorization — Runtime APIs](#2-authorization--runtime-apis)
4. [Authorization — User-Facing APIs](#3-authorization--user-facing-apis)
5. [Permissions Management](#4-permissions-management)
6. [Roles Management](#5-roles-management)
7. [Scopes Management](#6-scopes-management)
8. [Assignments Management](#7-assignments-management)
9. [Deny Rules Management](#8-deny-rules-management)
10. [Policies Management](#9-policies-management)
11. [Role Hierarchy](#10-role-hierarchy)
12. [Permission Groups](#11-permission-groups)
13. [Audit](#12-audit)
14. [Health & Metrics](#13-health--metrics)
15. [Assignment Conditions Reference](#assignment-conditions-reference)
16. [Policy Conditions Reference](#policy-conditions-reference)
17. [Error Response Format](#error-response-format)
18. [Changelog](#changelog)

---

## Authentication

Spring IAM supports two authentication mechanisms:

| Mechanism | Header | Granted Role | Used For |
|-----------|--------|--------------|----------|
| API Key | `X-Internal-Api-Key: <key>` | `ROLE_INTERNAL` | `/authorize` endpoints (service-to-service) |
| JWT | `Authorization: Bearer <token>` | Role-based (from assignments) | Admin and user endpoints |

### Public Endpoints (no authentication required)

| Pattern | Description |
|---------|-------------|
| `/api/v1/health/**` | Health checks and metrics |
| `/actuator/**` | Spring Boot Actuator |
| `/swagger-ui/**` | Swagger UI |
| `/api-docs/**` | OpenAPI specification |

---

## 1. Authentication (AuthN) APIs

All endpoints grouped under `/api/auth/`.

---

### POST /api/auth/register

Register a new user account.

**Auth:** Public (no authentication required)

#### Request Body

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `fullName` | string | Yes | 2-100 characters | User's full display name |
| `email` | string | Yes | Valid email format | User's email address (unique) |
| `password` | string | Yes | Minimum 6 characters | Account password |

#### Example Request

```http
POST /api/auth/register HTTP/1.1
Content-Type: application/json

{
  "fullName": "Jane Doe",
  "email": "jane.doe@example.com",
  "password": "securePass123"
}
```

#### Example Response — `201 Created`

```json
{
  "success": true,
  "message": "Registration successful. Please check your email to verify your account.",
  "timestamp": "2026-04-06T10:00:00Z"
}
```

#### Notes

- A verification email is sent upon successful registration.
- Duplicate email addresses return `400 Bad Request`.
- The user cannot log in until email is verified.

---

### POST /api/auth/login

Authenticate a user and receive a JWT access token.

**Auth:** Public (no authentication required)
**Rate Limited:** Yes

#### Request Body

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `email` | string | Yes | Valid email format | Registered email |
| `password` | string | Yes | Non-empty | Account password |

#### Example Request

```http
POST /api/auth/login HTTP/1.1
Content-Type: application/json

{
  "email": "jane.doe@example.com",
  "password": "securePass123"
}
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI1NTBl...",
    "tokenType": "Bearer",
    "expiresIn": 900,
    "identity": {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "email": "jane.doe@example.com",
      "displayName": "Jane Doe",
      "emailVerified": true
    }
  },
  "timestamp": "2026-04-06T10:00:00Z"
}
```

#### Notes

- Sets an `HttpOnly` cookie `__Host-Session-Id` containing the refresh token.
- `expiresIn` is in seconds.
- Failed login attempts are tracked for rate limiting.
- Deactivated accounts receive a `403 Forbidden` response with reactivation instructions.

---

### POST /api/auth/refresh

Refresh an access token using the refresh token cookie.

**Auth:** Requires `__Host-Session-Id` HttpOnly cookie (set during login)

#### Request Body

None. The refresh token is read from the HttpOnly cookie.

#### Example Request

```http
POST /api/auth/refresh HTTP/1.1
Cookie: __Host-Session-Id=dGhpcyBpcyBhIHJlZnJlc2ggdG9rZW4...
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI1NTBl...",
    "tokenType": "Bearer",
    "expiresIn": 900,
    "identity": {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "email": "jane.doe@example.com",
      "displayName": "Jane Doe",
      "emailVerified": true
    }
  },
  "timestamp": "2026-04-06T10:01:00Z"
}
```

#### Notes

- A new `__Host-Session-Id` cookie is set (token rotation).
- The old refresh token is invalidated.
- Returns `401 Unauthorized` if the cookie is missing, expired, or revoked.

---

### POST /api/auth/logout

Log out the current user and clear the session cookie.

**Auth:** Bearer JWT required

#### Request Body

None.

#### Example Request

```http
POST /api/auth/logout HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "message": "Logged out successfully.",
  "timestamp": "2026-04-06T10:05:00Z"
}
```

#### Notes

- Clears the `__Host-Session-Id` cookie.
- Revokes the current refresh token only.
- The JWT access token remains valid until it expires (short-lived by design).

---

### POST /api/auth/logout-all

Revoke all refresh tokens for the current user (log out of all devices).

**Auth:** Bearer JWT required

#### Request Body

None.

#### Example Request

```http
POST /api/auth/logout-all HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "message": "All sessions have been revoked.",
  "timestamp": "2026-04-06T10:06:00Z"
}
```

#### Notes

- Revokes ALL refresh tokens for the authenticated user.
- Existing JWT access tokens remain valid until their natural expiry.
- Use this when a user suspects account compromise.

---

### POST /api/auth/verify-email

Verify a user's email address.

**Auth:** Public

#### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `token` | string | Yes | Email verification token (from email link) |

#### Example Request

```http
POST /api/auth/verify-email?token=abc123def456 HTTP/1.1
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "message": "Email verified successfully.",
  "timestamp": "2026-04-06T10:07:00Z"
}
```

#### Notes

- Tokens are single-use and expire after a configured duration.
- Returns `400 Bad Request` for invalid or expired tokens.

---

### POST /api/auth/verify-email-and-setup-password

Verify email and set initial password in one step. Designed for invited users.

**Auth:** Public

#### Request Body

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `token` | string | Yes | Non-empty | Email verification token |
| `newPassword` | string | Yes | Minimum 6 characters | Initial password |

#### Example Request

```http
POST /api/auth/verify-email-and-setup-password HTTP/1.1
Content-Type: application/json

{
  "token": "abc123def456",
  "newPassword": "mySecurePassword123"
}
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "message": "Email verified and password set successfully.",
  "timestamp": "2026-04-06T10:08:00Z"
}
```

#### Notes

- Intended for users who were invited by an admin and do not yet have a password.
- The token must be a valid, unexpired email verification token.
- After this call, the user can log in normally.

---

### POST /api/auth/resend-verification

Resend the email verification link.

**Auth:** Public
**Rate Limited:** Yes

#### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `email` | string | Yes | Registered email address |

#### Example Request

```http
POST /api/auth/resend-verification?email=jane.doe@example.com HTTP/1.1
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "message": "Verification email sent.",
  "timestamp": "2026-04-06T10:09:00Z"
}
```

#### Notes

- Always returns `200 OK` regardless of whether the email exists (prevents user enumeration).
- Rate limited to prevent abuse.

---

### POST /api/auth/forgot-password

Request a password reset link.

**Auth:** Public
**Rate Limited:** Yes

#### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `email` | string | Yes | Registered email address |

#### Example Request

```http
POST /api/auth/forgot-password?email=jane.doe@example.com HTTP/1.1
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "message": "If an account with that email exists, a password reset link has been sent.",
  "timestamp": "2026-04-06T10:10:00Z"
}
```

#### Notes

- Always returns `200 OK` regardless of whether the email exists (prevents user enumeration).
- The reset token is sent via email and expires after a configured duration.

---

### POST /api/auth/reset-password

Reset password using a token from the forgot-password email.

**Auth:** Public
**Rate Limited:** Yes

#### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `token` | string | Yes | Password reset token |
| `newPassword` | string | Yes | New password (minimum 6 characters) |

#### Example Request

```http
POST /api/auth/reset-password?token=resetToken123&newPassword=newSecurePass456 HTTP/1.1
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "message": "Password reset successfully.",
  "timestamp": "2026-04-06T10:11:00Z"
}
```

#### Notes

- The reset token is single-use and expires after a configured duration.
- All existing refresh tokens for the user are revoked after a successful reset.

---

### POST /api/auth/change-password

Change the password for the currently authenticated user.

**Auth:** Bearer JWT required

#### Request Body

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `currentPassword` | string | Yes | Non-empty | Current account password |
| `newPassword` | string | Yes | Minimum 8 characters | New password |
| `confirmPassword` | string | Yes | Must match `newPassword` | Password confirmation |

#### Example Request

```http
POST /api/auth/change-password HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
Content-Type: application/json

{
  "currentPassword": "oldPassword123",
  "newPassword": "newSecurePass456",
  "confirmPassword": "newSecurePass456"
}
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "message": "Password changed successfully.",
  "timestamp": "2026-04-06T10:12:00Z"
}
```

#### Notes

- Returns `400 Bad Request` if `currentPassword` is incorrect.
- Returns `400 Bad Request` if `newPassword` and `confirmPassword` do not match.
- All existing refresh tokens for the user are revoked after a successful change.

---

### POST /api/auth/request-reactivation

Request account reactivation for a deactivated account.

**Auth:** Public
**Rate Limited:** Yes

#### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `email` | string | Yes | Email of the deactivated account |

#### Example Request

```http
POST /api/auth/request-reactivation?email=jane.doe@example.com HTTP/1.1
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "message": "If the account is deactivated, a reactivation link has been sent.",
  "timestamp": "2026-04-06T10:13:00Z"
}
```

#### Notes

- Always returns `200 OK` regardless of account status (prevents user enumeration).
- Only works for accounts that have been deactivated.

---

### POST /api/auth/verify-reactivation

Verify the reactivation token and reactivate the account.

**Auth:** Public

#### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `token` | string | Yes | Reactivation verification token |

#### Example Request

```http
POST /api/auth/verify-reactivation?token=reactivationToken789 HTTP/1.1
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "message": "Account reactivated successfully. You may now log in.",
  "timestamp": "2026-04-06T10:14:00Z"
}
```

#### Notes

- The token is single-use and expires after a configured duration.
- After reactivation, the user can log in with their existing credentials.

---

### GET /api/auth/me

Get the profile of the currently authenticated user.

**Auth:** Bearer JWT required

#### Example Request

```http
GET /api/auth/me HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "jane.doe@example.com",
    "emailVerified": true,
    "displayName": "Jane Doe",
    "phone": "+977-9841234567",
    "country": "Nepal",
    "avatarUrl": "https://cdn.example.com/avatars/jane.png",
    "lastLoginAt": "2026-04-06T09:55:00Z",
    "createdAt": "2026-01-15T08:30:00Z"
  },
  "timestamp": "2026-04-06T10:15:00Z"
}
```

#### Response Fields

| Field | Type | Nullable | Description |
|-------|------|----------|-------------|
| `id` | UUID | No | User's unique identifier |
| `email` | string | No | User's email |
| `emailVerified` | boolean | No | Whether email has been verified |
| `displayName` | string | Yes | Display name |
| `phone` | string | Yes | Phone number |
| `country` | string | Yes | Country |
| `avatarUrl` | string | Yes | URL to avatar image |
| `lastLoginAt` | ISO-8601 | Yes | Last login timestamp |
| `createdAt` | ISO-8601 | No | Account creation timestamp |

---

### PUT /api/auth/me

Update the profile of the currently authenticated user.

**Auth:** Bearer JWT required

#### Request Body

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `displayName` | string | No | Max 150 characters | Display name |
| `phone` | string | No | Max 30 characters | Phone number |
| `country` | string | No | Max 100 characters | Country |
| `avatarUrl` | string | No | Max 500 characters | URL to avatar image |

#### Example Request

```http
PUT /api/auth/me HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
Content-Type: application/json

{
  "displayName": "Jane M. Doe",
  "country": "Nepal"
}
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "jane.doe@example.com",
    "emailVerified": true,
    "displayName": "Jane M. Doe",
    "phone": "+977-9841234567",
    "country": "Nepal",
    "avatarUrl": "https://cdn.example.com/avatars/jane.png",
    "lastLoginAt": "2026-04-06T09:55:00Z",
    "createdAt": "2026-01-15T08:30:00Z"
  },
  "timestamp": "2026-04-06T10:16:00Z"
}
```

#### Notes

- Only provided fields are updated; omitted fields remain unchanged.
- Email cannot be changed through this endpoint.

---

### GET /api/auth/oauth/providers

List supported OAuth providers.

**Auth:** Public

#### Example Request

```http
GET /api/auth/oauth/providers HTTP/1.1
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "data": [
    {
      "name": "google",
      "displayName": "Google",
      "authorizationUrl": "/api/auth/oauth/login/google"
    },
    {
      "name": "github",
      "displayName": "GitHub",
      "authorizationUrl": "/api/auth/oauth/login/github"
    }
  ],
  "timestamp": "2026-04-06T10:17:00Z"
}
```

---

### GET /api/auth/oauth/login/{provider}

Initiate OAuth login flow by redirecting to the provider.

**Auth:** Public

#### Path Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `provider` | string | Yes | OAuth provider name (e.g. `google`, `github`) |

#### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `redirectUri` | string | No | URL to redirect to after OAuth completes |

#### Example Request

```http
GET /api/auth/oauth/login/google?redirectUri=https://app.example.com/dashboard HTTP/1.1
```

#### Response — `302 Found`

Redirects to the OAuth provider's authorization page.

```
HTTP/1.1 302 Found
Location: https://accounts.google.com/o/oauth2/auth?client_id=...&redirect_uri=...&scope=openid+email+profile
```

#### Notes

- After the user authenticates with the OAuth provider, they are redirected back to the application.
- On successful OAuth, a JWT is issued and a `__Host-Session-Id` cookie is set, same as login.
- Returns `404 Not Found` if the provider is not supported.

---

## 2. Authorization — Runtime APIs

These endpoints are the core of the IAM system. They evaluate whether a subject is authorized to perform an action.

---

### POST /api/v1/authorize

Evaluate a single authorization request. This is the most critical endpoint in the system.

**Auth:** API Key (`X-Internal-Api-Key`) or Bearer JWT with `ROLE_INTERNAL`, `SuperAdmin`, or `CountryAdmin`
**Performance Target:** <5ms latency, 10K-100K req/sec

#### Request Body

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `subject` | string | Yes | Non-empty | Subject identifier (usually user ID) |
| `permission` | string | Yes | Non-empty, dotted format | Permission key (e.g. `platform.role.create`) |
| `resource` | object | Yes | — | Resource being accessed |
| `resource.type` | string | No | — | Resource type (e.g. `role`, `user`) |
| `resource.id` | string | No | — | Resource instance ID |
| `resource.scopeId` | UUID | Yes | Valid UUID | Scope UUID for scope-based evaluation |
| `resource.metadata` | object | No | — | Key-value metadata for policy evaluation |
| `context` | object | No | — | Request context |
| `context.timestamp` | ISO-8601 | No | Valid datetime | Request time |
| `context.ipAddress` | string | No | Valid IP | Auto-populated from `X-Forwarded-For` if not provided |
| `context.userAgent` | string | No | — | Auto-populated from `User-Agent` header if not provided |
| `context.sessionId` | string | No | — | Session identifier |
| `context.requestId` | string | No | — | Correlation ID for tracing |
| `context.additionalContext` | object | No | — | Extra data (e.g. `{"mfa": true}`) |

#### Example Request — ALLOW scenario

```http
POST /api/v1/authorize HTTP/1.1
X-Internal-Api-Key: sk-internal-abc123
Content-Type: application/json

{
  "subject": "550e8400-e29b-41d4-a716-446655440000",
  "permission": "platform.role.read",
  "resource": {
    "type": "role",
    "id": "role-001",
    "scopeId": "d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f90"
  },
  "context": {
    "ipAddress": "10.0.1.50",
    "requestId": "req-abc-123",
    "additionalContext": {
      "mfa": true
    }
  }
}
```

#### Example Response — ALLOW `200 OK`

```json
{
  "authorized": true,
  "reason": "Permission granted via role 'CountryAdmin' at scope 'Nepal HQ'",
  "effectivePermissions": [
    "platform.role.read",
    "platform.role.create",
    "platform.role.update"
  ],
  "auditId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "timestamp": "2026-04-06T10:20:00.005Z",
  "latencyMs": 3
}
```

#### Example Request — DENY scenario

```http
POST /api/v1/authorize HTTP/1.1
X-Internal-Api-Key: sk-internal-abc123
Content-Type: application/json

{
  "subject": "550e8400-e29b-41d4-a716-446655440000",
  "permission": "platform.user.delete",
  "resource": {
    "type": "user",
    "id": "user-999",
    "scopeId": "d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f90"
  },
  "context": {
    "ipAddress": "203.0.113.50",
    "requestId": "req-def-456"
  }
}
```

#### Example Response — DENY `200 OK`

```json
{
  "authorized": false,
  "reason": "Deny rule active: 'Suspended pending investigation' (ref: TICKET-4521)",
  "effectivePermissions": [],
  "auditId": "f9e8d7c6-b5a4-3210-fedc-ba9876543210",
  "timestamp": "2026-04-06T10:20:01.002Z",
  "latencyMs": 2
}
```

#### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `authorized` | boolean | The authorization decision |
| `reason` | string | Human-readable explanation of the decision |
| `effectivePermissions` | string[] | Permissions the subject holds at the given scope |
| `auditId` | UUID | Reference to the audit log record |
| `timestamp` | ISO-8601 | Server timestamp of the decision |
| `latencyMs` | long | Processing time in milliseconds |

#### Notes

- Returns `200 OK` for both ALLOW and DENY decisions. A DENY is not an HTTP error; it is a valid authorization response.
- Returns `503 Service Unavailable` only for infrastructure errors (cache failure, DB unreachable). This is NOT a security denial.
- Evaluation order: deny rules > policies > role-based permissions > default deny.
- Results are heavily cached. Cache invalidation happens on assignment/deny-rule changes.

---

### POST /api/v1/authorize/batch

Evaluate multiple authorization requests in a single call.

**Auth:** API Key (`X-Internal-Api-Key`) or Bearer JWT with `ROLE_INTERNAL`, `SuperAdmin`, or `CountryAdmin`

#### Request Body

Array of authorization request objects (same schema as single authorize). Maximum **50 items** per batch.

#### Example Request

```http
POST /api/v1/authorize/batch HTTP/1.1
X-Internal-Api-Key: sk-internal-abc123
Content-Type: application/json

[
  {
    "subject": "550e8400-e29b-41d4-a716-446655440000",
    "permission": "platform.role.read",
    "resource": {
      "type": "role",
      "scopeId": "d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f90"
    }
  },
  {
    "subject": "550e8400-e29b-41d4-a716-446655440000",
    "permission": "platform.user.create",
    "resource": {
      "type": "user",
      "scopeId": "d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f90"
    }
  },
  {
    "subject": "550e8400-e29b-41d4-a716-446655440000",
    "permission": "platform.report.export",
    "resource": {
      "type": "report",
      "id": "report-42",
      "scopeId": "d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f90"
    }
  }
]
```

#### Example Response — `200 OK`

```json
{
  "platform.role.read:": {
    "authorized": true,
    "reason": "Permission granted via role 'CountryAdmin'",
    "effectivePermissions": ["platform.role.read"],
    "auditId": "a1b2c3d4-0001-0000-0000-000000000001",
    "timestamp": "2026-04-06T10:21:00.003Z",
    "latencyMs": 2
  },
  "platform.user.create:": {
    "authorized": true,
    "reason": "Permission granted via role 'CountryAdmin'",
    "effectivePermissions": ["platform.user.create"],
    "auditId": "a1b2c3d4-0001-0000-0000-000000000002",
    "timestamp": "2026-04-06T10:21:00.004Z",
    "latencyMs": 1
  },
  "platform.report.export:report-42": {
    "authorized": false,
    "reason": "No matching permission found at scope",
    "effectivePermissions": [],
    "auditId": "a1b2c3d4-0001-0000-0000-000000000003",
    "timestamp": "2026-04-06T10:21:00.004Z",
    "latencyMs": 1
  }
}
```

#### Notes

- Response is a map keyed by `"permission:resourceId"`.
- If `resourceId` is null/empty, the key is `"permission:"`.
- Maximum 50 items per batch. Exceeding this returns `400 Bad Request`.
- Each item in the batch is evaluated independently.

---

### POST /api/v1/effective-permissions

Retrieve all effective permissions for a subject at a given scope.

**Auth:** API Key (`X-Internal-Api-Key`) or Bearer JWT with `ROLE_INTERNAL`, `SuperAdmin`, or `CountryAdmin`

#### Request Body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `subject` | string | Yes | Subject identifier |
| `scopeId` | UUID | Yes | Scope to evaluate at |
| `resource` | object | No | Resource filter (same schema as authorize) |
| `context` | object | No | Request context (same schema as authorize) |
| `includeDenied` | boolean | No | If `true`, includes denied permissions in response |

#### Example Request

```http
POST /api/v1/effective-permissions HTTP/1.1
X-Internal-Api-Key: sk-internal-abc123
Content-Type: application/json

{
  "subject": "550e8400-e29b-41d4-a716-446655440000",
  "scopeId": "d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f90",
  "includeDenied": true
}
```

#### Example Response — `200 OK`

```json
{
  "subject": "550e8400-e29b-41d4-a716-446655440000",
  "scopeId": "d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f90",
  "permissions": [
    "platform.role.read",
    "platform.role.create",
    "platform.role.update",
    "platform.user.read",
    "platform.user.create"
  ],
  "deniedPermissions": [
    "platform.user.delete",
    "platform.config.update"
  ]
}
```

#### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `subject` | string | The subject identifier |
| `scopeId` | UUID | The scope evaluated |
| `permissions` | Set\<string\> | Granted permission keys |
| `deniedPermissions` | Set\<string\> | Denied permission keys (only if `includeDenied=true`) |

---

## 3. Authorization — User-Facing APIs

Endpoints for the authenticated user to query their own authorization state.

---

### GET /api/authz/me/scopes

Get all scopes where the current user has role assignments. Useful for building an organization switcher UI.

**Auth:** Bearer JWT required

#### Example Request

```http
GET /api/authz/me/scopes HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "data": [
    {
      "id": "d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f90",
      "type": "COUNTRY",
      "name": "Nepal HQ",
      "code": "NP"
    },
    {
      "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "type": "ORG",
      "name": "Kathmandu Office",
      "code": "KTM-01"
    }
  ],
  "timestamp": "2026-04-06T10:25:00Z"
}
```

---

### GET /api/authz/me/permissions

Get all permission keys the current user holds at a given scope.

**Auth:** Bearer JWT required

#### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `scopeId` | UUID | Yes | Scope to evaluate permissions at |

#### Example Request

```http
GET /api/authz/me/permissions?scopeId=d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f90 HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "data": [
    "platform.role.read",
    "platform.role.create",
    "platform.user.read",
    "platform.user.create",
    "platform.report.read"
  ],
  "timestamp": "2026-04-06T10:26:00Z"
}
```

---

## 4. Permissions Management

CRUD operations for permission definitions.

**Auth:** All endpoints require Bearer JWT with `SuperAdmin` role.

---

### GET /api/v1/permissions

List all permissions, optionally filtered by domain.

#### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `domain` | string | No | Filter by domain (e.g. `platform`, `billing`) |

#### Example Request

```http
GET /api/v1/permissions?domain=platform HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "data": [
    {
      "id": "b1c2d3e4-f5a6-7890-bcde-f12345678901",
      "key": "platform.role.create",
      "domain": "platform",
      "resource": "role",
      "action": "create",
      "description": "Create new roles"
    },
    {
      "id": "c2d3e4f5-a6b7-8901-cdef-234567890123",
      "key": "platform.role.read",
      "domain": "platform",
      "resource": "role",
      "action": "read",
      "description": "View roles"
    }
  ],
  "timestamp": "2026-04-06T10:30:00Z"
}
```

---

### GET /api/v1/permissions/{id}

Get a single permission by ID.

#### Path Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | UUID | Yes | Permission ID |

#### Example Request

```http
GET /api/v1/permissions/b1c2d3e4-f5a6-7890-bcde-f12345678901 HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "data": {
    "id": "b1c2d3e4-f5a6-7890-bcde-f12345678901",
    "key": "platform.role.create",
    "domain": "platform",
    "resource": "role",
    "action": "create",
    "description": "Create new roles"
  },
  "timestamp": "2026-04-06T10:31:00Z"
}
```

---

### POST /api/v1/permissions

Create one or more permissions. Accepts a single object OR an array for batch creation.

#### Request Body — Single

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `key` | string | Yes | Regex: `^[a-z_]+\.[a-z_]+\.[a-z_]+$` | Permission key in `domain.resource.action` format |
| `domain` | string | Yes | Non-empty | Domain category (e.g. `platform`, `billing`) |
| `resource` | string | Yes | Non-empty | Resource type (e.g. `role`, `user`) |
| `action` | string | Yes | Non-empty | Action verb (e.g. `create`, `read`, `update`, `delete`) |
| `description` | string | No | — | Human-readable description |

#### Example Request — Single

```http
POST /api/v1/permissions HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
Content-Type: application/json

{
  "key": "billing.invoice.create",
  "domain": "billing",
  "resource": "invoice",
  "action": "create",
  "description": "Create new invoices"
}
```

#### Example Request — Batch

```http
POST /api/v1/permissions HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
Content-Type: application/json

[
  {
    "key": "billing.invoice.create",
    "domain": "billing",
    "resource": "invoice",
    "action": "create",
    "description": "Create new invoices"
  },
  {
    "key": "billing.invoice.read",
    "domain": "billing",
    "resource": "invoice",
    "action": "read",
    "description": "View invoices"
  }
]
```

#### Example Response — `201 Created`

```json
{
  "success": true,
  "message": "Permission(s) created successfully.",
  "timestamp": "2026-04-06T10:32:00Z"
}
```

#### Notes

- Permission keys must be globally unique.
- The `key` must follow the `domain.resource.action` format exactly.
- Duplicate keys return `400 Bad Request`.

---

## 5. Roles Management

CRUD operations for role definitions and their permission assignments.

**Auth:**
- **GET** endpoints: Authenticated (any valid JWT).
- **POST/PUT** endpoints: Authenticated + delegation guard (permission ceiling enforced — you cannot grant permissions you do not hold).

---

### GET /api/v1/roles

List all roles, optionally filtered by organization type.

#### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `orgType` | string | No | Filter by organization type |

#### Example Request

```http
GET /api/v1/roles?orgType=COUNTRY HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "data": [
    {
      "id": "e1f2a3b4-c5d6-7890-ef01-234567890abc",
      "name": "CountryAdmin",
      "displayName": "Country Administrator",
      "description": "Full administrative access within a country scope",
      "orgType": "COUNTRY",
      "system": true,
      "permissionIds": [
        "b1c2d3e4-f5a6-7890-bcde-f12345678901",
        "c2d3e4f5-a6b7-8901-cdef-234567890123"
      ]
    }
  ],
  "timestamp": "2026-04-06T10:35:00Z"
}
```

---

### GET /api/v1/roles/{id}

Get a single role by ID.

#### Path Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | UUID | Yes | Role ID |

#### Example Request

```http
GET /api/v1/roles/e1f2a3b4-c5d6-7890-ef01-234567890abc HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "data": {
    "id": "e1f2a3b4-c5d6-7890-ef01-234567890abc",
    "name": "CountryAdmin",
    "displayName": "Country Administrator",
    "description": "Full administrative access within a country scope",
    "orgType": "COUNTRY",
    "system": true,
    "permissionIds": [
      "b1c2d3e4-f5a6-7890-bcde-f12345678901",
      "c2d3e4f5-a6b7-8901-cdef-234567890123"
    ]
  },
  "timestamp": "2026-04-06T10:36:00Z"
}
```

---

### GET /api/v1/roles/{id}/permissions

Get all permissions for a role, including inherited permissions from the role hierarchy.

#### Path Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | UUID | Yes | Role ID |

#### Example Request

```http
GET /api/v1/roles/e1f2a3b4-c5d6-7890-ef01-234567890abc/permissions HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "data": [
    {
      "id": "b1c2d3e4-f5a6-7890-bcde-f12345678901",
      "key": "platform.role.create",
      "domain": "platform",
      "resource": "role",
      "action": "create",
      "inherited": false
    },
    {
      "id": "d4e5f6a7-b8c9-0d1e-2f3a-567890abcdef",
      "key": "platform.role.read",
      "domain": "platform",
      "resource": "role",
      "action": "read",
      "inherited": true
    }
  ],
  "timestamp": "2026-04-06T10:37:00Z"
}
```

#### Notes

- Permissions with `"inherited": true` come from parent roles in the role hierarchy.

---

### POST /api/v1/roles

Create a new role.

#### Request Body

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `name` | string | Yes | Alphanumeric + underscore only | Role name (unique) |
| `displayName` | string | No | — | Human-readable name |
| `description` | string | No | — | Role description |
| `orgType` | string | No | Free-form string | Organization type filter |
| `permissionIds` | UUID[] | No | Valid permission UUIDs | Permissions to assign to this role |

#### Example Request

```http
POST /api/v1/roles HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
Content-Type: application/json

{
  "name": "ReportViewer",
  "displayName": "Report Viewer",
  "description": "Can view reports within their scope",
  "orgType": "ORG",
  "permissionIds": [
    "c2d3e4f5-a6b7-8901-cdef-234567890123"
  ]
}
```

#### Example Response — `201 Created`

```json
{
  "success": true,
  "data": {
    "id": "f1a2b3c4-d5e6-7890-abcd-ef0123456789",
    "name": "ReportViewer",
    "displayName": "Report Viewer",
    "description": "Can view reports within their scope",
    "orgType": "ORG",
    "system": false,
    "permissionIds": [
      "c2d3e4f5-a6b7-8901-cdef-234567890123"
    ]
  },
  "timestamp": "2026-04-06T10:38:00Z"
}
```

#### Notes

- **Permission ceiling enforced:** You cannot assign permissions to a role that you do not yourself hold. Attempting to do so returns `403 Forbidden`.
- Duplicate role names return `400 Bad Request`.

---

### PUT /api/v1/roles/{id}/permissions

Replace the permission set for a role.

#### Path Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | UUID | Yes | Role ID |

#### Request Body

UUID array of permission IDs (replaces the entire permission set).

```json
[
  "b1c2d3e4-f5a6-7890-bcde-f12345678901",
  "c2d3e4f5-a6b7-8901-cdef-234567890123",
  "d4e5f6a7-b8c9-0d1e-2f3a-567890abcdef"
]
```

#### Example Request

```http
PUT /api/v1/roles/f1a2b3c4-d5e6-7890-abcd-ef0123456789/permissions HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
Content-Type: application/json

[
  "b1c2d3e4-f5a6-7890-bcde-f12345678901",
  "c2d3e4f5-a6b7-8901-cdef-234567890123"
]
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "message": "Role permissions updated successfully.",
  "timestamp": "2026-04-06T10:39:00Z"
}
```

#### Notes

- **Cannot modify system roles.** Attempting to modify a system role returns `403 Forbidden`.
- **Permission ceiling enforced:** You cannot assign permissions you do not hold.
- This is a full replacement, not an additive operation. Omitted permissions are removed.

---

## 6. Scopes Management

CRUD operations for scope hierarchy (organizational structure).

**Auth:** All endpoints require Bearer JWT with `SuperAdmin` role.

---

### GET /api/v1/scopes

List all scopes, optionally filtered by type.

#### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `type` | string | No | Scope type filter (e.g. `COUNTRY`, `ORG`) |

#### Example Request

```http
GET /api/v1/scopes?type=COUNTRY HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "data": [
    {
      "id": "d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f90",
      "type": "COUNTRY",
      "name": "Nepal HQ",
      "code": "NP",
      "parentId": "00000000-0000-0000-0000-000000000001",
      "metadata": {
        "region": "South Asia",
        "timezone": "Asia/Kathmandu"
      }
    }
  ],
  "timestamp": "2026-04-06T10:40:00Z"
}
```

---

### GET /api/v1/scopes/{id}

Get a single scope by ID.

#### Path Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | UUID | Yes | Scope ID |

#### Example Request

```http
GET /api/v1/scopes/d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f90 HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "data": {
    "id": "d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f90",
    "type": "COUNTRY",
    "name": "Nepal HQ",
    "code": "NP",
    "parentId": "00000000-0000-0000-0000-000000000001",
    "metadata": {
      "region": "South Asia",
      "timezone": "Asia/Kathmandu"
    }
  },
  "timestamp": "2026-04-06T10:41:00Z"
}
```

---

### GET /api/v1/scopes/{id}/descendants

Get all descendant scopes of a given scope.

#### Path Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | UUID | Yes | Parent scope ID |

#### Example Request

```http
GET /api/v1/scopes/d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f90/descendants HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "data": [
    {
      "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "type": "ORG",
      "name": "Kathmandu Office",
      "code": "KTM-01",
      "parentId": "d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f90"
    },
    {
      "id": "b2c3d4e5-f6a7-8901-bcde-f23456789012",
      "type": "DEPT",
      "name": "Engineering",
      "code": "KTM-ENG",
      "parentId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    }
  ],
  "timestamp": "2026-04-06T10:42:00Z"
}
```

---

### POST /api/v1/scopes

Create a new scope.

#### Request Body

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `type` | string | Yes | One of: `GLOBAL`, `REGION`, `COUNTRY`, `ORG`, `DEPT`, `TEAM`, `PROJECT` | Scope type |
| `name` | string | Yes | Non-empty | Scope name |
| `code` | string | No | Unique if provided | Short code (e.g. `NP`, `KTM-01`) |
| `parentId` | UUID | Conditional | Required for non-`GLOBAL` types | Parent scope ID |
| `metadata` | object | No | Valid JSON | Arbitrary key-value metadata |

#### Example Request

```http
POST /api/v1/scopes HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
Content-Type: application/json

{
  "type": "ORG",
  "name": "Pokhara Office",
  "code": "PKR-01",
  "parentId": "d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f90",
  "metadata": {
    "address": "Lakeside, Pokhara",
    "timezone": "Asia/Kathmandu"
  }
}
```

#### Example Response — `201 Created`

```json
{
  "success": true,
  "data": {
    "id": "c3d4e5f6-a7b8-9012-cdef-345678901234",
    "type": "ORG",
    "name": "Pokhara Office",
    "code": "PKR-01",
    "parentId": "d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f90",
    "metadata": {
      "address": "Lakeside, Pokhara",
      "timezone": "Asia/Kathmandu"
    }
  },
  "timestamp": "2026-04-06T10:43:00Z"
}
```

#### Notes

- **Side effect:** A database trigger automatically populates the `scope_closure` table for transitive ancestor/descendant lookups.
- **Cache invalidation:** The scope cache is invalidated upon creation.
- `GLOBAL` scopes cannot have a `parentId`. Non-`GLOBAL` scopes must have a `parentId`.
- Duplicate `code` values return `400 Bad Request`.

---

## 7. Assignments Management

Manage role-to-subject assignments at specific scopes.

**Auth:** Authenticated + delegation guard (scope containment enforced — you can only manage assignments within scopes you administer).

---

### GET /api/v1/assignments

List assignments, filtered by subject.

#### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `subjectId` | string | No | Filter by subject identifier |

#### Example Request

```http
GET /api/v1/assignments?subjectId=550e8400-e29b-41d4-a716-446655440000 HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "data": [
    {
      "id": "aaa11111-2222-3333-4444-555566667777",
      "subjectId": "550e8400-e29b-41d4-a716-446655440000",
      "subjectType": "USER",
      "roleId": "e1f2a3b4-c5d6-7890-ef01-234567890abc",
      "scopeId": "d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f90",
      "expiresAt": null,
      "conditions": null,
      "createdAt": "2026-01-15T08:30:00Z"
    }
  ],
  "timestamp": "2026-04-06T10:45:00Z"
}
```

---

### POST /api/v1/assignments

Create a new role assignment.

#### Request Body

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `subjectId` | string | Yes | Non-empty | Subject identifier (user ID, service ID, etc.) |
| `subjectType` | string | No | Default: `"USER"` | Subject type |
| `roleId` | UUID | Yes | Valid role UUID | Role to assign |
| `scopeId` | UUID | Yes | Valid scope UUID | Scope for the assignment |
| `expiresAt` | ISO-8601 | No | Future datetime | Assignment expiration (null = permanent) |
| `conditions` | object | No | Valid JSON | Conditional constraints (see [Assignment Conditions Reference](#assignment-conditions-reference)) |

#### Example Request — Simple Assignment

```http
POST /api/v1/assignments HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
Content-Type: application/json

{
  "subjectId": "550e8400-e29b-41d4-a716-446655440000",
  "roleId": "e1f2a3b4-c5d6-7890-ef01-234567890abc",
  "scopeId": "d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f90"
}
```

#### Example Request — Conditional Assignment

```http
POST /api/v1/assignments HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
Content-Type: application/json

{
  "subjectId": "550e8400-e29b-41d4-a716-446655440000",
  "subjectType": "USER",
  "roleId": "e1f2a3b4-c5d6-7890-ef01-234567890abc",
  "scopeId": "d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f90",
  "expiresAt": "2026-12-31T23:59:59Z",
  "conditions": {
    "timeWindow": "09:00-17:00",
    "timezone": "Asia/Kathmandu",
    "ipRanges": ["10.0.0.0/8"],
    "requireMfa": true
  }
}
```

#### Example Response — `201 Created`

```json
{
  "success": true,
  "data": {
    "id": "bbb22222-3333-4444-5555-666677778888",
    "subjectId": "550e8400-e29b-41d4-a716-446655440000",
    "subjectType": "USER",
    "roleId": "e1f2a3b4-c5d6-7890-ef01-234567890abc",
    "scopeId": "d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f90",
    "expiresAt": "2026-12-31T23:59:59Z",
    "conditions": {
      "timeWindow": "09:00-17:00",
      "timezone": "Asia/Kathmandu",
      "ipRanges": ["10.0.0.0/8"],
      "requireMfa": true
    },
    "createdAt": "2026-04-06T10:46:00Z"
  },
  "timestamp": "2026-04-06T10:46:00Z"
}
```

#### Notes

- **Cache invalidation:** Clears the user's permission cache and deny cache immediately.
- **Delegation guard:** You can only assign roles within scopes you administer, and you cannot assign permissions you do not hold (permission ceiling).
- Duplicate assignments (same subject + role + scope) return `400 Bad Request`.

---

### DELETE /api/v1/assignments/{id}

Remove a role assignment.

#### Path Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | UUID | Yes | Assignment ID |

#### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `reason` | string | No | Reason for removal (recorded in audit log) |

#### Example Request

```http
DELETE /api/v1/assignments/bbb22222-3333-4444-5555-666677778888?reason=Role%20no%20longer%20needed HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "message": "Assignment removed successfully.",
  "timestamp": "2026-04-06T10:47:00Z"
}
```

#### Notes

- **Cache invalidation:** Clears the user's permission cache and deny cache immediately.
- The reason is recorded in the audit log for compliance.

---

## 8. Deny Rules Management

Manage explicit deny rules that override all ALLOW decisions.

**Auth:** Authenticated + delegation guard.

---

### GET /api/v1/deny-rules

List deny rules, filtered by subject.

#### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `subjectId` | string | No | Filter by subject identifier |

#### Example Request

```http
GET /api/v1/deny-rules?subjectId=550e8400-e29b-41d4-a716-446655440000 HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "data": [
    {
      "id": "ddd44444-5555-6666-7777-888899990000",
      "subjectId": "550e8400-e29b-41d4-a716-446655440000",
      "permissionKey": "platform.user.delete",
      "scopeId": "d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f90",
      "reason": "Suspended pending investigation",
      "referenceId": "TICKET-4521",
      "expiresAt": "2026-05-01T00:00:00Z",
      "createdAt": "2026-04-01T12:00:00Z"
    }
  ],
  "timestamp": "2026-04-06T10:50:00Z"
}
```

---

### POST /api/v1/deny-rules

Create a new deny rule.

#### Request Body

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `subjectId` | string | Yes | Non-empty | Subject to deny |
| `permissionKey` | string | Yes | Non-empty, supports wildcards | Permission key to deny (e.g. `platform.user.delete` or `*.*.*`) |
| `scopeId` | UUID | No | Valid UUID | Scope for the deny rule (null = global deny) |
| `reason` | string | Yes | Non-empty | Reason for the deny rule |
| `referenceId` | string | No | — | External reference (e.g. ticket number) |
| `expiresAt` | ISO-8601 | No | Future datetime | Expiration (null = permanent) |

#### Example Request

```http
POST /api/v1/deny-rules HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
Content-Type: application/json

{
  "subjectId": "550e8400-e29b-41d4-a716-446655440000",
  "permissionKey": "platform.user.delete",
  "scopeId": "d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f90",
  "reason": "Suspended pending investigation",
  "referenceId": "TICKET-4521",
  "expiresAt": "2026-05-01T00:00:00Z"
}
```

#### Example Response — `201 Created`

```json
{
  "success": true,
  "data": {
    "id": "eee55555-6666-7777-8888-999900001111",
    "subjectId": "550e8400-e29b-41d4-a716-446655440000",
    "permissionKey": "platform.user.delete",
    "scopeId": "d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f90",
    "reason": "Suspended pending investigation",
    "referenceId": "TICKET-4521",
    "expiresAt": "2026-05-01T00:00:00Z",
    "createdAt": "2026-04-06T10:51:00Z"
  },
  "timestamp": "2026-04-06T10:51:00Z"
}
```

#### Notes

- **Wildcard patterns** (e.g. `*.*.*`, `platform.*.*`, `platform.user.*`) require `SuperAdmin` role.
- Deny rules always take precedence over allow decisions in the authorization evaluation.
- A `null` scopeId means the deny rule applies globally across all scopes.
- **Cache invalidation:** Clears the subject's deny cache immediately.

---

### DELETE /api/v1/deny-rules/{id}

Remove a deny rule.

#### Path Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | UUID | Yes | Deny rule ID |

#### Example Request

```http
DELETE /api/v1/deny-rules/eee55555-6666-7777-8888-999900001111 HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "message": "Deny rule removed successfully.",
  "timestamp": "2026-04-06T10:52:00Z"
}
```

#### Notes

- **Cache invalidation:** Clears the subject's deny cache immediately.

---

## 9. Policies Management

Manage attribute-based policies for fine-grained access control.

**Auth:** All endpoints require Bearer JWT with `SuperAdmin` role.

---

### GET /api/v1/policies

List all policies.

#### Example Request

```http
GET /api/v1/policies HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "data": [
    {
      "id": "ppp11111-2222-3333-4444-555566667777",
      "name": "business-hours-only",
      "description": "Allow access only during business hours",
      "permissionKey": "platform.report.export",
      "resourceType": null,
      "scopeId": null,
      "effect": "ALLOW",
      "priority": 10,
      "conditions": {
        "all": [
          {"field": "context.timestamp", "op": "after", "value": "09:00"},
          {"field": "context.timestamp", "op": "before", "value": "17:00"}
        ]
      },
      "active": true,
      "createdAt": "2026-03-01T10:00:00Z",
      "updatedAt": "2026-03-15T14:00:00Z"
    }
  ],
  "timestamp": "2026-04-06T10:55:00Z"
}
```

---

### GET /api/v1/policies/{id}

Get a single policy by ID.

#### Path Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | UUID | Yes | Policy ID |

#### Example Request

```http
GET /api/v1/policies/ppp11111-2222-3333-4444-555566667777 HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "data": {
    "id": "ppp11111-2222-3333-4444-555566667777",
    "name": "business-hours-only",
    "description": "Allow access only during business hours",
    "permissionKey": "platform.report.export",
    "resourceType": null,
    "scopeId": null,
    "effect": "ALLOW",
    "priority": 10,
    "conditions": {
      "all": [
        {"field": "context.timestamp", "op": "after", "value": "09:00"},
        {"field": "context.timestamp", "op": "before", "value": "17:00"}
      ]
    },
    "active": true,
    "createdAt": "2026-03-01T10:00:00Z",
    "updatedAt": "2026-03-15T14:00:00Z"
  },
  "timestamp": "2026-04-06T10:56:00Z"
}
```

---

### POST /api/v1/policies

Create a new policy.

#### Request Body

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `name` | string | Yes | Unique, non-empty | Policy name |
| `description` | string | No | — | Human-readable description |
| `permissionKey` | string | No | — | Permission key to scope the policy to |
| `resourceType` | string | No | — | Resource type to scope the policy to |
| `scopeId` | UUID | No | Valid UUID | Scope to bind the policy to |
| `effect` | string | No | `ALLOW` or `DENY`, default `ALLOW` | Policy effect |
| `priority` | int | No | Default: `0` | Higher priority policies are evaluated first |
| `conditions` | object | No | Valid condition tree (see [Policy Conditions Reference](#policy-conditions-reference)) | Policy conditions |
| `active` | boolean | No | Default: `true` | Whether the policy is active |

#### Example Request — Owner-Only Policy

```http
POST /api/v1/policies HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
Content-Type: application/json

{
  "name": "owner-edit-only",
  "description": "Only the resource owner can edit",
  "permissionKey": "platform.document.update",
  "effect": "DENY",
  "priority": 100,
  "conditions": {
    "not": {
      "field": "subject",
      "op": "eq",
      "value": "$resource.metadata.ownerId"
    }
  },
  "active": true
}
```

#### Example Request — IP-Based Policy

```http
POST /api/v1/policies HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
Content-Type: application/json

{
  "name": "internal-network-only",
  "description": "Deny access from outside internal network",
  "permissionKey": "platform.config.update",
  "effect": "DENY",
  "priority": 50,
  "conditions": {
    "not": {
      "field": "context.ipAddress",
      "op": "in",
      "value": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    }
  },
  "active": true
}
```

#### Example Response — `201 Created`

```json
{
  "success": true,
  "data": {
    "id": "qqq22222-3333-4444-5555-666677778888",
    "name": "owner-edit-only",
    "description": "Only the resource owner can edit",
    "permissionKey": "platform.document.update",
    "resourceType": null,
    "scopeId": null,
    "effect": "DENY",
    "priority": 100,
    "conditions": {
      "not": {
        "field": "subject",
        "op": "eq",
        "value": "$resource.metadata.ownerId"
      }
    },
    "active": true,
    "createdAt": "2026-04-06T10:57:00Z",
    "updatedAt": "2026-04-06T10:57:00Z"
  },
  "timestamp": "2026-04-06T10:57:00Z"
}
```

#### Notes

- Policy names must be unique. Duplicate names return `400 Bad Request`.
- Policies with `null` permissionKey/resourceType/scopeId apply broadly (use with caution).
- Higher priority policies are evaluated first during authorization.

---

### PUT /api/v1/policies/{id}

Update an existing policy. Supports partial updates.

#### Path Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | UUID | Yes | Policy ID |

#### Request Body

All fields are optional (partial update). Same schema as POST, but only provided fields are updated.

#### Example Request

```http
PUT /api/v1/policies/qqq22222-3333-4444-5555-666677778888 HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
Content-Type: application/json

{
  "priority": 200,
  "description": "Updated: Only the resource owner can edit documents"
}
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "data": {
    "id": "qqq22222-3333-4444-5555-666677778888",
    "name": "owner-edit-only",
    "description": "Updated: Only the resource owner can edit documents",
    "permissionKey": "platform.document.update",
    "resourceType": null,
    "scopeId": null,
    "effect": "DENY",
    "priority": 200,
    "conditions": {
      "not": {
        "field": "subject",
        "op": "eq",
        "value": "$resource.metadata.ownerId"
      }
    },
    "active": true,
    "createdAt": "2026-04-06T10:57:00Z",
    "updatedAt": "2026-04-06T10:58:00Z"
  },
  "timestamp": "2026-04-06T10:58:00Z"
}
```

---

### DELETE /api/v1/policies/{id}

Deactivate a policy (soft delete).

#### Path Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | UUID | Yes | Policy ID |

#### Example Request

```http
DELETE /api/v1/policies/qqq22222-3333-4444-5555-666677778888 HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "message": "Policy deactivated successfully.",
  "timestamp": "2026-04-06T10:59:00Z"
}
```

#### Notes

- This is a **soft delete**: sets `active = false`. The policy record is retained for audit purposes.
- Deactivated policies are not evaluated during authorization.

---

## 10. Role Hierarchy

Manage parent-child relationships between roles. Child roles inherit all permissions from parent roles.

**Auth:** All endpoints require Bearer JWT with `SuperAdmin` role.

---

### GET /api/v1/role-hierarchy/parents/{roleId}

Get all parent roles of a given role.

#### Path Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `roleId` | UUID | Yes | Role ID |

#### Example Request

```http
GET /api/v1/role-hierarchy/parents/f1a2b3c4-d5e6-7890-abcd-ef0123456789 HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "data": [
    {
      "id": "e1f2a3b4-c5d6-7890-ef01-234567890abc",
      "name": "CountryAdmin",
      "displayName": "Country Administrator"
    }
  ],
  "timestamp": "2026-04-06T11:00:00Z"
}
```

---

### GET /api/v1/role-hierarchy/children/{roleId}

Get all child roles of a given role.

#### Path Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `roleId` | UUID | Yes | Role ID |

#### Example Request

```http
GET /api/v1/role-hierarchy/children/e1f2a3b4-c5d6-7890-ef01-234567890abc HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "data": [
    {
      "id": "f1a2b3c4-d5e6-7890-abcd-ef0123456789",
      "name": "ReportViewer",
      "displayName": "Report Viewer"
    },
    {
      "id": "a2b3c4d5-e6f7-8901-abcd-f01234567890",
      "name": "UserManager",
      "displayName": "User Manager"
    }
  ],
  "timestamp": "2026-04-06T11:01:00Z"
}
```

---

### POST /api/v1/role-hierarchy

Create a parent-child relationship between two roles.

#### Request Body

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `parentRoleId` | UUID | Yes | Valid role UUID | Parent role ID |
| `childRoleId` | UUID | Yes | Valid role UUID | Child role ID |

#### Example Request

```http
POST /api/v1/role-hierarchy HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
Content-Type: application/json

{
  "parentRoleId": "e1f2a3b4-c5d6-7890-ef01-234567890abc",
  "childRoleId": "f1a2b3c4-d5e6-7890-abcd-ef0123456789"
}
```

#### Example Response — `201 Created`

```json
{
  "success": true,
  "message": "Role hierarchy relationship created.",
  "timestamp": "2026-04-06T11:02:00Z"
}
```

#### Notes

- **Self-reference prevention:** A role cannot be its own parent. Returns `400 Bad Request`.
- **Cycle detection:** Circular hierarchies are detected and rejected. Returns `400 Bad Request`.
- The child role inherits all permissions from the parent role.

---

### DELETE /api/v1/role-hierarchy

Remove a parent-child relationship.

#### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `parentRoleId` | UUID | Yes | Parent role ID |
| `childRoleId` | UUID | Yes | Child role ID |

#### Example Request

```http
DELETE /api/v1/role-hierarchy?parentRoleId=e1f2a3b4-c5d6-7890-ef01-234567890abc&childRoleId=f1a2b3c4-d5e6-7890-abcd-ef0123456789 HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "message": "Role hierarchy relationship removed.",
  "timestamp": "2026-04-06T11:03:00Z"
}
```

---

## 11. Permission Groups

Organize permissions into logical groups for easier management.

**Auth:**
- **GET** endpoints: Authenticated (any valid JWT).
- **POST/PUT** endpoints: Bearer JWT with `SuperAdmin` role.

---

### GET /api/v1/permission-groups

List all permission groups.

#### Example Request

```http
GET /api/v1/permission-groups HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "data": [
    {
      "id": "ggg11111-2222-3333-4444-555566667777",
      "name": "User Management",
      "description": "Permissions related to user CRUD operations",
      "parentGroupId": null
    },
    {
      "id": "hhh22222-3333-4444-5555-666677778888",
      "name": "User Read Operations",
      "description": "Read-only user permissions",
      "parentGroupId": "ggg11111-2222-3333-4444-555566667777"
    }
  ],
  "timestamp": "2026-04-06T11:05:00Z"
}
```

---

### GET /api/v1/permission-groups/{id}

Get a single permission group by ID.

#### Path Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | UUID | Yes | Permission group ID |

#### Example Request

```http
GET /api/v1/permission-groups/ggg11111-2222-3333-4444-555566667777 HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "data": {
    "id": "ggg11111-2222-3333-4444-555566667777",
    "name": "User Management",
    "description": "Permissions related to user CRUD operations",
    "parentGroupId": null
  },
  "timestamp": "2026-04-06T11:06:00Z"
}
```

---

### GET /api/v1/permission-groups/{id}/permissions

Get all permissions in a permission group.

#### Path Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | UUID | Yes | Permission group ID |

#### Example Request

```http
GET /api/v1/permission-groups/ggg11111-2222-3333-4444-555566667777/permissions HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "data": [
    {
      "id": "b1c2d3e4-f5a6-7890-bcde-f12345678901",
      "key": "platform.user.create",
      "domain": "platform",
      "resource": "user",
      "action": "create"
    },
    {
      "id": "c2d3e4f5-a6b7-8901-cdef-234567890123",
      "key": "platform.user.read",
      "domain": "platform",
      "resource": "user",
      "action": "read"
    }
  ],
  "timestamp": "2026-04-06T11:07:00Z"
}
```

---

### POST /api/v1/permission-groups

Create a new permission group.

#### Request Body

| Field | Type | Required | Validation | Description |
|-------|------|----------|------------|-------------|
| `name` | string | Yes | Non-empty | Group name |
| `description` | string | No | — | Group description |
| `parentGroupId` | UUID | No | Valid group UUID | Parent group for nesting |

#### Example Request

```http
POST /api/v1/permission-groups HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
Content-Type: application/json

{
  "name": "Billing Permissions",
  "description": "All billing-related permissions",
  "parentGroupId": null
}
```

#### Example Response — `201 Created`

```json
{
  "success": true,
  "data": {
    "id": "iii33333-4444-5555-6666-777788889999",
    "name": "Billing Permissions",
    "description": "All billing-related permissions",
    "parentGroupId": null
  },
  "timestamp": "2026-04-06T11:08:00Z"
}
```

---

### PUT /api/v1/permission-groups/{id}/permissions

Set the permissions for a permission group.

#### Path Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | UUID | Yes | Permission group ID |

#### Request Body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `permissionIds` | UUID[] | Yes | Array of permission UUIDs |

#### Example Request

```http
PUT /api/v1/permission-groups/iii33333-4444-5555-6666-777788889999/permissions HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
Content-Type: application/json

{
  "permissionIds": [
    "b1c2d3e4-f5a6-7890-bcde-f12345678901",
    "c2d3e4f5-a6b7-8901-cdef-234567890123"
  ]
}
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "message": "Permission group updated successfully.",
  "timestamp": "2026-04-06T11:09:00Z"
}
```

---

## 12. Audit

Query authorization audit logs and statistics.

**Auth:** Bearer JWT with one of: `SuperAdmin`, `CountryAdmin`, `AccessAdmin`, `SecurityAdmin`, `AuditViewer`.

---

### GET /api/v1/audit/subject/{subjectId}

Get audit logs for a specific subject.

#### Path Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `subjectId` | string | Yes | Subject identifier |

#### Query Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `limit` | int | No | `100` | Maximum number of records to return |

#### Example Request

```http
GET /api/v1/audit/subject/550e8400-e29b-41d4-a716-446655440000?limit=5 HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "data": [
    {
      "id": "aud-0001-0000-0000-000000000001",
      "subject": "550e8400-e29b-41d4-a716-446655440000",
      "permission": "platform.role.read",
      "resourceType": "role",
      "resourceId": "role-001",
      "scopeId": "d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f90",
      "authorized": true,
      "reason": "Permission granted via role 'CountryAdmin'",
      "ipAddress": "10.0.1.50",
      "timestamp": "2026-04-06T10:20:00Z",
      "latencyMs": 3
    },
    {
      "id": "aud-0001-0000-0000-000000000002",
      "subject": "550e8400-e29b-41d4-a716-446655440000",
      "permission": "platform.user.delete",
      "resourceType": "user",
      "resourceId": "user-999",
      "scopeId": "d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f90",
      "authorized": false,
      "reason": "Deny rule active: 'Suspended pending investigation'",
      "ipAddress": "203.0.113.50",
      "timestamp": "2026-04-06T10:20:01Z",
      "latencyMs": 2
    }
  ],
  "timestamp": "2026-04-06T11:10:00Z"
}
```

---

### GET /api/v1/audit/resource/{resourceType}/{resourceId}

Get audit logs for a specific resource.

#### Path Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `resourceType` | string | Yes | Resource type (e.g. `role`, `user`) |
| `resourceId` | string | Yes | Resource ID |

#### Query Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `limit` | int | No | `100` | Maximum number of records to return |

#### Example Request

```http
GET /api/v1/audit/resource/user/user-999?limit=10 HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "data": [
    {
      "id": "aud-0002-0000-0000-000000000001",
      "subject": "550e8400-e29b-41d4-a716-446655440000",
      "permission": "platform.user.delete",
      "resourceType": "user",
      "resourceId": "user-999",
      "scopeId": "d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f90",
      "authorized": false,
      "reason": "Deny rule active",
      "ipAddress": "203.0.113.50",
      "timestamp": "2026-04-06T10:20:01Z",
      "latencyMs": 2
    }
  ],
  "timestamp": "2026-04-06T11:11:00Z"
}
```

---

### GET /api/v1/audit/statistics/{subjectId}

Get authorization statistics for a subject.

#### Path Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `subjectId` | string | Yes | Subject identifier |

#### Query Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `sinceDaysAgo` | int | No | `7` | Number of days to look back |

#### Example Request

```http
GET /api/v1/audit/statistics/550e8400-e29b-41d4-a716-446655440000?sinceDaysAgo=30 HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "data": {
    "total": 1542,
    "allowed": 1480,
    "denied": 62,
    "allowRate": 0.9598,
    "byPermission": {
      "platform.role.read": {
        "total": 820,
        "allowed": 820,
        "denied": 0
      },
      "platform.user.read": {
        "total": 450,
        "allowed": 445,
        "denied": 5
      },
      "platform.user.delete": {
        "total": 72,
        "allowed": 15,
        "denied": 57
      }
    }
  },
  "timestamp": "2026-04-06T11:12:00Z"
}
```

#### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `total` | int | Total authorization requests |
| `allowed` | int | Number of ALLOW decisions |
| `denied` | int | Number of DENY decisions |
| `allowRate` | double | Ratio of allowed to total (0.0 - 1.0) |
| `byPermission` | object | Breakdown by permission key |

---

## 13. Health & Metrics

Public endpoints for monitoring system health.

**Auth:** Public (no authentication required)

---

### GET /api/v1/health/cache-stats

Get cache key counts for all caches.

#### Example Request

```http
GET /api/v1/health/cache-stats HTTP/1.1
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "data": {
    "userPermissions": {
      "size": 1250,
      "hitRate": 0.94,
      "missRate": 0.06
    },
    "denyRules": {
      "size": 85,
      "hitRate": 0.98,
      "missRate": 0.02
    },
    "scopeClosure": {
      "size": 340,
      "hitRate": 0.99,
      "missRate": 0.01
    },
    "policies": {
      "size": 28,
      "hitRate": 0.97,
      "missRate": 0.03
    }
  },
  "timestamp": "2026-04-06T11:15:00Z"
}
```

---

### GET /api/v1/health/metrics

Get authorization processing metrics.

#### Example Request

```http
GET /api/v1/health/metrics HTTP/1.1
```

#### Example Response — `200 OK`

```json
{
  "success": true,
  "data": {
    "totalRequests": 2458903,
    "averageLatencyMs": 2.4,
    "p50LatencyMs": 1.8,
    "p95LatencyMs": 4.2,
    "p99LatencyMs": 8.1,
    "requestsPerSecond": 3420.5,
    "allowRate": 0.962,
    "denyRate": 0.038,
    "cacheHitRate": 0.95,
    "uptime": "14d 6h 32m"
  },
  "timestamp": "2026-04-06T11:16:00Z"
}
```

---

## Assignment Conditions Reference

Assignments can include conditions that restrict when the assignment is effective. These are evaluated at authorization time.

| Condition Key | Type | Example | Description |
|---------------|------|---------|-------------|
| `timeWindow` | string | `"09:00-17:00"` | Time-of-day window in `HH:mm-HH:mm` format. Supports wraparound (e.g. `"22:00-06:00"` for night shifts). |
| `timezone` | string | `"Asia/Kathmandu"` | IANA timezone for `timeWindow` evaluation. Default: `UTC`. |
| `ipRanges` | string[] | `["10.0.0.0/8", "192.168.1.0/24"]` | Allowed CIDR ranges. Request IP must match at least one range. |
| `requireMfa` | boolean | `true` | If `true`, MFA must be confirmed. Checked from `context.additionalContext.mfa`. |
| `ownershipRequired` | boolean | `true` | Subject must be the resource owner. Checks `resource.metadata.ownerId` and `resource.metadata.createdBy` against the subject ID. |
| `canOnlyAccessOwnCreated` | boolean | `true` | Same behavior as `ownershipRequired`. Subject must be the creator of the resource. |
| `cannotApproveOwnCreated` | boolean | `true` | Denies access if the subject IS the owner/creator. Enforces separation of duties (e.g. cannot approve your own purchase order). |
| `subjectMatchFields` | string[] | `["assigneeId", "reviewerId"]` | All listed fields in `resource.metadata` or `context` must equal the subject ID. Used for multi-field ownership checks. |

### Example: Business-Hours with MFA and IP Restriction

```json
{
  "timeWindow": "09:00-17:00",
  "timezone": "Asia/Kathmandu",
  "ipRanges": ["10.0.0.0/8", "172.16.0.0/12"],
  "requireMfa": true
}
```

### Example: Separation of Duties

```json
{
  "cannotApproveOwnCreated": true
}
```

This denies the permission if `subject == resource.metadata.ownerId` or `subject == resource.metadata.createdBy`. Useful for approval workflows.

### Example: Night-Shift Wraparound

```json
{
  "timeWindow": "22:00-06:00",
  "timezone": "America/New_York"
}
```

The `22:00-06:00` window wraps around midnight. Access is allowed from 10 PM to 6 AM in the specified timezone.

---

## Policy Conditions Reference

Policies use a tree-structured condition system supporting logical operators and leaf comparisons.

### Logical Operators

| Operator | Description | Structure |
|----------|-------------|-----------|
| `all` | Logical AND — all child conditions must be true | `{"all": [condition, ...]}` |
| `any` | Logical OR — at least one child condition must be true | `{"any": [condition, ...]}` |
| `not` | Logical NOT — negates a single condition | `{"not": condition}` |

### Leaf Condition Format

```json
{
  "field": "field.path",
  "op": "operator",
  "value": "comparison_value"
}
```

### Supported Operators

| Operator | Description | Value Type | Example |
|----------|-------------|------------|---------|
| `eq` | Equals | any | `{"field": "subject", "op": "eq", "value": "user-123"}` |
| `neq` | Not equals | any | `{"field": "resource.type", "op": "neq", "value": "admin"}` |
| `in` | Value is in list | array | `{"field": "context.ipAddress", "op": "in", "value": ["10.0.0.0/8"]}` |
| `not_in` | Value is not in list | array | `{"field": "resource.type", "op": "not_in", "value": ["secret", "config"]}` |
| `contains` | String contains | string | `{"field": "permission", "op": "contains", "value": "read"}` |
| `exists` | Field exists | boolean | `{"field": "context.sessionId", "op": "exists", "value": true}` |
| `gt` | Greater than | number/string | `{"field": "resource.metadata.level", "op": "gt", "value": 5}` |
| `gte` | Greater than or equal | number/string | `{"field": "resource.metadata.priority", "op": "gte", "value": 1}` |
| `lt` | Less than | number/string | `{"field": "resource.metadata.risk", "op": "lt", "value": 10}` |
| `lte` | Less than or equal | number/string | `{"field": "resource.metadata.cost", "op": "lte", "value": 1000}` |
| `regex` | Regular expression match | string (regex) | `{"field": "resource.id", "op": "regex", "value": "^proj-[0-9]+$"}` |
| `before` | Datetime is before | ISO-8601/time | `{"field": "context.timestamp", "op": "before", "value": "17:00"}` |
| `after` | Datetime is after | ISO-8601/time | `{"field": "context.timestamp", "op": "after", "value": "09:00"}` |

### Available Fields

| Field Path | Description |
|------------|-------------|
| `subject` | The subject identifier |
| `permission` | The permission key being evaluated |
| `resource.type` | Resource type |
| `resource.id` | Resource instance ID |
| `resource.scopeId` | Scope UUID |
| `resource.metadata.*` | Any key in resource metadata (e.g. `resource.metadata.ownerId`) |
| `context.timestamp` | Request timestamp |
| `context.ipAddress` | Client IP address |
| `context.userAgent` | Client user agent |
| `context.sessionId` | Session identifier |
| `context.requestId` | Request correlation ID |
| `context.additional.*` | Any key in additional context (e.g. `context.additional.mfa`) |

### Value References

Prefix a value with `$` to reference another field's value instead of a literal:

```json
{
  "field": "subject",
  "op": "eq",
  "value": "$resource.metadata.ownerId"
}
```

This checks if `subject == resource.metadata.ownerId` at evaluation time.

### Complex Condition Example

Allow access only during business hours, from internal IPs, when MFA is confirmed:

```json
{
  "all": [
    {"field": "context.timestamp", "op": "after", "value": "09:00"},
    {"field": "context.timestamp", "op": "before", "value": "17:00"},
    {
      "any": [
        {"field": "context.ipAddress", "op": "in", "value": ["10.0.0.0/8"]},
        {"field": "context.ipAddress", "op": "in", "value": ["172.16.0.0/12"]}
      ]
    },
    {"field": "context.additional.mfa", "op": "eq", "value": true}
  ]
}
```

### Separation of Duties Example

Deny if the subject is the resource owner (cannot approve your own work):

```json
{
  "not": {
    "field": "subject",
    "op": "neq",
    "value": "$resource.metadata.createdBy"
  }
}
```

---

## Error Response Format

All errors follow a standard format:

```json
{
  "timestamp": "2026-01-25T10:30:00Z",
  "status": 400,
  "error": "Bad Request",
  "message": "Description of what went wrong",
  "path": "/api/v1/...",
  "validationErrors": {
    "field": "message"
  }
}
```

### Status Codes

| Code | Meaning | When Used |
|------|---------|-----------|
| `200` | OK | Successful read/update/delete |
| `201` | Created | Successful resource creation |
| `302` | Found | OAuth redirect |
| `400` | Bad Request | Validation errors, duplicate resources, malformed input |
| `401` | Unauthorized | Missing or invalid authentication |
| `403` | Forbidden | Authenticated but insufficient permissions (permission ceiling, delegation guard) |
| `404` | Not Found | Resource does not exist |
| `429` | Too Many Requests | Rate limit exceeded |
| `503` | Service Unavailable | Infrastructure error (DB unreachable, cache failure). This is NOT a security denial. |

### Validation Error Example

```json
{
  "timestamp": "2026-04-06T10:30:00Z",
  "status": 400,
  "error": "Bad Request",
  "message": "Validation failed",
  "path": "/api/auth/register",
  "validationErrors": {
    "fullName": "Full name must be between 2 and 100 characters",
    "email": "Must be a valid email address",
    "password": "Password must be at least 6 characters"
  }
}
```

### Authentication Error Example

```json
{
  "timestamp": "2026-04-06T10:30:00Z",
  "status": 401,
  "error": "Unauthorized",
  "message": "Invalid or expired token",
  "path": "/api/v1/roles"
}
```

### Forbidden Error Example

```json
{
  "timestamp": "2026-04-06T10:30:00Z",
  "status": 403,
  "error": "Forbidden",
  "message": "Cannot assign permissions you do not hold (permission ceiling violated)",
  "path": "/api/v1/roles"
}
```

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-04-06 | Initial comprehensive API documentation |
