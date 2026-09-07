# Password Reset Implementation Plan

## Scope

Implement two password-management flows:

1. An authenticated user changes their password with their current password.
2. A user who has forgotten their password receives a one-time reset link and sets a new password.

After either succeeds, revoke all active access and refresh tokens so the user must sign in again. Email delivery is a pluggable interface; selecting and configuring a concrete provider is deferred.

## Current State

- Reset-token persistence is implemented: `PasswordResetToken` model, `PasswordResetTokenStore` contract, SQL implementation, and migration `007` (step 1).
- `UserRepo.UpdatePassword` exists as a dedicated password-persistence path, and `UserService.ResetPassword` already enforces non-zero user ID, non-empty password, and `utils.IsValidPassword` before bcrypt hashing.
- `RevokeAllTokensForUser` exists (`internal/repositories/token.go:160`, `internal/services/token.go:332`) but is not wired into any password flow.
- No password-reset HTTP route exists in `internal/api/routes.go`.
- No transaction support exists anywhere in `internal/` — there is no `sql.Tx` or `BeginTx` usage, and each repository owns its own `*sql.DB` with no shared executor abstraction.
- No mailer abstraction, email provider, or SMTP configuration exists in the codebase.
- The only HTTP middleware is CORS, heartbeat, and the auth middleware; there is no rate limiting.
- `api.NewServer` and `handlers.NewAuthHandler` each accept exactly two services, so adding a third is a signature change with roughly twenty test call sites.
- Existing password validation requires 8-128 characters with upper-case, lower-case, number, and special character.
- Architecture notes contain stale `/auth/...` examples, whereas the actual routes are unprefixed.

## API Contract

| Endpoint | Authentication | Request | Behavior |
| --- | --- | --- | --- |
| `POST /password/change` | Required | `current_password`, `new_password` | Verify current password, change it, and revoke all sessions. |
| `POST /password/forgot` | Public | `email` | Return a uniform `202` acknowledgement; send a reset link only for active accounts. |
| `POST /password/reset` | Public | `token`, `new_password` | Consume a valid one-time token, change password, and revoke all sessions. |

## Work Plan

### 1. Add reset-token persistence — implemented

- Create a password-reset-token model, repository contract, SQL implementation, and migration.
- Store only SHA-256 hashes of cryptographically random opaque tokens, associated user IDs, expiry timestamps, and nullable consumed timestamps.
- Add indexes for token-hash lookup and expiry cleanup.
- Provide repository operations to create a token, atomically consume a valid token once, and invalidate outstanding tokens for a user.

### 2. Password-change orchestration, reset-token service, mailer, and configuration

The orchestration and the reset-token service land together because the orchestration has no caller until the reset service exists.

- Generate URL-safe opaque tokens with `crypto/rand`, apply a 15-minute lifetime, hash before storing, and consume credentials atomically to prevent replay or concurrent double use.
- Define a narrow `PasswordResetMailer` interface that accepts a recipient and a prebuilt reset URL.
- Add a password-change orchestration that, in this fixed order, revokes every access and refresh token for the user, invalidates the user's outstanding reset tokens, and only then updates the password. Abort on the first failure.
  - The ordering, not a transaction, is what protects the security requirement. The only dangerous partial state is "password changed while old sessions remain live"; performing the password update last makes that state unreachable. Every earlier failure leaves the old password intact and costs the user at most a re-login or a new reset request.
  - See "Deferred work" for why a database transaction is not used here.
- Build the reset link base URL from configuration only. It must never be derived from the request `Host`, `X-Forwarded-Host`, or `Origin` header, which would let an attacker poison reset links.
- Add reset-link base URL and reset-token-lifetime configuration to `EnvConfig`. The base URL is required in production via `getEnvRequired`; the lifetime uses `env.GetEnvAsDuration`.
- Extend `api.NewServer` and `handlers.NewAuthHandler` to accept the password-reset service, and update the affected test call sites. Do this once here rather than repeating it in steps 3 and 4.
- Decide what `cmd/auth-service/main.go` injects as a mailer. A test fake alone is not sufficient: composition must not silently report email delivery that never happened. Until a provider is chosen, the acceptable options are a development-only mailer that records the link locally paired with a production `getEnvRequired` SMTP configuration, or leaving the flow unmounted.

### 3. Implement authenticated password change

- Add `ChangePassword` to `AuthHandler`.
- Mount `POST /password/change` within the existing authentication middleware group.
- Identify the user from middleware claims rather than a request user ID, verify the current password, validate the new password, then run the step-2 orchestration.
- Return project-standard JSON responses: invalid input `400`, invalid current password `401`, and service failures `500`.

### 4. Implement forgot-password recovery

- Add public `ForgotPassword` and `ResetPassword` handlers.
- Mount `POST /password/forgot` and `POST /password/reset`.
- Validate email format, but return the same accepted response for active, inactive, unknown, and existing addresses to avoid account enumeration.
- Send a reset link only for active users. Do not log raw tokens, passwords, or full reset URLs.
- Treat invalid, expired, and used tokens identically in client responses.
- Do not return reset tokens or replacement JWTs from either recovery endpoint.
- Rate-limit `POST /password/forgot` per source address and per email. No rate limiting exists in the service today, so this endpoint is otherwise an open email-flood and enumeration vector.
- A uniform `202` still leaks account existence through response time, because the existing-user path performs token generation, hashing, an insert, and a send. Either perform that work asynchronously after responding, or pad the unknown-account path.

### 5. Test and document

- Add repository tests for password persistence and atomic reset-token consumption.
- Add service tests for password-policy enforcement, hashed token storage, expiry, token reuse rejection, and token revocation.
- Add a service test asserting the orchestration ordering, so a later refactor cannot move the password update ahead of session revocation.
- Add handler and route tests for protected change-password access, current-password verification, uniform forgot responses, invalid recovery credentials, and successful flows.
- Add integration coverage using a fake mailer.
- Update `ARCHITECTURE_OVERVIEW.md` and `AUTHENTICATION_OVERVIEW.md` to use actual unprefixed routes and document the new password workflows.

## Deferred work

### Transactional unit-of-work

The password change writes to three tables and is not atomic. A transaction was considered and deliberately postponed:

- No transaction seam exists. Every repository holds its own `*sql.DB`, so making the writes atomic requires threading a shared executor interface through `UserRepo`, `TokenRepo`, and `PasswordResetTokenRepo` and reworking their existing tests.
- The ordering in step 2 already removes the security-relevant failure mode, so the transaction would buy durability convenience rather than correctness.
- A transaction would not close the concurrent-login window either: a login committing in a separate transaction can still mint a token during the change.

Revisit after step 4, when the real call sites exist and the executor seam can be designed against them instead of speculatively.

## Security Requirements

- Reset tokens are short-lived, random, opaque, single-use, and stored only as hashes.
- Forgot-password responses never reveal account existence, in status code, body, or timing.
- Successful password changes revoke every existing access and refresh token.
- The password update is the last write in the change sequence, so no partial failure can leave a changed password with live sessions.
- Reset link base URLs come from configuration, never from request headers.
- Passwords, raw reset tokens, and reset links must never be logged or returned by the API.
- A mailer interface is not delivery by itself; deployment needs a concrete sender and credentials configured outside source control.
