# Password Reset — Implementation Progress

Companion log to `PASSWORD_RESET_IMPLEMENTATION_PLAN.md`. Records what has been
implemented, step by step. The plan is executed one step at a time; each step is
appended here on completion.

## Steps

1. **Reset-token persistence** — `PasswordResetToken` model, `PasswordResetTokenStore`
   repository contract, SQL implementation, and migration. Store only SHA-256 hashes of
   opaque tokens; support create, atomic single-use consume, and per-user invalidation.
2. **Password-change orchestration, reset-token service, mailer, and config** —
   `crypto/rand` opaque token generation, 15-minute lifetime, hash-before-store, atomic
   consume; a narrow `PasswordResetMailer` interface; config-only reset-link base URL and
   token lifetime; an ordered orchestration that revokes all tokens, invalidates
   outstanding reset tokens, and updates the password last; service wiring through
   `NewServer` and `NewAuthHandler`.
3. **Authenticated password change** — `ChangePassword` on `AuthHandler`, mounted at
   `POST /password/change` inside the auth middleware group; identify the user from
   claims, verify current password, validate, then run the step-2 orchestration.
4. **Forgot-password recovery** — public `ForgotPassword` and `ResetPassword` handlers,
   mounted at `POST /password/forgot` and `POST /password/reset`; uniform `202`
   response regardless of account state; invalid/expired/used tokens treated
   identically; no tokens or JWTs returned; rate limiting and timing-uniformity on
   `/password/forgot`.
5. **Test and document** — repository, service, handler, route, and integration tests;
   update `ARCHITECTURE_OVERVIEW.md` and `AUTHENTICATION_OVERVIEW.md` with real
   unprefixed routes and the new password workflows.

Deferred: a transactional unit-of-work across the three password-change writes. See
"Deferred work" in the plan.

## Status

| Step | Status |
| --- | --- |
| 1. Reset-token persistence | Done |
| 2. Orchestration, reset-token service, mailer, config | Done |
| 3. Authenticated password change | Done |
| 4. Forgot-password recovery | Done |
| 5. Test and document | Done |

## Resolved decision

The mailer question that blocked step 2 was settled: development injects a file sink and
production requires SMTP configuration. Recorded in the step 2 entry below.

---

## Plan review (before step 2)

The plan was re-checked against the codebase after step 1. Findings and the resulting
changes:

- **The transaction in the original step 2 was dropped.** There is no `sql.Tx` or
  `BeginTx` anywhere in `internal/`, and each repository owns its own `*sql.DB`, so
  atomicity would require threading a shared executor through three repositories and
  reworking their tests before the feature exists. Replaced with a fixed write ordering —
  revoke tokens, invalidate reset tokens, update password last — which makes the
  dangerous partial state ("password changed, old sessions live") unreachable. The
  transaction is recorded as deferred work to revisit after step 4.
- **The original steps 2 and 3 were merged.** The rest of the old step 2 was already
  implemented: `UserRepo.UpdatePassword` (`internal/repositories/user.go:137`) and the
  password-policy guards in `UserService.ResetPassword` (`internal/services/user.go:214-224`).
  What remained was one orchestration function with no caller until the reset-token
  service exists, so the two steps now land together. Steps renumbered from six to five.
- **Service wiring was added to step 2's scope.** `api.NewServer` and
  `handlers.NewAuthHandler` each take exactly two services; adding a third touches
  roughly twenty call sites in `internal/api/handlers/auth_test.go`,
  `internal/api/routes_test.go`, and `tests/integration/integration_test.go`. Doing it
  once in step 2 avoids repeating it in steps 3 and 4.
- **Two security gaps were added to the requirements.** The reset-link base URL must come
  from configuration only, never from the request `Host`/`X-Forwarded-Host`/`Origin`
  header, which would allow reset-link poisoning. And `/password/forgot` needs rate
  limiting — the service has no rate limiting at all today — plus a fix for the timing
  side channel that a uniform `202` alone does not close.

---

## Step 5 — Test and document (Done)

### Changed / added

| File | What |
| --- | --- |
| `tests/integration/password_reset_test.go` (new) | 4 end-to-end tests over the real router with in-memory fakes, matching the style of the existing `TestTokenLifecycle` |
| `dev-notes/AUTHENTICATION_OVERVIEW.md` | Removed the "not implemented" note; added a `Password Workflows` section and TOC entry; route snippet now shows the recovery and change routes; fixed the stale `/api/me` and `/api/protected` examples and realigned the flow diagram |
| `dev-notes/ARCHITECTURE_OVERVIEW.md` | Password reset moved out of the "does NOT do" list; route map lists all three password endpoints |

### Integration coverage

| Test | Asserts |
| --- | --- |
| `TestPasswordRecoveryFlow` | Full forgot → email → reset path: the stored value is the SHA-256 of the emailed token, the password really changes to the submitted one, the pre-existing session stops working, no session is handed back, and a replayed link returns 400 without changing the password again |
| `TestPasswordRecoveryDoesNotRevealAccounts` | Unknown and existing addresses produce byte-identical responses, and only the real account produces a token and a link |
| `TestPasswordRecoveryRejectsExpiredToken` | An expired link is refused with the same 400 as a non-existent one and revokes nothing |
| `TestAuthenticatedPasswordChangeRevokesSessions` | A wrong current password revokes nothing; a correct one changes the password and invalidates the live session |

### Verification

- `go build ./...`, `go vet ./...`, `go test ./...` — all pass
- `go test -race ./...` — passes

### Notes

- The integration tests use in-memory fakes rather than a database, following the
  existing `TestTokenLifecycle`. `tests/integration/setup.go` is still a placeholder, so
  there is no database-backed harness to build on; the repository SQL remains covered by
  the sqlmock tests from step 1.
- The in-memory token store reproduces the repository's single-use and expiry semantics
  so the replay and expiry tests exercise real behaviour rather than a stub.
- The flow diagram in `AUTHENTICATION_OVERVIEW.md` had pre-existing misaligned borders
  from an earlier prefix removal; realigned while fixing the `/api/me` examples in the
  same document.

---

## Step 4 — Forgot-password recovery (Done)

### Changed / added

| File | What |
| --- | --- |
| `pkg/ratelimit/ratelimit.go` (new) | Fixed-window `Limiter` keyed by an arbitrary string, with a sweep that drops expired counters. Shared by the middleware and the service; nil and zero-limit are permissive |
| `internal/api/middleware/ratelimit.go` (new) | `RateLimit` middleware returning 429, keyed on `RemoteAddr` — never `X-Forwarded-For`, which the caller controls |
| `internal/api/handlers/auth.go` | `ForgotPassword` (uniform 202, work runs detached) and `ResetPassword` (200 / 400 / 500) |
| `internal/api/routes.go` | `POST /password/forgot` and `POST /password/reset` on a rate-limited public group |
| `internal/api/server.go` | `Server` owns the IP limiter so counters live for the process, not per `Routes()` call |
| `internal/services/password_reset.go` | Per-email limiter (3 per 15 minutes) checked after the account is confirmed active |
| `pkg/ratelimit/ratelimit_test.go` (new) | 7 tests including concurrent use and sweep behaviour |
| `internal/api/handlers/auth_test.go` | 8 new tests; the stubs became recording fakes shared with the step 3 tests |
| `internal/api/routes_test.go` | Both routes are public; the allowance is enforced on them and not on other endpoints |

### Anti-enumeration measures

- Every well-formed request returns 202 with the same body. A test compares the response
  bodies for unknown, inactive, and active accounts and fails if any differ.
- Service errors are logged and still answered with 202. Returning 500 would let an
  attacker separate "no such account" from "account exists but mail failed".
- Response timing is independent of account state: the handler answers first and does the
  lookup, insert, and send on a detached goroutine with its own 30s context.
- Invalid, expired, and already-used tokens share one 400 response.

### Rate limiting

Two independent limits, because they protect different things: per source address
(10/minute, HTTP middleware, returns 429) blunts sweeps from one origin, and per email
address (3 per 15 minutes, in the service, silently skips the send) protects a victim's
inbox from a distributed flood. The per-email check runs only after the account is known
to be active, so the limiter's key space stays bounded by real accounts.

### Verification

- `go build ./...`, `go vet ./...`, `go test ./...` — all pass
- `go test -race ./pkg/ratelimit/ ./internal/api/...` — passes, covering the detached
  goroutine and the shared limiter state

### Notes

- The detached goroutine recovers from panics. Nothing else can: a panic off the request
  goroutine is not reachable by HTTP middleware and would kill the process.
- Limiter state is per process and in memory, so a multi-instance deployment limits per
  instance. Adequate as an abuse brake, not a hard quota.
- Behind a reverse proxy the IP limit applies per proxy, since `X-Forwarded-For` is not
  trusted. The proxy should carry its own per-client limit.
- `ResetPassword` returns no tokens; the user signs in again. A test asserts the response
  carries neither an access token nor the submitted password.
- Both limits are compile-time constants. Move them to configuration if they need tuning
  per environment.

---

## Step 3 — Authenticated password change (Done)

### Changed / added

| File | What |
| --- | --- |
| `internal/api/handlers/auth.go` | New `ChangePassword` handler. Takes the user from `middleware.GetClaimsFromContext`, reads `current_password` / `new_password`, rejects empty fields, then delegates to `PasswordResetService.ChangePassword` |
| `internal/api/routes.go` | `POST /password/change` mounted on `protectedRoutes`, inside the auth middleware group |
| `internal/api/handlers/auth_test.go` | 5 new tests plus `stubResetTokenStore`, `stubResetMailer`, and helpers that build a real `PasswordResetService` over mock repositories |
| `internal/api/routes_test.go` | Asserts `/password/change` returns 401 without a bearer token |

### Response mapping

| Condition | Status |
| --- | --- |
| Missing/malformed body, empty field | 400 |
| `services.ErrWeakPassword` | 400 |
| `services.ErrInvalidCredentials` (wrong current password) | 401 |
| No claims in context (unauthenticated) | 401 |
| Anything else | 500, generic message |

### Verification

- `go build ./...` — ok
- `go vet ./...` — ok
- `go test ./...` — all packages pass

### Notes

- The user ID comes only from verified claims. A user ID in the request body would let a
  caller change another account's password, so the payload has no such field.
- Tests assert that a wrong current password touches neither `UpdatePassword` nor
  `RevokeAllTokensForUser`, and that the success response does not echo the new password.
- The handler tests build a real `PasswordResetService` rather than mocking it, so the
  step 2 write ordering is exercised through the HTTP layer as well.
- `ChangePassword` does not reject inactive accounts. `Authenticate` already refuses to
  issue tokens to them, so an inactive user cannot reach this route with a fresh token,
  and changing a deactivated account's password grants no access. Left out as
  out-of-scope for this step; revisit if deactivation must invalidate live sessions.

---

## Step 2 — Orchestration, reset-token service, mailer, config (Done)

### Changed / added

| File | What |
| --- | --- |
| `internal/services/password_reset.go` (new) | `PasswordResetService` with `RequestReset`, `ResetWithToken`, `ChangePassword`, and the private `applyNewPassword` orchestration; `crypto/rand` 32-byte opaque token, base64url-encoded, stored as its hex SHA-256 (64 chars, matching the column); `ErrWeakPassword`, `ErrInvalidResetToken`, `ErrInvalidCredentials` |
| `internal/services/interfaces.go` | New `PasswordResetMailer` interface (recipient + prebuilt URL) |
| `internal/mail/file.go` (new) | `FileMailer` — appends `timestamp\trecipient\tURL` to a `0600` file; development only |
| `internal/mail/smtp.go` (new) | `SMTPMailer` over `net/smtp`; `PlainAuth` refuses to send credentials without STARTTLS, so a misconfigured host fails instead of leaking |
| `pkg/env/env.go` | `PasswordResetBaseURL` and `SMTPHost/Port/Username/Password/From` on `EnvConfig`; all required in production via `getEnvRequired`, defaulted in development |
| `cmd/auth-service/main.go` | Constructs `passwordResetRepo` and `PasswordResetService`; selects `SMTPMailer` in production and `FileMailer` (`.reset-links.log`) otherwise, logging a warning |
| `internal/api/server.go`, `routes.go`, `handlers/auth.go` | `NewServer` and `NewAuthHandler` accept the password-reset service |
| `internal/services/password_reset_test.go` (new) | 9 tests, including the write-ordering assertion |
| `pkg/env/env_test.go` | `setProductionMailVars` helper; four production tests now set the newly required variables |
| `.env.example` | Documents `PASSWORD_RESET_BASE_URL`, `PASSWORD_RESET_TOKEN_LIFETIME`, and the SMTP keys |

### Write ordering

`applyNewPassword` runs revoke sessions → invalidate outstanding reset tokens → update
password, aborting on the first failure.
`TestPasswordResetService_ChangePasswordWriteOrder` asserts the exact sequence and
`TestPasswordResetService_PasswordNotUpdatedWhenRevokeFails` asserts the password is not
written when an earlier step fails, so a later refactor cannot reorder them silently.

### Verification

- `go build ./...` — ok
- `go vet ./...` — ok
- `go test ./...` — all packages pass

### Notes

- Password strength is checked before the reset token is consumed, so a rejected password
  does not burn the user's single-use link.
- `RequestReset` returns nil for unknown and inactive accounts and a real error only for
  genuine failures, so the caller cannot leak account existence. A test covers both.
- The raw token never reaches a log: it exists only in the returned URL handed to the
  mailer. Repository and service logs carry `user_id` and `token_id` only.
- Routes are still not mounted — that is steps 3 and 4. `PasswordResetService` is wired
  through `Server` and `AuthHandler` but has no HTTP caller yet.
- `gofmt -l` still flags pre-existing formatting in `interfaces.go` and `env.go` on lines
  this change did not touch; left as-is per the minimal-changes rule.

---

## Step 1 — Reset-token persistence (Done)

### Changed / added

| File | What |
| --- | --- |
| `internal/models/password_reset.go` (new) | `PasswordResetToken` struct (`TokenHash` only, `json:"-"`) + `DefaultPasswordResetTokenLifetime = 15m` |
| `migrations/007_create_password_reset_tokens_table.up.sql` / `.down.sql` (new) | `password_reset_tokens` table: `token_hash VARCHAR(64) UNIQUE`, FK to `users` `ON DELETE CASCADE`, `expires_at`, nullable `consumed_at`; indexes on `token_hash`, `user_id`, and a partial cleanup index `(expires_at) WHERE consumed_at IS NULL`; `CHECK (expires_at > created_at)` — matches the style of migration `002` |
| `internal/repositories/interfaces.go` | New `PasswordResetTokenStore` interface (`Create`, `Consume`, `InvalidateForUser`) |
| `internal/repositories/password_reset.go` (new) | Impl + `ErrResetTokenNotFound` sentinel. `ConsumePasswordResetToken` is a single `UPDATE … WHERE token_hash=$ AND consumed_at IS NULL AND expires_at > now RETURNING …` so check-and-consume is atomic and replay-safe; missing/expired/used all collapse to `ErrResetTokenNotFound` |
| `internal/repositories/password_reset_test.go` (new) | sqlmock tests: create, successful consume, not-found → `ErrResetTokenNotFound`, exec error stays distinct, invalidate-for-user |

### Verification

- `go build ./...` — ok
- `go vet ./...` — ok
- `go test ./...` — all packages pass (new repo tests included)

### Notes

- The repo isn't wired into `cmd/auth-service/main.go` yet — that happens in step 2 (service composition) when there's a consumer.
- `gofmt -l` still flags one pre-existing 2-space-indented line in `interfaces.go` (the `Insert` method, unrelated to this change); left as-is per the minimal-changes rule.
- Migrations are applied by an external runner (`scripts/migrate.sh` is a placeholder); no Go migration wiring needed here.
