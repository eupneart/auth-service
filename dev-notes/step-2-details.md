# Step 2 — Details

## What Step 2 did

Step 1 built the *storage* for reset tokens but nothing used it. Step 2 built the **logic layer** on top: generating tokens, emailing them, and actually performing a password change safely. Everything is now reachable from the handlers — but no HTTP routes exist yet, so none of it runs in response to a request. That's Steps 3 and 4.

The central piece is the decision made during the plan review: no database transaction. Instead, the three writes of a password change happen in a fixed order that makes the dangerous failure state impossible.

## New files and their goal

| File | Goal |
|---|---|
| **`internal/services/password_reset.go`** | The whole feature's business logic. Three public methods — `RequestReset` (forgot-password), `ResetWithToken` (redeem a link), `ChangePassword` (authenticated change) — plus the private `applyNewPassword` that all password changes funnel through. Also generates the token: 32 random bytes → base64url for the URL, hex SHA-256 for the database. Defines `ErrWeakPassword`, `ErrInvalidResetToken`, `ErrInvalidCredentials` so handlers can map failures to status codes without inspecting strings. |
| **`internal/mail/file.go`** | `FileMailer` — the development sink. Appends `timestamp → recipient → URL` to `.reset-links.log` with `0600` permissions. Exists so the flow can be clicked through locally. Its doc comment states plainly that it must never run in production. |
| **`internal/mail/smtp.go`** | `SMTPMailer` — real delivery via `net/smtp`. Chosen over a third-party library because the standard library covers it and CLAUDE.md discourages new dependencies. Notably, `smtp.PlainAuth` refuses to transmit credentials over a connection the server hasn't secured with STARTTLS, so a misconfigured host produces an error instead of quietly leaking the SMTP password. |
| **`internal/services/password_reset_test.go`** | Nine tests. Two exist specifically to protect the ordering guarantee (below); the rest cover hash-not-raw storage, account-existence silence, and error mapping. |

## Modified files and why

| File | Change | Why |
|---|---|---|
| **`internal/services/interfaces.go`** | Added the `PasswordResetMailer` interface | The service depends on "something that can send a link," not on SMTP. That's what lets tests inject a fake and lets production swap providers later. Defined in `services` because that's the consumer — standard Go practice, and it matches where `TokenService` already lives. |
| **`pkg/env/env.go`** | Added `PasswordResetBaseURL` and five SMTP fields; required in production, defaulted in development | Two reasons. The base URL must come from config so it can never be built from a request `Host` header — otherwise an attacker sends a forgot-password request with a forged header and the victim's reset link points at the attacker's server. And making SMTP `getEnvRequired` means production **fails to start** rather than silently falling back to a mailer that doesn't deliver. |
| **`cmd/auth-service/main.go`** | Constructs the reset repo, picks a mailer by environment, builds the service | This is the composition root — the only place that knows SMTP exists. The dev branch logs a warning so a file-mailer deployment is loud, not silent. |
| **`internal/api/server.go`**, **`routes.go`**, **`handlers/auth.go`** | All three now carry `*PasswordResetService` | Pure plumbing, done once here. Both constructors took exactly two services, so Steps 3 and 4 would each have hit the same signature change; doing it now means touching those ~20 test call sites once instead of twice. |
| **`internal/api/handlers/auth_test.go`**, **`routes_test.go`**, **`tests/integration/integration_test.go`** | Pass `nil` for the new parameter | Mechanical consequence of the signature change. `nil` is safe because no test exercises a password route yet. |
| **`pkg/env/env_test.go`** | Added `setProductionMailVars`; four production tests call it | Making the SMTP vars required broke every test that loads a production config. The helper keeps the fix in one place rather than repeating five `Setenv` lines four times. |
| **`.env.example`** | Documented the new keys | It's the tracked config reference (`.env.development` is gitignored), so this is where a deployer finds out these are now mandatory in production. |

## The design decision worth understanding

`applyNewPassword` does three writes with no transaction wrapping them:

1. Revoke all access/refresh tokens
2. Invalidate outstanding reset tokens
3. Update the password

The order isn't cosmetic. There's exactly one partial-failure state that's genuinely dangerous — *password changed, old sessions still valid* — because it means an attacker who stole a session keeps it after the victim's "fix." Putting the password update last makes that state unreachable: any earlier failure aborts with the old password still in place, and the user just retries. That's why two of the nine tests assert the sequence explicitly. Since a comment can't stop a future refactor from reordering the calls, a failing test can.

The two related security details: password strength is checked *before* the token is consumed, so a weak password doesn't waste the single-use link; and `RequestReset` returns `nil` (not an error) for unknown and inactive accounts, so the handler in Step 4 has no way to leak existence even accidentally.
