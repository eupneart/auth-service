# Step 3 — Details

## What Step 3 did

Steps 1 and 2 built storage and logic that nothing could reach. Step 3 opened the first door: `POST /password/change` is now a live endpoint. An authenticated user can change their password, and doing so signs out every one of their sessions.

Notably, **no new files** were created this step. That's the payoff from Step 2 — the service already had `ChangePassword` ready, so this step was purely wiring HTTP to it. The handler is thin on purpose: it parses, validates presence, delegates, and maps errors to status codes. No security logic lives in it.

## Modified files and why

| File | Change | Why |
|---|---|---|
| **`internal/api/handlers/auth.go`** | Added the `ChangePassword` handler (~60 lines) | The HTTP entry point. Reads the user from `middleware.GetClaimsFromContext` and takes only `current_password` / `new_password` from the body. It follows the existing handler shape in this file — `utils.ReadJSON`, `utils.ErrorJSON`, `utils.JsonResponse`, `slog` with `method`/`remote_addr` keys — so it reads like its neighbours rather than introducing a second style. |
| **`internal/api/routes.go`** | One line: `protectedRoutes.Post("/password/change", authHandler.ChangePassword)` | Mounts it inside the existing `mux.With(authMiddleware)` group, so authentication is enforced by the router rather than by a check inside the handler that someone could later forget to copy. |
| **`internal/api/handlers/auth_test.go`** | Five tests, two stubs, three helpers | Covers the response mapping and, more importantly, asserts what must *not* happen on failure. |
| **`internal/api/routes_test.go`** | One table row | Confirms the route is actually in the protected group — a regression here would be silent, since the handler would still work when called directly. |

## The design decisions

**The payload has no user ID field.** This is the single most important line of the handler. If the request body could name a user, any authenticated caller could change any account's password. Taking it from verified claims makes that impossible by construction rather than by a validation check. It's why the handler has a comment there — it explains a choice, not the code.

**The handler holds no security logic.** Verifying the current password, enforcing strength, revoking sessions, ordering the writes — all of that stayed in `PasswordResetService`. The handler only translates. That's what makes Step 4's two handlers cheap: they'll be the same shape over `RequestReset` and `ResetWithToken`.

**Error mapping via sentinel errors, not string matching:**

| Condition | Status |
|---|---|
| Malformed body or empty field | 400 |
| `services.ErrWeakPassword` | 400 |
| `services.ErrInvalidCredentials` | 401 — `"current password is incorrect"` |
| No claims in context | 401 |
| Anything else | 500, generic message |

The default case deliberately discards the underlying error text and logs it instead. A database failure shouldn't describe itself to the client.

## About the tests

The helper builds a **real** `PasswordResetService` over mock repositories rather than mocking the service. That's the choice worth understanding: mocking the service would have tested only that the handler calls a method. Building the real one means Step 2's write ordering — revoke → invalidate → update — is exercised through the HTTP layer too. If someone later reorders those writes, these handler tests fail alongside the service tests.

Two tests assert absence rather than presence, which is where the real risk lives:

- Wrong current password → neither `UpdatePassword` nor `RevokeAllTokensForUser` is called
- Success → the response body does not contain the new password

## One thing deliberately left out

`ChangePassword` doesn't reject inactive accounts, though `GetMe` does. Judged out of scope: `Authenticate` already refuses to issue tokens to inactive users, so one can't reach this route with a fresh token, and changing a deactivated account's password grants no access anyway. If deactivation is ever meant to kill live sessions immediately, that's a middleware-level gap affecting every protected route — not something to patch inside this one handler.
