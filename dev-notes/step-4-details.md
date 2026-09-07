# Step 4 — Details

## What Step 4 did

Step 3 opened the authenticated door. Step 4 opened the public one: a user who has forgotten their password can now request a link at `POST /password/forgot` and redeem it at `POST /password/reset`. With this the feature is functionally whole — every endpoint in the original API contract exists and works.

This step carried more than the handlers, because the plan review added two requirements the original plan had missed: rate limiting (the service had none at all) and closing the timing side channel that a uniform `202` alone leaves open. Both are security requirements rather than features, and both shaped the design more than the handlers did.

## New files and their goal

| File | Goal |
|---|---|
| **`pkg/ratelimit/ratelimit.go`** | A fixed-window counter keyed by an arbitrary string. Lives in `pkg/` rather than inside `middleware` because both the HTTP layer and the service layer need it, and `services` importing `api/middleware` would invert the dependency direction. Nil and zero-limit are permissive, so a missing limiter degrades to "no limit" rather than "no service". |
| **`internal/api/middleware/ratelimit.go`** | The HTTP wrapper: returns 429 once a source address exceeds its allowance. Matches the existing middleware style in this package (`http.Error`, `slog` with `remote_addr`). |
| **`pkg/ratelimit/ratelimit_test.go`** | Seven tests covering the allowance, key independence, window reset, sweep behaviour, the permissive cases, and concurrent use. |

## Modified files and why

| File | Change | Why |
|---|---|---|
| **`internal/api/handlers/auth.go`** | Added `ForgotPassword` and `ResetPassword` | The two public entry points. `ResetPassword` is the same thin shape as `ChangePassword` — parse, validate presence, delegate, map errors. `ForgotPassword` is deliberately *not* that shape; see below. |
| **`internal/api/routes.go`** | Mounted both on a new rate-limited group | Only the recovery routes get the limiter. Applying it globally would change behaviour for existing endpoints, which is outside this step's scope. |
| **`internal/api/server.go`** | `Server` now owns the IP limiter | Building it inside `Routes()` would reset every counter whenever routes are constructed. `Routes()` happens once in `main`, but the dead `ServeHttp` method calls it per request — so a limiter built there would be silently useless if anyone ever wired that up. |
| **`internal/services/password_reset.go`** | Added a per-email limiter to `RequestReset` | The second of the two limits (below). |
| **`internal/api/handlers/auth_test.go`** | Eight new tests; the Step 3 stubs became recording fakes | The stubs couldn't observe anything. The fakes record created tokens and sent mail, with mutexes because the detached goroutine writes to them. |
| **`internal/api/routes_test.go`** | Both routes are public; the allowance is enforced on them and not elsewhere | A rate limit applied to the wrong route group would be invisible without this. |

## The design decisions

### ForgotPassword responds before doing the work

The handler validates the email format, returns `202`, and *then* runs the lookup, token insert, and mail send on a detached goroutine.

This is the timing fix. A uniform `202` closes the obvious leak, but not the measurable one: the existing-account path does a database insert and an SMTP round trip, while the unknown-account path returns almost immediately. That difference is enough to enumerate accounts. Responding first makes the response time independent of account state.

Three consequences followed from that choice:

- **The request context can't be reused.** It is cancelled the moment the handler returns, which would kill the work that was just started. The goroutine builds its own context with a 30-second timeout.
- **The goroutine recovers from panics.** A panic raised off the request goroutine cannot be caught by any HTTP middleware, so an unguarded one would take down the whole process rather than failing one request. This is the one place in the codebase where a bare `recover()` is warranted, and it is commented as such.
- **Tests need `assert.Eventually`.** Nothing about the response tells you the work finished.

### Service errors still return 202

If a database failure or a mail-send failure produced a `500`, an attacker could separate "no such account" (fast `202`) from "account exists, mail failed" (`500`). So `RequestReset`'s error is logged and the response stays `202` regardless. The status code carries no information about the account.

This is why `RequestReset` was written in Step 2 to return `nil` for unknown and inactive accounts and a real error only for genuine failures — the handler can log the difference without exposing it.

### Two rate limits, not one

They protect different resources, so neither substitutes for the other:

| Limit | Where | Response |
|---|---|---|
| 10 per minute per source address | HTTP middleware | 429 |
| 3 per 15 minutes per email address | Inside `RequestReset` | Silently skips the send, still 202 |

The IP limit stops one origin from sweeping the user table. It does nothing against a botnet pointed at one victim's inbox — that's what the per-email limit is for. Conversely the per-email limit does nothing against a sweep across many addresses.

The per-email check runs *after* the account is confirmed active, which matters: keying on raw request input would let an attacker fill the limiter's map with millions of made-up addresses. Keying on a confirmed account bounds the key space to real users. The limiter also sweeps expired counters for the same reason.

The per-email limit returns `202` rather than `429` because a `429` on a specific address would reveal that someone recently requested a reset for it.

### RemoteAddr, not X-Forwarded-For

The IP limiter keys on `r.RemoteAddr`. `X-Forwarded-For` is set by the caller, and there is no trusted-proxy configuration in this service, so honouring it would let an attacker reset their own counter on every request by varying the header. Chi's `RealIP` middleware does exactly that and was deliberately not used.

The trade-off is that behind a reverse proxy this limits per proxy rather than per client. The proxy should carry its own per-client limit. This is noted in the middleware's doc comment so nobody "fixes" it later.

## About the tests

The uniformity test is the one that matters most: it collects the response bodies for unknown, inactive, and active accounts and asserts they are byte-identical. A future change that adds a helpful detail to one branch fails here.

The delivery test asserts the opposite side — that a link is sent *only* for the active account — so uniformity of the response is not achieved by simply never sending anything.

The throttle test issues eight rapid requests, confirms all eight return `202`, and confirms sends stopped partway. Both halves are necessary: the response must not change, and the mail must actually stop.

`go test -race` was run over `pkg/ratelimit` and `internal/api/...` because this step introduced the first shared mutable state in the codebase — the limiter maps and the fakes written from the detached goroutine.

## Known limitations

- **Limiter state is per process and in memory.** A multi-instance deployment limits per instance. It is an abuse brake, not a hard quota. Shared state would need Redis or similar.
- **Both limits are compile-time constants.** They should move to configuration if they need tuning per environment.
- **The per-email limiter never forgets across restarts.** A restart resets every counter. Acceptable for a brake; worth knowing.
