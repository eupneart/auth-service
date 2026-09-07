# Step 5 — Details

## What Step 5 did

Steps 1 through 4 built the feature. Step 5 proved it works end to end and made the project's documentation tell the truth about it.

No production code changed in this step — every edit is a test or a document. That was the point: if landing the tests had required changing the implementation, it would have meant the earlier steps were wrong.

The work split in two. First, integration tests that drive the real router through the whole recovery journey, rather than testing each layer in isolation as the earlier steps did. Second, the documentation, which still described password reset as an unimplemented future feature and carried route examples that had never matched the actual routes.

## New files and their goal

| File | Goal |
|---|---|
| **`tests/integration/password_reset_test.go`** | Four end-to-end tests over `server.Routes()` with in-memory fakes, in the style of the existing `TestTokenLifecycle`. These are the only tests that follow a real token from the email it was sent in to the password it changes. |

## Modified files and why

| File | Change | Why |
|---|---|---|
| **`dev-notes/AUTHENTICATION_OVERVIEW.md`** | Removed the "not implemented" note; added a `Password Workflows` section plus TOC entry; route snippet now shows the recovery and change routes; fixed the stale `/api/me` and `/api/protected` examples; realigned the flow diagram | The document actively said this feature did not exist. The route examples had a prefix the service has never used, so anyone copying them would get a 404. |
| **`dev-notes/ARCHITECTURE_OVERVIEW.md`** | Password reset moved out of the "What it does NOT do" list; route map lists all three password endpoints | Same problem, shorter fix. The rate-limiting entry was narrowed rather than deleted, since only the recovery endpoints are limited. |

## What the integration tests cover

| Test | Asserts |
|---|---|
| `TestPasswordRecoveryFlow` | The stored value is the SHA-256 of the emailed token; the password really changes to the submitted one; the pre-existing session stops working; no session is handed back; a replayed link returns 400 **without** changing the password again |
| `TestPasswordRecoveryDoesNotRevealAccounts` | Unknown and existing addresses produce byte-identical responses, and only the real account produces a token and a link |
| `TestPasswordRecoveryRejectsExpiredToken` | An expired link is refused with the same 400 as one that never existed, and revokes nothing |
| `TestAuthenticatedPasswordChangeRevokesSessions` | A wrong current password revokes nothing; a correct one changes the password and invalidates the live session |

## The design decisions

### The fakes implement real semantics, not canned answers

`recoveryTokenStore` is an in-memory map, but it reproduces the repository's actual behaviour: a token is consumable exactly once, and only while unexpired. Both conditions are checked under a mutex, mirroring the `UPDATE ... WHERE consumed_at IS NULL AND expires_at > now RETURNING` statement the real repository runs.

This matters because a stub that simply returned "not found" would make the replay and expiry tests pass without proving anything. With real semantics, the replay test genuinely redeems a valid token and then genuinely fails to redeem it a second time.

Likewise `recoveryUserRepo` stores the bcrypt hash and lets the test read it back, so "the password changed" is verified with `bcrypt.CompareHashAndPassword` against the value that was actually submitted — not merely by observing that `UpdatePassword` was called.

### Tests assert the negative, not just the positive

The most valuable assertions in this file are about things that must *not* happen:

- A replayed token must not change the password a second time
- An expired token must not revoke sessions
- A wrong current password must not revoke sessions
- The reset response must not contain an access token

A regression in any of these would leave the happy path working perfectly. Only the negative assertion catches it.

### Uniformity is checked by comparing bodies, not by inspecting them

`TestPasswordRecoveryDoesNotRevealAccounts` does not assert that the response contains some expected string. It captures the response for an unknown address and the response for a real one and asserts the two are byte-identical. Any future change that adds a helpful detail to one branch and not the other fails here, even if nobody thought to write an assertion for that particular detail.

### In-memory fakes rather than a database

`tests/integration/setup.go` is a placeholder — it logs, returns an empty struct, and connects to nothing. There is no database-backed harness in this project to build on, and the existing `TestTokenLifecycle` uses in-memory fakes for the same reason.

The honest trade-off: these tests verify the wiring, the HTTP contract, and the orchestration, but not the SQL. The atomic single-use `UPDATE ... RETURNING` is the one piece that genuinely deserves a real database, because its correctness under concurrency is a property of Postgres rather than of the Go code. It remains covered by the sqlmock tests from Step 1, which verify the statement shape and the error mapping but not the concurrency guarantee.

Building a real integration harness is worthwhile, but it is its own piece of work and would have expanded this step considerably.

## An incidental fix

While correcting the `/api/me` examples I found the ASCII flow diagram's box borders were already misaligned — an earlier removal of the `/api` prefix had shortened lines without repadding them. My own edit added one more misaligned line. Rather than leave the diagram half-broken, I realigned the whole box to a consistent width.

## Status after this step

All five steps of the plan are complete. One item remains deliberately deferred: the transactional unit-of-work across the three password-change writes, which the plan review postponed until the real call sites existed. They exist now.
