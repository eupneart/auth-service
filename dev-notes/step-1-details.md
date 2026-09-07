# Step 1 — Details

## What Step 1 did

Added the storage layer for forgotten-password reset tokens. Nothing is wired into the running app yet — this is just the data model, the database table, and the repository methods that later steps will call. When a user requests a reset, the service (Step 2) will generate a random token, email the raw value to the user, and store only its SHA-256 hash here. When the user clicks the link, the token is looked up by hash and "consumed" exactly once.

## New files and their goal

| File | Goal |
|---|---|
| **`internal/models/password_reset.go`** | Defines the `PasswordResetToken` domain type (id, user id, token **hash**, created/expires/consumed timestamps). `TokenHash` is `json:"-"` so it can never leak in an API response. Also holds the `15m` default lifetime constant. |
| **`migrations/007_create_password_reset_tokens_table.up.sql`** | Creates the `password_reset_tokens` table with a unique `token_hash`, a foreign key to `users` (`ON DELETE CASCADE`), an `expires_at`, and a nullable `consumed_at`. Indexes for hash lookup, per-user lookup, and a partial index for the expired-token cleanup job. A CHECK enforces `expires_at > created_at`. A separate table is needed because `token_metadata` only allows `access`/`refresh` types (migration `002`). |
| **`migrations/007_...down.sql`** | Drops the table — the reverse migration. |
| **`internal/repositories/password_reset.go`** | The repository: `CreatePasswordResetToken`, `ConsumePasswordResetToken`, `InvalidatePasswordResetTokensForUser`. `Consume` is a single `UPDATE ... WHERE not-consumed AND not-expired RETURNING ...` so redeeming a token is atomic and can't be replayed. Also defines `ErrResetTokenNotFound`, the sentinel that makes "invalid", "expired", and "already used" indistinguishable to callers (anti-enumeration). |
| **`internal/repositories/password_reset_test.go`** | sqlmock unit tests for the four repository behaviors: create, successful consume, not-found mapping to `ErrResetTokenNotFound`, real DB errors staying distinct, and per-user invalidation. |

## Modified file

| File | Change |
|---|---|
| **`internal/repositories/interfaces.go`** | Added the `PasswordResetTokenStore` interface so services depend on the contract, not the concrete type — matching how `TokenStore` / `UserRepoInterface` are already used. |
