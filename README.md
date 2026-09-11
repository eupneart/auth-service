# auth-service

The authentication service of the EupneArt project: a Go microservice that handles
user registration, login, JWT issuing/validation and password recovery.

## Features

- Registration and login with bcrypt password hashing
- JWT access and refresh tokens, with session-scoped revocation on logout and
  periodic cleanup of expired metadata
- Protected routes via `Authorization: Bearer <token>` middleware
- Password reset by email (SMTP in production, local file mailbox in development)
- Per-IP rate limiting on the recovery endpoints
- Structured JSON logging with a request correlation id (`X-Request-Id`)

## Tech stack

Go 1.23 · chi v5 · PostgreSQL (pgx) · golang-jwt v5 · slog · testify / sqlmock · Docker

## Getting started

Requires Go 1.23+ and a reachable PostgreSQL instance.

```bash
cp .env.example .env               # then adjust the values below
make migrate-up                    # apply database migrations
make run                           # start the service
```

`GET /ping` answers once the service is up.

Three values in `.env.example` are set for running **inside** a container network
and need adjusting for a local run:

| Variable  | Example value | Set to        | Why                                              |
| --------- | ------------- | ------------- | ------------------------------------------------ |
| `DB_HOST` | `postgres`    | `localhost`   | `postgres` is a container name; it does not resolve on the host |
| `DB_PORT` | `5432`        | `5433`        | the port Postgres is published on (see below)    |
| `APP_PORT`| `80`          | `8080`        | binding a port below 1024 requires root          |

The file **must** be named `.env`. `pkg/env` reads `.env.<APP_ENV>` only when
`APP_ENV` is already set in the environment, and otherwise reads `.env` — so
copying to `.env.development` without also exporting `APP_ENV=development` leaves
the service with no configuration at all. If you prefer a per-environment file,
export the variable first:

```bash
export APP_ENV=development         # then .env.development is used instead
```

> **Migrations are not applied automatically.** Skipping `make migrate-up` leaves
> `password_reset_tokens` missing, and `POST /password/forgot` still answers `202`
> while failing internally — the failure appears only in the service logs.

## Running with Docker Compose

Optional, and self-contained: this brings up the service and its database only.
Save it as `docker-compose.yml` in this directory.

```yaml
services:
  auth-service:
    build:
      context: .
      dockerfile: auth-service.dockerfile
    ports:
      - "8081:8080"          # host:container — the container side must equal APP_PORT
    env_file:
      - .env                 # no .env is baked into the image; it is injected here
    environment:
      # Override the two values .env holds for host use. Inside the network the
      # database answers on its service name and its own port.
      DB_HOST: postgres
      DB_PORT: 5432
    depends_on:
      postgres:
        condition: service_healthy

  postgres:
    image: postgres:14.2
    ports:
      - "5433:5432"          # published so migrations can run from the host
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: password   # must match DB_PASSWORD in .env
      POSTGRES_DB: users            # must match DB_NAME in .env
    volumes:
      - postgres-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 5

volumes:
  postgres-data:
```

```bash
docker compose up --build -d
make migrate-up                 # from the host, against localhost:5433
curl -i http://localhost:8081/ping
```

Because `environment:` overrides `env_file:`, one `.env` serves both paths: it
keeps `DB_HOST=localhost` / `DB_PORT=5433` for host-run commands such as
`make migrate-up` and `make run`, while the container gets `postgres:5432`.

Without `env_file:` the container starts with no database configuration, falls
back to `localhost` with an empty database name, and crash-loops on `restart`.

## Configuration

Configuration comes from the environment. `pkg/env` loads a single file: it reads
`.env.<APP_ENV>` when `APP_ENV` is set in the environment, and `.env` otherwise.
There is **no fallback between the two** — if the chosen file is missing, the
service continues with the process environment alone. Values already present in
the environment always win, so `DB_HOST=localhost make migrate-up` overrides the
file without editing it. See `.env.example` for the full list.

In development every value has a default and a random `JWT_SECRET` is generated
at startup. In production the service refuses to start without `DB_HOST`,
`DB_PASSWORD`, `DB_NAME`, `JWT_SECRET`, `PASSWORD_RESET_BASE_URL`, `SMTP_HOST`,
`SMTP_USERNAME`, `SMTP_PASSWORD` and `SMTP_FROM`.

Never commit real secrets: `.env`, `.env.development` and `.env.production` are
git-ignored.

## Migrations

SQL migrations live in `migrations/` and are applied by `cmd/migrate`, a small
in-repo tool with no external migration dependency:

```bash
make migrate-up      # apply everything not yet applied
make migrate-down    # roll back the most recent migration only
```

Both resolve the database connection exactly like the service does, through
`pkg/env` — so the rules in [Configuration](#configuration) apply, including
overriding `DB_HOST` inline when Postgres runs in a container.

**Naming.** Each migration is a pair, `<version>_<name>.up.sql` and
`<version>_<name>.down.sql`. The numeric prefix is the version and sets the
order: files are sorted numerically rather than alphabetically, so `010`
correctly follows `002`.

**Tracking.** Applied versions are recorded in `schema_migrations`
(`version`, `applied_at`), created automatically on first run. `up` applies every
file whose version is missing from that table; `down` rolls back only the highest
recorded version, so a mistaken invocation costs one migration instead of the
whole schema.

**Atomicity.** Each file and its bookkeeping row commit in one transaction, so a
failure can never leave the schema changed while the version row claims it
landed. A single file may hold several semicolon-separated statements.

**Writing one.** Prefer `IF NOT EXISTS` so a file stays re-runnable. Note that
`ALTER TABLE ... ADD CONSTRAINT` has no such form — declare `CHECK` and foreign
key constraints inline in `CREATE TABLE`, as `001_initial_schema.up.sql` does.

The `-path` flag points the tool at a different directory (default `migrations`):

```bash
go run ./cmd/migrate -path ./migrations up
```

## API

| Method | Path               | Auth   | Description                                      |
| ------ | ------------------ | ------ | ------------------------------------------------ |
| GET    | `/ping`            | –      | Health check                                     |
| POST   | `/register`        | –      | Create a user (`first_name`, `last_name`, `email`, `password`) |
| POST   | `/authenticate`    | –      | Log in (`email`, `password`) and receive tokens  |
| POST   | `/refresh`         | –      | Exchange a refresh token for a new access token  |
| POST   | `/validate`        | –      | Validate an access token                         |
| POST   | `/password/forgot` | –      | Send a reset link (rate limited)                 |
| POST   | `/password/reset`  | –      | Reset a password with a reset token (rate limited) |
| POST   | `/logout`          | Bearer | End the session, revoking its access and refresh tokens |
| GET    | `/me`              | Bearer | Current user profile                             |
| POST   | `/password/change` | Bearer | Change the password of the logged-in user        |

The recovery endpoints allow 10 requests per IP per minute.

## Make targets

| Target              | Description                              |
| ------------------- | ---------------------------------------- |
| `make build`        | Build the Linux binary into `bin/`       |
| `make run`          | Run the service locally                  |
| `make test`         | Run all tests with race detection        |
| `make test-integration` | Run only `tests/integration`, with race detection |
| `make coverage`     | Print the total and write `coverage.html` |
| `make coverage-check` | Fail if a package is below its minimum |
| `make lint`         | `go vet` plus a `gofmt` check            |
| `make fmt`          | Format the code                          |
| `make migrate-up`   | Apply pending migrations                 |
| `make migrate-down` | Roll back the last applied migration     |
| `make docker-build` | Build the Docker image                   |
| `make clean`        | Remove build and coverage artifacts      |

`migrate-up` and `migrate-down` run on the host and resolve their connection the
same way the service does, so they need `.env` to point at a reachable database.
When Postgres runs in a container, override the two values inline rather than
editing the file:

```bash
DB_HOST=localhost DB_PORT=5433 make migrate-up
```

## Project layout

```
cmd/           service and migration entrypoints
internal/api/  HTTP handlers, middleware and routes
internal/      services (business logic), repositories, models, db, mail, logging
pkg/           reusable helpers (env, ratelimit)
migrations/    SQL migrations
tests/         integration tests
dev-notes/     project documentation and analysis
```

## Tests

```bash
make test                      # everything, with -race
go test ./internal/services/   # a single package
```

The suite runs without external services: repositories are covered with `sqlmock`
and the tests under `tests/integration` exercise the HTTP layer in memory.

### Integration tests

`tests/integration/` drives the real chi router through `httptest`, so a request
travels the whole middleware → handler → service path. Only the outermost
dependencies are substituted — the user repository, token store, token service
and mailer are in-memory fakes.

```bash
make test               # runs them with everything else
make test-integration   # just this package
```

Both carry `-race`; the integration tests are the ones most likely to need it,
since `POST /password/forgot` does its work on a detached goroutine.

They cover the token lifecycle (refresh, validate, `/me`, logout, reuse of a
revoked token, logout revoking the whole session while leaving other sessions
signed in) and the recovery flows: link issuing, that only the token hash is
stored, single-use redemption, expired tokens, session revocation on both reset
and change, and identical responses for known and unknown addresses.

**They do not connect to a database, deliberately.** What this layer is
responsible for is HTTP and service wiring, which fakes cover completely and in
milliseconds; a live Postgres would make `make test` depend on Docker without
testing anything more about it. SQL correctness belongs instead in a separate
build-tagged suite at the repository level, kept out of the default run — worth
adding once more than one person writes migrations, or a second deployed
environment exists.

## Coverage

```bash
make coverage                                    # whole project, prints the total
                                                 # and writes coverage.html
go test -cover ./internal/services/              # a single module
```

For a line-by-line view of one module, generate a profile and inspect it:

```bash
go test -coverprofile=coverage.out ./internal/services/
go tool cover -func=coverage.out                 # per-function percentages
go tool cover -html=coverage.out                 # annotated source in the browser
```

### Minimum thresholds

The whole project should stay at or above **70%**, with per-module minimums
weighted by risk:

| Module                                    | Minimum |
| ----------------------------------------- | ------- |
| `internal/services`                       | 85%     |
| `internal/api/middleware`                 | 85%     |
| `internal/api`, `internal/api/handlers`   | 80%     |
| `pkg/`                                    | 80%     |
| `internal/repositories`, `internal/logging` | 70%   |
| `internal/mail`                           | 50%     |

`make coverage-check` enforces this table and exits non-zero when a package
falls below its minimum. The machine-readable copy of the thresholds lives in
`scripts/coverage-check.sh`; change both together.

The percentage is a floor, not a goal: 85% on `internal/services` means little if
the uncovered part is a token expiry check. Every authentication and
authorization decision should have an explicit negative-path test.

### Excluded packages

`make coverage` measures the package list from `COVERAGE_PKGS` in the `Makefile`,
which drops three packages:

- `cmd/` holds the service and migration entrypoints — wiring and process
  startup, exercised by running the service rather than by unit tests.
- `internal/db` opens the database connection and retries ten times with
  cumulative sleeps of about a minute. There is no seam to shorten that, so a
  test of it would be slow rather than useful.
- `utils` mixes thin JSON helpers, covered indirectly through the handlers that
  call them, with validation helpers that do have direct tests. It stays
  excluded as a package because the JSON half has none of its own.

Including them charged the total for a large block of statements no test is
meant to reach, which pulled the aggregate down far enough to hide regressions
in the code that does matter. `make test` still compiles and runs all three, so
they are not skipped by the suite.

## Docker

```bash
make docker-build   # eupneart/auth-service:latest
```

The image is a multi-stage build running as an unprivileged user. No `.env` file
is baked in; supply the configuration through the environment at run time.

## Documentation

Deeper design notes and guides live in [`dev-notes/`](dev-notes/) — architecture,
JWT, middleware, logging, correlation ids and the password reset implementation.
