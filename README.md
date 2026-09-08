# auth-service

The authentication service of the EupneArt project: a Go microservice that handles
user registration, login, JWT issuing/validation and password recovery.

## Features

- Registration and login with bcrypt password hashing
- JWT access and refresh tokens, with revocation and periodic cleanup of expired metadata
- Protected routes via `Authorization: Bearer <token>` middleware
- Password reset by email (SMTP in production, local file mailbox in development)
- Per-IP rate limiting on the recovery endpoints
- Structured JSON logging with a request correlation id (`X-Request-Id`)

## Tech stack

Go 1.23 · chi v5 · PostgreSQL (pgx) · golang-jwt v5 · slog · testify / sqlmock · Docker

## Getting started

Requires Go 1.23+ and a reachable PostgreSQL instance.

```bash
cp .env.example .env.development   # adjust the values
make migrate-up                    # apply database migrations
make run                           # start the service (default port 8080)
```

`GET /ping` answers once the service is up.

## Configuration

Configuration comes from the environment. `pkg/env` loads `.env.<APP_ENV>` (for
example `.env.development`) and falls back to `.env`, then to the process
environment; see `.env.example` for the full list.

In development every value has a default and a random `JWT_SECRET` is generated
at startup. In production the service refuses to start without `DB_HOST`,
`DB_PASSWORD`, `DB_NAME`, `JWT_SECRET`, `PASSWORD_RESET_BASE_URL`, `SMTP_HOST`,
`SMTP_USERNAME`, `SMTP_PASSWORD` and `SMTP_FROM`.

Never commit real secrets: `.env`, `.env.development` and `.env.production` are
git-ignored.

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
| POST   | `/logout`          | Bearer | Revoke the current access token                  |
| GET    | `/me`              | Bearer | Current user profile                             |
| POST   | `/password/change` | Bearer | Change the password of the logged-in user        |

The recovery endpoints allow 10 requests per IP per minute.

## Make targets

| Target              | Description                              |
| ------------------- | ---------------------------------------- |
| `make build`        | Build the Linux binary into `bin/`       |
| `make run`          | Run the service locally                  |
| `make test`         | Run all tests with race detection        |
| `make coverage`     | Generate `coverage.html`                 |
| `make lint`         | `go vet` plus a `gofmt` check            |
| `make fmt`          | Format the code                          |
| `make migrate-up`   | Apply pending migrations                 |
| `make migrate-down` | Roll back the last migration             |
| `make docker-build` | Build the Docker image                   |
| `make clean`        | Remove build and coverage artifacts      |

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

## Docker

```bash
make docker-build   # eupneart/auth-service:latest
```

The image is a multi-stage build running as an unprivileged user. No `.env` file
is baked in; supply the configuration through the environment at run time.

## Documentation

Deeper design notes and guides live in [`dev-notes/`](dev-notes/) — architecture,
JWT, middleware, logging, correlation ids and the password reset implementation.
