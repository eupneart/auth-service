# Build stage: compiles a static binary so the runtime image needs no toolchain
# and no libc beyond what Alpine provides.
FROM golang:1.23-alpine AS builder

WORKDIR /src

# Dependencies are copied first so module downloads stay cached across source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/auth-service ./cmd/auth-service

# Runtime stage
FROM alpine:3.21

# ca-certificates is required for TLS database connections (DB_SSLMODE) and any
# other outbound TLS; tzdata backs the DB_TIMEZONE setting.
RUN apk add --no-cache ca-certificates tzdata

# The service needs no privileges, so it runs as a dedicated unprivileged user.
RUN adduser -D -u 10001 app

WORKDIR /app

COPY --from=builder /out/auth-service /app/auth-service

# The development file mailer appends reset links to this file, and the service
# runs unprivileged in a root-owned WORKDIR, so it cannot create it itself.
# Granting only the file keeps /app root-owned, so the binary stays unreplaceable.
# Never reached in production, where SMTP is used instead.
RUN touch /app/.reset-links.log \
    && chown app:app /app/.reset-links.log

USER app

EXPOSE 8080

# Configuration is supplied through the environment at run time. No .env file is
# baked into the image: it would ship JWT_SECRET and the database password in a
# readable layer. pkg/env falls back to the process environment when the file is
# absent.
CMD ["/app/auth-service"]
