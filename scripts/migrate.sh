#!/bin/bash
set -e

# Connection settings come from the same .env files the service uses, so there
# is one source of truth; see pkg/env.LoadEnv.
COMMAND=${1:-up}

echo "Running migrations ($COMMAND)..."
exec go run ./cmd/migrate "$COMMAND"
