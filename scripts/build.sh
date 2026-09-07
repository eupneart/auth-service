#!/bin/bash
set -e

echo "Building auth-service..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ./bin/auth-service ./cmd/auth-service

echo "✓ Build complete: ./bin/auth-service"
