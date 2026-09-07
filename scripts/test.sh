#!/bin/bash
set -e

echo "Running tests with race detection..."
go test -v -race -cover ./...

echo "✓ All tests passed"
