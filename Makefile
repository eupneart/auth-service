.PHONY: build run test coverage coverage-check lint fmt migrate-up migrate-down docker-build clean help

# Entrypoints (cmd), the database bootstrap (internal/db) and thin helpers
# (utils) are exercised through the service and its integration tests, not
# measured directly, so they are excluded from the coverage profile to keep the
# aggregate meaningful.
COVERAGE_PKGS = $(shell go list ./... | grep -Ev "/(cmd/|internal/db$$|utils$$)")

help:
	@echo "Auth Service Makefile Commands:"
	@echo ""
	@echo "  make build          Build binary for Linux"
	@echo "  make run            Run auth-service locally"
	@echo "  make test           Run all tests with race detection"
	@echo "  make coverage       Generate HTML coverage report"
	@echo "  make coverage-check Fail if any package is below its coverage minimum"
	@echo "  make lint           Run linter (go vet and go fmt check)"
	@echo "  make fmt            Format all Go code"
	@echo "  make migrate-up     Apply pending database migrations"
	@echo "  make migrate-down   Roll back the last applied migration"
	@echo "  make docker-build   Build Docker image"
	@echo "  make clean          Remove build artifacts"
	@echo ""

build:
	@echo "Building auth-service..."
	@mkdir -p bin
	@./scripts/build.sh

run:
	@echo "Running auth-service..."
	@go run ./cmd/auth-service/main.go

test:
	@echo "Running tests..."
	@./scripts/test.sh

coverage:
	@echo "Generating coverage report..."
	@go test -coverprofile=coverage.out $(COVERAGE_PKGS)
	@go tool cover -html=coverage.out -o coverage.html
	@go tool cover -func=coverage.out | tail -1
	@echo "✓ Coverage report generated: coverage.html"

coverage-check:
	@COVERAGE_PKGS="$(COVERAGE_PKGS)" ./scripts/coverage-check.sh

lint:
	@echo "Running linter..."
	@go vet ./...
	@unformatted=$$(gofmt -l .); \
	 if [ -n "$$unformatted" ]; then \
	   echo "⚠ Unformatted files (run 'make fmt'):"; echo "$$unformatted"; exit 1; \
	 else echo "✓ All files properly formatted"; fi

fmt:
	@echo "Formatting code..."
	@go fmt ./...
	@echo "✓ Code formatted"

migrate-up:
	@./scripts/migrate.sh up

migrate-down:
	@./scripts/migrate.sh down

docker-build:
	@echo "Building Docker image..."
	@./scripts/docker-build.sh

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf ./bin/
	@rm -f coverage.out coverage.html
	@echo "✓ Clean complete"
