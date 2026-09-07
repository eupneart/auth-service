.PHONY: build run test coverage lint fmt migrate-up migrate-down docker-build clean help

help:
	@echo "Auth Service Makefile Commands:"
	@echo ""
	@echo "  make build          Build binary for Linux"
	@echo "  make run            Run auth-service locally"
	@echo "  make test           Run all tests with race detection"
	@echo "  make coverage       Generate HTML coverage report"
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
	@go test -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "✓ Coverage report generated: coverage.html"

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
