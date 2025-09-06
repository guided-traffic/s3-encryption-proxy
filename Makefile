.PHONY: build build-keygen build-all test test-unit test-integration coverage coverage-ci clean run dev deps lint fmt security gosec vuln static quality all-checks helm-lint helm-test helm-install helm-dev helm-prod

# Build variables
BINARY_NAME=s3-encryption-proxy
KEYGEN_BINARY=s3ep-keygen
BUILD_DIR=build
COVERAGE_DIR=coverage
HELM_CHART_DIR=deploy/helm/s3-encryption-proxy

# Go variables
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=gofmt

# Build the application
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/s3-encryption-proxy

# Build the key generation tool
build-keygen:
	@echo "Building $(KEYGEN_BINARY)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/$(KEYGEN_BINARY) ./cmd/keygen

# Build all binaries
build-all: build build-keygen

# Run the application
run: build
	@echo "Running $(BINARY_NAME)..."
	./$(BUILD_DIR)/$(BINARY_NAME)

# Development run with live reload (requires air)
dev:
	@which air > /dev/null || (echo "Installing air..." && go install github.com/cosmtrek/air@latest)
	air

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

# Run all tests
test:
	@echo "Running all tests..."
	$(GOTEST) -v ./...

# Run unit tests only
test-unit:
	@echo "Running unit tests..."
	$(GOTEST) -v -short ./...

# Run integration tests only
test-integration:
	@echo "Running integration tests..."
	$(GOTEST) -v -tags=integration -run Integration ./...

# Generate test coverage
coverage:
	@echo "Generating coverage report..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -coverprofile=$(COVERAGE_DIR)/coverage.out ./...
	$(GOCMD) tool cover -html=$(COVERAGE_DIR)/coverage.out -o $(COVERAGE_DIR)/coverage.html
	$(GOCMD) tool cover -func=$(COVERAGE_DIR)/coverage.out > $(COVERAGE_DIR)/coverage.txt
	@echo "Coverage report generated at $(COVERAGE_DIR)/coverage.html"
	@echo "Coverage summary:"
	@grep "total:" $(COVERAGE_DIR)/coverage.txt

# Generate coverage for CI
coverage-ci:
	@echo "Generating CI coverage report..."
	@mkdir -p coverage
	$(GOTEST) -coverprofile=coverage/coverage.out ./...
	$(GOCMD) tool cover -func=coverage/coverage.out > coverage/coverage.txt
	@grep "total:" coverage/coverage.txt

# Lint the code
lint: ## Run linting
	@echo "Running static analysis..."
	go vet ./...
	gofmt -l .
	golangci-lint run --no-config --timeout=5m

# Format the code
fmt:
	@echo "Formatting code..."
	$(GOFMT) -s -w .

# Clean build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -rf $(COVERAGE_DIR)

# Install development tools
tools:
	@echo "Installing development tools..."
	go install github.com/cosmtrek/air@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Gosec security scan only
gosec:
	@echo "Running gosec security scan..."
	@which gosec > /dev/null || (echo "Installing gosec..." && go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest)
	gosec ./...

# Vulnerability check
vuln:
	@echo "Checking for vulnerabilities..."
	@which govulncheck > /dev/null || (echo "Installing govulncheck..." && GOTOOLCHAIN=go1.25.0 go install golang.org/x/vuln/cmd/govulncheck@latest)
	GOTOOLCHAIN=go1.25.0 govulncheck ./...

# Static analysis
static:
	@echo "Running static analysis..."
	go vet ./...
	$(GOFMT) -l .

# Code quality checks (linting and formatting)
quality: static lint fmt

# Security checks only
security: gosec vuln

# All checks (quality + security)
all-checks: quality security

# Help
help:
	@echo "Available targets:"
	@echo "  build           - Build the application"
	@echo "  run             - Run the application"
	@echo "  dev             - Run with live reload"
	@echo "  deps            - Download dependencies"
	@echo "  test            - Run all tests"
	@echo "  test-unit       - Run unit tests only"
	@echo "  test-integration - Run integration tests only"
	@echo "  coverage        - Generate test coverage report"
	@echo "  coverage-ci     - Generate coverage report for CI"
	@echo "  lint            - Lint the code"
	@echo "  fmt             - Format the code"
	@echo "  static          - Run static analysis"
	@echo "  quality         - Run code quality checks (static + lint + fmt)"
	@echo "  security        - Run security checks (gosec + vuln)"
	@echo "  gosec           - Run gosec security scan only"
	@echo "  vuln            - Check for vulnerabilities"
	@echo "  all-checks      - Run all checks (quality + security)"
	@echo "  clean           - Clean build artifacts"
	@echo "  tools           - Install development tools"
	@echo "  helm-lint       - Lint Helm chart"
	@echo "  helm-test       - Test Helm chart"
	@echo "  helm-install    - Install Helm chart (dev)"
	@echo "  helm-dev        - Install development Helm chart"
	@echo "  helm-prod       - Install production Helm chart"
	@echo "  help            - Show this help"

# Helm commands
helm-lint:
	@echo "Linting Helm chart..."
	@which helm > /dev/null || (echo "Helm not found. Please install Helm." && exit 1)
	helm lint $(HELM_CHART_DIR)

helm-test: helm-lint
	@echo "Testing Helm chart..."
	helm template test-release $(HELM_CHART_DIR) > /dev/null
	@echo "Helm chart template test passed"

helm-install: helm-test
	@echo "Installing Helm chart in development mode..."
	./deploy/helm/install.sh dev

helm-dev: helm-test
	@echo "Installing development Helm chart..."
	./deploy/helm/install.sh dev

helm-prod: helm-test
	@echo "Installing production Helm chart..."
	./deploy/helm/install.sh prod
