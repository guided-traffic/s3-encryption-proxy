.PHONY: build build-keygen build-all license-tool setup-dev-license generate-license test test-unit test-integration test-integration-tls test-integration-all test-integration-performance e2e-up e2e-down test-e2e-velero e2e-velero coverage test-unit-coverage coverage-integration-collect coverage-report clean run dev deps lint fmt security gosec vuln static quality all-checks helm-lint helm-test helm-install helm-dev helm-prod helm-monitoring run-monitoring test-monitoring

# Go toolchain. The Containerfile FROM line is the single source of truth for
# the Go version in this repo (see CLAUDE.md, "Go toolchain version"); nothing
# else in the Makefile spells it out. GO_PIN forces exactly that version and
# lets go download it once if it is not installed.
GO_VERSION := $(shell sed -n 's/^FROM golang:\([0-9][0-9.]*\)-.*/\1/p' Containerfile)
GO_PIN := GOTOOLCHAIN=go$(GO_VERSION)

# Build variables
BINARY_NAME=s3-encryption-proxy
KEYGEN_BINARY=s3ep-keygen
BUILD_DIR=build
COVERAGE_DIR=coverage
HELM_CHART_DIR=deploy/helm/s3-encryption-proxy
PROXY_TLS_ENDPOINT?=https://127.0.0.1:8443

# Go variables
GOCMD=go
GOBUILD=GOFLAGS="-buildvcs=false" $(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=GOFLAGS="-buildvcs=false" $(GOCMD) test
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

# Build the license tool
license-tool:
	@echo "Building license-tool..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/license-tool ./cmd/license-tool

# Build all binaries
build-all: build build-keygen license-tool

# Setup development license (not committed to git)
setup-dev-license:
	@echo "Setting up development license..."
	./setup-dev-license.sh

# Generate a new license using the license tool
generate-license: license-tool
	@echo "Generating new license..."
	./$(BUILD_DIR)/license-tool

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

# Run integration tests only.
# performance-test is deliberately excluded: it compares proxy throughput against
# direct MinIO, so running it alongside the rest of the suite makes it contend
# for the same backend and report a lower efficiency than it would alone. That is
# what made TestPerformanceComparison/100MB fail inside the full suite and pass
# on its own. Run it with test-integration-performance.
INTEGRATION_PKGS = ./test/integration \
	./test/integration/180-degree-variants \
	./test/integration/360-degree-variants \
	./test/integration/authentication \
	./test/integration/encryption-modes \
	./test/integration/s3-methods

test-integration:
	@echo "Running integration tests..."
	$(GOTEST) -v -tags=integration -count=1 -timeout=60m $(INTEGRATION_PKGS)

# Run the SDK-based integration suites against the TLS proxy endpoint.
# aws-sdk-go-v2 only emits STREAMING-UNSIGNED-PAYLOAD-TRAILER framing and
# checksum trailers over HTTPS, so the plain-HTTP run below cannot reach that
# code path at all. Both are needed.
test-integration-tls:
	@echo "Running integration tests against the TLS proxy endpoint..."
	S3EP_TEST_PROXY_ENDPOINT=$(PROXY_TLS_ENDPOINT) $(GOTEST) -v -tags=integration -count=1 -timeout=60m $(INTEGRATION_PKGS)

# Both transports, plus the order-sensitive performance package on its own.
test-integration-all: test-integration test-integration-tls test-integration-performance

# The performance package compares proxy throughput against direct MinIO and is
# order sensitive: run in parallel with the rest of the suite it competes for
# the same MinIO and reports a lower efficiency than it would alone. -p 1 and a
# dedicated invocation keep the numbers comparable between runs.
test-integration-performance:
	@echo "Running performance integration tests in isolation..."
	$(GOTEST) -v -tags=integration -count=1 -p 1 -timeout=60m ./test/integration/performance-test/...

# --- Velero end-to-end suite (local kind cluster) -------------------------
# e2e-up creates the cluster and installs MinIO, the CSI hostpath driver, the
# proxy and Velero. It is idempotent; re-running rebuilds and reloads the proxy
# image so a code change can be retested without a fresh cluster.
e2e-up:
	./test/e2e/velero/e2e-up.sh

e2e-down:
	./test/e2e/velero/e2e-down.sh

test-e2e-velero:
	@echo "Running Velero e2e suite..."
	$(GOTEST) -v -tags=e2e -count=1 -timeout=60m ./test/e2e/velero/...

# Full cycle for a cold machine.
e2e-velero: e2e-up test-e2e-velero

# --- Coverage ---------------------------------------------------------------
# Coverage comes from two sources that live in different processes: the unit
# tests, and the proxy binary the integration suite talks to over HTTP. Both
# emit Go's binary coverage format (GOCOVERDIR) into subdirectories of
# $(COVERAGE_DIR), and coverage-report merges every directory it finds there.
#
#   make test-unit-coverage              -> coverage/unit
#   GOCOVER=1 ./start-demo.sh            instrumented proxy containers
#   make test-integration test-integration-tls
#   make coverage-integration-collect    -> coverage/integration-http, -tls
#   make coverage-report                 -> coverage/coverage.txt, coverage.html
#
# Every input has to come from the same Go toolchain: block layout and package
# hashes differ between Go releases, and covdata then keeps both variants of a
# package and double counts the denominator (observed 2026-09-06: 1.26 unit data
# + 1.27 proxy data reported 25.9% for a package that was really at 62.8%). The
# proxy image is built with $(GO_VERSION), so the coverage targets run under
# exactly that version via $(GO_PIN).

# Unit tests only (local one-shot): equivalent of the old unit-only report.
coverage: test-unit-coverage coverage-report

test-unit-coverage:
	@echo "Running unit tests with coverage..."
	@rm -rf $(COVERAGE_DIR)/unit && mkdir -p $(COVERAGE_DIR)/unit
	$(GO_PIN) $(GOTEST) -v -short -cover -covermode=atomic ./... -args -test.gocoverdir=$(abspath $(COVERAGE_DIR)/unit)

# Stops the proxy containers (a clean exit is what flushes the counters) and
# copies their coverage data out. They must have been built with GOCOVER=1,
# otherwise the directories come back empty.
coverage-integration-collect:
	@echo "Collecting coverage data from the proxy containers..."
	docker compose -f docker-compose.demo.yml stop s3-encryption-proxy s3-encryption-proxy-tls
	@rm -rf $(COVERAGE_DIR)/integration-http $(COVERAGE_DIR)/integration-tls
	docker cp proxy:/coverage $(COVERAGE_DIR)/integration-http
	docker cp proxy-tls:/coverage $(COVERAGE_DIR)/integration-tls
	@ls $(COVERAGE_DIR)/integration-http $(COVERAGE_DIR)/integration-tls | grep -q covcounters \
		|| { echo "no counter files: were the containers built with GOCOVER=1?"; exit 1; }

coverage-report:
	@dirs=$$(ls -d $(COVERAGE_DIR)/*/ 2>/dev/null | sed 's:/$$::' | paste -sd, -); \
	[ -n "$$dirs" ] || { echo "no coverage data under $(COVERAGE_DIR)/ (run test-unit-coverage and/or coverage-integration-collect first)"; exit 1; }; \
	echo "Merging coverage from: $$dirs"; \
	$(GO_PIN) $(GOCMD) tool covdata textfmt -i=$$dirs -o $(COVERAGE_DIR)/merged.out && \
	$(GO_PIN) $(GOCMD) tool cover -func=$(COVERAGE_DIR)/merged.out > $(COVERAGE_DIR)/coverage.txt && \
	$(GO_PIN) $(GOCMD) tool cover -html=$(COVERAGE_DIR)/merged.out -o $(COVERAGE_DIR)/coverage.html && \
	echo "Coverage report generated at $(COVERAGE_DIR)/coverage.html" && \
	grep "total:" $(COVERAGE_DIR)/coverage.txt

# Lint the code
lint: ## Run linting
	@echo "Running static analysis..."
	go vet ./...
	@# gofmt -l only prints; without this guard an unformatted file passed lint
	@# and the list scrolled by unnoticed. Same flags as the fmt target.
	@unformatted="$$($(GOFMT) -s -l . || true)"; \
	if [ -n "$$unformatted" ]; then \
		echo "not gofmt-clean, run 'make fmt':"; \
		echo "$$unformatted"; \
		exit 1; \
	fi
	golangci-lint run --timeout=5m

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
	@which gosec > /dev/null || (echo "Installing gosec..." && go install github.com/securego/gosec/v2/cmd/gosec@v2.22.8)
	GOFLAGS="-buildvcs=false" gosec ./...

# Vulnerability check
vuln:
	@echo "Checking for vulnerabilities..."
	@which govulncheck > /dev/null || (echo "Installing govulncheck..." && $(GO_PIN) go install golang.org/x/vuln/cmd/govulncheck@latest)
	$(GO_PIN) GOFLAGS="-buildvcs=false" govulncheck ./...

# Static analysis
static:
	@echo "Running static analysis..."
	GOFLAGS="-buildvcs=false" go vet ./...
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

# Monitoring targets
run-monitoring: build
	@echo "Starting S3 Encryption Proxy with monitoring enabled..."
	@if [ -f config/license.jwt ]; then \
		export S3EP_LICENSE_TOKEN=$$(cat config/license.jwt); \
	fi; \
	./$(BUILD_DIR)/$(BINARY_NAME) --config config/aes-example.yaml --monitoring

test-monitoring: build
	@echo "Testing monitoring endpoints..."
	@if [ -f config/license.jwt ]; then \
		export S3EP_LICENSE_TOKEN=$$(cat config/license.jwt); \
	fi; \
	./$(BUILD_DIR)/$(BINARY_NAME) --config config/aes-example.yaml --monitoring & \
	SERVER_PID=$$!; \
	sleep 3; \
	echo "Testing health endpoint..."; \
	curl -f http://localhost:9090/health || (kill $$SERVER_PID; exit 1); \
	echo "Testing metrics endpoint..."; \
	curl -f http://localhost:9090/metrics > /dev/null || (kill $$SERVER_PID; exit 1); \
	echo "Testing custom metrics..."; \
	curl -s http://localhost:9090/metrics | grep -q "s3ep_" || (kill $$SERVER_PID; exit 1); \
	kill $$SERVER_PID; \
	echo "All monitoring tests passed!"

helm-monitoring: helm-test
	@echo "Installing Helm chart with monitoring enabled..."
	helm upgrade --install s3-encryption-proxy $(HELM_CHART_DIR) \
		--values $(HELM_CHART_DIR)/values-monitoring.yaml \
		--namespace default \
		--create-namespace
