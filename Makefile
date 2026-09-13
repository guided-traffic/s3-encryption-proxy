.PHONY: helm-unittest-plugin build build-keygen build-all license-tool generate-license test test-unit test-unit-race test-integration test-integration-race test-integration-tls test-integration-all test-integration-performance test-conformance test-conformance-minio test-conformance-localstack test-conformance-parallel test-conformance-wasabi test-conformance-wasabi-seed perf-baseline perf-baseline-quick perf-baseline-offline perf-compare e2e-up e2e-down test-e2e-velero e2e-velero e2e-rclone-up e2e-rclone-down test-e2e-rclone e2e-rclone e2e-s3cmd-up e2e-s3cmd-down test-e2e-s3cmd e2e-s3cmd coverage test-unit-coverage coverage-integration-collect coverage-report clean run dev deps lint fmt security gosec vuln static quality all-checks helm-lint helm-test helm-install helm-dev helm-prod helm-monitoring run-monitoring test-monitoring

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

# Version stamp. The Containerfile passes the same three -X flags for the image;
# without them a binary built here reports main.version = "dev", which is what
# every released binary has reported so far. VERSION falls back to the nearest
# tag so a local build says something true rather than nothing.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GIT_COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -w -s -X main.version=$(VERSION) -X main.commit=$(GIT_COMMIT) -X main.buildTime=$(BUILD_TIME)

# Build the application
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/s3-encryption-proxy

# Build the key generation tool
build-keygen:
	@echo "Building $(KEYGEN_BINARY)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(KEYGEN_BINARY) ./cmd/keygen

# Build the license tool
license-tool:
	@echo "Building license-tool..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/license-tool ./cmd/license-tool

# Build all binaries
build-all: build build-keygen license-tool

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

# Unit tests under the Go race detector. Its own target, not a flag on the one
# above: the detector costs roughly 2-20x runtime and 5-10x memory, and it only
# reports races on paths a run actually takes. The concurrency it is here for is
# the multipart producer's worker pool and free list, the session map, the DEK
# cache and the shutdown drain counters.
test-unit-race:
	@echo "Running unit tests under the race detector..."
	$(GOTEST) -race -short -count=1 ./...

# The integration suites under the detector. Needs the demo stack (./start-demo.sh);
# -p 1 because the suites share one backend and the detector makes them slow
# enough for that to matter.
test-integration-race:
	@echo "Running integration tests under the race detector..."
	$(GOTEST) -race -tags=integration -count=1 -p 1 -timeout=120m $(INTEGRATION_PKGS)

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

# The conformance suite asserts what S3 specifies, against a proxy pointed at any
# backend, and the same binary runs against each. MinIO is not S3 and neither is
# any other implementation — a header one acts on and another ignores is the
# class of defect a single-backend suite cannot see — so the difference between
# these runs is the finding, not a flake (ADR 0027).
#
# Each target starts its own backend and its own proxy on its own port, so they
# can run at once. That is also how CI runs them: one runner per backend.
#
#   scripts/conformance-run.sh <backend> [--seed|--clean]
#
# minio and localstack are free and throwaway. wasabi is BILLED: it charges every
# written byte for a minimum of ninety days and refunds nothing on delete, which
# is why only --seed writes and why the seed is idempotent.
test-conformance: test-conformance-minio test-conformance-localstack

test-conformance-minio:
	./scripts/conformance-run.sh minio --seed

test-conformance-localstack:
	./scripts/conformance-run.sh localstack --seed

# Both free backends at once, which is what CI does and what makes the wall clock
# the slowest one rather than the sum.
test-conformance-parallel:
	@./scripts/conformance-run.sh minio --seed      > build/conformance-minio.out 2>&1 & \
	 minio_pid=$$!; \
	 ./scripts/conformance-run.sh localstack --seed > build/conformance-localstack.out 2>&1 & \
	 ls_pid=$$!; \
	 wait $$minio_pid; minio_rc=$$?; \
	 wait $$ls_pid;    ls_rc=$$?; \
	 tail -n 40 build/conformance-minio.out build/conformance-localstack.out; \
	 exit $$((minio_rc + ls_rc))

# THIS COSTS MONEY. See the header above.
test-conformance-wasabi:
	./scripts/conformance-run.sh wasabi

test-conformance-wasabi-seed:
	./scripts/conformance-run.sh wasabi --seed

# The performance package compares proxy throughput against direct MinIO and is
# order sensitive: run in parallel with the rest of the suite it competes for
# the same MinIO and reports a lower efficiency than it would alone. -p 1 and a
# dedicated invocation keep the numbers comparable between runs.
test-integration-performance:
	@echo "Running performance integration tests in isolation..."
	$(GOTEST) -v -tags=integration -count=1 -p 1 -timeout=60m ./test/integration/performance-test/...

# --- Local performance baseline (ADR 0020 D17) ----------------------------
# Deliberately local and referenced by no CI workflow: a baseline compares two
# commits on the same machine, and a shared runner cannot do that. The suite
# carries its own build tag so nothing else can pick it up by accident.
#
#   make perf-baseline                       full run, needs ./start-demo.sh
#   make perf-baseline-quick                 fewer repetitions, throughput sizes <= 8 MiB
#   PERF_LABEL="post-v2" make perf-baseline  label the run
#   PERF_REPS=15 make perf-baseline          more repetitions
#
# Output: perf-baseline/<UTC timestamp>-<commit>/{run.json,REPORT.md}, plus a
# LATEST file naming the newest run.
# Both spellings work: PERF_LABEL=x make perf-baseline, or an exported S3EP_PERF_LABEL.
# The recipes below set the S3EP_* variables as shell assignment prefixes, which would
# otherwise override an exported value.
PERF_REPS ?= $(or $(S3EP_PERF_REPS),7)
PERF_LABEL ?= $(or $(S3EP_PERF_LABEL),unlabelled)

perf-baseline:
	@echo "Running the local performance baseline (label: $(PERF_LABEL))..."
	cd test/perf && S3EP_PERF_REPS=$(PERF_REPS) S3EP_PERF_LABEL="$(PERF_LABEL)" \
		$(GOTEST) -v -tags=perf -count=1 -p 1 -timeout=180m ./...

# Same instruments, small enough to finish while someone watches.
perf-baseline-quick:
	@echo "Running the local performance baseline (quick)..."
	cd test/perf && S3EP_PERF_REPS=3 S3EP_PERF_MAX_SIZE=8388608 \
		S3EP_PERF_LABEL="$(PERF_LABEL)-quick" \
		$(GOTEST) -v -tags=perf -count=1 -p 1 -timeout=60m ./...

# Compare two recorded runs. This is what a baseline is for.
#   make perf-compare BEFORE=perf-baseline/<id> AFTER=perf-baseline/<id>
perf-compare:
	@test -n "$(BEFORE)" -a -n "$(AFTER)" || { echo "usage: make perf-compare BEFORE=<dir> AFTER=<dir>"; exit 2; }
	./test/perf/compare.py "$(BEFORE)" "$(AFTER)"

# The instruments that need no proxy: key unwrap and the in-process crypto floor.
# These are the only "before" numbers that survive the storage format rewrite
# untouched, because they depend on no stack and no stored object.
perf-baseline-offline:
	@echo "Running the stack-free performance instruments..."
	cd test/perf && S3EP_PERF_REPS=$(PERF_REPS) S3EP_PERF_LABEL="$(PERF_LABEL)-offline" \
		$(GOTEST) -v -tags=perf -count=1 -p 1 -timeout=60m \
		-run 'TestUnwrapMicrobenchmark|TestCryptoFloor' ./...

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

# --- Client end-to-end suites (demo compose stack) --------------------------
# rclone and s3cmd, driven as real binaries against the running demo stack. They
# are the proof behind the README's claim to serve these clients (ADR 0006 D7);
# each up-script installs its pinned client and hands the stack to
# ./start-demo.sh, so a workstation and a runner cannot drift apart.
#
# One tool, one set of targets, and one CI job each. They are never bundled: a
# failure has to name the client, and one client's trouble must not withhold the
# other's verdict. Both bring up the same demo stack, so either down target stops
# it.
e2e-rclone-up:
	./test/e2e/rclone/e2e-up.sh

e2e-rclone-down:
	./test/e2e/rclone/e2e-down.sh

test-e2e-rclone:
	@echo "Running rclone e2e suite..."
	$(GOTEST) -v -tags=e2e -count=1 -timeout=30m ./test/e2e/rclone/...

e2e-rclone: e2e-rclone-up test-e2e-rclone

e2e-s3cmd-up:
	./test/e2e/s3cmd/e2e-up.sh

e2e-s3cmd-down:
	./test/e2e/s3cmd/e2e-down.sh

test-e2e-s3cmd:
	@echo "Running s3cmd e2e suite..."
	$(GOTEST) -v -tags=e2e -count=1 -timeout=30m ./test/e2e/s3cmd/...

e2e-s3cmd: e2e-s3cmd-up test-e2e-s3cmd

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
#   make coverage-report                 -> coverage/coverage.txt, coverage.html,
#                                           merged.out, unit.out, integration.out
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
	@# docker cp creates the leaf directory but not its parent. On a fresh checkout
	@# (every CI job) $(COVERAGE_DIR) does not exist yet - only test-unit-coverage
	@# creates it, and the integration job never runs that - so without this line
	@# the copy fails with 'invalid output path'.
	@mkdir -p $(COVERAGE_DIR)
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
	@# One profile per source next to the merged one, so the CI report can show
	@# unit and integration coverage side by side (.github/scripts/coverage-summary.py).
	@rm -f $(COVERAGE_DIR)/unit.out $(COVERAGE_DIR)/integration.out
	@if [ -d $(COVERAGE_DIR)/unit ]; then $(GO_PIN) $(GOCMD) tool covdata textfmt -i=$(COVERAGE_DIR)/unit -o $(COVERAGE_DIR)/unit.out; fi
	@idirs=$$(ls -d $(COVERAGE_DIR)/integration-*/ 2>/dev/null | sed 's:/$$::' | paste -sd, -); \
	if [ -n "$$idirs" ]; then $(GO_PIN) $(GOCMD) tool covdata textfmt -i=$$idirs -o $(COVERAGE_DIR)/integration.out; fi

# Lint the code
#
# LINT_TAGS is every build tag the test tree carries. Without them golangci-lint
# and go vet see neither test/ nor the internal tests behind a tag -- most of the
# Go files in this repository -- and report a green that means "not looked at".
LINT_TAGS := integration,conformance,e2e,perf

lint: ## Run linting
	@echo "Running static analysis..."
	go vet ./...
	go vet -tags=$(LINT_TAGS) ./...
	@# gofmt -l only prints; without this guard an unformatted file passed lint
	@# and the list scrolled by unnoticed. Same flags as the fmt target.
	@unformatted="$$($(GOFMT) -s -l . || true)"; \
	if [ -n "$$unformatted" ]; then \
		echo "not gofmt-clean, run 'make fmt':"; \
		echo "$$unformatted"; \
		exit 1; \
	fi
	golangci-lint run --timeout=5m --build-tags $(LINT_TAGS)

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
# GOLANGCI_LINT_VERSION is the coordinate CI installs. It must stay identical to
# the one in .github/workflows/release.yml: .golangci.yml is a v2 configuration
# and the v1 binary refuses it, so a drift means CI and the workstation lint
# different trees. The path carries /v2 on purpose -- cmd/golangci-lint@latest
# still resolves to the last v1 release.
GOLANGCI_LINT_VERSION := v2.13.1

tools:
	@echo "Installing development tools..."
	@# The last unpinned coordinate in this repository. air is a live-reload
	@# convenience for `make dev` and builds nothing that ships, so a moving
	@# version cannot change an artifact; gosec, govulncheck and golangci-lint
	@# are all pinned because they gate.
	go install github.com/cosmtrek/air@latest
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	@echo "Installed to $$(go env GOPATH)/bin -- make sure it is on your PATH."

# Gosec security scan only
# gosec loads packages through the go/packages of the x/tools it was built with, so a
# binary built against an older Go cannot read the export data of a newer toolchain and
# dies with 'package X without types'. v2.22.8 did exactly that on Go 1.27, in CI and on
# a workstation whose Homebrew gosec was built with 1.26. go run builds the pinned version
# with the toolchain that compiles the code, and never picks up a stray PATH binary.
# Not managed by Renovate; bump by hand together with the Go version.
GOSEC_VERSION := v2.29.0

gosec:
	@echo "Running gosec $(GOSEC_VERSION)..."
	GOFLAGS="-buildvcs=false" go run github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION) ./...

# Vulnerability check
# Same reasoning as GOSEC_VERSION: a govulncheck built with an older Go refuses packages
# that require a newer one ("application built with go1.26"), so the binary must be built
# by the toolchain that compiles the code. The vulnerability database is fetched at run
# time regardless of the binary version, so pinning costs no freshness.
GOVULNCHECK_VERSION := v1.7.0

vuln:
	@echo "Checking for vulnerabilities with govulncheck $(GOVULNCHECK_VERSION)..."
	$(GO_PIN) GOFLAGS="-buildvcs=false" go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

# Static analysis. The formatting check lives in `lint`, which fails on it; a
# second, non-failing copy of it here is how the first one got trusted.
static:
	@echo "Running static analysis..."
	GOFLAGS="-buildvcs=false" go vet ./...

# Code quality checks. fmt runs FIRST: make stops at the first failing
# prerequisite, so with lint ahead of it an unformatted tree never reached the
# target that would have fixed it.
quality: fmt static lint

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
	@echo "  test-unit-race  - Unit tests under the race detector"
	@echo "  test-integration - Run integration tests only"
	@echo "  coverage        - Generate test coverage report"
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

# The helm-unittest plugin version CI installs. Renovate bumps it through the
# custom manager in renovate.json, which keeps it off automerge: this job gates
# semantic-release.
HELM_UNITTEST_VERSION := v1.1.2

helm-unittest-plugin:
	@helm plugin list | grep -q '^unittest' || \
		helm plugin install https://github.com/helm-unittest/helm-unittest \
			--version $(HELM_UNITTEST_VERSION) --verify=false

# Renders EVERY values file, not just the default. Two override files shipped
# unrenderable for months because this target proved only that values.yaml works.
# The Velero values are a real consumer of the chart and a drift there costs a
# 45-minute e2e run to discover, so they render here too.
helm-test: helm-lint helm-unittest-plugin
	@echo "Testing Helm chart..."
	helm template test-release $(HELM_CHART_DIR) > /dev/null
	@for f in $(HELM_CHART_DIR)/values-*.yaml test/e2e/velero/values-proxy.yaml; do \
		echo "  rendering $$f"; \
		helm template test-release $(HELM_CHART_DIR) -f $$f > /dev/null || exit 1; \
	done
	helm unittest $(HELM_CHART_DIR)
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
# Both targets load config/aes-example.yaml, which references ${S3EP_AES_KEY}
# and carries no key of its own (ADR 0021), so they generate one the way the
# demo bring-up does. --if-needed keeps a key that is already there.
run-monitoring: build
	@echo "Starting S3 Encryption Proxy with monitoring enabled..."
	@./scripts/gen-keys.sh --if-needed >/dev/null
	@set -a; . ./.env; set +a; \
	if [ -f config/license.jwt ]; then \
		export S3EP_LICENSE_TOKEN=$$(cat config/license.jwt); \
	fi; \
	./$(BUILD_DIR)/$(BINARY_NAME) --config config/aes-example.yaml

test-monitoring: build
	@echo "Testing monitoring endpoints..."
	@./scripts/gen-keys.sh --if-needed >/dev/null
	@set -a; . ./.env; set +a; \
	if [ -f config/license.jwt ]; then \
		export S3EP_LICENSE_TOKEN=$$(cat config/license.jwt); \
	fi; \
	./$(BUILD_DIR)/$(BINARY_NAME) --config config/aes-example.yaml & \
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
