#!/bin/bash

# Performance Test Script for S3 Encryption Proxy
# This script runs performance tests and generates detailed markdown reports

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/test-results"
TZ_OFFSET="+0200"  # Central European Time (CET/CEST)

# Test size configuration
QUICK_MODE=false  # Always run full tests (quick mode disabled)
KEEP_RAW_LOG=${KEEP_RAW_LOG:-false}  # Set to true to keep the raw log file

# Performance testing configuration
# These settings ensure no caching occurs and tests always run fresh

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Generate timestamp for German timezone
get_timestamp() {
    # Use TZ environment variable for German timezone
    TZ="Europe/Berlin" date '+%Y%m%d-%H%M%S'
}

# Generate ISO timestamp for reports
get_iso_timestamp() {
    TZ="Europe/Berlin" date -Iseconds
}

# Check if required tools are available
check_dependencies() {
    log_info "Checking dependencies..."

    local missing_deps=()

    if ! command -v go &> /dev/null; then
        missing_deps+=("go")
    fi

    if ! command -v docker &> /dev/null; then
        missing_deps+=("docker")
    fi

    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        missing_deps+=("docker-compose")
    fi

    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        log_error "Please install the missing dependencies and try again."
        exit 1
    fi

    log_success "All dependencies are available"
}

# Check if services are running
check_services() {
    log_info "Checking if MinIO and S3 Encryption Proxy are running..."

    # Check MinIO
    if ! curl -k -f https://localhost:9000/minio/health/ready &> /dev/null; then
        log_error "MinIO is not running or not accessible at https://localhost:9000"
        log_info "Starting services with docker-compose..."

        # Stop any existing containers
        docker-compose -f docker-compose.demo.yml down 2>/dev/null || true

        # Build and start services
        if ! ./start-demo.sh; then
            log_error "Failed to start services with start-demo.sh"
            exit 1
        fi

        # Wait for services to be ready
        log_info "Waiting for services to be ready..."
        sleep 10

        # Check again
        local retries=0
        while [ $retries -lt 30 ]; do
            if curl -k -f https://localhost:9000/minio/health/ready &> /dev/null; then
                break
            fi
            sleep 2
            ((retries++))
        done

        if [ $retries -eq 30 ]; then
            log_error "MinIO failed to start after 60 seconds"
            exit 1
        fi
    fi

    # Check S3 Encryption Proxy
    if ! curl -f http://localhost:8080/health &> /dev/null; then
        log_error "S3 Encryption Proxy is not running or not accessible at http://localhost:8080"
        exit 1
    fi

    log_success "Services are running and accessible"
}

# Build the project
build_project() {
    log_info "Building project..."

    if ! make build; then
        log_error "Failed to build project"
        exit 1
    fi

    log_success "Project built successfully"
}

# Create results directory
setup_results_dir() {
    mkdir -p "${RESULTS_DIR}"
    log_info "Results will be stored in: ${RESULTS_DIR}"
}

# Run performance tests and capture output
run_performance_tests() {
    local timestamp="$1"
    local output_file="${RESULTS_DIR}/performance-raw-${timestamp}.log"
    local markdown_file="${RESULTS_DIR}/performance-report-${timestamp}.md"

    # Set global variable for cleanup function
    RAW_LOG_FILE="${output_file}"

    log_info "Running performance tests..."
    log_warning "FULL MODE: Testing file sizes from 100KB to 1GB - this may take 15-30 minutes"
    log_info "Test includes: 100KB, 500KB, 1MB, 3MB, 5MB, 10MB, 50MB, 100MB, 500MB, 1GB"
    log_info "NO CACHING: All caches cleared, tests will run fresh every time"
    log_info "Raw output will be saved to: ${output_file}"

    # Set environment variables for tests
    export CGO_ENABLED=0
    export GOFLAGS="-a"                  # Force rebuilding of all packages
    # Note: QUICK_MODE is not exported to ensure tests always run in full mode

    # Clear Go build and test cache to ensure fresh results
    log_info "Clearing Go build and test cache for fresh results..."
    go clean -cache -testcache -modcache 2>/dev/null || true

    # Also clear any potential build artifacts
    rm -rf ./build/* 2>/dev/null || true

    # Force rebuild to ensure no cached binaries
    log_info "Force rebuilding project to ensure fresh binaries..."
    make clean 2>/dev/null || true
    make build || {
        log_error "Failed to rebuild project"
        exit 1
    }

    # Named rather than left to the test's default, which is relative to the
    # package directory. Removed first so a run that produces no summary embeds
    # nothing instead of the previous run's numbers.
    export S3EP_PERF_SUMMARY="${RESULTS_DIR}/performance-summary.md"
    rm -f "${S3EP_PERF_SUMMARY}" "${RESULTS_DIR}/performance-totals.env"

    # Run the specific performance tests with verbose output and extended timeout for large files
    # Use -count=1 to disable test result caching and ensure fresh results every time
    # Use -a flag to force rebuilding of packages
    local test_output
    if test_output=$(go test -a -count=1 -v -tags=integration ./test/integration/performance-test -run="TestPerformanceComparison|TestStreamingPerformance" -timeout=30m 2>&1); then
        log_success "Performance tests completed successfully"
    else
        log_warning "Performance tests completed with warnings (exit code: $?)"
    fi

    # Save raw output
    echo "$test_output" > "$output_file"

    # Generate markdown report
    generate_markdown_report "$test_output" "$markdown_file" "$timestamp"

    log_success "Results saved to: $markdown_file"
}

# Parse test output and generate markdown report
generate_markdown_report() {
    local test_output="$1"
    local markdown_file="$2"
    local timestamp="$3"
    local iso_timestamp
    iso_timestamp=$(get_iso_timestamp)

    log_info "Generating markdown report..."

    cat > "$markdown_file" <<EOF
# S3 Encryption Proxy - Performance Test Report

**Test Execution Date:** ${iso_timestamp}
**Test ID:** ${timestamp}
**Generated by:** performance.sh

## Executive Summary

This report compares the S3 Encryption Proxy against direct MinIO access, on the same
machine and in the same run. Both legs move the same bytes with the same client.

### Key Metrics

- **Ratio:** how much of the direct leg's throughput the proxy leg retains. It is a proxy path against a direct path, not the cost of encryption (ADR 0020 D16)
- **Proxy adds:** the milliseconds the proxy leg costs per MiB. No baseline in the denominator, so it is the only figure on which the upload and the download leg may be compared with each other
- **Throughput:** MiB/s, total bytes over total time for the overall table, one sample per size below it

---

EOF

    # The comparison tables are rendered by the measurement itself and copied in
    # whole. They used to be rebuilt here by awking the test log's fixed-width
    # table apart and grepping three summary lines by position, which published
    # the equal-weighted mean of the per-size ratios rather than the
    # byte-weighted numbers the test computes (ADR 0020 D16).
    if [ -f "${RESULTS_DIR}/performance-summary.md" ]; then
        cat "${RESULTS_DIR}/performance-summary.md" >> "$markdown_file"
        echo >> "$markdown_file"
    else
        echo "No performance comparison summary was produced." >> "$markdown_file"
        echo >> "$markdown_file"
    fi

    # Parse streaming performance results
    if echo "$test_output" | grep -q "Streaming Performance Test Results"; then
        cat >> "$markdown_file" <<EOF
## Streaming Performance Results

The following shows detailed performance metrics for streaming operations through the encryption proxy:

EOF

        # Extract streaming performance table - look for the actual log format
        echo "$test_output" | grep "performance_test.go:110:" > /tmp/streaming_data.txt || true

        if [ -s /tmp/streaming_data.txt ]; then
            cat >> "$markdown_file" <<EOF
| File Size | Upload Time | Download Time | Upload MB/s | Download MB/s | Total Time |
|-----------|-------------|---------------|-------------|---------------|------------|
EOF

            # Process streaming performance data
            while IFS= read -r line; do
                if echo "$line" | grep -q "performance_test.go:110:"; then
                    # Extract the data after the log prefix, handling multiple tabs
                    data_part=$(echo "$line" | sed 's/.*performance_test.go:110: //')

                    # Replace multiple tabs with single tabs and split
                    normalized_data=$(echo "$data_part" | tr -s '\t' '\t')

                    # Split on tabs and extract fields
                    size=$(echo "$normalized_data" | cut -f1)
                    upload_time=$(echo "$normalized_data" | cut -f2)
                    download_time=$(echo "$normalized_data" | cut -f3)
                    upload_mbps=$(echo "$normalized_data" | cut -f4)
                    download_mbps=$(echo "$normalized_data" | cut -f5)
                    total_time=$(echo "$normalized_data" | cut -f6)

                    if [[ -n "$size" && "$size" != "Size" ]]; then
                        echo "| $size | $upload_time | $download_time | $upload_mbps | $download_mbps | $total_time |" >> "$markdown_file"
                    fi
                fi
            done < /tmp/streaming_data.txt

            cat >> "$markdown_file" <<EOF

**Additional Details:**
\`\`\`
$(echo "$test_output" | grep -A 10 "Performance Summary" || echo "No summary available")
\`\`\`
EOF

            rm -f /tmp/streaming_data.txt
        fi
    fi

    # Add encryption overhead analysis
    cat >> "$markdown_file" <<EOF
## What the ratio contains

The proxy leg is not the direct leg plus a cipher. It carries, in this order:

1. **One extra network hop**, plaintext client to proxy, on top of the proxy's own TLS hop to the backend
2. **One AES-256-GCM segment chain per object**, sealed by a trailer that authenticates the plaintext length and its CRC32C
3. **One data key per object**, wrapped by the configured key encryption key
4. **Checksum verification** of every digest the client declares, against the decoded plaintext

A ratio worse than roughly a third of the direct path is a finding and is reported
as one (ADR 0020 D9); nothing here fails a build (ADR 0020 D11).

---

## Technical Details

### Test Environment

- **Proxy Version:** $(./build/s3-encryption-proxy --version 2>/dev/null || echo "Unknown")
- **Test Method:** Go integration tests with real MinIO backend
- **Encryption Provider:** aes (AES-256-GCM segment chain, one wrapped data key per object)
- **Test Data:** Randomly generated binary data

### Test Configuration

- **MinIO Endpoint:** https://localhost:9000 (TLS enabled)
- **Proxy Endpoint:** http://localhost:8080
- **Upload Method:** AWS S3 Manager with 5MB part size
- **Download Method:** Full object retrieval and reading
- **Concurrency:** 3 parallel parts for multipart uploads

### Limitations

- Tests are performed in a local Docker environment
- Network latency is minimal compared to real-world scenarios
- Results may vary based on system resources and load
- File sizes limited to avoid test environment instability

---

## Raw Test Output

<details>
<summary>Click to expand raw test output</summary>

\`\`\`
$test_output
\`\`\`

</details>

---

*Report generated on $(date -Iseconds) by S3 Encryption Proxy Performance Test Suite*
EOF

    log_success "Markdown report generated successfully"
}

# Display summary of results
show_summary() {
    local timestamp="$1"
    local markdown_file="${RESULTS_DIR}/performance-report-${timestamp}.md"
    local raw_log_file="${RESULTS_DIR}/performance-raw-${timestamp}.log"

    echo
    log_success "Performance test completed!"
    echo
    echo "Results:"
    echo "  - Markdown Report: ${markdown_file}"
    if [[ "${KEEP_RAW_LOG}" == "true" ]]; then
        echo "  - Raw Log: ${raw_log_file} (kept)"
    else
        echo "  - Raw Log: ${raw_log_file} (will be deleted)"
    fi
    echo

    if [ -f "$markdown_file" ]; then
        log_info "Quick Summary from Report:"
        echo
        # Extract key metrics if available
        if [ -f "${RESULTS_DIR}/performance-summary.md" ]; then
            sed -n '/^| \*\*Upload\*\*/p;/^| \*\*Download\*\*/p' \
                "${RESULTS_DIR}/performance-summary.md" | sed 's/^/  /'
        fi
        echo
    fi

    log_info "View the complete report with: cat ${markdown_file}"
    log_info "Or open it in your preferred markdown viewer"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up temporary files..."
    rm -f /tmp/streaming_data.txt

    # Clean up raw log file unless KEEP_RAW_LOG is set
    if [[ "${KEEP_RAW_LOG}" != "true" && -n "${RAW_LOG_FILE:-}" && -f "${RAW_LOG_FILE}" ]]; then
        log_info "Removing raw log file: ${RAW_LOG_FILE}"
        rm -f "${RAW_LOG_FILE}"
    elif [[ "${KEEP_RAW_LOG}" == "true" && -n "${RAW_LOG_FILE:-}" ]]; then
        log_info "Keeping raw log file: ${RAW_LOG_FILE}"
    fi
}

# Main execution
main() {
    # Handle help flag
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        cat <<EOF
S3 Encryption Proxy - Performance Test Suite

USAGE:
    ./performance.sh [OPTIONS]

DESCRIPTION:
    Runs comprehensive performance tests comparing encrypted S3 operations
    (via proxy) against unencrypted operations (direct MinIO). Results are
    saved as timestamped markdown reports in the test-results/ directory.

    All caches are cleared and tests always run fresh to ensure accurate
    performance measurements.

OPTIONS:
    -h, --help    Show this help message

ENVIRONMENT VARIABLES:
    KEEP_RAW_LOG=true     Keep the raw log file after test completion (default: false)

EXAMPLES:
    ./performance.sh                    # Full test suite (100KB-1GB), raw log deleted
    KEEP_RAW_LOG=true ./performance.sh  # Full test, keep raw log

REQUIREMENTS:
    - Go (for building and running tests)
    - Docker and docker-compose (for services)
    - MinIO and S3 Encryption Proxy running (auto-started if needed)

OUTPUT:
    - test-results/performance-report-YYYYMMDD-HHMMSS.md (always kept)
    - test-results/performance-raw-YYYYMMDD-HHMMSS.log (deleted by default, use KEEP_RAW_LOG=true to keep)

EXAMPLES:
    ./performance.sh              # Run full performance tests (100KB - 1GB)
    ./performance.sh --help       # Show this help

TEST SIZES:
    All tests: 100KB, 500KB, 1MB, 3MB, 5MB, 10MB, 50MB, 100MB, 500MB, 1GB

EXPECTED RUNTIME:
    All tests: 15-30 minutes (depending on system performance)

For more information, see docs/developer/performance.md
EOF
        exit 0
    fi

    local timestamp
    timestamp=$(get_timestamp)

    echo "================================================================"
    echo "S3 Encryption Proxy - Performance Test Suite"
    echo "================================================================"
    echo "Timestamp: $timestamp"
    echo "Results Directory: $RESULTS_DIR"
    echo "================================================================"
    echo

    # Set trap for cleanup
    trap cleanup EXIT

    # Run all steps
    check_dependencies
    setup_results_dir
    build_project
    check_services
    run_performance_tests "$timestamp"
    show_summary "$timestamp"

    log_success "Performance testing completed successfully!"
}

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
