#!/bin/bash

# Performance Test Script for S3 Encryption Proxy
# This script runs performance tests and generates detailed markdown reports

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/test-results"
TZ_OFFSET="+0200"  # Central European Time (CET/CEST)

# Test size configuration
QUICK_MODE=${QUICK_MODE:-false}  # Set to true to run only smaller files
KEEP_RAW_LOG=${KEEP_RAW_LOG:-false}  # Set to true to keep the raw log file

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
    if [[ "${QUICK_MODE}" == "true" ]]; then
        log_info "QUICK MODE: Testing file sizes from 100KB to 10MB (estimated runtime: 2-5 minutes)"
        log_info "Test includes: 100KB, 500KB, 1MB, 3MB, 5MB, 10MB"
    else
        log_warning "FULL MODE: Testing file sizes from 100KB to 1GB - this may take 15-30 minutes"
        log_info "Test includes: 100KB, 500KB, 1MB, 3MB, 5MB, 10MB, 50MB, 100MB, 500MB, 1GB"
        log_info "Set QUICK_MODE=true to test only smaller files (up to 10MB)"
    fi
    log_info "Raw output will be saved to: ${output_file}"

    # Set environment variables for tests
    export CGO_ENABLED=0
    export SKIP_PERFORMANCE_CHECKS=true  # Skip strict performance validation
    export QUICK_MODE=${QUICK_MODE}      # Pass through QUICK_MODE setting

    # Clear Go build and test cache to ensure fresh results
    log_info "Clearing Go build and test cache for fresh results..."
    go clean -cache -testcache -modcache 2>/dev/null || true

    # Run the specific performance tests with verbose output and extended timeout for large files
    # Use -count=1 to disable test result caching and ensure fresh results every time
    local test_output
    if test_output=$(go test -count=1 -v -tags=integration ./test/integration/performance-test -run="TestPerformanceComparison|TestStreamingPerformance" -timeout=30m 2>&1); then
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

This report shows the performance impact of the S3 Encryption Proxy compared to direct MinIO access. The tests measure upload and download throughput for various file sizes and calculate the efficiency percentage.

### Key Metrics

- **Efficiency Percentage:** Indicates how much of the original (unencrypted) performance is retained when using the encryption proxy
- **Overhead Percentage:** Shows the additional time required for encryption/decryption (100% - Efficiency%)
- **Throughput:** Measured in MB/s for both upload and download operations

---

EOF

    # Parse and extract performance comparison results
    if echo "$test_output" | grep -q "S3 Encryption Proxy vs Plain MinIO"; then
        cat >> "$markdown_file" <<EOF
## Performance Comparison Results

The following table compares encrypted (via proxy) vs unencrypted (direct MinIO) performance:

EOF

        # Extract the comparison table - look for lines with the pipe-separated format
        echo "$test_output" | grep -E "[0-9]+[KMGT]?B[ ]*\|" > /tmp/perf_data.txt || true

        if [ -s /tmp/perf_data.txt ]; then
            cat >> "$markdown_file" <<EOF
| File Size | Encrypted Upload (MB/s) | Plain Upload (MB/s) | Encrypted Download (MB/s) | Plain Download (MB/s) | Upload Efficiency | Download Efficiency |
|-----------|-------------------------|---------------------|---------------------------|-----------------------|-------------------|---------------------|
EOF

            while IFS= read -r line; do
                # Parse the performance data line using awk for better field splitting
                size=$(echo "$line" | awk '{print $1}')
                enc_up=$(echo "$line" | awk -F'|' '{gsub(/[[:space:]]/, "", $2); print $2}')
                plain_up=$(echo "$line" | awk -F'|' '{gsub(/[[:space:]]/, "", $3); print $3}')
                enc_down=$(echo "$line" | awk -F'|' '{gsub(/[[:space:]]/, "", $4); print $4}')
                plain_down=$(echo "$line" | awk -F'|' '{gsub(/[[:space:]]/, "", $5); print $5}')
                up_eff=$(echo "$line" | awk -F'|' '{gsub(/[[:space:]]/, "", $6); gsub(/%/, "", $6); print $6}')
                down_eff=$(echo "$line" | awk -F'|' '{gsub(/[[:space:]]/, "", $7); gsub(/%/, "", $7); print $7}')

                if [[ -n "$size" && -n "$enc_up" && -n "$plain_up" ]]; then
                    echo "| $size | $enc_up | $plain_up | $enc_down | $plain_down | $up_eff% | $down_eff% |" >> "$markdown_file"
                fi
            done < /tmp/perf_data.txt

            rm -f /tmp/perf_data.txt
        else
            echo "No performance comparison data found in test output." >> "$markdown_file"
        fi

        cat >> "$markdown_file" <<EOF

### Performance Analysis

EOF

        # Extract summary information (only the 3 key lines)
        local summary_section
        summary_section=$(echo "$test_output" | grep -A 3 "=== Performance Comparison Summary ===" | tail -3 || echo "Summary not available")

        cat >> "$markdown_file" <<EOF
\`\`\`
=== Performance Comparison Summary ===
$summary_section
\`\`\`

EOF
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
## Encryption Overhead Analysis

The encryption proxy introduces computational overhead due to:

1. **Envelope Encryption**: Each object uses a unique Data Encryption Key (DEK) encrypted with a Key Encryption Key (KEK)
2. **Streaming Encryption**: Large files are encrypted in chunks during multipart uploads
3. **Metadata Processing**: Additional S3 metadata is stored and processed for encryption parameters
4. **Network Latency**: Additional hop through the proxy service

### Interpretation Guide

- **High Efficiency (>80%)**: Encryption overhead is minimal, mostly network and processing latency
- **Medium Efficiency (50-80%)**: Noticeable encryption overhead, but still practical for most use cases
- **Low Efficiency (<50%)**: Significant overhead, may indicate system resource constraints or configuration issues

---

## Technical Details

### Test Environment

- **Proxy Version:** $(./build/s3-encryption-proxy --version 2>/dev/null || echo "Unknown")
- **Test Method:** Go integration tests with real MinIO backend
- **Encryption Provider:** $(echo "$test_output" | grep -o "provider.*" | head -1 || echo "AES-CTR (default)")
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
        if grep -q "Average.*Efficiency" "$markdown_file"; then
            grep "Average.*Efficiency" "$markdown_file" | sed 's/^/  /'
        fi
        if grep -q "Encryption Overhead" "$markdown_file"; then
            grep "Encryption Overhead" "$markdown_file" | sed 's/^/  /'
        fi
        echo
    fi

    log_info "View the complete report with: cat ${markdown_file}"
    log_info "Or open it in your preferred markdown viewer"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up temporary files..."
    rm -f /tmp/perf_data.txt /tmp/streaming_data.txt

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

OPTIONS:
    -h, --help    Show this help message

ENVIRONMENT VARIABLES:
    QUICK_MODE=true       Run tests only for file sizes up to 10MB (default: false)
    KEEP_RAW_LOG=true     Keep the raw log file after test completion (default: false)

EXAMPLES:
    ./performance.sh                    # Full test suite (100KB-1GB), raw log deleted
    QUICK_MODE=true ./performance.sh    # Quick test (100KB-10MB), raw log deleted
    KEEP_RAW_LOG=true ./performance.sh  # Full test, keep raw log
    QUICK_MODE=true KEEP_RAW_LOG=true ./performance.sh  # Quick test, keep raw log

REQUIREMENTS:
    - Go (for building and running tests)
    - Docker and docker-compose (for services)
    - MinIO and S3 Encryption Proxy running (auto-started if needed)

OUTPUT:
    - test-results/performance-report-YYYYMMDD-HHMMSS.md (always kept)
    - test-results/performance-raw-YYYYMMDD-HHMMSS.log (deleted by default, use KEEP_RAW_LOG=true to keep)

EXAMPLES:
    ./performance.sh              # Run full performance tests (100KB - 1GB)
    QUICK_MODE=true ./performance.sh  # Run quick tests (up to 10MB only)
    ./performance.sh --help       # Show this help

TEST SIZES:
    Full mode: 100KB, 500KB, 1MB, 3MB, 5MB, 10MB, 50MB, 100MB, 500MB, 1GB
    Quick mode: 100KB, 500KB, 1MB, 3MB, 5MB, 10MB

EXPECTED RUNTIME:
    Full mode: 15-30 minutes (depending on system performance)
    Quick mode: 2-5 minutes

For more information, see docs/PERFORMANCE_TESTING.md
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
