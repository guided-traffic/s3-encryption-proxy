# 180-Degree Variants Integration Tests

This directory contains integration tests that focus on memory usage analysis and performance evaluation of large file operations.

## Test Structure

These tests are designed to run independently to allow for precise memory profiling and performance measurement of specific operations.

### Available Tests

#### `large_multipart_upload_test.go`
- **Test**: `TestLargeMultipartUpload2GB`
- **Purpose**: Tests uploading a 2GB file using multipart upload with AES-CTR encryption
- **Features**:
  - Memory-efficient streaming upload using 5MB parts
  - Deterministic data generation for reproducible tests
  - SHA256 integrity verification
  - Memory usage monitoring throughout the process
  - Performance metrics (throughput calculation)

#### `large_multipart_download_test.go`
- **Test**: `TestLargeMultipartDownload2GB`
- **Purpose**: Tests downloading a 2GB file with streaming verification
- **Features**:
  - Memory-efficient streaming download with 1MB read buffer
  - Real-time data integrity verification using deterministic data generation
  - SHA256 hash comparison without storing entire file in memory
  - Memory usage monitoring throughout the process
  - Performance metrics (throughput calculation)

## Running the Tests

### Prerequisites
- Docker environment with MinIO running (`./start-demo.sh`)
- System with at least 8GB RAM (tests will skip on systems with less memory)
- Set `INTEGRATION_TEST=1` environment variable

### Individual Test Execution

```bash
# Run only the upload test
INTEGRATION_TEST=1 go test -v ./test/integration/180-degree-variants/ -run TestLargeMultipartUpload2GB

# Run only the download test
INTEGRATION_TEST=1 go test -v ./test/integration/180-degree-variants/ -run TestLargeMultipartDownload2GB

# Run both tests
INTEGRATION_TEST=1 go test -v ./test/integration/180-degree-variants/
```

### Memory Profiling

To analyze memory usage during these tests:

```bash
# Upload test with memory profiling
INTEGRATION_TEST=1 go test -v ./test/integration/180-degree-variants/ -run TestLargeMultipartUpload2GB -memprofile=upload.mem

# Download test with memory profiling
INTEGRATION_TEST=1 go test -v ./test/integration/180-degree-variants/ -run TestLargeMultipartDownload2GB -memprofile=download.mem

# Analyze memory profiles
go tool pprof upload.mem
go tool pprof download.mem
```

## Test Design Principles

### Memory Efficiency
- Tests use streaming approaches to minimize memory footprint
- Data is generated on-demand rather than pre-allocated
- Immediate cleanup of buffers after use
- Regular garbage collection and memory monitoring

### Data Integrity
- Deterministic pseudo-random data generation ensures reproducible results
- SHA256 hashing for integrity verification without hex dumps
- Real-time verification during download to avoid storing duplicate data

### Performance Monitoring
- Throughput calculations in MB/s
- Memory usage tracking at key intervals
- Duration measurements for complete operations

## Expected Behavior

### Memory Usage
- Upload test should maintain relatively stable memory usage throughout the upload process
- Download test should maintain minimal memory usage by streaming verification
- Neither test should consume more than a few hundred MB of memory despite handling 2GB files

### Performance
- Upload throughput depends on encryption overhead and network/storage performance
- Download throughput includes decryption and integrity verification overhead
- Both operations should demonstrate efficient streaming without memory spikes

### Data Integrity
- All uploaded data must be successfully verified during download
- SHA256 hashes must match between upload and download operations
- Tests will fail if any data corruption is detected

## System Requirements

- **Memory**: Minimum 8GB system RAM (tests skip on systems with less)
- **Storage**: Sufficient disk space for Docker containers and temporary S3 storage
- **Network**: Local network performance for MinIO communication
- **Runtime**: Go 1.19+ with integration test build tags

## Troubleshooting

### Memory Issues
- If tests fail with out-of-memory errors, check available system memory
- Verify no other memory-intensive processes are running
- Consider adjusting buffer sizes if needed for constrained environments

### Performance Issues
- Slow performance may indicate encryption/decryption bottlenecks
- Check MinIO container resource allocation
- Verify network performance between proxy and MinIO

### Test Failures
- Ensure MinIO is running and accessible via `./start-demo.sh`
- Check that integration test environment variable is set
- Verify sufficient disk space for temporary files and containers
