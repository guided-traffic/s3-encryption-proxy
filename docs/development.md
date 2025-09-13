# Development Guide

## Overview

This guide provides comprehensive information for developers working on the S3 Encryption Proxy project, including setup, architecture, testing, and contribution guidelines.

## Development Environment Setup

### Prerequisites

- **Go 1.25+** (latest stable)
- **Docker & Docker Compose** (for integration testing)
- **Make** (for build automation)
- **Git** (version control)

### Initial Setup

```bash
# Clone the repository
git clone https://github.com/guided-traffic/s3-encryption-proxy.git
cd s3-encryption-proxy

# Install Go dependencies
make deps

# Install development tools
make tools

# Build the project
make build

# Run tests to verify setup
make test
```

### Development Tools

**Required Tools:**
```bash
# Install linting and formatting tools
go install golang.org/x/tools/cmd/goimports@latest
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
```

**VS Code Extensions (Recommended):**
- Go (official Go extension)
- Docker
- YAML
- GitLens
- Error Lens

## Project Architecture

### Directory Structure

```
s3-encryption-proxy/
├── cmd/                       # Application entry points
│   ├── s3-encryption-proxy/   # Main proxy application
│   │   └── main.go           # Application bootstrap
│   └── keygen/               # Key generation utility
│       └── main.go           # Key generator bootstrap
├── internal/                  # Private application code
│   ├── config/               # Configuration management
│   │   ├── config.go         # Configuration loading/validation
│   │   └── config_test.go    # Configuration tests
│   ├── encryption/           # Encryption management layer
│   │   └── manager.go        # Encryption manager implementation
│   ├── proxy/                # HTTP proxy server
│   │   └── server.go         # HTTP server and routing
│   └── s3/                   # S3 client wrapper
│       └── client.go         # S3 operations with encryption
├── pkg/                      # Public reusable packages
│   ├── encryption/           # Encryption interfaces
│   │   ├── types.go          # Common types and interfaces
│   │   ├── aes_gcm.go        # Direct AES-GCM implementation
│   │   └── aes_gcm_test.go   # AES-GCM tests
│   └── envelope/             # Envelope encryption
│       ├── envelope.go       # Tink-based envelope encryption
│       └── envelope_test.go  # Envelope encryption tests
├── test/                     # Test utilities and integration tests
│   └── integration/          # Integration test suites
│       ├── integration_test.go
│       └── encryption_test.go
├── config/                   # Configuration examples
├── docs/                     # Documentation
├── .github/workflows/        # CI/CD pipelines
├── Makefile                  # Build automation
├── go.mod                    # Go module definition
└── go.sum                    # Go module checksums
```

### Architectural Patterns

#### Clean Architecture

The project follows clean architecture principles:

```
┌─────────────────────────────────────────────────────────────┐
│                     Presentation Layer                     │
│                    (cmd/, HTTP handlers)                   │
├─────────────────────────────────────────────────────────────┤
│                    Application Layer                       │
│                   (internal/proxy/)                        │
├─────────────────────────────────────────────────────────────┤
│                      Domain Layer                          │
│                (pkg/encryption/, interfaces)               │
├─────────────────────────────────────────────────────────────┤
│                   Infrastructure Layer                     │
│              (internal/s3client/, internal/config/)              │
└─────────────────────────────────────────────────────────────┘
```

#### Dependency Injection

```go
// Example: Encryption manager with injected dependencies
type Manager struct {
    encryptor encryption.Encryptor
    config    *Config
    logger    *logrus.Logger
}

func NewManager(encryptor encryption.Encryptor, config *Config, logger *logrus.Logger) *Manager {
    return &Manager{
        encryptor: encryptor,
        config:    config,
        logger:    logger,
    }
}
```

#### Interface-based Design

```go
// pkg/encryption/types.go
type Encryptor interface {
    Encrypt(ctx context.Context, data io.Reader, associatedData []byte) (*EncryptionResult, error)
    Decrypt(ctx context.Context, encryptedData io.Reader, metadata map[string]string, associatedData []byte) (io.Reader, error)
}

// Multiple implementations
type AESGCMEncryptor struct { ... }    // Direct AES-GCM
type EnvelopeEncryptor struct { ... }  // Tink envelope encryption
```

## Core Components

### Configuration Management

**Location:** `internal/config/`

**Features:**
- Multi-source configuration (files, env vars, CLI flags)
- Validation and defaults
- Environment-specific configs

**Example Usage:**
```go
// Load configuration
config, err := config.Load("config.yaml")
if err != nil {
    log.Fatal(err)
}

// Access configuration
endpoint := config.TargetEndpoint
encryptionType := config.EncryptionType
```

### Encryption Manager

**Location:** `internal/encryption/manager.go`

**Responsibilities:**
- Factory for encryption implementations
- Configuration-based encryptor selection
- Lifecycle management

**Example:**
```go
// Create encryption manager
manager, err := encryption.NewManager(config)
if err != nil {
    return err
}

// Use for encryption
result, err := manager.Encrypt(ctx, data, associatedData)
```

### HTTP Proxy Server

**Location:** `internal/proxy/server.go`

**Features:**
- S3 API compatible endpoints
- Request/response transformation
- Error handling and logging

**Key Endpoints:**
```go
// S3 API endpoints
PUT    /{bucket}/{key}     // PutObject with encryption
GET    /{bucket}/{key}     // GetObject with decryption
DELETE /{bucket}/{key}     // DeleteObject (passthrough)
HEAD   /{bucket}/{key}     // HeadObject (passthrough)

// Health endpoints
GET    /health            // Health check
GET    /ready             // Readiness check
```

### S3 Client Wrapper

**Location:** `internal/s3client/client.go`

**Features:**
- AWS SDK integration
- Encryption metadata handling
- Error translation

## Development Workflow

### Code Style and Standards

**Go Standards:**
- Follow effective Go principles
- Use `gofmt` and `goimports`
- Write idiomatic Go code
- Include comprehensive comments

**Example Good Practice:**
```go
// EncryptionResult represents the result of an encryption operation.
// It contains the encrypted data and associated metadata required for decryption.
type EncryptionResult struct {
    // EncryptedData contains the encrypted payload
    EncryptedData io.Reader

    // Metadata contains encryption-specific information
    // that will be stored as S3 object metadata
    Metadata map[string]string
}

// Encrypt encrypts the provided data using the configured encryption method.
// The associatedData parameter is used for authenticated encryption and
// typically contains the S3 object key for additional security.
func (e *AESGCMEncryptor) Encrypt(ctx context.Context, data io.Reader, associatedData []byte) (*EncryptionResult, error) {
    if data == nil {
        return nil, errors.New("data cannot be nil")
    }

    // Implementation...
}
```

### Testing Strategy

#### Unit Tests

**Coverage Requirements:**
- Minimum 80% code coverage
- All public functions tested
- Error cases covered
- Edge cases included

**Example Unit Test:**
```go
func TestAESGCMEncryption(t *testing.T) {
    tests := []struct {
        name           string
        data           []byte
        associatedData []byte
        expectError    bool
    }{
        {
            name:           "successful encryption",
            data:           []byte("hello world"),
            associatedData: []byte("test-object-key"),
            expectError:    false,
        },
        {
            name:           "empty data",
            data:           []byte(""),
            associatedData: []byte("test-key"),
            expectError:    false,
        },
        {
            name:           "nil associated data",
            data:           []byte("data"),
            associatedData: nil,
            expectError:    false,
        },
    }

    encryptor := NewAESGCMEncryptor(generateKey())

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result, err := encryptor.Encrypt(context.Background(),
                bytes.NewReader(tt.data), tt.associatedData)

            if tt.expectError {
                assert.Error(t, err)
                assert.Nil(t, result)
            } else {
                assert.NoError(t, err)
                assert.NotNil(t, result)
                assert.NotEmpty(t, result.Metadata)
            }
        })
    }
}
```

#### Integration Tests

**Setup with Docker Compose:**
```yaml
# test/integration/docker-compose.test.yml
version: '3.8'
services:
  minio:
    image: minio/minio:latest
    environment:
      MINIO_ACCESS_KEY: minioadmin
      MINIO_SECRET_KEY: minioadmin
    command: server /data
    ports:
      - "9000:9000"

  s3-encryption-proxy:
    build: ../..
    environment:
      S3EP_TARGET_ENDPOINT: http://minio:9000
      S3EP_ENCRYPTION_TYPE: aes256-gcm
      S3EP_AES_KEY: SGVsbG8gV29ybGQhIFRoaXMgaXMgYSAzMi1ieXRlIGtleQ==
    ports:
      - "8080:8080"
    depends_on:
      - minio
```

**Integration Test Example:**
```go
func TestEndToEndEncryption(t *testing.T) {
    // Setup test environment
    client := setupS3Client(t, "http://localhost:8080")
    bucket := "test-bucket"
    key := "test-object"
    content := []byte("sensitive data")

    // Create bucket
    err := client.CreateBucket(bucket)
    require.NoError(t, err)

    // Put object (should be encrypted)
    err = client.PutObject(bucket, key, bytes.NewReader(content))
    require.NoError(t, err)

    // Get object (should be decrypted)
    data, err := client.GetObject(bucket, key)
    require.NoError(t, err)

    // Verify content matches
    result, err := io.ReadAll(data)
    require.NoError(t, err)
    assert.Equal(t, content, result)

    // Verify object is encrypted in storage
    directClient := setupS3Client(t, "http://localhost:9000") // Direct to MinIO
    encryptedData, err := directClient.GetObject(bucket, key)
    require.NoError(t, err)

    encryptedResult, err := io.ReadAll(encryptedData)
    require.NoError(t, err)
    assert.NotEqual(t, content, encryptedResult) // Should be encrypted
}
```

### Build System

**Makefile Targets:**
```makefile
# Development
.PHONY: dev
dev: build
	./build/s3-encryption-proxy --config config/dev.yaml

.PHONY: deps
deps:
	go mod download
	go mod verify

.PHONY: tools
tools:
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Building
.PHONY: build
build:
	go build -o build/s3-encryption-proxy ./cmd/s3-encryption-proxy

.PHONY: build-keygen
build-keygen:
	go build -o build/s3ep-keygen ./cmd/keygen

.PHONY: build-all
build-all: build build-keygen

# Testing
.PHONY: test
test: test-unit test-integration

.PHONY: test-unit
test-unit:
	go test -v -race -coverprofile=coverage/coverage.out ./...

.PHONY: test-integration
test-integration:
	cd test/integration && INTEGRATION_TESTS=true go test -v

.PHONY: coverage
coverage: test-unit
	go tool cover -html=coverage/coverage.out -o coverage/coverage.html

# Quality
.PHONY: lint
lint:
	golangci-lint run

.PHONY: fmt
fmt:
	gofmt -s -w .
	goimports -w .

.PHONY: quality
quality: fmt lint security

.PHONY: security
security:
	gosec ./...
	govulncheck ./...
```

## Adding New Features

### Feature Development Process

1. **Create Feature Branch**
```bash
git checkout -b feature/your-feature-name
```

2. **Implement Feature**
- Add tests first (TDD approach)
- Implement the feature
- Update documentation
- Add configuration if needed

3. **Test Thoroughly**
```bash
make test
make quality
```

4. **Submit Pull Request**
- Follow PR template
- Include tests and documentation
- Ensure CI passes

### Example: Adding New Encryption Algorithm

**1. Define Interface Implementation**
```go
// pkg/encryption/new_algo.go
type NewAlgorithmEncryptor struct {
    key []byte
}

func NewNewAlgorithmEncryptor(key []byte) *NewAlgorithmEncryptor {
    return &NewAlgorithmEncryptor{key: key}
}

func (e *NewAlgorithmEncryptor) Encrypt(ctx context.Context, data io.Reader, associatedData []byte) (*EncryptionResult, error) {
    // Implementation
}

func (e *NewAlgorithmEncryptor) Decrypt(ctx context.Context, encryptedData io.Reader, metadata map[string]string, associatedData []byte) (io.Reader, error) {
    // Implementation
}
```

**2. Add Configuration Support**
```go
// internal/config/config.go
type Config struct {
    EncryptionType string `yaml:"encryption_type"`
    // Add new algorithm config
    NewAlgorithmKey string `yaml:"new_algorithm_key"`
}
```

**3. Update Encryption Manager**
```go
// internal/encryption/manager.go
func NewManager(config *Config) (*Manager, error) {
    switch config.EncryptionType {
    case "aes256-gcm":
        return NewAESGCMEncryptor(config.AESKey)
    case "tink":
        return NewEnvelopeEncryptor(config.KEKUri, config.CredentialsPath)
    case "new-algorithm":
        return NewNewAlgorithmEncryptor(config.NewAlgorithmKey)
    default:
        return nil, fmt.Errorf("unsupported encryption type: %s", config.EncryptionType)
    }
}
```

**4. Add Tests**
```go
// pkg/encryption/new_algo_test.go
func TestNewAlgorithmEncryption(t *testing.T) {
    // Comprehensive tests
}
```

**5. Update Documentation**
- Add to configuration guide
- Update architecture documentation
- Add example configurations

## Debugging and Troubleshooting

### Debug Mode

**Enable Debug Logging:**
```bash
./s3-encryption-proxy --log-level debug --config config/dev.yaml
```

**Environment Variable:**
```bash
export S3EP_LOG_LEVEL=debug
```

### Common Development Issues

**1. Import Path Issues**
```bash
# Ensure module path is correct
go mod edit -module github.com/guided-traffic/s3-encryption-proxy
go mod tidy
```

**2. Test Failures**
```bash
# Run specific test
go test -v -run TestSpecificFunction ./pkg/encryption

# Run with race detection
go test -race ./...

# Verbose output
go test -v ./...
```

**3. Build Issues**
```bash
# Clean build cache
go clean -cache
go clean -modcache

# Rebuild
make clean
make build
```

### Profiling and Performance

**CPU Profiling:**
```go
import _ "net/http/pprof"

// Add to main.go
go func() {
    log.Println(http.ListenAndServe("localhost:6060", nil))
}()
```

**Memory Profiling:**
```bash
# Get memory profile
go tool pprof http://localhost:6060/debug/pprof/heap

# CPU profile
go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30
```

**Benchmarking:**
```go
func BenchmarkEncryption(b *testing.B) {
    encryptor := NewAESGCMEncryptor(generateKey())
    data := make([]byte, 1024*1024) // 1MB

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := encryptor.Encrypt(context.Background(),
            bytes.NewReader(data), []byte("benchmark"))
        if err != nil {
            b.Fatal(err)
        }
    }
}
```

## Contribution Guidelines

### Pull Request Process

1. **Fork the Repository**
2. **Create Feature Branch**
3. **Make Changes**
   - Follow coding standards
   - Add comprehensive tests
   - Update documentation
4. **Submit Pull Request**
   - Clear description
   - Link to related issues
   - Include test results

### Code Review Checklist

**Functionality:**
- [ ] Feature works as described
- [ ] All tests pass
- [ ] No breaking changes (unless intentional)

**Code Quality:**
- [ ] Follows Go best practices
- [ ] Proper error handling
- [ ] Comprehensive logging
- [ ] Security considerations addressed

**Testing:**
- [ ] Unit tests included
- [ ] Integration tests updated
- [ ] Edge cases covered
- [ ] Error conditions tested

**Documentation:**
- [ ] Code comments added
- [ ] Documentation updated
- [ ] Configuration examples provided
- [ ] API changes documented

### Release Process

**Version Bumping:**
- Use semantic versioning
- Follow conventional commits
- Update CHANGELOG.md

**Pre-release Checklist:**
- [ ] All tests pass
- [ ] Security scan clean
- [ ] Documentation updated
- [ ] Performance tests run
- [ ] Integration tests pass

For more information on contributing, see [CONTRIBUTING.md](../CONTRIBUTING.md).
