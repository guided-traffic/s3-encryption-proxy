# S3 Encryption Proxy - AI Coding Instructions

## Project Overview
This is a Go-based transparent S3 encryption proxy that provides envelope encryption, multi-provider support, and streaming multipart uploads. The proxy sits between S3 clients and S3 storage, automatically encrypting objects before storage and decrypting them on retrieval.

## Architecture Deep Dive

### Core Components
- **`cmd/s3-encryption-proxy/`**: Main CLI application using Cobra
- **`internal/encryption/`**: Encryption manager with multi-provider envelope encryption
- **`internal/proxy/`**: Unified HTTP proxy server with integrated S3 client functionality
- **`pkg/encryption/`**: Encryption interfaces and factory pattern implementations
- **`internal/config/`**: Viper-based configuration with provider validation

### Unified Architecture
**COMPLETED**: The `internal/s3client/` package has been successfully migrated into `internal/proxy/` for unified architecture:

- **Current State**: Fully integrated proxy handlers with embedded S3 client functionality
- **Architecture Goal**: Unified proxy handlers with direct AWS SDK integration and encryption
- **Key Principle**: Proxy handlers directly integrate encryption without separate client wrapper layer
- **Implementation Order**: We currently hav no customers, no need for backward compatibility

### Architecture Guidelines
**CURRENT IMPLEMENTATION**:
1. **Direct AWS SDK integration** - proxy handlers call AWS SDK directly with encryption
2. **Unified encryption flow** - encryption manager integrated directly in proxy handlers
3. **Single source of truth** - no duplicate chunked encoding logic or wrapper layers
4. **Streaming optimization** - direct streaming multipart uploads through proxy handlers
5. **Clean separation** - encryption, proxy handling, and S3 operations cleanly separated

### Critical Data Flow (Post-Migration)
1. **PUT**: Client → Proxy Handlers → Encryption Manager → Factory → AWS S3 SDK → S3 Storage
2. **GET**: Client ← Proxy Handlers ← Encryption Manager ← Factory ← AWS S3 SDK ← S3 Storage

### Encryption Providers Architecture
The system uses **envelope encryption** with separate **Key Encryption Key (KEK)** and **Data Encryption Key (DEK)** layers:

#### KEK (Key Encryption Key) Providers - `pkg/encryption/keyencryption/`
Handle encryption/decryption of DEKs:
- **AES Provider**: Symmetric key encryption for DEKs (fast, requires pre-shared key)
- **RSA Provider**: Asymmetric key encryption for DEKs (self-hosted, no external dependencies)
- **Tink Provider**: Google Tink with KMS integration (production, cloud-native)

#### DEK (Data Encryption Key) Providers - `pkg/encryption/dataencryption/`
Handle actual data encryption using ephemeral keys:
- **AES-GCM**: Authenticated encryption for small objects
- **AES-CTR**: Streaming encryption for large files and multipart uploads

#### Special Providers
- **None Provider**: Pure pass-through without encryption (testing/end of life scenarios)

The **Factory pattern** (`pkg/encryption/factory/`) combines KEK + DEK providers based on content type:
- `ContentTypeWhole`: Uses AES-GCM for complete objects
- `ContentTypeMultipart`: Uses AES-CTR for streaming uploads

Each provider has unique fingerprints stored in S3 metadata for decryption provider selection.

allowed metadata are:
- dek-algorithm
- encrypted-dek
- aes-iv
- kek-algorithm
- kek-fingerprint
- hmac (for integrity verification)

with the prefix of metadata_key_prefix from configuration (default `s3ep-`).

## Development Workflows

### Build Commands (Makefile-driven)
```bash
make build              # Build main binary to build/s3-encryption-proxy
make build-keygen       # Build AES key generator to build/s3ep-keygen
make test-integration   # Run integration tests (requires Docker)
make coverage           # Generate HTML coverage report
start-demo.sh           # Build project in container and run a docker compose-environment with minio and s3-encryption-proxy
```

### Key Generation Patterns
```bash
# AES keys
make build-keygen && ./build/s3ep-keygen

# RSA keys
go build ./cmd/rsa-keygen && ./rsa-keygen 2048
```

### Testing Strategy
- **Unit tests**: `make test-unit` - Fast tests with `-short` flag
- **Integration tests**: `make test-integration` - Requires MinIO via `./start-demo.sh`
- Use build tag `//go:build integration` for integration tests
- Test helper: `test/integration/minio_test_helper.go` provides `TestContext` with MinIO and proxy clients
- You are not allowed to disable, skip or remove integration tests, they represent the end-user experience
- Don't call your work done until all integration tests pass
- Integration Test need to be prepared with ./start-demo.sh
- If you want to get the recent logs from s3-encryption-proxy container use: docker logs demo-s3-encryption-proxy | tail -50
- Try integrate new unit-tests into existing files if it makes sense


## Project-Specific Conventions

### Configuration Pattern
Use multi-provider configuration with aliases:
```yaml
encryption:
  encryption_method_alias: "current-provider"  # Active for writes
  providers:                                   # All providers for reads
    - alias: "current-provider"
      type: "aes-ctr"  # or "tink", "rsa-envelope", "aes-gcm", "none"
      config: { ... }
```

### Metadata Conventions
- Encryption metadata stored with prefix `s3ep-` (configurable)
- Critical fields: `encrypted-dek`, `encryption-mode`, algorithm metadata
- Metadata filtered from client responses (security isolation)
- **Important**: `provider_alias` is NOT stored in metadata - only used for configuration selection and logging

### Error Handling Patterns
- Use structured logging with `logrus.WithFields()` for all error reporting and context
- Log errors with appropriate levels: `logrus.Error()`, `logrus.Warn()`, `logrus.Debug()`
- Provider errors should include provider alias and type
- Include relevant context fields: bucket, key, operation, error details in log entries

### Integration Points (Migration Target)
- **Proxy Handlers**: `internal/proxy/handlers/` with embedded encryption and S3 operations
- **Encryption Manager**: `internal/encryption/manager.go` coordinates KEK/DEK operations with factory
- **Provider Factory**: `pkg/encryption/factory/` combines KEK + DEK providers based on content type
- **AWS S3 SDK**: Direct integration in proxy handlers, no intermediate client wrapper
- **Multipart State**: `internal/encryption/manager.go` tracks upload state with thread-safe maps
- **Request Processing**: Raw HTTP body handling with encryption, no duplicate chunked encoding

### File Naming Patterns
- Interfaces: `pkg/encryption/interfaces.go`
- Provider implementations: `pkg/encryption/{provider}/` directories
- Integration tests: `*_test.go` in `test/integration/`
- Config examples: `config/config-{provider}.yaml`

## Common Development Tasks

### Critical Data Flow (Post-Migration)
1. **PUT**: Client → Proxy Handlers → Encryption Manager → Factory → AWS S3 SDK → S3 Storage
2. **GET**: Client ← Proxy Handlers ← Encryption Manager ← Factory ← AWS S3 SDK ← S3 Storage

### Adding New Encryption Provider
#### For KEK (Key Encryption Key) Providers:
1. Implement `KeyEncryptor` interface in `pkg/encryption/keyencryption/{name}/`
2. Add factory support in `pkg/encryption/factory/factory.go`
3. Update `internal/config/config.go` validation
4. Add config example in `config/config-{name}.yaml`
5. Add integration test in `test/integration/`

#### For DEK (Data Encryption Key) Providers:
1. Implement `DataEncryptor` interface in `pkg/encryption/dataencryption/{name}/`
2. Update factory content type handling in `pkg/encryption/factory/factory.go`
3. Add algorithm metadata handling
4. Test with both small and large file scenarios

### Debugging Encryption Issues
- Enable debug logging: `log_level: "debug"` in config
- Check provider fingerprints in logs and metadata
- Use `TestContext` in tests for MinIO/proxy client comparison
- Verify `optimizations.streaming_segment_size` (min 5MB, default 12MB) for large uploads

### Debugging Migration Issues
- **Chunked Encoding**: Check that proxy handlers pass raw HTTP body to AWS SDK
- **Duplicate Logic**: Ensure encryption happens only once in proxy handlers, not in multiple layers
- **Interface Compatibility**: Verify proxy handlers implement expected S3 client interfaces
- **Request Routing**: Confirm proper handler registration and middleware setup

### Docker Development
Use `docker-compose.demo.yml` for local development with MinIO backend and dual S3 explorers (encrypted vs direct access).

## Key Files for Context
- **Main entry**: `cmd/s3-encryption-proxy/main.go`
- **Config loading**: `internal/config/config.go` (lines 400+ have provider validation)
- **Encryption manager**: `internal/encryption/manager.go` (multipart upload state)
- **Factory pattern**: `pkg/encryption/factory/factory.go`
- **Test helpers**: `test/integration/minio_test_helper.go`
- **Migration Source**: `internal/s3client/` (to be migrated into proxy handlers)
- **Unified Handlers**: `internal/proxy/handlers/` (unified S3 operations with encryption)

# MAIN GOALS
1. Ensure data is always encrypted at rest in S3
2. encrypt and decrypt data as fast as possible (performance is key)
3. use streaming to decrease memory footprint
4. keep the architecture as simple as possible (no unnecessary layers)

# CRITICAL REFACTORING TARGET: Encryption Manager Restructuring

## Current Problem Analysis
The `internal/encryption/manager.go` has become extremely complex and opaque with multiple unclear data paths:

## Target Architecture: Modular Separation

### 1. Core Manager (Orchestration Only)
**File**: `internal/encryption/manager_v2.go`
```go
type ManagerV2 struct {
    config          *config.Config
    providerManager *ProviderManager
    singlePartOps   *SinglePartOperations
    multipartOps    *MultipartOperations
    streamingOps    *StreamingOperations
    metadataManager *MetadataManager
    hmacManager     *HMACManager
}
```

**Responsibilities**:
- Request routing to appropriate operation handler
- Configuration management
- Component coordination
- Public API facade

### 2. Provider Manager
**File**: `internal/encryption/providers.go`
```go
type ProviderManager struct {
    factory           *factory.Factory
    activeFingerprint string
    config            *config.Config
    keyCache          map[string][]byte // Cached DEKs for performance
}
```

**Responsibilities**:
- KEK/DEK encryption and decryption operations
- Provider registration and lifecycle management
- Fingerprint tracking and validation
- Provider selection for decryption
- Key caching for performance optimization

**Key Methods**:
- `EncryptDEK(dek []byte, providerAlias string) ([]byte, error)`
- `DecryptDEK(encryptedDEK []byte, providerAlias string) ([]byte, error)`
- `GetActiveProvider() (string, error)`
- `GetProviderByFingerprint(fingerprint string) (encryption.KeyEncryptor, error)`

### 3. Single Part Operations
**File**: `internal/encryption/singlepart.go`
```go
type SinglePartOperations struct {
    providerManager *ProviderManager
    metadataManager *MetadataManager
    hmacManager     *HMACManager
    bufferPool      *sync.Pool
}
```

**Clear Data Paths**:
- **EncryptGCM()**: Data ≤ streaming_threshold → AES-GCM → Complete object encryption
- **EncryptCTR()**: Data > streaming_threshold → AES-CTR → Streaming encryption
- **DecryptGCM()**: AES-GCM encrypted objects → Full decryption
- **DecryptCTR()**: AES-CTR single-part objects → Streaming decryption

**Key Methods**:
- `EncryptGCM(ctx context.Context, data []byte, objectKey string) (*EncryptionResult, error)`
- `EncryptCTR(ctx context.Context, data []byte, objectKey string) (*EncryptionResult, error)`
- `DecryptGCM(ctx context.Context, encryptedData []byte, metadata map[string]string, objectKey string) ([]byte, error)`
- `DecryptCTR(ctx context.Context, encryptedData []byte, metadata map[string]string, objectKey string) ([]byte, error)`

### 4. Multipart Operations
**File**: `internal/encryption/multipart.go`
```go
type MultipartOperations struct {
    sessions        map[string]*MultipartSession
    mutex           sync.RWMutex
    providerManager *ProviderManager
    hmacManager     *HMACManager
    partProcessor   *PartProcessor
}

type MultipartSession struct {
    UploadID         string
    ObjectKey        string
    BucketName       string
    DEK              []byte
    IV               []byte
    KeyFingerprint   string
    PartETags        map[int]string
    PartSizes        map[int]int64
    HMACCalculator   hash.Hash
    NextPartNumber   int
    CreatedAt        time.Time
    mutex            sync.RWMutex
}
```

**Clear Session Lifecycle**:
1. **InitiateSession()**: Create DEK, IV, setup HMAC calculator
2. **ProcessPart()**: Encrypt part with AES-CTR, update HMAC sequentially
3. **FinalizeSession()**: Complete HMAC verification, generate final metadata
4. **AbortSession()**: Clean up resources and state

**Key Methods**:
- `InitiateSession(ctx context.Context, uploadID, objectKey, bucketName string) (*MultipartSession, error)`
- `ProcessPart(ctx context.Context, uploadID string, partNumber int, data []byte) (*EncryptionResult, error)`
- `FinalizeSession(ctx context.Context, uploadID string) (map[string]string, error)`
- `AbortSession(ctx context.Context, uploadID string) error`

### 5. Streaming Operations
**File**: `internal/encryption/streaming.go`
```go
type StreamingOperations struct {
    providerManager *ProviderManager
    bufferPool      *sync.Pool
    segmentSize     int64
}
```

**Optimized for Memory Efficiency**:
- **CreateEncryptionReader()**: Wrap input stream for on-the-fly encryption
- **CreateDecryptionReader()**: Wrap encrypted stream for on-the-fly decryption
- **StreamWithSegments()**: Process data in configurable segments for large objects

**Key Methods**:
- `CreateEncryptionReader(ctx context.Context, reader io.Reader, objectKey string) (io.Reader, map[string]string, error)`
- `CreateDecryptionReader(ctx context.Context, reader io.Reader, metadata map[string]string) (io.Reader, error)`
- `StreamWithSegments(ctx context.Context, reader io.Reader, segmentCallback func([]byte) error) error`

### 6. HMAC Manager
**File**: `internal/encryption/hmac.go`
```go
type HMACManager struct {
    enabled    bool
    config     *config.Config
    keyDeriver func(dek []byte) []byte
}
```

**Centralized Integrity Operations**:
- **deriveHMACKey()**: HKDF-based key derivation from DEK
- **createCalculator()**: Initialize HMAC-SHA256 calculator
- **verifyIntegrity()**: Compare calculated vs expected HMAC
- **isEnabled()**: Check if HMAC verification is configured

**Key Methods**:
- `deriveHMACKey(dek []byte) []byte`
- `createCalculator(dek []byte) hash.Hash`
- `verifyIntegrity(data []byte, expectedHMAC []byte, dek []byte) error`
- `calculateHMAC(data []byte, dek []byte) []byte`

## Explicit Data Flow Documentation

### PUT Request Flow (Upload)
```
Client Request → ManagerV2.Encrypt()
                ↓
        [Size Check: < 5MB?]
                ↓                    ↓
         SinglePartOps.           SinglePartOps.
         EncryptGCM()           EncryptCTR()
                ↓                    ↓
         [AES-GCM Path]           [AES-CTR Path]
                ↓                    ↓
         ProviderManager.         ProviderManager.
         EncryptDEK()            EncryptDEK()
                ↓                    ↓
         Factory.CreateGCM()     Factory.CreateCTR()
                ↓                    ↓
         [Single Operation]      [Streaming Operation]
                ↓                    ↓
         MetadataManager.        MetadataManager.
         BuildResult()           BuildResult()
                ↓                    ↓
              S3 Storage            S3 Storage
```

### Multipart PUT Flow
```
Client Initiate → MultipartOps.InitiateSession()
                        ↓
                [Create DEK, IV, HMAC Calculator]
                        ↓
Client Part Upload → MultipartOps.ProcessPart()
                        ↓
                [AES-CTR Encrypt + Sequential HMAC]
                        ↓
                [Store Part ETag & Size]
                        ↓
Client Complete → MultipartOps.FinalizeSession()
                        ↓
                [Verify Final HMAC]
                        ↓
                [Generate Object Metadata]
                        ↓
                     S3 Storage
```

### GET Request Flow (Download)
```
S3 Storage → ManagerV2.Decrypt()
                ↓
        MetadataManager.GetAlgorithm()
                ↓
        [Algorithm Check: GCM vs CTR?]
                ↓                    ↓
         SinglePartOps.           SinglePartOps.
         DecryptGCM()            DecryptCTR()
                ↓                    ↓
         ProviderManager.         ProviderManager.
         DecryptDEK()            DecryptDEK()
                ↓                    ↓
         Factory.CreateGCM()     Factory.CreateCTR()
                ↓                    ↓
         [Single Operation]      [Streaming Operation]
                ↓                    ↓
         HMACManager.            HMACManager.
         verifyIntegrity()       verifyIntegrity()
                ↓                    ↓
              Client               Client
```

## Implementation Strategy

### Phase 1: Foundation
1. **Create new module structure** without breaking existing code:
   - `internal/encryption/manager_v2.go` (new orchestrator)
   - `internal/encryption/providers.go` (extract provider logic)
   - `internal/encryption/metadata.go` (extract metadata logic)

2. **Implement ProviderManager** with full test coverage:
   - Extract all KEK/DEK operations from current manager
   - Add comprehensive error handling and logging
   - Implement provider caching for performance

3. **Create MetadataManager** for centralized metadata handling:
   - Extract metadata prefix logic
   - Standardize metadata key generation
   - Add metadata validation

### Phase 2: Core Operations
1. **Implement SinglePartOperations**:
   - Clear separation between GCM and CTR paths
   - Extract size-based decision logic
   - Add comprehensive logging for debugging

2. **Implement HMACManager**:
   - Centralize all HMAC operations
   - Add configuration-based enable/disable
   - Standardize key derivation

3. **Create comprehensive unit tests** for each component:
   - Mock dependencies properly
   - Test error scenarios extensively
   - Validate data paths explicitly

### Phase 3: Advanced Operations
1. **Implement MultipartOperations**:
   - Session-based state management
   - Sequential HMAC processing
   - Resource cleanup and error handling

2. **Implement StreamingOperations**:
   - Memory-optimized readers
   - Configurable segment processing
   - Buffer pool management

3. **Integration testing**:
   - Test all data paths with MinIO
   - Validate performance characteristics
   - Verify memory usage patterns

### Phase 4: Migration and Cleanup
1. **Update proxy handlers** to use ManagerV2:
   - Modify all encryption calls
   - Update error handling
   - Preserve existing API contracts

2. **Update integration tests**:
   - Migrate test cases to new structure
   - Add tests for new explicit paths
   - Verify backward compatibility

3. **Performance validation**:
   - Run performance benchmarks
   - Compare memory usage
   - Validate streaming performance

4. **Remove old manager**:
   - Delete `manager.go` after full migration
   - Update all imports and dependencies
   - Clean up unused code

## Critical Success Criteria

### Code Quality Requirements
1. **Single Responsibility**: Each component has one clear purpose
2. **Explicit Data Paths**: Every encryption/decryption path is clearly documented
3. **Comprehensive Testing**: >90% test coverage for all new components
4. **Performance Parity**: No regression in encryption/decryption speed
5. **Memory Efficiency**: Maintain or improve memory usage patterns

### Documentation Requirements
1. **API Documentation**: Clear documentation for all public methods
2. **Data Flow Diagrams**: Visual representation of all paths
3. **Migration Guide**: Step-by-step migration instructions
4. **Troubleshooting Guide**: Common issues and debugging steps

### Validation Requirements
1. **Integration Tests Pass**: All existing tests continue to work
2. **Performance Benchmarks**: No degradation in key metrics
3. **Memory Profiling**: Verify memory usage improvements
4. **Security Review**: Ensure no security regressions

## Development Guidelines for This Refactoring

### Code Organization Principles
1. **One Component Per File**: Keep related functionality together
2. **Clear Interfaces**: Define explicit interfaces between components
3. **Dependency Injection**: Use constructor injection for all dependencies
4. **Error Wrapping**: Wrap errors with context for better debugging
5. **Structured Logging**: Use consistent logging with relevant context

### Testing Strategy
1. **Unit Tests**: Test each component in isolation with mocks
2. **Integration Tests**: Test complete data paths end-to-end
3. **Performance Tests**: Validate speed and memory characteristics
4. **Error Tests**: Verify error handling in all scenarios

### Performance Considerations
1. **Buffer Reuse**: Use sync.Pool for frequent allocations
2. **Streaming**: Avoid loading entire objects into memory
3. **Caching**: Cache frequently used values (DEKs, metadata)
4. **Lazy Loading**: Only initialize components when needed

This refactoring is critical for maintaining the codebase and must be completed with full backward compatibility and comprehensive testing.

WE DONT NEED BACKWARD COMPATIBILITY, we have no customers yet!
