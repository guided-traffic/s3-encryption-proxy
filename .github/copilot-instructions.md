# S3 Encryption Proxy - AI Coding Instructions

## Project Overview
This is a Go-based transparent S3 encryption proxy that provides envelope encryption, multi-provider support, and streaming multipart uploads. The proxy sits between S3 clients and S3 storage, automatically encrypting objects before storage and decrypting them on retrieval.

## Architecture Deep Dive

### Core Components
- **`cmd/s3-encryption-proxy/`**: Main CLI application using Cobra
- **`internal/orchestration/`**: High-level encryption orchestration with business logic and state management
- **`internal/proxy/`**: Unified HTTP proxy server with integrated S3 client functionality
- **`pkg/encryption/`**: Low-level crypto primitives, provider implementations, and factory patterns
- **`internal/validation/`**: Data integrity validation including HMAC operations and HKDF utilities
- **`internal/config/`**: Viper-based configuration with provider validation

### Package Architecture & Separation

#### `pkg/encryption/` - Crypto Primitives & Provider Layer
**Responsibilities:**
- **Interfaces** (`interfaces.go`): Core encryption contracts and type definitions
- **KEK Providers** (`keyencryption/`): AES, RSA, Tink, None - encrypt/decrypt Data Encryption Keys
- **DEK Providers** (`dataencryption/`): AES-CTR, AES-GCM - encrypt/decrypt actual data
- **Factory Pattern** (`factory/`): Combines KEK+DEK providers based on content type
- **Envelope Encryption** (`envelope/`): Low-level envelope encryption abstractions

**Characteristics**: Pure cryptographic implementations, no business logic, reusable components

#### `internal/orchestration/` - Business Logic & State Management
**Responsibilities:**
- **Manager** (`manager.go`): Central orchestration of all encryption operations
- **Provider Management** (`providers.go`): Provider lifecycle, fingerprints, caching
- **Single-Part Operations** (`singlepart.go`): Logic for small objects (GCM vs CTR decisions)
- **Multipart Operations** (`multipart.go`): Session management for large uploads
- **Streaming** (`streaming.go`): Memory-optimized stream processing
- **Metadata** (`metadata.go`): S3 metadata management and filtering

**Characteristics**: Business logic, state management, S3-specific integration, operation coordination

#### `internal/validation/` - Data Integrity & Cryptographic Utilities
**Responsibilities:**
- **HMAC** (`hmac.go`): Integrity verification with HMAC-SHA256
- **HKDF** (`hkdf.go`): Key derivation function utilities

**Characteristics**: Data validation, integrity verification, cryptographic utilities

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
- **Encryption Manager**: `internal/orchestration/manager.go` coordinates KEK/DEK operations with factory
- **Provider Factory**: `pkg/encryption/factory/` combines KEK + DEK providers based on content type
- **AWS S3 SDK**: Direct integration in proxy handlers, no intermediate client wrapper
- **Multipart State**: `internal/orchestration/manager.go` tracks upload state with thread-safe maps
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
- **Encryption manager**: `internal/orchestration/manager.go` (multipart upload state)
- **Factory pattern**: `pkg/encryption/factory/factory.go`
- **Test helpers**: `test/integration/minio_test_helper.go`
- **Migration Source**: `internal/s3client/` (to be migrated into proxy handlers)
- **Unified Handlers**: `internal/proxy/handlers/` (unified S3 operations with encryption)

# Encryption Manager

### 1. Core Manager (Orchestration Only)
**File**: `internal/orchestration/manager.go`

**Responsibilities**:
- Request routing to appropriate operation handler
- Configuration management
- Component coordination
- Public API facade

### 2. Provider Manager
**File**: `internal/orchestration/providers.go`

**Responsibilities**:
- KEK/DEK encryption and decryption operations
- Provider registration and lifecycle management
- Fingerprint tracking and validation
- Provider selection for decryption
- Key caching for performance optimization

### 3. Single Part Operations
**File**: `internal/orchestration/singlepart.go`

**Clear Data Paths**:
- **EncryptGCM()**: Data ≤ streaming_threshold → AES-GCM → Complete object encryption
- **EncryptCTR()**: Data > streaming_threshold → AES-CTR → Streaming encryption
- **DecryptGCM()**: AES-GCM encrypted objects → Full decryption
- **DecryptCTR()**: AES-CTR single-part objects → Streaming decryption

### 4. Multipart Operations
**File**: `internal/orchestration/multipart.go`

**Clear Session Lifecycle**:
1. **InitiateSession()**: Create DEK, IV, setup HMAC calculator
2. **ProcessPart()**: Encrypt part with AES-CTR, update HMAC sequentially
3. **FinalizeSession()**: Complete HMAC verification, generate final metadata
4. **AbortSession()**: Clean up resources and state

### 5. Streaming Operations
**File**: `internal/orchestration/streaming.go`

**Optimized for Memory Efficiency**:
- **CreateEncryptionReader()**: Wrap input stream for on-the-fly encryption
- **CreateDecryptionReader()**: Wrap encrypted stream for on-the-fly decryption
- **StreamWithSegments()**: Process data in configurable segments for large objects

### 6. HMAC Manager
**File**: `internal/validation/hmac.go`

**Centralized Integrity Operations**:
- **deriveHMACKey()**: HKDF-based key derivation from DEK
- **createCalculator()**: Initialize HMAC-SHA256 calculator
- **verifyIntegrity()**: Compare calculated vs expected HMAC
- **isEnabled()**: Check if HMAC verification is configured


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


--- Main Goals are the most importent
# MAIN GOALS
1. Ensure data is always encrypted at rest in S3
2. encrypt and decrypt data as fast as possible (performance is key)
3. use streaming to decrease memory footprint
4. keep the architecture as simple as possible (no unnecessary layers)

# WORK ORDER
1. use sha256 hashed to compare files in tests, no hex dumps


## Always pay attention to performance. If you notice an underperforming implementation, stop what you are doing and report the problem to me.

# WE DONT NEED BACKWARD COMPATIBILITY, remove unnecessary code
