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

## INTEGRITY VERIFICATION FEATURE (In Development)

### Overview
Implement optional data integrity verification using HMAC-SHA256 for encrypted files. This feature ensures data integrity without sacrificing streaming performance by running HMAC calculation parallel to data transfer.

### Design Principles
- **Optional Feature**: Configurable via `encryption.integrity_verification` flag
- **Performance First**: Streaming HMAC calculation parallel to data transfer
- **DEK-Derived Keys**: Use HKDF to derive HMAC keys from existing DEKs
- **Backward Compatible**: Missing HMAC metadata treated as valid (no verification)
- **Early Abort**: Streaming downloads abort on HMAC mismatch to save bandwidth

### Technical Implementation

#### HKDF Key Derivation
- **Algorithm**: HKDF-SHA256
- **Source**: DEK (Data Encryption Key) from envelope encryption
- **Constants**:
  - `INTEGRITY_SALT = "s3-proxy-integrity-v1"`
  - `INTEGRITY_INFO = "file-hmac-key"`
- **Output**: 32-byte HMAC key for HMAC-SHA256

#### HMAC Calculation
- **Algorithm**: HMAC-SHA256
- **Input**: Raw (unencrypted) file data
- **Storage**: As S3 metadata `{metadata_key_prefix}hmac`
- **Timing**:
  - **Upload**: Calculate during encryption, store in metadata
  - **Download**: Calculate during decryption, verify at stream end

#### Configuration
```yaml
encryption:
  integrity_verification: true  # Enable/disable feature
  metadata_key_prefix: "s3ep-"  # Prefix for all metadata including HMAC
```

#### Integration Points
- **AES-GCM Path**: HMAC calculation for small objects (ContentTypeWhole)
- **AES-CTR Path**: Streaming HMAC calculation for large objects (ContentTypeMultipart)
- **Encryption Manager**: Coordinate HMAC operations with existing encryption flows
- **Metadata Handling**: Store/retrieve HMAC alongside existing encryption metadata

#### Streaming Behavior
- **Upload**: Stream encryption + parallel HMAC calculation
- **Download**: Stream decryption + parallel HMAC verification
- **Performance**: Start data transfer immediately, abort on final HMAC mismatch
- **Error Handling**: Connection abort before stream completion on integrity failure

#### Backward Compatibility
- Objects without HMAC metadata are treated as valid when `integrity_verification` is enabled
- No verification performed on legacy objects
- New objects always get HMAC when feature is enabled

#### Error Scenarios
- **Upload**: HMAC calculation failure → upload abort with error
- **Download**: HMAC verification failure → stream abort with integrity error
- **Missing DEK**: Cannot derive HMAC key → fallback to no verification with warning

#### Implementation Steps
1. **Config Extension**: Add `integrity_verification` flag to `EncryptionConfig`
2. **HKDF Utility**: Implement key derivation with specified constants
3. **HMAC Integration**:
   - Extend AES-GCM provider with HMAC calculation
   - Extend AES-CTR provider with streaming HMAC
4. **Metadata Handling**: Store/retrieve HMAC in S3 object metadata
5. **Verification Logic**: Implement streaming verification with abort capability
6. **Testing**: Unit and integration tests for both encryption paths

#### Files to Modify
- `internal/config/config.go`: Add `integrity_verification` configuration
- `internal/encryption/manager.go`: Coordinate HMAC operations
- `pkg/encryption/dataencryption/aes/`: Extend AES providers with HMAC
- `pkg/encryption/factory/factory.go`: Include HMAC in encryption/decryption flows
- Integration tests for upload/download verification scenarios
