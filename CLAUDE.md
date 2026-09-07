# S3 Encryption Proxy - AI Coding Instructions

## Project Overview
This is a Go-based transparent S3 encryption proxy that provides envelope encryption, multi-provider support, and streaming multipart uploads. The proxy sits between S3 clients and S3 storage, automatically encrypting objects before storage and decrypting them on retrieval.

## Start with the knowledge graph (graphify)

This project has a graphify knowledge graph at `graphify-out/` (`graph.json`,
`GRAPH_REPORT.md`, `wiki/`). It is the fastest way to see how the pieces hang
together before touching code, and it is committed, so it is always available.

**Use it first, especially at the start of a ticket and for any code research:**
- Read `graphify-out/wiki/index.md`, then the community articles that name the
  packages the task touches (e.g. *Orchestration Manager and Multipart*, *Object
  PUT and Auto-Multipart*, *HMAC Integrity and Streaming IO*, *SigV4
  Authentication*). One article is a map of one subsystem; read two or three
  before opening raw files.
- `graphify query "<question>"` gives BFS context around a question,
  `graphify explain "<symbol>"` explains one node and its neighbours,
  `graphify path "A" "B"` finds how two concepts connect. All read
  `graphify-out/graph.json` and cost no API tokens.
- Before answering architecture or codebase questions, read the *Community Hubs*
  section of `graphify-out/GRAPH_REPORT.md`. Skip its *God Nodes* section: in this
  repo it lists `run()`, `contains()` and `New()`, which are call-resolution
  artifacts (every call site of that name is attached to one file), not
  architectural hubs.
- Treat a graph hit as a pointer, not a fact. Wiki articles built from a document
  inherit that document's staleness (the *Orchestration Package Architecture*
  article is built from `internal/orchestration/README.md`, which still names a
  `streaming.go` and a `ManagerV2` that do not exist). Verify in the code before
  citing anything.
- The graph lags the code. The build date is in the first line of
  `GRAPH_REPORT.md`; `git log -1 --format=%ad -- graphify-out` shows when it was
  last committed.

**Updating the graph is a manual, user-approved step.** `graphify update .`
(AST-only, no API cost) and the full `/graphify` run both rewrite `graphify-out/`
and are committed as their own change. They need explicit approval from the user
and are usually run in a separate session. Never run them unprompted. After
changing code, say in the final report that the graph is behind and needs an
update; do not run it yourself. Corpus scope lives in `.graphifyignore`
(`test-results`, `coverage`, `build`, `dist` and graphify's own outputs are
excluded; `graphify-out/memory/` stays indexed on purpose).

## Architecture Deep Dive

### Core Components
- **`cmd/s3-encryption-proxy/`**: Main CLI application using Cobra (`main.go`: config loading, license start, server lifecycle, graceful shutdown)
- **`cmd/keygen/`**: AES-256 key generator (built as `build/s3ep-keygen`)
- **`cmd/license-tool/`**: License JWT generator (built as `build/license-tool`)
- **`internal/proxy/`**: HTTP proxy server: router, middleware, request/response helpers and the S3 handlers, talking to the backend through `aws-sdk-go-v2`
- **`internal/orchestration/`**: High-level encryption orchestration with business logic and state management
- **`pkg/encryption/`**: Low-level crypto primitives, provider implementations, and factory patterns
- **`internal/validation/`**: Data integrity validation including HMAC operations and HKDF utilities
- **`internal/config/`**: Viper-based configuration with provider validation
- **`internal/license/`**: License JWT validation and the startup gate
- **`internal/monitoring/`**: Prometheus metrics server and middleware, pprof on its own loopback listener

### Package Architecture & Separation

#### `pkg/encryption/` - Crypto Primitives & Provider Layer
**Responsibilities:**
- **Interfaces** (`interfaces.go`): `KeyEncryptor`, `DataEncryptor`, `EnvelopeEncryptor`, `EncryptionProvider`, `IVProvider`
- **KEK Providers** (`keyencryption/`, one file per provider: `aes.go`, `rsa.go`, `none.go`, `tink.go`): encrypt/decrypt Data Encryption Keys
- **DEK Providers** (`dataencryption/aes_ctr.go`, `dataencryption/aes_gcm.go`): encrypt/decrypt actual data; `AESCTRStatefulEncryptor` and `NewCTRRangeReader` are what the streaming and ranged-read paths use
- **Factory Pattern** (`factory/factory.go`): `CreateEnvelopeEncryptor(contentType, fingerprint, prefix)` combines KEK+DEK by content type; `DetermineContentTypeFromHTTPContentType` is the size/force decision
- **Envelope Encryption** (`envelope/envelope.go`): `EnvelopeEncryptor` implementation over one KEK + one DEK provider
- **Ciphertext size** (`ciphertext_size.go`): plaintext-to-ciphertext size arithmetic per algorithm

**Characteristics**: Pure cryptographic implementations, no business logic, reusable components

#### `internal/orchestration/` - Business Logic & State Management
**Responsibilities:**
- **Manager** (`manager.go`): Central orchestration of all encryption operations; public facade the handlers call
- **Provider Management** (`providers.go`): Provider lifecycle, fingerprints, DEK cache
- **Single-Part Operations** (`singlepart.go`): `EncryptGCM`/`EncryptCTR`, `DecryptGCMStream`/`DecryptCTRStream`, the CTR decryption reader construction
- **Multipart Operations** (`multipart.go`): `MultipartOperations` session management for multipart uploads
- **Streaming readers** (`streaming_io.go`): `encryptionReader`, `decryptionReader`, `hmacValidatingReader`, `hmacGatedDecryptionReader`
- **Ranged reads** (`rangeread.go`): `SupportsRangeDecryption`, `CreateRangeDecryptionReader` (AES-CTR only)
- **Metadata** (`metadata.go`): S3 metadata management and filtering
- **Types** (`types.go`): `EncryptionResult`

There is no `streaming.go`; `internal/orchestration/README.md` is older than this layout and still describes one.

**Characteristics**: Business logic, state management, S3-specific integration, operation coordination

#### `internal/validation/` - Data Integrity & Cryptographic Utilities
**Responsibilities:**
- **HMAC manager** (`hmac_manager.go`): mode handling (`IsEnabled`, `GetIntegrityMode`), `CreateCalculator`, `FinalizeCalculator`, `VerifyIntegrity`
- **HMAC calculator** (`hmac_calculator.go`): incremental HMAC-SHA256 (`Add`, `AddFromStream`, `Sum`, `Cleanup`)
- **HKDF** (`hkdf.go`): `DeriveIntegrityKey(dek)` derives the HMAC key from the DEK

**Characteristics**: Data validation, integrity verification, cryptographic utilities

#### `internal/proxy/` - HTTP surface
- `server.go`: HTTP and optional TLS listener (`tls.enabled`), `router.go`: gorilla/mux routes, `middleware_setup.go`: middleware chain
- `middleware/`: SigV4 header and pre-signed URL authentication (`s3auth_*.go`), CORS, logging, request tracking
- `request/`: request parser, aws-chunked and HTTP chunked body decoders, query parameters
- `response/`: S3 error documents and backend error mapping, XML helpers
- `handlers/root/` (ListBuckets), `handlers/bucket/` (bucket CRUD and every bucket sub-resource), `handlers/object/` (GET/PUT/HEAD/DELETE, ranged reads, auto-multipart, object sub-resources), `handlers/multipart/` (Create/UploadPart/UploadPartCopy/Complete/Abort/List), `handlers/health/`
- `interfaces/s3_backend.go`: `S3BackendInterface`, the subset of `aws-sdk-go-v2/service/s3` the handlers use (mocked in unit tests)

### Critical Data Flow
1. **PUT**: Client → Router → Middleware (SigV4 auth) → Object/Multipart Handler → `orchestration.Manager` → Factory/Envelope → AWS S3 SDK → S3 Storage
2. **GET**: Client ← Object Handler ← `orchestration.Manager` (decryption readers) ← AWS S3 SDK ← S3 Storage

The exact branching is under [Explicit Data Flow Documentation](#explicit-data-flow-documentation).

### Encryption Providers Architecture
The system uses **envelope encryption** with separate **Key Encryption Key (KEK)** and **Data Encryption Key (DEK)** layers:

#### KEK (Key Encryption Key) Providers - `pkg/encryption/keyencryption/`
Handle encryption/decryption of DEKs:
- **AES Provider** (`aes.go`, type `aes`): Symmetric key encryption for DEKs (fast, requires pre-shared key)
- **RSA Provider** (`rsa.go`, type `rsa`): Asymmetric key encryption for DEKs (self-hosted, no external dependencies)
- **Tink Provider** (`tink.go`, type `tink`): **an unreachable stub**. Config validation refuses `type: "tink"` ("not yet implemented"), the factory returns the same error, and the stub mints a random in-memory keyset instead of talking to a KMS. Ticket 025 (D-23) completes it against HashiCorp Vault after ticket 013; do not describe it as available

#### DEK (Data Encryption Key) Providers - `pkg/encryption/dataencryption/`
Handle actual data encryption using ephemeral keys:
- **AES-GCM** (`aes_gcm.go`): Authenticated encryption for small objects
- **AES-CTR** (`aes_ctr.go`): Streaming encryption for large files and multipart uploads

#### Special Providers
- **None Provider** (`none.go`, type `none`): Pure pass-through without encryption (testing/end of life scenarios); fingerprint `none-provider-fingerprint`

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
make license-tool       # Build the license tool to build/license-tool
make build-all          # All three binaries
make test-unit          # Unit tests (-short)
make test-integration   # Integration tests against the plain-HTTP proxy (requires ./start-demo.sh)
make test-integration-tls          # Same suites against the TLS endpoint (aws-chunked trailer path only exists over HTTPS)
make test-integration-performance  # Proxy-vs-MinIO throughput, run alone on purpose
make test-integration-all          # HTTP + TLS + performance
make coverage           # Unit-test coverage report; see Makefile for the combined unit + integration flow (GOCOVER=1)
make lint / fmt / gosec / vuln / all-checks
./start-demo.sh         # Build project in container and run a docker compose-environment with minio and s3-encryption-proxy
```

### Go toolchain version
The Go version is spelled out in exactly two files. Every other place derives
it, so a bump touches only these two and they must always agree:

| File | Line | Role |
|---|---|---|
| `Containerfile` | `FROM golang:<version>-alpine AS builder` | Source of truth for the shipped image. The Makefile parses this line into `GO_VERSION` and pins `GO_PIN := GOTOOLCHAIN=go$(GO_VERSION)` for `vuln`, `test-unit-coverage` and `coverage-report`. |
| `go.mod` | `go <version>` | Source of truth for CI and local builds: every `setup-go` step in `.github/workflows/release.yml` uses `go-version-file: go.mod`, and the go command auto-downloads this toolchain for anyone running an older local Go. |

Derived, no literal, do not add one:
- `Makefile`: `GO_VERSION` / `GO_PIN` (parsed from the Containerfile)
- `.github/workflows/release.yml`: `go-version-file: go.mod` (no `GO_VERSION` env)
- `README.md` and `.github/release-template.hbs`: the Go badge is the shields.io `go-mod/go-version` endpoint that reads go.mod

Renovate (`renovate.json`) bumps both literals in one PR, group "Go version": the
`dockerfile` manager handles the Containerfile (depName `golang`), a custom regex
manager handles the go directive in go.mod (depName `go`). The gomod manager has
never bumped the directive in this repo on its own, which is why the regex
manager exists. If you introduce a new place that needs the version, derive it
from one of the two files or extend the custom manager and this table; never
hardcode it.

Why the Makefile pins the Containerfile version rather than trusting go.mod:
combined coverage merges unit-test data with data from the instrumented proxy
binary, and Go coverage data only merges across identical toolchains (block
layout and package hashes change between releases; a 1.26/1.27 mix reported a
package at 25.9% that was really at 62.8%). A newer local Go would satisfy
go.mod but silently corrupt that merge.

### Key Generation Patterns
```bash
# AES keys (cmd/keygen prints a banner around the key; sed -n 2p takes the key line)
make build-keygen && ./build/s3ep-keygen

# RSA keys: there is no RSA generator in this repository, use openssl
openssl genrsa -out private-key.pem 2048
openssl rsa -in private-key.pem -pubout -out public-key.pem

# Development license (config/license.jwt, gitignored)
make setup-dev-license
```

### Testing Strategy
- **Unit tests**: `make test-unit` - Fast tests with `-short` flag
- **Integration tests**: `make test-integration` - Requires MinIO via `./start-demo.sh`
- Use build tag `//go:build integration` for integration tests
- Integration packages: `test/integration` (root helpers + one smoke test), `180-degree-variants`, `360-degree-variants`, `authentication`, `encryption-modes`, `s3-methods` (the bulk of the suite) and `performance-test`, which the Makefile runs on its own because it measures proxy-vs-MinIO throughput and the other packages would compete for the same backend
- Test helper: `test/integration/minio_test_helper.go` provides `TestContext` with MinIO and proxy clients; `encryption_validation_helper.go` asserts that stored bytes are ciphertext (entropy checks)
- You are not allowed to disable, skip or remove integration or Velero e2e tests, they represent the end-user experience
- Don't call your work done until all integration tests pass
- Integration Test need to be prepared with ./start-demo.sh (it takes 30 seconds to start)
- If you want to get the recent logs from s3-encryption-proxy container use: docker logs proxy | tail -50 (the TLS listener is a second container, `proxy-tls`)
- Try integrate new unit-tests into existing files if it makes sense

#### Velero e2e suite (`test/e2e/velero/`)
- **e2e tests**: `make test-e2e-velero` - build tag `//go:build e2e`, 13 tests: a preflight plus the V1-V10 backup/restore scenarios (V1b and V8b included), with encryption-at-rest assertions read directly from the MinIO backend
- Environment: `make e2e-up` brings it up, `make e2e-down` tears it down, `make e2e-velero` does up + run for a cold machine. Both scripts live next to the tests (`test/e2e/velero/e2e-up.sh`, `e2e-down.sh`) and CI runs the identical scripts, so a workstation and a runner cannot drift apart
- Bring-up cost is nothing like the 30 seconds of `./start-demo.sh`: `e2e-up` generates the test PKI when needed, creates a kind cluster, builds and side-loads the proxy image for the local architecture, installs MinIO over TLS, the CSI hostpath driver + snapshotter, the proxy via its own Helm chart and Velero, and waits for the BackupStorageLocation to go Available. It is idempotent and reloads a freshly built image, so retest a code change with `make e2e-up && make test-e2e-velero` rather than recreating the cluster. The suite itself ran 592s on 2026-09-06; the CI job budgets 45 minutes for up + run + down
- `e2e-up` needs a license or the proxy pod never becomes ready: it takes `S3EP_LICENSE_TOKEN`, falls back to `config/license.jwt`, and aborts if neither exists (`make setup-dev-license`)
- The no-skip rule above covers this suite: it is the end-user experience for this product, and `e2e-velero` is a deliberate release gate in `.github/workflows/release.yml`


## Project-Specific Conventions

### Complete Configuration Structure
All configuration files follow this unified structure. Values marked `# default`
are the defaults set in `internal/config/config.go` (`setDefaults`); everything
else is an example.

```yaml
# Server Configuration
bind_address: "0.0.0.0:8080"  # default
log_level: "info"             # default; debug, info, warn, error
log_format: "text"            # default; text or json
log_health_requests: false    # default
shutdown_timeout: 30          # example, seconds; unset = main.go fallback
tls:                          # TLS listener of the proxy itself
  enabled: false              # default
  cert_file: "test/ssl-setup/proxy.crt"  # example
  key_file: "test/ssl-setup/proxy.key"   # example

# S3 Backend Configuration
s3_backend:
  target_endpoint: "https://minio:9000"  # example
  region: "us-east-1"                    # default
  access_key_id: "minioadmin"            # example
  secret_key: "minioadmin123"            # example, ${ENV} references work
  use_tls: true                          # default
  insecure_skip_verify: false            # default; the demo configs set true

# S3 Client Authentication (Enterprise Security)
s3_clients:
  - type: "static"
    access_key_id: "username0"
    secret_key: "minimum-16-chars"  # minimum 16 characters, enforced at startup
    description: "Client authentication"

# S3 Security Configuration
# Only max_clock_skew_seconds reaches any code path (pre-signed URL validator).
# The other six keys are parsed and validated and then read by nothing; ticket 015
# deletes them. Do not present them as controls.
s3_security:
  strict_signature_validation: true
  max_clock_skew_seconds: 900   # default, max 3600
  enable_rate_limiting: true    # default, dead
  max_requests_per_minute: 100  # default, dead
  enable_security_logging: true # default, dead
  max_failed_attempts: 10       # default, dead
  unblock_ip_seconds: 60        # default, dead

# Monitoring
monitoring:
  enabled: false                        # default
  bind_address: ":9090"                 # default
  metrics_path: "/metrics"              # default
  pprof_enabled: false                  # default
  pprof_bind_address: "127.0.0.1:6060"  # default; must be a loopback address or startup fails (heap holds DEKs)

# License
license_file: "config/license.jwt"  # default

# Encryption Configuration
encryption:
  encryption_method_alias: "current-provider"  # Active for writes
  integrity_verification: "off"               # default; HMAC modes: off, lax, strict, hybrid
  metadata_key_prefix: "s3ep-"                # default; must match ^[a-z0-9-]+$ or startup fails
  providers:
    - alias: "current-provider"
      type: "aes"  # or "rsa", "none"
      description: "Provider description"
      config: { ... }

# Performance Optimizations
optimizations:
  streaming_buffer_size: 65536      # default, 64KB (4KB - 2MB range)
  streaming_segment_size: 12582912  # default, 12MB (5MB - 5GB range); size of one S3 part in auto-multipart
  enable_adaptive_buffering: false  # default; experimental adaptive buffers
  streaming_threshold: 5242880      # default, 5MB threshold for GCM vs CTR (min 1MB)
  clean_aws_signature_v4_chunked: true   # default; decode aws-chunked bodies
  clean_http_transfer_chunked: true      # default; HTTP Transfer-Encoding handling
  multipart_session_cleanup_interval: 300  # default, seconds (min 60)
  multipart_session_max_age: 3600          # default, seconds (min 900)
  multipart_upload_concurrency: 4          # default, parallel S3 UploadPart calls in auto-multipart (1-32)
```

Legacy top-level `target_endpoint`, `region`, `access_key_id`, `secret_key`,
`use_tls` and `skip_ssl_verification` are still migrated into `s3_backend` by
`migrateLegacyConfig`; that is backward-compatibility code and a deletion candidate.

### Integrity Verification Modes
- **`off`**: No HMAC is written or read. No integrity signal at all
- **`lax`**: HMAC written on upload and verified on download; a mismatch is logged and the file is delivered
- **`strict`**: HMAC written on upload and verified on download. **It does not abort an `aes-ctr` download.** The verifying reader releases the plaintext before it verifies (`internal/orchestration/streaming_io.go:199-251`) and is not constructed at all when the backend response has no `Content-Length` (`internal/orchestration/singlepart.go:483`), so the mismatch is only a log line. `aes-gcm` objects are protected by their own tag, checked inside the cipher before anything is served
- **`hybrid`**: Documented as `strict` plus a pass for objects with no HMAC. In the tree that is not a difference — a missing `s3ep-hmac` is skipped silently in `strict` too (`internal/orchestration/singlepart.go:510`)

Ticket 013 (storage format v2) fixes this by construction; decision D-20 says
documentation only until then. Do not describe any mode as "maximum security" or
as aborting a tampered download. The full analysis is H-5 in
`SECURITY_ARCHITECTURE.md`; the reader that would hold the tail back
(`hmacGatedDecryptionReader`) exists but its only entry point,
`MultipartOperations.DecryptMultipartWithHMACVerification`, has no production caller.

### Provider Types and Configuration
#### AES Provider (type: "aes")
```yaml
- alias: "aes-envelope"
  type: "aes"
  description: "AES envelope encryption (auto-selects AES-CTR for multipart, AES-GCM for whole files)"
  config:
    aes_key: "base64-encoded-256-bit-key"
```

#### RSA Provider (type: "rsa")
```yaml
- alias: "rsa-envelope"
  type: "rsa"
  description: "RSA envelope encryption"
  config:
    public_key_pem: |
      -----BEGIN PUBLIC KEY-----
      ...
      -----END PUBLIC KEY-----
    private_key_pem: "${RSA_PRIVATE_KEY}"  # Can use env vars
```

#### None Provider (type: "none")
```yaml
- alias: "default"
  type: "none"
  # No config needed, pass-through without encryption
```

### Metadata Conventions
- Encryption metadata stored with prefix `s3ep-` (configurable)
- Written keys are exactly the six listed above (`MetadataManager.BuildMetadataForEncryption` plus `SetHMAC`); `encryption-mode` and `key-id` appear only in the filter and fallback lists of `metadata.go` and are never written
- `metadata.go` still reads the unprefixed legacy keys as a fallback; that is backward-compatibility code and a deletion candidate
- Metadata filtered from client responses (security isolation): `FilterMetadataForClient`
- **Important**: `provider_alias` is NOT stored in metadata - only used for configuration selection and logging

### Error Handling Patterns
- Use structured logging with `logrus.WithFields()` for all error reporting and context
- Log errors with appropriate levels: `logrus.Error()`, `logrus.Warn()`, `logrus.Debug()`
- Provider errors should include provider alias and type
- Include relevant context fields: bucket, key, operation, error details in log entries

### File Naming Patterns
- Interfaces: `pkg/encryption/interfaces.go`
- KEK provider implementations: `pkg/encryption/keyencryption/{name}.go` (flat files, not directories)
- DEK provider implementations: `pkg/encryption/dataencryption/{name}.go`
- Unit tests next to the code; the `*_coverage_test.go` files are the coverage round of 2026-09 and are ordinary unit tests
- Integration tests: `*_test.go` under `test/integration/<package>/`
- Config examples: `config/{provider}-example.yaml` (aes-example.yaml, aes-tls-example.yaml, rsa-example.yaml, multi-example.yaml, none-example.yaml)
- Tickets: `docs/tickets/NNN-<slug>.md`, index and label definitions in `docs/tickets/README.md`

## Common Development Tasks

### Adding New Encryption Provider
#### For KEK (Key Encryption Key) Providers:
1. Implement `KeyEncryptor` interface in `pkg/encryption/keyencryption/{name}.go`
2. Add the type to `KeyEncryptionType` and `CreateKeyEncryptorFromConfig` in `pkg/encryption/factory/factory.go`
3. Update `isValidProviderType` and `validateProvider` in `internal/config/config.go`, and the type switch in `ProviderManager.registerProvider` (`internal/orchestration/providers.go`)
4. Add config example in `config/{name}-example.yaml`
5. Add integration test in `test/integration/`

#### For DEK (Data Encryption Key) Providers:
1. Implement `DataEncryptor` interface in `pkg/encryption/dataencryption/{name}.go`
2. Update factory content type handling in `pkg/encryption/factory/factory.go`
3. Add algorithm metadata handling
4. Test with both small and large file scenarios

### Debugging Encryption Issues
- Enable debug logging: `log_level: "debug"` in config
- Check provider fingerprints in logs and metadata
- Use `TestContext` in tests for MinIO/proxy client comparison
- Verify `optimizations.streaming_segment_size` (min 5MB, default 12MB) for large uploads
- Chunked encoding: the handlers route on the decoded plaintext length (`RequestParser.DecodedContentLength`), not on the wire `Content-Length`; aws-chunked framing is decoded before encryption
- Encryption happens exactly once, in the handler's call into `orchestration.Manager`; there is no second encryption layer

### Docker Development
`docker-compose.demo.yml` (started by `./start-demo.sh`) runs `minio`, the proxy
twice (`proxy` on :8080, `proxy-tls` on :8443, same image), `proxy-healthcheck`,
one S3 explorer through the proxy (`encrypted-manager`, :8081) and `vault`. The
second, direct-to-MinIO explorer is commented out in the compose file. The MinIO
console on :9001 shows the raw stored objects.

## Key Files for Context
- **Main entry**: `cmd/s3-encryption-proxy/main.go`
- **Config loading**: `internal/config/config.go` (`setDefaults`, `validate`, `validateEncryption`, `validateProvider`, `validateOptimizations`, `validateS3Clients`)
- **Routes**: `internal/proxy/router.go`
- **Object handler**: `internal/proxy/handlers/object/operations.go` (GET/PUT/HEAD/DELETE, `putObjectAutoMultipart`) and `range.go`
- **Multipart handler**: `internal/proxy/handlers/multipart/` (`create.go`, `upload.go`, `complete.go`, `abort.go`)
- **Encryption manager**: `internal/orchestration/manager.go`
- **Multipart state**: `internal/orchestration/multipart.go` (`MultipartOperations`, sessions keyed by upload id, background expiry)
- **Factory pattern**: `pkg/encryption/factory/factory.go`
- **Test helpers**: `test/integration/minio_test_helper.go`
- **Security design**: `SECURITY_ARCHITECTURE.md` (threat model, H-1..H-n hardening list)

# Encryption Manager

### 1. Core Manager (Orchestration Only)
**File**: `internal/orchestration/manager.go`

**Responsibilities**:
- Request routing to appropriate operation handler
- Configuration management
- Component coordination
- Public API facade: `EncryptDataWithHTTPContentType`, `DecryptData`/`DecryptDataWithMetadata`, `CreateStreamingDecryptionReaderWithSize`, `InitiateMultipartUpload`/`UploadPartStreaming`/`CompleteMultipartUpload`/`AbortMultipartUpload`, `UploadPartStreamingBuffer`, `CreateEncryptionReader`/`CreateDecryptionReader`, `FilterMetadataForClient`

### 2. Provider Manager
**File**: `internal/orchestration/providers.go`

**Responsibilities**:
- KEK/DEK encryption and decryption operations (`EncryptDEK`, `DecryptDEK`)
- Provider registration and lifecycle management
- Fingerprint tracking and validation
- Provider selection for decryption (`GetProviderByFingerprint`)
- DEK caching for performance (cache key includes the encrypted DEK, ticket 011)
- `CreateEnvelopeEncryptor(contentType, prefix)` for the active provider

### 3. Single Part Operations
**File**: `internal/orchestration/singlepart.go`

**Clear Data Paths**:
- **EncryptGCM()**: `ContentTypeWhole` → AES-GCM → Complete object encryption
- **EncryptCTR()**: `ContentTypeMultipart` → AES-CTR → Streaming encryption. With HMAC on it buffers the plaintext once (`io.ReadAll` through a `TeeReader`) because the HMAC must be known before the PutObject header; that is why HMAC-enabled objects ≥ 5 MiB go through auto-multipart in the handler instead
- **DecryptGCMStream()**: AES-GCM encrypted objects → Full decryption, wrapped in `hmacValidatingReader` when an HMAC is present
- **DecryptCTRStream()** / `createDecryptionReaderWithSizeInternal`: AES-CTR objects → Streaming decryption; `hmacValidatingReader` only when `expectedSize > 0` and an HMAC is present

### 4. Multipart Operations
**File**: `internal/orchestration/multipart.go`

**Clear Session Lifecycle**:
1. **InitiateSession()**: Create DEK, take the IV from a fresh `AESCTRStatefulEncryptor`, set up the HMAC calculator
2. **ProcessPart()**: Encrypt part with AES-CTR, update HMAC sequentially; out-of-order parts are buffered (`PartBuffer`) until their predecessors arrive
3. **FinalizeSession()**: Encrypt the DEK, build the object metadata, add the final HMAC (`FinalizeCalculator` + `SetHMAC`). No verification happens here; verification is a download-side step
4. **AbortSession()** / **CleanupSession()**: Clean up resources and state; `CleanupExpiredSessions` runs from the manager's background loop

### 5. Streaming Operations
**Files**: `internal/orchestration/streaming_io.go`, `rangeread.go`, `manager.go`

**Optimized for Memory Efficiency**:
- **Manager.CreateEncryptionReader()**: Wrap input stream for on-the-fly encryption
- **Manager.CreateDecryptionReader()**: Wrap encrypted stream for on-the-fly decryption
- **Manager.UploadPartStreamingBuffer()**: Process a part in `streaming_segment_size` segments with a per-segment callback (used by auto-multipart)
- **Manager.CreateRangeDecryptionReader()**: AES-CTR ranged decryption from an arbitrary plaintext offset (`NewCTRRangeReader`); not HMAC-verified (H-1 in `SECURITY_ARCHITECTURE.md`)

### 6. HMAC Manager
**File**: `internal/validation/hmac_manager.go` (+ `hmac_calculator.go`, `hkdf.go`)

**Centralized Integrity Operations**:
- **DeriveIntegrityKey()** (`hkdf.go`): HKDF-based key derivation from DEK
- **CreateCalculator()**: Initialize HMAC-SHA256 calculator
- **FinalizeCalculator()**: Produce the final HMAC for metadata
- **VerifyIntegrity()**: Compare calculated vs expected HMAC (constant time), mode-aware (lax swallows the mismatch)
- **IsEnabled()**: Check if HMAC verification is configured (`integrity_verification != off`)


## Explicit Data Flow Documentation

### PUT Request Flow (Upload)
```
Client PUT /{bucket}/{key} → object.Handler.handlePutObject()
        ↓
  [x-amz-copy-source?] → refused: CopyObject is not supported with encryption
        ↓
  plaintextLen = RequestParser.DecodedContentLength(r)   (aws-chunked framing removed)
  forced       = Content-Type application/x-s3ep-force-aes-ctr
        ↓
  [forced && plaintextLen < 1 KiB]      → putObjectDirect with forced CTR
  [plaintextLen unknown, or
   HMAC on && plaintextLen ≥ 5 MiB
   && provider != none]                 → putObjectAutoMultipart
  [forced || plaintextLen ≥ streaming_threshold] → putObjectStreamingReader
  [else]                                 → putObjectDirect
        ↓                                        ↓
  Manager.EncryptDataWithHTTPContentType(isMultipart=true/false)
        ↓                                        ↓
  Manager.EncryptCTR()                    Manager.EncryptGCM()
        ↓                                        ↓
  ProviderManager.CreateEnvelopeEncryptor(ContentTypeMultipart|Whole)
        ↓                                        ↓
  envelope.EncryptDataStream → metadata (encrypted-dek, dek-algorithm, kek-*, aes-iv[, hmac])
        ↓                                        ↓
  s3Backend.PutObject(encrypted body, metadata)  → S3 Storage
```

`putObjectAutoMultipart` is the internal multipart pipeline: `InitiateMultipartUpload`,
`UploadPartStreamingBuffer` in `streaming_segment_size` segments with up to
`multipart_upload_concurrency` parallel S3 `UploadPart` calls (encryption stays
sequential, CTR needs it), `CompleteMultipartUpload`, then a self-copy
(`CopyObject` with `MetadataDirective=REPLACE`) to attach the encryption metadata,
because S3 does not carry metadata from CreateMultipartUpload to the completed object.

### Multipart PUT Flow (client-driven)
```
POST ?uploads          → multipart.CreateHandler → Manager.InitiateMultipartUpload()
                                                    → MultipartOperations.InitiateSession()
                                                      [Create DEK, IV, HMAC Calculator]
PUT ?partNumber&uploadId → multipart.UploadHandler → Manager.UploadPartStreaming()
                                                    → MultipartOperations.ProcessPart()
                                                      [AES-CTR Encrypt + Sequential HMAC,
                                                       out-of-order parts buffered]
                                                    → s3Backend.UploadPart
POST ?uploadId         → multipart.CompleteHandler → Manager.CompleteMultipartUpload()
                                                    → MultipartOperations.FinalizeSession()
                                                      [Encrypt DEK, build metadata, final HMAC]
                                                    → s3Backend.CompleteMultipartUpload
                                                    → self-copy to attach the metadata
DELETE ?uploadId       → multipart.AbortHandler    → s3Backend.AbortMultipartUpload
```

### GET Request Flow (Download)
```
Client GET /{bucket}/{key} → object.Handler.handleGetObject()
        ↓
  [Range header?] → handleGetObjectRange()
                      aes-ctr: fetch only the ciphertext range,
                               Manager.CreateRangeDecryptionReader() (no HMAC check, H-1)
                      aes-gcm: serveRangeByFullDecryption() (full decrypt, then slice)
        ↓
  s3Backend.GetObject → metadata
        ↓
  [no encrypted-dek] → pass through unchanged
        ↓
  dek-algorithm from metadata (missing → "aes-gcm")
        ↓                                        ↓
  aes-ctr                                   aes-gcm
  handleGetObjectStreamingDecryption        handleGetObjectMemoryDecryption
        ↓                                        ↓
  Manager.CreateStreamingDecryptionReader   Manager.DecryptDataWithMetadata
  WithSize(expectedSize=Content-Length)          ↓
        ↓                                   Manager.DecryptData → DecryptGCMStream
  ProviderManager.DecryptDEK (cached)            ↓
        ↓                                   ProviderManager.DecryptDEK (cached)
  decryptionReader (AES-CTR stateful)            ↓
  [+ hmacValidatingReader if Content-      envelope.DecryptDataStream (GCM tag checked
   Length known and hmac present]           inside the cipher) [+ hmacValidatingReader]
        ↓                                        ↓
  FilterMetadataForClient → response headers → Client
```

# MAIN GOALS
1. Ensure data is always encrypted at rest in S3
2. encrypt and decrypt data as fast as possible (performance is key)
3. use streaming to decrease memory footprint
4. keep the architecture as simple as possible (no unnecessary layers)

# WORK ORDER
1. use sha256 hashed to compare files in tests, no hex dumps


## Always pay attention to performance. If you notice an underperforming implementation, stop what you are doing and report the problem to me.

# WE DONT NEED BACKWARD COMPATIBILITY, remove unnecessary code
