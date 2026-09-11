# S3 Encryption Proxy - AI Coding Instructions

## Project Overview
A Go-based transparent S3 encryption proxy. It sits between S3 clients and S3 storage,
encrypting objects before storage and decrypting them on retrieval. Every object is stored in
one format: an authenticated AES-256-GCM segment chain closed by a sealed trailer (ADR 0003),
under one random data key per object that is wrapped by the configured key encryption key
(ADR 0002). There is no second cipher, no configurable integrity mode and no format switch.

## Decisions live in ADRs; tickets are work lists that get deleted

**Every design decision of this project is recorded as an ADR** under
[docs/adr/](docs/adr/) — see [docs/adr/README.md](docs/adr/README.md) for the
format and the ground rules. Write the ADR in the session the decision is taken,
not when the work is finished. An ADR states what the product does and why; it
carries **no references into the code** (no file paths, line numbers, function or
package names) so it stays true when the tree moves. The product's own vocabulary
— configuration keys, `s3ep-*` metadata keys, S3 error codes, header and
algorithm names — is not a code reference and must be exact.

**A ticket is a work list and nothing else.** It lives in `docs/tickets/`, it
exists while work is outstanding, and it is closed by **deleting the file** when
the work lands. Before deleting it, move anything durable out of it: the decision
into an ADR, the user-facing consequence into `README.md` or
`SECURITY_ARCHITECTURE.md`. Finish, document, delete — a backlog that outlives
its work costs focus.

**Nothing outside `docs/tickets/` may reference a ticket.** Not `README.md`, not
`SECURITY_ARCHITECTURE.md`, not this file, not a code comment, not a commit
message, not a pull request. Cite the ADR instead; ADRs may be referenced from
anywhere. A code comment that has to point at a pending change points at its ADR
("the segmented format, ADR 0003"), never at a ticket number. Before deleting a
ticket, `git grep` for its number and clear whatever is left.

## Developer documentation lives in `docs/developer/`

Overviews for people changing the code — the package map, the storage format and
its invariants, the request paths, multipart, the error conventions, the test
layers, how to measure performance. Start at
[docs/developer/README.md](docs/developer/README.md).

**Read the page for a subsystem before you change it**, and **update it in the
same change** when you move what it describes. Unlike an ADR, a page here points
at files and functions on purpose, so it goes stale when the tree moves.

Where a durable insight belongs:

| Kind | Home |
|---|---|
| A decision — what the product does and why, what was rejected | an [ADR](docs/adr/), with no references into the code |
| How a subsystem works, an invariant, a hard-won detail | [docs/developer/](docs/developer/) |
| What an operator or a client needs | [README.md](README.md) |
| The threat model and residual risks | [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md) |
| Work still outstanding | a [ticket](docs/tickets/), deleted when the work lands |

Do not let implementation detail accumulate in `README.md`; that page is for
operators and clients. If you catch yourself explaining the code there, the
explanation belongs in `docs/developer/`.

## Start with the knowledge graph (graphify)

This project has a graphify knowledge graph at `graphify-out/` (`graph.json`,
`GRAPH_REPORT.md`, `wiki/`). It is the fastest way to see how the pieces hang
together before touching code, and it is committed, so it is always available.

**The committed graph was built on 2026-09-09 and predates the 5.0.0 removal**
that deleted the pre-segment-chain code. A large share of its articles name
packages, files and symbols that no longer exist — `internal/validation`,
`pkg/encryption/envelope`, the AES-CTR and AES-GCM data encryptors, every HMAC
article, the old orchestration `singlepart`/`multipart`/`streaming_io` split.
Use it for shape, never for facts, until it is rebuilt.

**Use it first, especially at the start of a ticket and for any code research:**
- Read `graphify-out/wiki/index.md`, then the community articles that name the
  packages the task touches (e.g. *Bucket Sub-Resource Handlers*, *Encryption
  Metadata Management*, *DEK Cache and Providers*, *SigV4 Pre-Signed URL Auth*).
  One article is a map of one subsystem; read two or three before opening raw
  files.
- `graphify query "<question>"` gives BFS context around a question,
  `graphify explain "<symbol>"` explains one node and its neighbours,
  `graphify path "A" "B"` finds how two concepts connect. All read
  `graphify-out/graph.json` and cost no API tokens.
- Before answering architecture or codebase questions, read the *Community Hubs*
  section of `graphify-out/GRAPH_REPORT.md`. Skip its *God Nodes* section: in this
  repo it lists test fixtures and constructors (`EnsureMinIOAndProxyAvailable()`,
  `NewErrorWriter()`, `MockS3Backend` four times over), which are call-resolution
  artifacts, not architectural hubs.
- Treat a graph hit as a pointer, not a fact. Wiki articles built from a document
  inherit that document's staleness, and several were built from documents that
  have since been deleted (`internal/orchestration/README.md`,
  `docs/architecture/`, `test/integration/README.md`). Verify in the code before
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
excluded). Its graphify-out rules name sub-paths instead of the whole directory
on purpose: graphify always scans `graphify-out/memory/` (Q&A results filed by
`graphify save-result`) when it exists but still applies the ignore file to it,
so a blanket `graphify-out` rule would drop it. That directory does not exist in
this repo yet.

## Architecture Deep Dive

### Core Components
- **`cmd/s3-encryption-proxy/`**: Main CLI application using Cobra (`main.go`: config loading, license start, server lifecycle, graceful shutdown incl. `Server.Shutdown`)
- **`cmd/keygen/`**: AES-256 key generator (built as `build/s3ep-keygen`)
- **`cmd/license-tool/`**: License JWT generator (built as `build/license-tool`)
- **`internal/proxy/`**: HTTP proxy server: router, middleware, request/response helpers and the S3 handlers, talking to the backend through `aws-sdk-go-v2`
- **`internal/orchestration/`**: The encryption facade the handlers call: providers, object metadata, the segmented write/read entry points and the client-driven multipart session table
- **`pkg/encryption/`**: The codec and the KEK providers — no business logic
- **`internal/config/`**: Viper-based configuration with provider validation
- **`internal/license/`**: License JWT validation and the startup gate
- **`internal/monitoring/`**: Prometheus metrics server and middleware, pprof on its own loopback listener

There is no `internal/validation` package and no `pkg/encryption/envelope`; the
HMAC layer and the envelope indirection they held are gone. Integrity is not a
layer any more — it is the storage format itself.

### Package Architecture & Separation

#### `pkg/encryption/` - Codec & KEK Providers
**Responsibilities:**
- **Interfaces** (`interfaces.go`): `KeyEncryptor` and nothing else. `EncryptDEK`, `DecryptDEK`, `Name`, `Fingerprint`
- **KEK Providers** (`keyencryption/`, one file per provider: `aes.go`, `exit.go`): wrap and unwrap Data Encryption Keys
- **Codec** (`dataencryption/segmented_gcm.go`): `Codec`, `NewCodec(dek, objectKey)`, `Checksum`/`NewChecksum`/`Append`, `SealTrailer`/`OpenTrailer`, `CiphertextSize`/`PlaintextSize`, and the format constants `SegmentSize` (65536), `SegmentOverhead` (28), `TrailerSize` (40), `FormatID` (`s3ep-gcm-seg-v2`), `MaxPlaintextLen` (5 TiB)
- **Codec IO** (`dataencryption/segmented_gcm_io.go`): `NewWriter`/`NewPartWriter`/`FinishPart`, `NewReader`, `NewEncryptReader`/`NewPartEncryptReader`. The `EncryptReader` pair is what makes a write pullable: the backend SDK reads the body and each segment is sealed on demand, so no write path materialises more than one segment
- **Range planner** (`dataencryption/segmented_gcm_range.go`): `Window`, `PlanRange`, `NewRangeReader`. Planning needs no key, so a handler can issue the backend request before it unwraps anything

**Characteristics**: Pure cryptographic implementations, no business logic, reusable components

#### `internal/orchestration/` - Provider state, metadata and the write/read entry points
**Responsibilities:**
- **Manager** (`manager.go`): construction, provider queries, the metadata prefix, the background session sweeper and `Shutdown`. Nothing else lives here
- **Provider Management** (`providers.go`): provider registration, fingerprints, `EncryptDEK`/`DecryptDEK`, the DEK LRU
- **Segmented objects** (`segmented.go`): `NewSegmentedWrite`, `NewSegmentedUpload` (+ `SealedPart`), `OpenSegmented`, `OpenSegmentedRange`, `IsSegmentedObject`, `PlanRange`, `PlaintextSize`, `PartStoredLen`, and the two read-refusal errors `ErrForeignObject` / `ErrKeyMaterialUnreadable`
- **Client-driven multipart** (`segmented_session.go`): `SegmentedSession` and the manager's session table (`NewSegmentedSession`, `RegisterSegmentedSession`, `SegmentedSession`, `CloseSegmentedSession`, `CleanupExpiredSegmentedSessions`, `ShortPartBufferSize`)
- **Metadata** (`metadata.go`): `MetadataManager` — `BuildSegmentedMetadata`, `GetEncryptedDEK`, `GetAlgorithm`, `GetFingerprint`, `GetMetadataPrefix`

**Characteristics**: Business logic, state management, S3-specific integration, operation coordination

#### `internal/proxy/` - HTTP surface
- `server.go`: HTTP and optional TLS listener (`tls.enabled`), the backend SDK client, and `Server.Shutdown`, which stops the manager's background session sweeper; `router.go`: gorilla/mux routes, `middleware_setup.go`: middleware chain and the fixed per-code authentication error messages
- `middleware/`: SigV4 header and pre-signed URL authentication (`s3auth_robust.go`, `s3auth_presigned.go`), CORS, logging, request tracking. `logSecurityEvent` logs `remote_addr` and `x_forwarded_for` as two separate fields; there is no per-IP failure accounting and no rate limiting (ADR 0014)
- `request/`: request parser (`ReadBody`, `StreamingReader`, `DecodedContentLength`, `PlaintextContentLength`), the streaming aws-chunked decoder, the HTTP chunked decoder, `IsAWSProtocolQueryParam`
- `response/`: S3 error documents and backend error mapping, XML helpers
- `handlers/root/` (ListBuckets), `handlers/bucket/`, `handlers/object/`, `handlers/multipart/`, `handlers/health/`. `SECURITY_ARCHITECTURE.md` §6.5 explains why refusing beats pretending
- `interfaces/s3_backend.go`: `S3BackendInterface`, the 42-method slice of `aws-sdk-go-v2/service/s3` the handlers compile against (mocked in the handler unit tests). `CopyObject` is deliberately absent: both server-side copy verbs are refused (ADR 0011 D9)

What the S3 surface actually does today:
- **Bucket sub-resources**: 13 routed. Every GET arm reaches the backend. PUT reaches the backend for `acl`, `cors`, `lifecycle`, `logging`, `notification`, `policy`, `tagging` and — only with an empty body — `versioning`; PUT answers NotImplemented for `accelerate`, `replication`, `requestPayment` and `website`. DELETE reaches the backend for `cors`, `lifecycle`, `policy`, `replication`, `tagging` and `website`. Any unrouted query parameter is refused with NotImplemented in `handler.go`
- **Object sub-resources**: only `?torrent` is live. `acl`, `tagging`, `legal-hold`, `retention`, `select` and `attributes` answer NotImplemented; a sub-resource that has a route but did not match it answers MethodNotAllowed rather than running the base verb
- **Multipart**: Create/UploadPart/Complete/Abort implemented; UploadPartCopy answers NotSupportedWithEncryption, ListMultipartUploads NotImplemented, ListParts returns a constant empty document (ADR 0011 D6, outstanding)
- **Listings** report the plaintext size under an encrypting provider, computed from the stored size with `dataencryption.PlaintextSize` — no metadata read, no extra request (`bucket/listing.go`, `reportedSize`). Under the exit provider the stored size is reported **verbatim**, because such a bucket holds both kinds of object and a listing cannot tell them apart without a HEAD per key; inverting would under-report plain objects, and a sync client that believes the remote is shorter uploads over it. Over-reporting only costs a re-transfer, so the error is kept on that side (ADR 0010)

### Critical Data Flow
1. **PUT**: Client → Router → Middleware (SigV4 auth) → Object/Multipart Handler → `orchestration.Manager` → AWS S3 SDK → S3 Storage. The Manager draws a data key, wraps it, builds the complete metadata set and hands back a body that seals as the backend pulls it. Every metadata value exists before the first backend byte, which is why no write path rewrites the object afterwards
2. **GET**: Client ← Object Handler ← `orchestration.Manager` (`OpenSegmented` / `OpenSegmentedRange`) ← AWS S3 SDK ← S3 Storage

The exact branching is under [Explicit Data Flow Documentation](#explicit-data-flow-documentation).

### Encryption Providers Architecture
Envelope encryption with separate **Key Encryption Key (KEK)** and **Data Encryption Key (DEK)**
layers. The DEK layer is not pluggable: it is the segment chain, always.

#### KEK (Key Encryption Key) Providers - `pkg/encryption/keyencryption/`
Wrap and unwrap the per-object data key:
- **AES Provider** (`aes.go`, type `aes`): the one local key provider (ADR 0004). `aes_key` is base64 of exactly 32 random bytes; HKDF-SHA256 derives the fingerprint (label `s3ep-kek-fingerprint`) and every per-wrap key from it, and a DEK is wrapped with AES-256-GCM as `salt(16) ‖ nonce ‖ ciphertext ‖ tag` under the AAD `s3ep-dek-wrap-v1`. A tampered or foreign wrap fails with `ErrWrappedDEKAuth`, which the read path turns into a permanent refusal
- **Exit Provider** (`exit.go`, type `exit`): the provider an operator selects to **leave the product**. It holds no key material: `EncryptDEK` and `DecryptDEK` both return `ErrExitProviderKeyUse`, and there is no short-circuit anywhere else — that error is the enforcement, so a backend labelling an object `exit-provider-fingerprint` gets a failed read rather than a data key of its own choosing (ADR 0001). Selected while it is active, every write path stores what the client sent, with no `<prefix>` metadata; every read decides **per object**, so an object this proxy encrypted earlier is still decrypted through the `aes` provider its own `kek-fingerprint` names. That provider therefore has to stay configured beside it (ADR 0004). It needs **no license**: the gate looks at the active provider only, which is what makes getting the data out independent of a valid license (ADR 0016). `type: "none"` is refused by name in `validateProvider`, with a message pointing at `exit`

There is no tink provider in the tree. `type: "tink"` is still refused by name in
`validateProvider` so an old configuration fails loudly instead of silently
falling through to the `unsupported encryption type` message. A key held in a KMS
is a provider type of its own and nothing of it is built (ADR 0005).

#### DEK (Data Encryption Key) layer - `pkg/encryption/dataencryption/`
One codec, one format. `Codec` binds the object's data key to the client's object key and seals
every segment under `formatID ‖ objectKey ‖ segmentIndex`, so a hostile backend cannot reorder
segments, move one between objects, or truncate the chain without the read failing (ADR 0001,
ADR 0003):

```
segment i : nonce(12) ‖ AES-256-GCM(plaintext ≤ 65536) ‖ tag(16)
trailer   : nonce(12) ‖ AES-256-GCM(uint64 length ‖ uint32 CRC32C) ‖ tag(16)
```

The **Factory** (`pkg/encryption/factory/`) is only the KEK registry now:
`NewFactory`, `RegisterKeyEncryptor`, `GetKeyEncryptor(fingerprint)`,
`CreateKeyEncryptorFromConfig(KeyEncryptionTypeAES|KeyEncryptionTypeExit, config)`.
It knows nothing about content types or data encryption.

On decryption `ProviderManager.DecryptDEK` selects the KEK provider by the
fingerprint stored on the object, through `factory.GetKeyEncryptor` — which is
what lets a retired key still read what it wrote.

Written metadata is exactly four keys:
- `dek-algorithm` — always `s3ep-gcm-seg-v2`
- `encrypted-dek`
- `kek-algorithm`
- `kek-fingerprint`

with the prefix of `metadata_key_prefix` from configuration (default `s3ep-`).
There is no `aes-iv` (the nonce is inline in every segment) and no `hmac` (the
trailer is the integrity record). `MetadataManager.BuildSegmentedMetadata` is the
only writer of all four.

## Development Workflows

### Build Commands (Makefile-driven)
```bash
make build              # Build main binary to build/s3-encryption-proxy
make build-keygen       # Build AES key generator to build/s3ep-keygen
make license-tool       # Build the license tool to build/license-tool
make build-all          # All three binaries
make test-unit          # Unit tests (-short)
make test-integration   # Integration tests against the plain-HTTP proxy (requires ./start-demo.sh)
make test-integration-tls          # Same suites against the TLS endpoint (aws-sdk-go-v2 emits STREAMING-UNSIGNED-PAYLOAD-TRAILER framing only over HTTPS, so only this run reaches the trailer decoder)
make test-integration-performance  # Proxy-vs-MinIO throughput, run alone on purpose
make test-integration-all          # HTTP + TLS + performance
make perf-baseline      # Local before/after throughput baseline (ADR 0020); perf-baseline-quick, perf-baseline-offline, perf-compare
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
manager handles the go directive in go.mod (depName `go`). No Renovate PR has
ever bumped the go directive deliberately (the one gomod-manager "Update
dependency go" PR moved only the since-removed `toolchain` line), which is why
the regex manager exists. If you introduce a new place that needs the version, derive it
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

# Development license: config/license.jwt (gitignored) or S3EP_LICENSE_TOKEN, supplied
# out of band. `make generate-license` builds and runs cmd/license-tool, which needs
# license_private_key.pem / license_public_key.pem next to the binary (not in the repo,
# ADR 0021). There is no setup-dev-license target.
```

### Testing Strategy
- **Unit tests**: `make test-unit` - Fast tests with `-short` flag
- **Integration tests**: `make test-integration` - Requires MinIO via `./start-demo.sh`
- Use build tag `//go:build integration` for integration tests. Exception in the tree: four `bucket_*_test.go` files in `s3-methods` (`acl`, `cors`, `location`, `logging`) carry no tag (offline XML/validation tests) and therefore also run under `make test-unit`
- Integration packages: `test/integration` (helpers + `s3_signing_test.go`), `180-degree-variants`, `360-degree-variants`, `authentication`, `encryption-modes`, `s3-methods` (the bulk of the suite) and `performance-test`, which the Makefile runs on its own because it measures proxy-vs-MinIO throughput and the other packages would compete for the same backend
- Test helper: `test/integration/minio_test_helper.go` provides `TestContext` with MinIO and proxy clients; `encryption_validation_helper.go` asserts that stored bytes are ciphertext (entropy checks)
- You are not allowed to disable, skip or remove integration or Velero e2e tests, they represent the end-user experience (ADR 0019)
- Don't call your work done until all integration tests pass
- Integration Test need to be prepared with ./start-demo.sh (it takes 30 seconds to start)
- If you want to get the recent logs from s3-encryption-proxy container use: docker logs proxy | tail -50 (the TLS listener is a second container, `proxy-tls`)
- Try integrate new unit-tests into existing files if it makes sense

#### Velero e2e suite (`test/e2e/velero/`)
- **e2e tests**: `make test-e2e-velero` - build tag `//go:build e2e`, 13 tests: a preflight plus the V1-V10 backup/restore scenarios (V1b and V8b included), with encryption-at-rest assertions read directly from the MinIO backend
- Environment: `make e2e-up` brings it up, `make e2e-down` tears it down, `make e2e-velero` does up + run for a cold machine. Both scripts live next to the tests (`test/e2e/velero/e2e-up.sh`, `e2e-down.sh`) and CI runs the identical scripts, so a workstation and a runner cannot drift apart
- Bring-up cost is nothing like the 30 seconds of `./start-demo.sh`: `e2e-up` generates the test PKI when needed, creates a kind cluster, builds and side-loads the proxy image for the local architecture, installs MinIO over TLS, the CSI hostpath driver + snapshotter, the proxy via its own Helm chart and Velero, and waits for the BackupStorageLocation to go Available. It is idempotent and reloads a freshly built image, so retest a code change with `make e2e-up && make test-e2e-velero` rather than recreating the cluster. The suite itself ran 592s on 2026-09-06; the CI job budgets 45 minutes for up + run + down
- `e2e-up` needs a license or the proxy pod never becomes ready: it takes `S3EP_LICENSE_TOKEN`, falls back to `config/license.jwt`, and aborts if neither exists. Supply the token out of band (CI injects the `S3EP_LICENSE_TOKEN` secret)
- The no-skip rule above covers this suite: it is the end-user experience of one supported S3 client exercised end to end, and `e2e-velero` is a deliberate release gate in `.github/workflows/release.yml`


## Project-Specific Conventions

### Complete Configuration Structure
This is every key the code reads, and since ADR 0013 D11 it is also every key the
proxy accepts: the loader decodes in its exact mode, so a key that is not here
refuses the start and the error names it. Values marked `# default` are the
defaults set in `internal/config/config.go` (`setDefaults`); everything else is an
example. **Adding a key to the struct and forgetting this table is now a startup
failure for anyone whose configuration carries it**, so the two move together.

```yaml
# Server Configuration
bind_address: "0.0.0.0:8080"  # default
log_level: "info"             # default; debug, info, warn, error
log_format: "text"            # default; text or json
log_health_requests: false    # default
shutdown_timeout: 30          # example, seconds; unset = 30s fallback. Bounds the
                              # request drain and the manager stop, and the chart
                              # derives terminationGracePeriodSeconds from it
read_timeout: 0               # default, seconds; 0 = no deadline on a request body
write_timeout: 0              # default, seconds; 0 = no deadline on a response body
read_header_timeout: 30       # default, seconds; may not be 0 (slow-header bound)
idle_timeout: 60              # default, seconds; may not be 0 (keep-alive bound)
tls:                          # TLS listener of the proxy itself
  enabled: false              # default
  cert_file: "test/ssl-setup/public.crt"   # example, gen-certs.sh output
  key_file: "test/ssl-setup/private.key"   # example, gen-certs.sh output

# S3 Backend Configuration
s3_backend:
  target_endpoint: "https://minio:9000"  # example; required, and its scheme decides
                                         # whether the backend leg is TLS. A missing
                                         # scheme refuses the start, and so does
                                         # http:// under a provider that encrypts
  region: "us-east-1"                    # default
  access_key_id: "minioadmin"            # example
  secret_key: "minioadmin123"            # example, ${ENV} references work
  insecure_skip_verify: false            # default; the demo configs set true

# S3 Client Authentication (required - the proxy refuses to start without at least one)
s3_clients:
  - type: "static"                  # the only supported type
    access_key_id: "username0"      # minimum 8 characters, enforced at startup
    secret_key: "minimum-16-chars"  # minimum 16 characters, enforced at startup
    description: "Client authentication"

# S3 Security Configuration
# Both keys govern both authentication forms (ADR 0014 D4/D5). Neither accepts 0:
# there is no value that switches a check off, and a silent fallback to the
# default is what ADR 0017 D8 forbids.
s3_security:
  max_clock_skew_seconds: 900       # default, 1-3600 checked at startup
  max_presign_expiry_seconds: 3600  # default, 1-604800 (the S3 seven-day maximum)

# Monitoring
monitoring:
  enabled: false                        # default
  bind_address: ":9090"                 # default
  metrics_path: "/metrics"              # default
  pprof_enabled: false                  # default
  pprof_bind_address: "127.0.0.1:6060"  # default; with pprof_enabled: true it must be a loopback IP or "localhost" or startup fails (heap holds DEKs); unchecked while pprof is off

# License
license_file: "config/license.jwt"  # default

# Encryption Configuration
encryption:
  encryption_method_alias: "current-provider"  # active for writes; must name one of the providers
  metadata_key_prefix: "s3ep-"                 # default; must match ^[a-z0-9][a-z0-9-]{2,}-$
                                               # (ADR 0009 D2) or startup fails
  providers:
    - alias: "current-provider"
      type: "aes"  # or "exit"
      description: "Provider description"   # parsed, never read
      config: { ... }

# Performance Optimizations
# The validate:"min=..." struct tags in config.go are never evaluated (no validator
# library); only the ranges written out in validateOptimizations() are enforced.
optimizations:
  streaming_segment_size: 12582912  # default, 12MB (5MB - 5GB checked at startup).
                                    # Two jobs: the size of one S3 part in the internal
                                    # multipart producer, and the ceiling above which a
                                    # PUT stops being a single request
  clean_http_transfer_chunked: true      # default; HTTP chunked handling, in ReadBody only
                                         # (aws-chunked decoding is not configurable, ADR 0013)
  multipart_session_cleanup_interval: 300  # default, seconds, not range-checked; 0 disables the sweeper
  multipart_session_max_age: 3600          # default, seconds, not range-checked
  multipart_upload_concurrency: 4          # default, parallel S3 UploadPart calls in the internal producer (1-32 checked at startup)
  multipart_short_part_buffer_size: 67108864  # default, 64MB (minimum 5MB when set); what one
                                              # client-driven upload may hold for a short last part
```

There is no legacy top-level backend block any more. A configuration that still
uses top-level `target_endpoint` / `region` / `access_key_id` / `secret_key` /
`use_tls` / `skip_ssl_verification` is ignored in full and the proxy refuses to
start with `s3_backend.target_endpoint is required`.

### Integrity is not configurable
There is no `encryption.integrity_verification` and no `off`/`lax`/`strict`/`hybrid`
mode. Integrity is inseparable from decryption (ADR 0001, ADR 0003):

- Every segment is opened with its own tag under associated data that binds the format id, the object key and the segment index. A byte the reader has not authenticated is never handed out
- The trailer authenticates the object's plaintext length and its CRC32C, and the reader verifies it before it reports `io.EOF`. A truncated, extended or reordered chain fails
- An object with no proxy metadata, or metadata naming a format this proxy does not read, is refused under an encrypting provider: `403 InvalidObjectState`, on GET, HEAD and ranged GET alike. There is no pass-through opt-out and no setting that softens it. The one provider that serves such an object is `exit`, and it decides per object — an object that *does* carry the format's metadata is still opened and still refused when its key material does not authenticate
- A wrapped data key that does not authenticate is the same answer, deliberately not a 5xx: it is a permanent state of that object and a retrying SDK must not report it as a passing outage

**The honest gap (ADR 0003 D14, not implemented).** The read is one forward pass,
not the tail-first pair the ADR describes. The response status and
`Content-Length` are already sent when the body starts flowing, so a fault found
at the end of the stream cuts the body short at a segment boundary instead of
answering an error — every byte the client did receive carried its own tag, but
the client learns of the failure as a short read, not as an S3 error.
`x-amz-checksum-crc32c` is served nowhere.

**The upload leg (ADR 0012, built 2026-09-11 except D10).** Every checksum a
client declares is verified against the decoded plaintext — `Content-MD5`,
`x-amz-checksum-crc32`/`-crc32c`/`-crc64nvme`/`-sha1`/`-sha256`/`-sha512`/`-md5`,
as a request header or as an aws-chunked trailer — on every write path, and then
dropped: no value reaches the backend and none is stored. Anything else under
`x-amz-checksum-` answers `501 NotImplemented` (the `xxhash` family the SDK can
send, which has no stdlib hash); `-algorithm`, `-mode` and `-type` carry no
digest and pass. `CompleteMultipartUpload` is the one exemption: there the header
is the digest of the completed **object**, not of the document, so it is read
through `ReadBodyUnverified` and dropped. A mismatch is `400 BadDigest`, a
value that is not a digest of its length is `400 InvalidDigest`, and
`DeleteObjects` refuses a request carrying no digest with `400 InvalidRequest`.
The verifier is `internal/proxy/request/checksum.go`, wrapped around both parser
entry points; it holds the final payload byte back until the verdict is in, so a
refused upload stores nothing. `MapError` recognises the two sentinels, so a
verdict is never reported as a 5xx. What is still open is D10: the proxy's own
sealed CRC32C is served nowhere.

### Provider Types and Configuration
#### AES Provider (type: "aes")
```yaml
- alias: "aes-envelope"
  type: "aes"
  description: "AES envelope encryption"
  config:
    aes_key: "base64-encoded-256-bit-key"  # base64 of exactly 32 random bytes
```
`validateAESKey` refuses anything that is not base64 of exactly 32 bytes, and
additionally refuses a decoded value that is all printable ASCII or carries fewer
than 16 distinct byte values — that is a passphrase, not a key. Generate one with
`s3ep-keygen` or `openssl rand -base64 32`.

#### Exit Provider (type: "exit")
```yaml
- alias: "exit"
  type: "exit"
  # No config: it holds no key material. Keep the aes provider that wrote the
  # existing objects listed alongside it, or they become unreadable.
```

### Metadata Conventions
- Encryption metadata stored with prefix `s3ep-` (configurable via `encryption.metadata_key_prefix`)
- Written keys are exactly the four listed above, by `MetadataManager.BuildSegmentedMetadata` alone. It is called from `Manager.newSegmentedObject`, which every write path goes through: single-request PUT, the internal multipart producer and client-driven CreateMultipartUpload
- Only the prefixed key is ever read. The unprefixed name lies outside the proxy's namespace, so a client could set it through `x-amz-meta-*` (ADR 0009 D1)
- The prefix is the proxy's exclusive namespace in both directions: `userMetadataFromRequest` (object handler) and `CreateHandler.userMetadata` drop any client `x-amz-meta-<prefix>*` header on the way in, and `Handler.cleanMetadata` drops every key carrying the prefix on the way out, case-insensitively, on GET, HEAD and ranged responses
- **Important**: `provider_alias` is NOT stored in metadata - only used for configuration selection and logging

### Error Handling Patterns
- Use structured logging with `logrus.WithFields()` for all error reporting and context
- Log errors with appropriate levels: `logrus.Error()`, `logrus.Warn()`, `logrus.Debug()`
- Provider errors should include provider alias and type
- Include relevant context fields: bucket, key, operation, error details in log entries
- Never reflect a raw error string into a response body; the client-facing wording per S3 error code is fixed. See [docs/developer/errors.md](docs/developer/errors.md)

### File Naming Patterns
- Interfaces: `pkg/encryption/interfaces.go`
- KEK provider implementations: `pkg/encryption/keyencryption/{name}.go` (flat files, not directories)
- The codec: `pkg/encryption/dataencryption/segmented_gcm{,_io,_range}.go`
- Unit tests next to the code; the `*_coverage_test.go` files are the coverage round of 2026-09 and are ordinary unit tests
- Integration tests: `*_test.go` with `//go:build integration` under `test/integration/<package>/`, plus `test/integration/s3_signing_test.go` next to the helpers
- Config examples: `config/{provider}-example.yaml` (aes-example.yaml, aes-tls-example.yaml, multi-example.yaml, exit-example.yaml)
- ADRs: `docs/adr/NNNN-<kebab-title>.md`, index in `docs/adr/README.md` — permanent
- Tickets: `docs/tickets/NNN-<slug>.md` — work lists, deleted when the work lands, referenced from nowhere else

## Common Development Tasks

### Adding a new KEK provider
1. Implement `KeyEncryptor` (`pkg/encryption/interfaces.go`) in `pkg/encryption/keyencryption/{name}.go`
2. Add the type to `KeyEncryptionType` and `CreateKeyEncryptorFromConfig` in `pkg/encryption/factory/factory.go`
3. Update `isValidProviderType` and `validateProvider` in `internal/config/config.go`, and the provider-type switch in `NewProviderManager` (`internal/orchestration/providers.go`)
4. Add config example in `config/{name}-example.yaml`
5. Add integration test in `test/integration/`

`Fingerprint()` must identify the key without revealing anything about it, and it
must be stable: it is what a stored object names, so a provider that changes its
fingerprint stops reading its own objects.

There is no DEK provider extension point. The data layer is the segment chain,
and changing it is a storage format change (ADR 0003, ADR 0017).

### Debugging Encryption Issues
- Enable debug logging: `log_level: "debug"` in config
- Check provider fingerprints in logs and metadata; a `403 InvalidObjectState` on a GET is either an object this proxy did not write or a wrap that does not authenticate under the fingerprint it names
- Use `TestContext` in tests for MinIO/proxy client comparison
- `optimizations.streaming_segment_size` (min 5MB, default 12MB) decides both the single-request PUT ceiling and the internal part size
- Sizes: stored and plaintext lengths convert both ways without a key (`CiphertextSize` / `PlaintextSize`). A stored length no chain of this format could have produced is an error, never a fabricated size
- Chunked encoding: the handlers route on `request.Parser.DecodedContentLength` (`X-Amz-Decoded-Content-Length` when present, else `Content-Length`; a routing hint, not an authoritative plaintext size). Where a mismatch must be an error — the producer's short-body check — use `PlaintextContentLength`, which reports whether the number really describes the plaintext
- Encryption happens exactly once, in the handler's call into `orchestration.Manager`; there is no second encryption layer

### Docker Development
`docker-compose.demo.yml` (started by `./start-demo.sh`) runs `minio`, the proxy
twice (services `s3-encryption-proxy` / `s3-encryption-proxy-tls`, containers
`proxy` on :8080 and `proxy-tls` on :8443, same Containerfile build),
`proxy-healthcheck`, one S3 explorer through the proxy (service
`s3-explorer-encrypted`, container `encrypted-manager`, :8081) and `vault`.
Container names go with `docker logs`, service names with `docker compose`. The
second, direct-to-MinIO explorer is commented out in the compose file. The MinIO
console on :9001 shows the raw stored objects. Vault runs in development mode and
no proxy code talks to it — it is there for the KMS work that is not built
(ADR 0005).

## Key Files for Context
- **Main entry**: `cmd/s3-encryption-proxy/main.go`
- **Config loading**: `internal/config/config.go` (`setDefaults`, `validate`, `validateEncryption`, `validateProvider`, `validateAESKey`, `validateOptimizations`, `validateS3Clients`, `validateMonitoring`)
- **Routes**: `internal/proxy/router.go`
- **Object handler**: `internal/proxy/handlers/object/operations.go` (GET/PUT/HEAD/DELETE, `putObjectAutoMultipart`) and `range.go`
- **Multipart handler**: `internal/proxy/handlers/multipart/` (`create.go`, `upload.go`, `complete.go`, `abort.go`)
- **Encryption entry points**: `internal/orchestration/segmented.go` and `segmented_session.go`
- **The codec**: `pkg/encryption/dataencryption/segmented_gcm.go` (+ `_io.go`, `_range.go`)
- **KEK registry**: `pkg/encryption/factory/factory.go`
- **Test helpers**: `test/integration/minio_test_helper.go`
- **Security design**: `SECURITY_ARCHITECTURE.md` (threat model, H-1..H-n hardening list)

# Encryption Manager

### 1. Core Manager
**File**: `internal/orchestration/manager.go`

**Responsibilities**:
- Construction: the provider manager, the metadata manager, the session table, the background sweeper
- Provider queries the handlers need: `IsExitProvider`, `GetLoadedProviders`, `GetMetadataKeyPrefix`
- `Shutdown(ctx)`: cancels the sweeper and waits for it, bounded by the context. Wired from `proxy.Server.Shutdown`, which `main.go` calls after the request drain — without that the goroutine outlived the process's own shutdown

The background sweeper runs when `optimizations.multipart_session_cleanup_interval > 0`
and calls `CleanupExpiredSegmentedSessions(multipart_session_max_age)`. It sweeps the
live session map; an unfinished client-driven upload therefore no longer holds its
buffered short part and its data key in the heap forever.

### 2. Provider Manager
**File**: `internal/orchestration/providers.go`

**Responsibilities**:
- KEK wrap/unwrap of the data key (`EncryptDEK`, `DecryptDEK`)
- Provider registration at startup: one `KeyEncryptor` per configured alias, registered with the factory under its fingerprint; a per-alias registry keeps `GetLoadedProviders` honest during a rotation, where two providers share a type
- Fingerprint tracking: `GetActiveFingerprint`, `GetActiveProviderAlias`, `GetActiveProviderAlgorithm`
- Provider selection for decryption: inside `DecryptDEK` via `factory.GetKeyEncryptor(fingerprint)`
- DEK cache: an LRU bounded at `dekCacheCapacity` (1024), key `fingerprint:objectKey:hex(SHA-256(encryptedDEK)[:8])` (`buildDEKCacheKey`). The wrapped DEK is in the key so a re-upload cannot serve a stale DEK (ADR 0002). The cache has a bound and **no expiry**, which is a prerequisite for any provider with a network round trip behind it (ADR 0005 D10). `DecryptDEK` returns the cache's own slice — callers must treat it as read-only

### 3. Segmented objects
**File**: `internal/orchestration/segmented.go`

**Write**:
- **`NewSegmentedWrite(objectKey, plaintext, plaintextLen, userMetadata)`**: one request. Returns the sealing body, the exact stored `ContentLength` and the complete metadata. Needs a known plaintext length; nothing beyond one segment is buffered
- **`NewSegmentedUpload(objectKey, userMetadata)`**: a multipart object. Its metadata goes into CreateMultipartUpload, so the object is readable the moment Complete returns. `SealPart(offset, plaintext, endsObject)` returns a `SealedPart` whose `Body()` seals as the backend pulls it and can be called again to re-seal for a retry (fresh nonces are safe: a segment is bound to its index, not to when it was written). `BodyWithTrailer(sum)` is for the last part of a layout the proxy chose; `Trailer(sum)` is the standalone record

**Read**:
- **`OpenSegmented(objectKey, metadata, body)`**: the whole object
- **`OpenSegmentedRange(objectKey, metadata, body, window)`**: exactly the window's plaintext; `body` must deliver the window's stored bytes and nothing else
- **`IsSegmentedObject(metadata)`**: the gate every read verb goes through first
- Both readers go through `codecFor`, which refuses a foreign object with `ErrForeignObject` and an unauthenticated wrap with `ErrKeyMaterialUnreadable`

**Keyless arithmetic** (ADR 0003 D12, ADR 0010): `PlanRange`, `PlaintextSize`, `PartStoredLen`.

### 4. Client-driven multipart sessions
**File**: `internal/orchestration/segmented_session.go`

The proxy owns the part layout it stores (ADR 0011): one client part becomes one backend part,
each part but the last covers whole segments, and the part table the session keeps is the
authority at Complete — not the list the client sends.

1. **`NewSegmentedSession` + `RegisterSegmentedSession`**: the session exists before the backend has given out an upload id, because its metadata has to go into CreateMultipartUpload
2. **`SealPart(partNumber, plaintext, shortBufferLimit)`**: a part that covers whole segments *and* clears the 5 MiB S3 minimum is sealed and returned for immediate upload. Anything else can only be an object's last part, so the session holds it (`pending`) until Complete and answers the client a derived ETag; a second such part is `ErrShortPartAlreadyBuffered`, one over the limit is `ErrShortPartBufferFull` (back pressure, the upload survives it). The inferred part size only ever takes a part that could be a *middle* part, because uploaders routinely deliver the short last part first
3. **`VerifyClientParts(claimed)`**: the client's list is checked against the table and a disagreement is reported, never silently overruled
4. **`Complete()`**: validates the table (contiguous from 1, uniform except for the last, segment-aligned, each at its computed offset), combines the parts' CRC32C in order, and returns the one part the proxy still has to upload — the short last part sealed with the trailer behind it, or the trailer as a part of its own. `ErrPartTableInvalid` for a layout that cannot be stored as a chain
5. **`CloseSegmentedSession`**: on Complete and on Abort. `CleanupExpiredSegmentedSessions` is the safety net for neither

### 5. Metadata Manager
**File**: `internal/orchestration/metadata.go`

`BuildSegmentedMetadata` writes the four keys; `GetEncryptedDEK`, `GetAlgorithm` and
`GetFingerprint` read them, prefixed only; `GetMetadataPrefix` is what the handlers compare
client headers against.


## Explicit Data Flow Documentation

### PUT Request Flow (Upload)
```
Client PUT /{bucket}/{key} → object.Handler.handlePutObject()
        ↓
  [x-amz-copy-source?] → refused: CopyObject is not supported with encryption
        ↓
  plaintextLen = request.Parser.DecodedContentLength(r)
                 (X-Amz-Decoded-Content-Length if present, else Content-Length; -1 = unknown)
        ↓
  [plaintextLen < 0 || > streaming_segment_size] → putObjectAutoMultipart (see below)
  [else]                                         → putObjectSegmented
        ↓
  putObjectSegmented:
    exit provider  → body and user metadata straight through, ContentLength = plaintextLen
    otherwise      → Manager.NewSegmentedWrite(key, body, plaintextLen, userMetadata)
                       ProviderManager.EncryptDEK (wrap the fresh data key)
                       MetadataManager.BuildSegmentedMetadata
                       body = codec.NewEncryptReader(plaintext)   # seals as the backend pulls
                       ContentLength = dataencryption.CiphertextSize(plaintextLen)
        ↓
  metadata: dek-algorithm (s3ep-gcm-seg-v2), encrypted-dek, kek-algorithm, kek-fingerprint
        ↓
  s3Backend.PutObject(sealing body, metadata) → S3 Storage
```

`putObjectAutoMultipart` is the internal multipart producer. The client never sees it, and
nothing runs after Complete — every metadata value exists before the first backend byte, so
the finished object is never rewritten (ADR 0011 D8, ADR 0024):

```
[exit provider] → passThrough = true: no NewSegmentedUpload, no SealPart, no
                  trailer, no proxy metadata. Everything below is the same — the
                  free list, the workers, the abort, the completion — only the
                  sealing step is skipped and the part body is buffer[:n]

Manager.NewSegmentedUpload(key, userMetadata)
        ↓
s3Backend.CreateMultipartUpload(Metadata = upload.Metadata(), entity headers)
        ↓
producer loop, one buffer at a time out of a free list of (concurrency + 1) buffers
  io.ReadFull(body, buffer)                       # buffer is streaming_segment_size
  upload.SealPart(offset, buffer[:n], eof)
  part.Body()  /  part.BodyWithTrailer(sum) on the last part
        ↓
jobs channel → up to multipart_upload_concurrency workers → s3Backend.UploadPart
  (the worker returns the buffer to the free list only after the backend is done with it,
   because the body seals straight out of it)
        ↓
short-body check: PlaintextContentLength vs bytes actually read — a client that hangs up
  mid-body must not commit a truncated object that verifies against its own trailer
        ↓
s3Backend.CompleteMultipartUpload
  any failure → AbortMultipartUpload on a cleanup context of its own
```

### Multipart PUT Flow (client-driven)
```
[exit provider] → no session is registered at all. Create sends the client's own user
   metadata, UploadPart stores the part unchanged (uploadPassThroughPart), Complete builds
   the completed-part list from the client's own list because the proxy owns no part table,
   and Abort forwards without needing a branch. The backend owns the part layout, so the
   64 KiB-multiple part rule does not apply

POST ?uploads          → multipart.CreateHandler
                           → Manager.NewSegmentedSession()   [data key, wrap, metadata]
                           → s3Backend.CreateMultipartUpload(Metadata = session metadata)
                           → Manager.RegisterSegmentedSession(uploadId, session)
PUT ?partNumber&uploadId → multipart.UploadHandler
                           → Parser.ReadBody (the part is buffered whole)
                           → Manager.SegmentedSession(uploadId)  [404 NoSuchUpload if gone]
                           → session.SealPart(...)
                               part != nil → s3Backend.UploadPart, session.RecordETag
                               part == nil → held for Complete, derived ETag answered
POST ?uploadId         → multipart.CompleteHandler
                           → session.VerifyClientParts(client's list)  [400 InvalidPart]
                           → session.Complete()                        [400 InvalidPart + abort]
                           → s3Backend.UploadPart(final: short last part + trailer, or trailer)
                           → s3Backend.CompleteMultipartUpload(session.PartNumbers())
                           → Manager.CloseSegmentedSession
DELETE ?uploadId       → multipart.AbortHandler
                           → s3Backend.AbortMultipartUpload (cleanup context)
                           → Manager.CloseSegmentedSession
```

### GET Request Flow (Download)
```
Client GET /{bucket}/{key} → object.Handler.handleGetObject()
        ↓
  [Range header?] → handleGetObjectRange()  (see below)
        ↓
  serveWholeObject:
    s3Backend.GetObject
        ↓
    [!IsSegmentedObject(metadata)] → exit provider: the stored bytes are served as
                                     they are; otherwise 403 InvalidObjectState
        ↓
    Manager.OpenSegmented(key, metadata, body)
      IsSegmentedObject?  no → 403 InvalidObjectState (ErrForeignObject)
      MetadataManager.GetEncryptedDEK / GetFingerprint
      ProviderManager.DecryptDEK (LRU cached)  → ErrWrappedDEKAuth → 403 InvalidObjectState
      dataencryption.NewCodec(dek, objectKey).NewReader(body)
        ↓
    Content-Length = orchestration.PlaintextSize(stored length)
    Metadata = Handler.cleanMetadata (drops <prefix>* keys)
        ↓
    response composed from an allowlist — no backend checksum header is ever emitted
        ↓
    copyWithPooledBuffer(w, plaintext)  then Close(): the reader verifies the trailer
      against what it produced, and reports it here
```

Ranged reads (`handleGetObjectRange`) are verified like any other read:

```
  [exit provider] → one HeadObject to decide per object (the one extra round trip
                    the exit provider costs, and the only provider that pays it):
                    not segmented → passThroughRange with the client's own Range header,
                    segmented     → on into the plan below
        ↓
  explicit "bytes=a-b"  → provisionalWindow(spec): plan as if every segment were full,
                          let the backend clamp, then re-plan against the real length
                          taken from the answer's Content-Range. No extra round trip
  suffix / open-ended   → one HeadObject first, because both are relative to the end
        ↓
  orchestration.PlanRange(start, length, totalPlaintext) → dataencryption.Window
        ↓
  s3Backend.GetObject(Range = computed ciphertext window)   # never the client's header
        ↓
  Manager.OpenSegmentedRange(key, metadata, io.LimitReader(body, window.CiphertextLength), window)
        ↓
  206 with the plaintext Content-Range; malformed or multi-range headers are ignored
  and the whole object is served (RFC 7233), an unsatisfiable one is 416 InvalidRange
```

HEAD takes the same gate: a non-segmented object under an encrypting provider is
`403 InvalidObjectState`, and the reported `Content-Length` is
`PlaintextSize(stored length)` — computed, never a round trip (ADR 0010). Under
the exit provider HEAD decides per object too: a segmented object reports the
plaintext size, a plain one the stored size, and neither is refused.

# MAIN GOALS
1. Ensure data is always encrypted at rest in S3
2. encrypt and decrypt data as fast as possible (performance is key)
3. use streaming to decrease memory footprint
4. keep the architecture as simple as possible (no unnecessary layers)

# WORK ORDER
1. use sha256 hashed to compare files in tests, no hex dumps


## Always pay attention to performance. If you notice an underperforming implementation, stop what you are doing and report the problem to me.

# WE DONT NEED BACKWARD COMPATIBILITY, remove unnecessary code
