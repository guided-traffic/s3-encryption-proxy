# S3 Encryption Proxy

[![Build Status](https://github.com/guided-traffic/s3-encryption-proxy/actions/workflows/release.yml/badge.svg)](https://github.com/guided-traffic/s3-encryption-proxy/actions)
[![Coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/guided-traffic/s3-encryption-proxy/main/.github/badges/coverage.json)](https://github.com/guided-traffic/s3-encryption-proxy)
[![Go Version](https://img.shields.io/github/go-mod/go-version/guided-traffic/s3-encryption-proxy?logo=go)](go.mod)
[![License](https://img.shields.io/badge/License-BSL%201.1-blue.svg)](LICENSE)

A Go-based proxy that provides transparent encryption/decryption for S3 objects with envelope encryption, streaming multipart uploads, and HMAC integrity verification.


## Overview

The S3 Encryption Proxy intercepts S3 API calls and automatically:
- **Encrypts** objects before storing them in S3 using envelope encryption (unique DEK per object)
- **Decrypts** objects when retrieving them from S3 with automatic provider detection
- **Detects** tampering with HMAC-SHA256 over the plaintext, in configurable modes — detection, not refusal, with the limits under [Integrity verification](#integrity-verification)
- **Maintains** S3 API compatibility with streaming support for large files, with the
  exceptions listed under [S3 API behaviour worth knowing](#s3-api-behaviour-worth-knowing)

**Key Features:**
- 🔒 **Transparent Encryption**: No client-side changes required
- 🔑 **Envelope Encryption**: one local AES-256 key encryption key, a unique AES data encryption key per object, and an authenticated wrap
- 🚀 **S3 API Compatible**: Works with existing S3 clients and tools
- 📤 **Streaming Uploads**: Memory-efficient multipart uploads with configurable buffer sizes
- 🛡️ **Integrity Verification**: HMAC-SHA256 over the plaintext, in off/lax/strict/hybrid modes — a detection signal today, not enforcement on the `aes-ctr` path ([details](#integrity-verification))
- 🔐 **Client Authentication**: AWS Signature V4 validation, both the `Authorization` header and the pre-signed query form
- 🌍 **Environment Variable Support**: Secrets via `${VAR}` references in config files
- 📦 **Production Ready**: Comprehensive testing, monitoring, and CI/CD

## Quick Start

### Local Demo (Fastest)

```bash
# Start MinIO, both S3 Encryption Proxy endpoints (HTTP and TLS) and the explorer.
# The first run generates the local test PKI in test/ssl-setup (needs openssl);
# those certificates are test-only and are never committed.
./start-demo.sh

# Proxy endpoint:     http://localhost:8080
# Proxy TLS endpoint: https://localhost:8443 (CA: test/ssl-setup/ca.crt)
# Metrics endpoint:   http://localhost:9090/metrics
# S3 Explorer through the proxy (decrypted view): http://localhost:8081
# MinIO Console, raw stored objects:              https://localhost:9001
#   (minioadmin / minioadmin123, self-signed cert)
#
# The second "direct" explorer is commented out in docker-compose.demo.yml;
# uncomment the s3-explorer-direct service to get it on port 8082.
```

### Docker (Recommended)

Start it with the AES provider:

```bash
# AES envelope encryption
docker run -p 8080:8080 -p 9090:9090 \
  -v $(pwd)/config:/config:ro \
  -e AES_ENCRYPTION_KEY=$(openssl rand -base64 32) \
  ghcr.io/guided-traffic/s3-encryption-proxy:latest \
  --config /config/aes-example.yaml
```

> The example configs under `config/` carry demo keys inline; the `${VAR}`
> references are commented out. Uncomment them before these environment
> variables have any effect.

### From Source

```bash
# Clone and build
git clone https://github.com/guided-traffic/s3-encryption-proxy.git
cd s3-encryption-proxy
make build

# Generate a key
make build-keygen && ./build/s3ep-keygen   # prints a base64 256-bit key
# openssl rand -base64 32                  # equivalent

# Update config file with the generated key
# Edit config/aes-example.yaml

# Run with configuration
./build/s3-encryption-proxy --config config/aes-example.yaml
```

### Client Usage

Use any S3 client with the proxy endpoint:

```bash
# AWS CLI
aws s3 --endpoint-url http://localhost:8080 cp file.txt s3://my-bucket/

# Python boto3
import boto3
s3 = boto3.client('s3', endpoint_url='http://localhost:8080')
s3.put_object(Bucket='my-bucket', Key='file.txt', Body=b'data')
```

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   S3 Client     │───►│ Encryption      │───►│   S3 Storage    │
│   (boto3, aws   │    │ Proxy           │    │   (AWS/MinIO)   │
│   cli, etc.)    │◄───│ (Go Service)    │◄───│                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                      ┌─────────────┐
                      │     KMS     │
                      │ (Optional)  │
                      └─────────────┘
```

## Encryption Providers

The S3 Encryption Proxy supports multiple encryption providers, each optimized for different use cases:

### 🔐 Provider Comparison

| Feature | **AES Envelope** | **None** |
|---------|------------------|----------|
| **Security Level** | 🟢 High | ❌ None |
| **Performance** | 🟢 Excellent | 🟢 Excellent |
| **KMS Dependency** | ✅ None | ✅ None |
| **Key Rotation** | 🔄 Manual, by adding the retired key as a second provider | ❌ N/A |
| **Unique DEK per Object** | ✅ Yes | ❌ N/A |
| **Setup Complexity** | 🟢 Simple | 🟢 Simple |
| **Production Ready** | ✅ Yes | ❌ Testing Only |

### 1. **AES Envelope Encryption**

**When to use:** every deployment that stores data. It is the only key provider
that encrypts.

```yaml
providers:
  - alias: "aes-envelope"
    type: "aes"
    description: "AES envelope encryption (auto-selects AES-CTR for multipart, AES-GCM for whole files)"
    config:
      aes_key: "base64-encoded-256-bit-key"   # base64 of exactly 32 random bytes
```

`aes_key` is base64 of exactly 32 random bytes. Nothing else is accepted: a
passphrase, a hex string that was base64-encoded, or a key with too few distinct
byte values is refused at startup, naming the field. Generate one with
`./build/s3ep-keygen` or `openssl rand -base64 32`.

The key is never used directly. Both the wrapping key and the published
`s3ep-kek-fingerprint` are derived from it with HKDF-SHA256 under separate
labels, and each data key is wrapped with AES-256-GCM under a per-wrap salt. So
the fingerprint reveals nothing about the key, and a wrapped data key that was
tampered with, or that belongs to another key, fails to unwrap instead of
yielding wrong key material.

**Advantages:**
- ⚡ High performance with envelope security
- 🟢 Simple setup and configuration
- 🏠 No external dependencies
- 🔑 Unique DEK per object, wrapped under an authenticated wrap
- 🔧 Minimal operational complexity

**Disadvantages:**
- 🔑 Single master key for all DEK encryption
- 🔄 Key compromise affects all data
- 📁 The key has to be delivered to the proxy and kept out of the repository

### 2. **None Provider (Testing Only)**

**When to use:** Development testing, performance benchmarking
```yaml
providers:
  - alias: "default"
    type: "none"
```

**Advantages:**
- ⚡ Maximum performance (no encryption)
- 🔧 Zero configuration required

**Disadvantages:**
- ❌ No encryption or security
- 🚫 Never use in production

## Multi-Provider Support

The proxy supports multiple providers simultaneously for migration and compatibility:

```yaml
encryption:
  # Active provider for new objects
  encryption_method_alias: "aes-current"

  # Integrity verification: off, lax, strict, hybrid
  # What each mode actually enforces: see "Integrity verification" below
  integrity_verification: "strict"

  # All providers for reading existing objects
  providers:
    - alias: "aes-current"
      type: "aes"
      description: "Current AES envelope encryption"
      config:
        aes_key: "XZmcGLpObUuGV8CFOmfLKs7rggrX2TwIk5/Lbt9Azl4="

    - alias: "aes-retired"
      type: "aes"
      description: "Retired key, kept so objects written under it stay readable"
      config:
        aes_key: "${S3EP_AES_KEY_RETIRED}"
```

Every listed provider can decrypt; only `encryption_method_alias` writes. The
provider for a read is chosen by the `s3ep-kek-fingerprint` stored on the object,
so rotating a key means adding the new one, pointing the alias at it, and keeping
the old one listed for as long as objects written under it exist.

## Key Generation Tools

### Generate AES Keys
```bash
# Build and run the AES key generator ([cmd/keygen](./cmd/keygen))
make build-keygen && ./build/s3ep-keygen
```

It prints a short banner around the key, so copy the key out rather than
capturing the whole output.

`openssl rand -base64 32` produces the same thing.

## Configuration

### Complete Configuration File Structure

Every value below is either the built-in default, marked `# default`, or an
example, marked `# example`. The defaults are set in
[`internal/config/config.go`](./internal/config/config.go) (`setDefaults`).

```yaml
# Server Configuration
bind_address: "0.0.0.0:8080"  # default
log_level: "info"             # default; debug, info, warn, error
log_format: "text"            # default; text or json
log_health_requests: false    # default
shutdown_timeout: 30          # seconds; 30 is used when unset or 0

# TLS listener of the proxy itself (optional)
tls:
  enabled: false                  # default
  cert_file: "/certs/public.crt"  # example; required when tls.enabled
  key_file: "/certs/private.key"  # example; required when tls.enabled

# S3 Backend Configuration
s3_backend:
  target_endpoint: "https://s3.amazonaws.com"  # example
  region: "us-east-1"               # default
  access_key_id: "your-access-key"  # example
  secret_key: "your-secret-key"     # example
  use_tls: true                     # default
  insecure_skip_verify: false       # default; development only

# S3 Client Authentication (Enterprise Security)
s3_clients:
  - type: "static"                  # example
    access_key_id: "client-user"    # example
    secret_key: "minimum-16-chars"  # example; minimum 16 characters
    description: "Client authentication"

# S3 Security Configuration
# Only max_clock_skew_seconds reaches any code path, and only on the pre-signed
# URL validator. The six keys below it are parsed and validated and then read by
# nothing - see "No rate limiting" under Security.
s3_security:
  max_clock_skew_seconds: 900        # default; pre-signed URL path only
  strict_signature_validation: false # accepted, not implemented; no default is
                                     # set, so the zero value false applies
  enable_rate_limiting: true         # default; accepted, not implemented
  max_requests_per_minute: 100       # default; accepted, not implemented
  enable_security_logging: true      # default; accepted, not implemented
  max_failed_attempts: 10            # default; accepted, not implemented
  unblock_ip_seconds: 60             # default; accepted, not implemented

# Monitoring
monitoring:
  enabled: false            # default
  bind_address: ":9090"     # default
  metrics_path: "/metrics"  # default
  pprof_enabled: false      # default; /debug/pprof on its OWN listener, not this one
  pprof_bind_address: "127.0.0.1:6060"  # default; must be loopback, anything else refuses to start

# License
license_file: "config/license.jwt"  # default

# Encryption Configuration
encryption:
  encryption_method_alias: "current-provider"  # example
  integrity_verification: "off"  # default; off, lax, strict, hybrid. What each mode
                                 # enforces today: see "Integrity verification"
  metadata_key_prefix: "s3ep-"   # default; must match ^[a-z0-9-]+$ or the proxy
                                 # refuses to start. An empty or non-lowercase
                                 # prefix used to be accepted and served
                                 # ciphertext as plaintext
  providers:
    - alias: "current-provider"  # example
      type: "aes"                # example; or "none"
      config: { ... }

# Performance Optimizations
optimizations:
  streaming_buffer_size: 65536          # default 64KB (4KB - 2MB)
  streaming_segment_size: 12582912      # default 12MB (5MB - 5GB)
  enable_adaptive_buffering: false      # default
  streaming_threshold: 5242880          # default 5MB; the 1MB minimum is only
                                        # enforced with enable_adaptive_buffering
  clean_aws_signature_v4_chunked: true  # default
  clean_http_transfer_chunked: true     # default
  multipart_upload_concurrency: 4       # default; parallel UploadPart calls (1 - 32)
  multipart_session_cleanup_interval: 300  # default; seconds (minimum 60)
  multipart_session_max_age: 3600          # default; seconds (minimum 900)
```

> **`s3_security` is mostly aspirational.** `strict_signature_validation`,
> `enable_rate_limiting`, `max_requests_per_minute`, `enable_security_logging`,
> `max_failed_attempts` and `unblock_ip_seconds` are accepted and validated by
> the config loader and then referenced by no code path, so setting them changes
> nothing. They are documented here only because the shipped example configs
> still contain them. Deleting them is decided in
> [ADR 0013](./docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md): a
> configuration key exists only if code reads it.

### Environment Variable References

Configuration values can reference environment variables using the `${VAR_NAME}` syntax. This avoids storing secrets directly in config files.

**Supported fields:**
- `s3_backend.access_key_id`, `s3_backend.secret_key`
- `s3_clients[].access_key_id`, `s3_clients[].secret_key`
- All string values in `encryption.providers[].config` (e.g., `aes_key`, `public_key_pem`, `private_key_pem`)

**Behavior:**
- Only `${VAR}` syntax is expanded (bare `$VAR` is **not** expanded — safe for passwords containing `$`)
- If a referenced variable is not set or empty, the proxy **refuses to start** with a clear error message
- Partial expansion works: `"prefix-${VAR}-suffix"`
- Values without `${...}` are used as-is (no change to existing configs)

**Example configuration:**
```yaml
s3_backend:
  access_key_id: "${S3_ACCESS_KEY_ID}"
  secret_key: "${S3_SECRET_KEY}"

s3_clients:
  - type: "static"
    access_key_id: "${CLIENT_ACCESS_KEY}"
    secret_key: "${CLIENT_SECRET_KEY}"

encryption:
  providers:
    - alias: "aes-envelope"
      type: "aes"
      config:
        aes_key: "${AES_ENCRYPTION_KEY}"
```

**Setting the variables:**
```bash
# S3 Backend credentials
export S3_ACCESS_KEY_ID="your-access-key"
export S3_SECRET_KEY="your-secret-key"

# AES key. s3ep-keygen prints a banner around the key, so take the key line only.
export AES_ENCRYPTION_KEY="$(./build/s3ep-keygen | sed -n 2p)"
```

### Configuration Examples

See complete examples in the `config/` directory:

#### AES Envelope Configuration (`config/aes-example.yaml`)
```yaml
encryption:
  encryption_method_alias: "aes-envelope"
  integrity_verification: "strict"
  providers:
    - alias: "aes-envelope"
      type: "aes"
      description: "AES envelope encryption (auto-selects AES-CTR for multipart, AES-GCM for whole files)"
      config:
        aes_key: "XZmcGLpObUuGV8CFOmfLKs7rggrX2TwIk5/Lbt9Azl4="
```

#### Multi-Provider Configuration (`config/multi-example.yaml`)
```yaml
encryption:
  encryption_method_alias: "aes-current"
  integrity_verification: "strict"
  providers:
    # Current encryption for new objects
    - alias: "aes-current"
      type: "aes"
      description: "Current AES envelope encryption"
      config:
        aes_key: "XZmcGLpObUuGV8CFOmfLKs7rggrX2TwIk5/Lbt9Azl4="

    # The retired key, still able to read what it wrote
    - alias: "aes-retired"
      type: "aes"
      description: "Retired key, kept for reading"
      config:
        aes_key: "${S3EP_AES_KEY_RETIRED}"
```

#### None Provider Configuration (`config/none-example.yaml`)
```yaml
encryption:
  encryption_method_alias: "default"
  integrity_verification: "lax"
  providers:
    - alias: "default"
      type: "none"
```

## Documentation

| Document | What it covers |
|---|---|
| **[SECURITY_ARCHITECTURE.md](./SECURITY_ARCHITECTURE.md)** | Trust boundaries, where keys and secrets live, what the proxy defends against and what it does not, residual risks and how to report a vulnerability |
| **[docs/architecture/ARCHITECTURE_ANALYSIS.md](./docs/architecture/ARCHITECTURE_ANALYSIS.md)** | Package layout and generated call graphs of the entrypoint, proxy and orchestration layers |
| **[docs/adr/](./docs/adr/)** | Architecture decision records: what was decided, why, what was rejected and what it costs. Start at [docs/adr/README.md](./docs/adr/README.md) |
| **[CONTRIBUTING.md](./CONTRIBUTING.md)** | How to contribute |
| **[CHANGELOG.md](./CHANGELOG.md)** | Release history |

The configuration reference above and
[S3 API behaviour worth knowing](#s3-api-behaviour-worth-knowing) below are the
current reference for operators.

## Deployment Options

### Docker

#### With Configuration File (Recommended)
```bash
# Build
docker build -t s3-encryption-proxy .

# Run with config file
docker run -d \
  -p 8080:8080 \
  -v $(pwd)/config:/config:ro \
  s3-encryption-proxy --config /config/aes-example.yaml
```

#### With Environment Variables
```bash
# AES Envelope
docker run -d \
  -p 8080:8080 \
  -e AES_ENCRYPTION_KEY="$(./build/s3ep-keygen | sed -n 2p)" \
  -v $(pwd)/config:/config:ro \
  s3-encryption-proxy --config /config/aes-example.yaml
```

> The shipped example configs carry their demo keys **inline** and have the
> `${VAR}` lines commented out, so passing these variables changes nothing until
> you edit the config to reference them (see
> [Environment Variable References](#environment-variable-references)).

### Docker Compose

```yaml
version: '3.8'
services:
  s3-encryption-proxy:
    image: ghcr.io/guided-traffic/s3-encryption-proxy:latest
    ports:
      - "8080:8080"
      - "9090:9090"  # Metrics
    environment:
      - AES_ENCRYPTION_KEY=${AES_ENCRYPTION_KEY}
    volumes:
      - ./config:/config:ro
    command: ["--config", "/config/aes-example.yaml"]
```

### Kubernetes with Helm

```bash
# The chart lives in deploy/helm/s3-encryption-proxy and ships values files for
# development, production and monitoring.
cd deploy/helm/s3-encryption-proxy
helm install s3-encryption-proxy . \
  --values values-production.yaml \
  --set-file config=../../../config/aes-example.yaml

# deploy/helm/install.sh is a wrapper around the same thing. It takes no
# positional argument, only --dry-run, --upgrade and --help.
```

> The chart has **no key for the master key**. The proxy configuration is
> rendered from the single `config` value straight into a ConfigMap, so a key
> written there is stored in clear text and readable by anyone with
> `get configmaps` in the namespace. Put the key in a Secret you manage yourself,
> reference it as `${S3EP_AES_KEY}` inside `config`, and inject the variable
> through the chart's `env` list with a `secretKeyRef`. See the chart's own
> [README](./deploy/helm/s3-encryption-proxy/README.md).

Example custom values (the shipped `values-production.yaml` sets different
numbers; this block shows the keys, not that file):

```yaml
replicaCount: 3

autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70

resources:
  limits:
    cpu: 500m
    memory: 512Mi
  requests:
    cpu: 100m
    memory: 128Mi

monitoring:
  enabled: true
  serviceMonitor:
    enabled: true
```

## S3 API behaviour worth knowing

The proxy is transparent for the operations clients actually use. The
behaviours below differ from a plain S3 endpoint in ways worth stating.

### Ranged reads (`Range: bytes=...`)

Supported for encrypted objects, which matters for any client that reads
objects in pieces rather than whole (kopia, and therefore Velero volume
backups, do exactly this).

| Stored algorithm | How the range is served | Cost |
|---|---|---|
| `aes-ctr` (objects at or above `streaming_threshold`, and all multipart) | The AES-CTR keystream is positioned at the range start and exactly the requested ciphertext window is fetched from the backend | One backend request, no read amplification |
| `aes-gcm` (objects below `streaming_threshold`) | The authentication tag covers the whole ciphertext, so the object is fetched and decrypted in full and the window is taken from the plaintext | Bounded by `streaming_threshold` |
| no `s3ep-*` metadata | The backend response is passed through undecrypted, **whatever the active provider is** — see the pass-through warning under [Security](#security) | One backend request |

The response is a normal `206 Partial Content` whose `Content-Range` describes
**plaintext** offsets and the plaintext total, so a client never has to know the
object is stored encrypted.

> **Integrity caveat.** The per-object HMAC (`encryption.integrity_verification`)
> covers the whole object and cannot be verified against a partial read. A
> ranged read of an `aes-ctr` object is therefore authenticated by the backend
> and by TLS, not by the proxy HMAC. Ranged reads of `aes-gcm` objects keep full
> verification, because the object is read in full anyway. Whole-object reads of
> `aes-ctr` objects are not refused on a mismatch either, for a different reason
> — see [Integrity verification](#integrity-verification) directly below. What
> this does and does not defend against is written out in
> [SECURITY_ARCHITECTURE.md](./SECURITY_ARCHITECTURE.md).

### Integrity verification

`encryption.integrity_verification` makes the proxy write an HMAC-SHA256 over the
**plaintext** of every object it encrypts — in every mode except `off` — and store
it as `s3ep-hmac`. What happens with that value on the way back depends on how the
object is stored, and the honest summary is short:

| Stored algorithm | What a tampered object gets you |
|---|---|
| `aes-gcm` | **Refused.** The GCM tag is checked inside the cipher before a single plaintext byte is returned, so the request is answered `500 DecryptionError` and nothing is served. This holds in every mode, `off` included |
| `aes-ctr` | **Delivered.** The whole tampered plaintext is written to the client behind `200 OK` with a matching `Content-Length`; the HMAC mismatch appears only as a proxy log line. `strict` does not change this |

Which objects are which is decided on upload. `aes-gcm` is used for a single `PUT`
whose body is smaller than `optimizations.streaming_threshold` (5 MiB by default),
or smaller than 5 MiB when integrity verification is on. `aes-ctr` is used for
everything else: objects at or above that boundary, uploads whose `Content-Length`
is unknown at any size, every multipart upload, and anything sent with the
`application/x-s3ep-force-aes-ctr` content type. For a Velero or kopia bucket that
is nearly every object.

Two independent defects cause the second row, both reproduced by tests in this
repository: the verifying reader releases the plaintext to the client before it
verifies, and the check is not wired in at all when the backend answers without a
`Content-Length` — a header the backend chooses. They are written out as
[H-5 in SECURITY_ARCHITECTURE.md](./SECURITY_ARCHITECTURE.md#h-5-integrity_verification-does-not-refuse-a-tampered-aes-ctr-object).

So set `integrity_verification: "strict"`, but set it for what it gives you today:

- the HMAC is written on upload, which is what the replacement storage format will
  verify against,
- a mismatch produces `HMAC validation FAILED` in the proxy log, which is a real
  detection signal worth alerting on,
- and `aes-gcm` objects are genuinely protected — by their own tag, not by this knob.

It does **not** give you a proxy that refuses tampered data. Until the storage
format is replaced by the authenticated segment chain of
[ADR 0003](./docs/adr/0003-objects-are-an-authenticated-segment-chain.md),
treat the backend as trusted infrastructure.

The four modes as the code implements them:

| Mode | What it does today |
|---|---|
| `off` | No HMAC is written and none is read. No detection signal at all |
| `lax` | HMAC written; a mismatch is logged and the data is delivered |
| `strict` | HMAC written; on `aes-ctr` a mismatch is logged and the data is delivered anyway, for the reasons above. On `aes-gcm` the tag has already refused the object before this runs |
| `hybrid` | As `strict`. The documented difference — an object with no `s3ep-hmac` is delivered rather than refused — is not a difference: a missing `s3ep-hmac` is skipped silently in `strict` as well |

### Pre-signed URLs

Query-string AWS Signature V4 is validated alongside the `Authorization` header
form, so URLs minted with `PresignGetObject` and friends work through the proxy.
`X-Amz-Expires` is mandatory and is bounded to the AWS maximum of 7 days, and
the signing time is subject to `s3_security.max_clock_skew_seconds`, so a URL
cannot extend its own lifetime.

### Object size

`HEAD` and `GET` report the **plaintext** size. The stored object is larger for
`aes-gcm` (a 12-byte nonce and a 16-byte tag), and reading it back directly from
the backend will show that difference.

### Operations the proxy does not implement

A sub-resource the proxy does not implement is answered with
`501 NotImplemented`. It used to fall through to the base operation for its HTTP
method instead, which is how `DELETE /bucket?encryption` **deleted the bucket**.
Only query parameters on an allowlist now reach the base bucket operations
([`internal/proxy/handlers/bucket/handler.go`](./internal/proxy/handlers/bucket/handler.go));
any other parameter is refused by name.

Four object sub-resources previously answered `200` for work they did wrongly or
not at all, and now answer `501 NotImplemented` as well:

| Request | What it used to do |
|---|---|
| `PUT /bucket/key?legal-hold` | Always set the hold **on**, whatever the body asked for, so a request to release one applied one |
| `GET /bucket/key?legal-hold` | Empty `200` with no document |
| `PUT`/`GET /bucket/key?retention` | Sent `Mode=Governance` with no retain-until date, or answered an empty `200` |
| `POST /bucket/key?select&select-type=2` | Ran a fabricated query, discarded the event stream, answered an empty `200` |
| `GET /bucket/key?attributes` | Returned the object **bytes** where `GetObjectAttributes` expects an XML document |

`CopyObject` (`PUT` with `x-amz-copy-source`) and `UploadPartCopy` answer
`422 NotSupportedWithEncryption`: a server-side copy runs inside the backend,
where the proxy cannot decrypt and re-encrypt. `UploadPartCopy` used to be
unreachable and its request stored an empty part; it is now routed and refused.

### Checksums

Client checksum headers (`Content-MD5`, `x-amz-checksum-*`) are **not** forwarded
to the backend. They describe the plaintext while the body the proxy uploads is
ciphertext, so a digest-checking backend would answer `BadDigest` for a perfectly
good upload. They are also **not verified by the proxy yet**, so sending one has
no effect today; closing that gap is the checksum verification decided in
[ADR 0012](./docs/adr/0012-client-checksums-are-verified-never-forwarded.md). Responses carry no backend
checksum header either, for the mirror-image reason: it would describe the stored
ciphertext, not the plaintext delivered. Object integrity is covered by the
per-object HMAC (`encryption.integrity_verification`) instead — which on the
`aes-ctr` path detects tampering without refusing it, see
[Integrity verification](#integrity-verification).

### Versioned buckets

`versionId` is forwarded to the backend on `GET`, ranged `GET`, `HEAD` and
`DELETE`, so a client addressing one specific version gets that version rather
than the current one. `x-amz-version-id` is returned on `GET`, `HEAD`, `PUT`,
`DELETE` and `CompleteMultipartUpload`, and `x-amz-delete-marker` on a `DELETE`
that created one. Note that an encrypted multipart or auto-multipart upload
writes a second version: the encryption metadata is attached by a self-copy after
the upload completes, and it is that version, whose id is the one returned, that
carries the metadata.

## Velero

The proxy serves any S3 client: aws cli, rclone, the SDKs, database backups
with CNPG Barman. Velero is one of them and has its own end-to-end suite in
[`test/e2e/velero/`](./test/e2e/velero/), run against the newest Velero in a
local `kind` cluster:

```bash
make e2e-up            # kind cluster + MinIO + CSI hostpath + proxy + Velero
make test-e2e-velero   # backup/restore scenarios, incl. encryption-at-rest checks
make e2e-down
```

Pinned versions live in
[`test/e2e/velero/versions.env`](./test/e2e/velero/versions.env) and are tracked
by Renovate as the group "Velero e2e".

Configuration notes for a real Velero deployment:

- Point the `BackupStorageLocation` at the proxy over **HTTPS** with
  `s3ForcePathStyle: "true"`. Modern AWS SDKs only emit their checksum-trailer
  request framing over TLS, and that framing is the one the proxy must decode.
- Set `publicUrl` if the `velero` CLI runs outside the cluster: pre-signed URLs
  are minted by the in-cluster server and fetched by the CLI.
- Nothing throttles Velero: the proxy performs **no request rate limiting** at
  all, so its backup bursts are not a concern. See
  [No rate limiting](#security) below for what that means for everyone else.
- Three open gaps decide how far this goes against a backend you do not control:
  a ranged read of an `aes-ctr` object is not covered by the proxy HMAC, and
  kopia reads its pack blobs exactly that way; a whole-object read of an
  `aes-ctr` object is not refused when the HMAC does not match, in any mode,
  `strict` included; and an object whose `s3ep-*` metadata has been stripped is
  served as-is. All three are written out as H-1, H-5 and H-6 in
  [SECURITY_ARCHITECTURE.md](./SECURITY_ARCHITECTURE.md). Until the storage
  format closes them, treat the backend as trusted infrastructure.

> **⚠️ Set the kopia repository password before the first backup.**
>
> Velero creates the secret `velero-repo-credentials` with the hardcoded
> password `static-passw0rd` if that secret does not already exist
> ([`pkg/repository/keys/keys.go`](https://github.com/velero-io/velero/blob/main/pkg/repository/keys/keys.go),
> [velero#6443](https://github.com/velero-io/velero/issues/6443),
> [velero#8137](https://github.com/velero-io/velero/issues/8137)). With that
> default, kopia's AES-GCM and its content HMACs are forgeable by anyone who can
> read the bucket - the repository salt sits in `kopia.repository`, in the same
> bucket as the data - so kopia's own layer provides neither confidentiality nor
> integrity against the storage backend. Velero's other objects (the resource
> tarballs, which contain Secrets, plus logs and results) are never encrypted by
> Velero at all. This proxy is the only real protection for both, and a strong
> repository password is what makes kopia a second layer instead of a decoration.
>
> Create the secret yourself, in the Velero namespace, **before the first
> backup**:
>
> ```bash
> kubectl -n velero create secret generic velero-repo-credentials \
>   --from-literal=repository-password="$(openssl rand -base64 32)"
> ```
>
> Velero writes the secret only when it is missing, and an existing kopia
> repository keeps the password it was created with, so this cannot be fixed
> after the fact. Store the value where you store your other break-glass
> secrets: without it, existing repositories cannot be read. The e2e suite in
> this repository does not set it and runs with the upstream default.

## Security

- **🔐 AES-GCM/AES-CTR Encryption**: Industry-standard authenticated encryption
- **🔑 Envelope Encryption**: KEK/DEK separation for maximum security
- **🛡️ Integrity Verification**: HMAC-SHA256 over the plaintext, in configurable modes (off, lax, strict, hybrid) — see [Integrity verification](#integrity-verification) for what each mode enforces
- **🔒 Client Authentication**: AWS Signature V4 validation, both the `Authorization` header and the pre-signed query form
- **⚠️ No rate limiting**: the proxy does **not** throttle requests. `s3_security.enable_rate_limiting` and `max_requests_per_minute` are parsed and validated by the config loader and read by no code path, so an unauthenticated caller is limited only by what is in front of the proxy. Put a real limiter there if you need one; shipping no rate limiting is a decision ([ADR 0014](./docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md)) and removing the misleading keys is decided in [ADR 0013](./docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md)
- **⚠️ Ranged reads**: a partial read of an `aes-ctr` object cannot be checked against the whole-object HMAC (see [Ranged reads](#ranged-reads-range-bytes) and [SECURITY_ARCHITECTURE.md](./SECURITY_ARCHITECTURE.md))
- **⚠️ A tampered `aes-ctr` object is delivered, not refused**: on the `aes-ctr` read path the HMAC is verified only after the last plaintext byte has been written to the client, and it is not verified at all when the backend answers without a `Content-Length`. No value of `integrity_verification`, `strict` included, refuses tampered data. `aes-gcm` objects are unaffected — their tag is checked inside the cipher before anything is served. Written out as H-5 in [SECURITY_ARCHITECTURE.md](./SECURITY_ARCHITECTURE.md); the fix is the authenticated segment chain of [ADR 0003](./docs/adr/0003-objects-are-an-authenticated-segment-chain.md)
- **⚠️ Objects without encryption metadata are served as-is**: `GET` and ranged `GET` return the stored bytes unchanged when an object carries no `s3ep-*` metadata, **even when the active provider encrypts** ([`operations.go:65`](./internal/proxy/handlers/object/operations.go#L65), [`range.go:142`](./internal/proxy/handlers/object/range.go#L142)). Anyone who can write to the backend bucket can substitute an object by stripping its metadata. Do not point an encrypting provider at a bucket that also holds objects the proxy did not write; failing closed is decided in [ADR 0003](./docs/adr/0003-objects-are-an-authenticated-segment-chain.md) and the defect is written out as H-6 in [SECURITY_ARCHITECTURE.md](./SECURITY_ARCHITECTURE.md)

See [SECURITY_ARCHITECTURE.md](./SECURITY_ARCHITECTURE.md) for the trust
boundaries, the secret flow, what the proxy does and does not defend against,
and the residual-risk checklist.

## Development

```bash
# Setup development environment
make deps && make tools

# Run tests
make test-unit                   # fast, no infrastructure
./start-demo.sh                  # MinIO + both proxy endpoints (HTTP and TLS)
make test-integration            # against the plain-HTTP proxy endpoint
make test-integration-tls        # against the TLS endpoint: the only way to
                                 # reach the SDK checksum-trailer request path
make test-integration-performance # isolated, so the numbers stay comparable

# Local performance baseline: records a run, never asserts. Compare two commits
# on the same machine; see test/perf/README.md
S3EP_PERF_LABEL="before" make perf-baseline
make perf-compare BEFORE=perf-baseline/<id> AFTER=perf-baseline/<id>

# Code quality checks
make quality

# Local development server
make dev
```

`make help` lists the common targets; the Makefile has more.

## License

See [LICENSE](./LICENSE) file for details.
