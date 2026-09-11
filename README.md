# S3 Encryption Proxy

[![Build Status](https://github.com/guided-traffic/s3-encryption-proxy/actions/workflows/release.yml/badge.svg)](https://github.com/guided-traffic/s3-encryption-proxy/actions)
[![Coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/guided-traffic/s3-encryption-proxy/main/.github/badges/coverage.json)](https://github.com/guided-traffic/s3-encryption-proxy)
[![Go Version](https://img.shields.io/github/go-mod/go-version/guided-traffic/s3-encryption-proxy?logo=go)](go.mod)
[![License](https://img.shields.io/badge/License-BSL%201.1-blue.svg)](LICENSE)

A Go-based proxy that provides transparent encryption/decryption for S3 objects with envelope encryption, streaming multipart uploads, and an authenticated storage format that refuses a modified object rather than reporting it.


## Overview

The S3 Encryption Proxy intercepts S3 API calls and automatically:
- **Encrypts** objects before storing them in S3 using envelope encryption (unique DEK per object)
- **Decrypts** objects when retrieving them from S3 with automatic provider detection
- **Refuses** a modified object: every 64 KiB segment carries its own AES-256-GCM tag, bound to its index and to the object key ([storage format](#storage-format-s3ep-gcm-seg-v2))
- **Maintains** S3 API compatibility with streaming support for large files, with the
  exceptions listed under [S3 API behaviour worth knowing](#s3-api-behaviour-worth-knowing)

**Key Features:**
- 🔒 **Transparent Encryption**: No client-side changes required
- 🔑 **Envelope Encryption**: one local AES-256 key encryption key, a unique AES data encryption key per object, and an authenticated wrap
- 🚀 **S3 API Compatible**: Works with existing S3 clients and tools
- 📤 **Streaming Uploads**: an upload is forwarded to the backend while it is still being received; memory is bounded by the configured part size, never by the object size
- 🛡️ **Authenticated Storage**: each segment and the trailer are sealed and bound to their position and object; a modified, reordered or truncated object fails the read ([details](#storage-format-s3ep-gcm-seg-v2))
- 🔐 **Client Authentication**: AWS Signature V4 validation, both the `Authorization` header and the pre-signed query form
- 🌍 **Environment Variable Support**: Secrets via `${VAR}` references in config files
- 📦 **Production Ready**: Comprehensive testing, monitoring, and CI/CD

## Quick Start

### Local Demo (Fastest)

```bash
# The demo runs the aes provider, so it needs a license: export S3EP_LICENSE_TOKEN
# before starting, or the proxy containers exit at startup (see License below).
#
# Start MinIO, both S3 Encryption Proxy endpoints (HTTP and TLS) and the explorer.
# The first run generates the local test PKI in test/ssl-setup and the local key
# encryption key into .env (both need openssl). Neither is committed: no usable
# key is tracked in this repository, so the generator runs on every bring-up and
# keeps what it already produced (ADR 0021).
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
  -e S3EP_LICENSE_TOKEN="$S3EP_LICENSE_TOKEN" \
  -e S3EP_AES_KEY=$(openssl rand -base64 32) \
  ghcr.io/guided-traffic/s3-encryption-proxy:latest \
  --config /config/aes-example.yaml
```

> The example configs under `config/` reference `${S3EP_AES_KEY}` and carry no
> key of their own (ADR 0021). An unset variable fails the configuration load
> and the proxy refuses to start.

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
                      ┌──────────────────┐
                      │  Local AES-256   │
                      │  key encryption  │
                      │  key (aes_key)   │
                      └──────────────────┘
```

The key encryption key is read from the configuration at startup and never
leaves the process. There is no KMS integration: wrapping a data key with a
remote key is specified and unbuilt
([ADR 0005](./docs/adr/0005-a-kms-key-is-a-provider.md)).

## Encryption Providers

Two key providers exist: `aes`, the only one that encrypts and the one local
key provider there is ([ADR 0004](./docs/adr/0004-one-local-key-provider.md)),
and `exit`, the provider you select to **leave the product**: it stores what the
client sends and keeps decrypting what this proxy encrypted earlier. Nothing else
is accepted: `type: "none"` is refused by name and pointed at `exit`, `type:
"tink"` is refused by name at startup, any other type is refused as unsupported,
and no KMS-backed provider is implemented — that is decided and unbuilt
([ADR 0005](./docs/adr/0005-a-kms-key-is-a-provider.md)).

### 🔐 Provider Comparison

| Feature | **AES Envelope** | **Exit** |
|---------|------------------|----------|
| **What it is for** | Every deployment that stores data | Leaving the product with your data readable |
| **New objects at rest** | 🟢 Sealed segment chain, AES-256-GCM | ❌ Stored exactly as the client sent them |
| **Reads what this proxy encrypted** | ✅ Yes | ✅ Yes, through the `aes` provider that still holds the key |
| **License required** | ✅ Yes | ❌ No |
| **Performance** | 🟢 Excellent | 🟢 Excellent |
| **KMS Dependency** | ✅ None | ✅ None |
| **Key Rotation** | 🔄 Manual, by adding the retired key as a second provider | ❌ N/A — it holds no key material |
| **Unique DEK per Object** | ✅ Yes | ❌ N/A — no new object gets one |
| **Setup Complexity** | 🟢 Simple | 🟢 Simple |

### 1. **AES Envelope Encryption**

**When to use:** every deployment that stores data. It is the only key provider
that encrypts.

```yaml
providers:
  - alias: "aes-envelope"
    type: "aes"
    description: "AES envelope encryption"
    config:
      aes_key: "base64-encoded-256-bit-key"   # base64 of exactly 32 random bytes
```

`aes_key` is base64 of exactly 32 random bytes. Nothing else is accepted: a
passphrase, a hex string that was base64-encoded, or a key with too few distinct
byte values is refused at startup, naming the field. Generate one with
`./build/s3ep-keygen` or `openssl rand -base64 32`.

The key is never used directly. Both the wrapping key and the published
`s3ep-kek-fingerprint` are derived from it with HKDF-SHA256 under separate
labels, and each data key is wrapped with AES-256-GCM under a per-wrap salt,
giving a 76-byte `salt ‖ nonce ‖ ciphertext ‖ tag`. So the fingerprint reveals
nothing about the key, and a wrapped data key that was tampered with, or that
belongs to another key, fails to unwrap instead of yielding wrong key material.

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

### 2. **Exit Provider (type `exit`)**

**When to use:** when you are leaving the product, or when a license has expired
and you need your data back. It is the one provider that needs **no license** —
that is the point of it: getting your data out must never depend on a licence
being valid. The decision behind it is
[ADR 0025](./docs/adr/0025-leaving-is-a-supported-mode.md).

```yaml
encryption:
  # The provider that writes. Pointed at the exit provider, every new object is
  # stored as the client sent it.
  encryption_method_alias: "exit"        # example
  providers:
    - alias: "exit"                      # example
      type: "exit"
      description: "Leaving the product: store plaintext, keep reading what is encrypted"

    # Keep the key that wrote the objects already in the bucket. The exit
    # provider holds no key material; this one does the unwrapping on read.
    - alias: "aes-current"               # example
      type: "aes"
      config:
        aes_key: "${S3EP_AES_KEY}"
```

**Keep the `aes` provider listed alongside it.** The provider for a read is
chosen by the `s3ep-kek-fingerprint` stored on the object, so the key that
wrapped an object has to stay configured or that object becomes permanently
unreadable. There is no background re-encryption: copying the data out through
the proxy is the migration.

What the exit provider does:

- **Every write path stores what the client sent.** A `PUT` that fits one
  request, a large or undeclared `PUT` that the proxy splits into an internal
  multipart upload, and a client's own multipart upload all pass the body
  through unchanged. No data key is drawn and no `s3ep-*` metadata is written,
  so the object at rest is your file — and anyone who can read the bucket can
  read it. The proxy says so in a warning line at every start.
- **Reads still decrypt.** An object this proxy encrypted before the switch is
  opened and verified exactly as it was before, segment by segment.
- **The decision is per object, not per provider.** A bucket on the way out
  legitimately holds both kinds, and `GET`, `HEAD` and a ranged `GET` each decide
  from the object's own metadata. Under an encrypting provider an object the
  proxy did not write is still refused rather than passed through
  ([ADR 0001](./docs/adr/0001-the-backend-is-hostile.md), and
  [Objects this proxy did not write](#objects-this-proxy-did-not-write)).
- **A listing reports the stored size verbatim** under this provider, for every
  entry — see [Object size](#object-size) for why that is the safe direction to
  be wrong in.
- **A ranged read costs one extra `HEAD`** under this provider, and only under
  this one — see [Ranged reads](#ranged-reads-range-bytes).

`type: "none"` no longer exists. A configuration that still names it is refused
at startup by name, with a message pointing at `exit` and at the provider that
has to stay beside it.

## Multi-Provider Support

The proxy supports multiple providers simultaneously for migration and compatibility:

```yaml
encryption:
  # Active provider for new objects
  encryption_method_alias: "aes-current"

  # All providers for reading existing objects
  providers:
    - alias: "aes-current"
      type: "aes"
      description: "Current AES envelope encryption"
      config:
        aes_key: "${S3EP_AES_KEY}"

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
shutdown_timeout: 30          # example, seconds; 30 applies when unset or 0
                              # The budget an in-flight transfer gets when the
                              # process is asked to stop, and the only
                              # server-side limit on a running transfer. The
                              # Helm chart derives terminationGracePeriodSeconds
                              # from it (this value plus five seconds).

# Listener budgets, in seconds. The two body budgets are 0 by default, which
# means no deadline: a transfer lasts as long as the client and the backend keep
# it going, whatever the object size and the link speed. Set one only if you
# want a ceiling and know your workload — any finite value makes the largest
# object you can move a function of the client's bandwidth.
read_timeout: 0               # default; 0 = no deadline on reading a request body
write_timeout: 0              # default; 0 = no deadline on writing a response body
# These two bound what is *not* a transfer and may not be 0; startup refuses it.
# read_header_timeout is the only limit on a connection that opens and never
# finishes its headers, and with both budgets above at 0 an idle_timeout of 0
# would hold a keep-alive connection forever.
read_header_timeout: 30       # default
idle_timeout: 60              # default

# TLS listener of the proxy itself (optional)
tls:
  enabled: false                  # default
  # Both are required when tls.enabled, and both files must exist or startup fails
  cert_file: "/certs/public.crt"  # example
  key_file: "/certs/private.key"  # example

# S3 Backend Configuration
s3_backend:
  # The scheme of target_endpoint decides whether the backend connection uses TLS,
  # and it is required: a scheme-less endpoint refuses the start. Under a provider
  # that encrypts, http:// refuses the start too — aws-sdk-go-v2 will not send an
  # unseekable streaming body without TLS, so every upload would fail at runtime.
  # The exit provider may use http://, because it stores what the client sent.
  target_endpoint: "https://s3.amazonaws.com"  # example
  region: "us-east-1"               # default
  access_key_id: "your-access-key"  # example
  secret_key: "your-secret-key"     # example
  insecure_skip_verify: false       # default; development only

# S3 Client Authentication. Required: without at least one client the proxy
# refuses to start, and there is no unauthenticated mode.
s3_clients:
  - type: "static"                  # example; the only accepted type
    access_key_id: "client-user"    # example; minimum 8 characters
    secret_key: "minimum-16-chars"  # example; minimum 16 characters
    description: "Client authentication"  # example; optional, never read

# S3 Security Configuration
s3_security:
  # Applies to both authentication forms. There is no value that switches the
  # check off: 0 is refused at startup rather than read as the default.
  max_clock_skew_seconds: 900  # default, 1 to 3600
  # Longest lifetime a pre-signed URL may declare. Deliberately below the S3
  # maximum of seven days, which is the hard cap this may not exceed: a leaked
  # URL is a bearer credential for exactly as long as it says.
  max_presign_expiry_seconds: 3600  # default, 1 to 604800

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
  # The provider that writes. Required as soon as providers are configured, and
  # it has to name one of them.
  encryption_method_alias: "current-provider"  # example
  # An empty or upper-case prefix would disable decryption on the way back, so
  # it is refused at startup rather than normalised.
  metadata_key_prefix: "s3ep-"   # default; must match ^[a-z0-9-]+$
  providers:
    - alias: "current-provider"  # example
      type: "aes"                # example; or "exit"
      config: { ... }

# Performance Optimizations
optimizations:
  # The size of one backend part, and the declared plaintext size above which a
  # PUT becomes an internal multipart upload. Must be a multiple of 64 KiB.
  streaming_segment_size: 12582912      # default 12MB (5MB - 5GB)
  # Parallel UploadPart calls.
  multipart_upload_concurrency: 4       # default, 1 - 32
  # What one client-driven upload may hold for a final part that does not cover
  # whole segments. These three keys decide peak resident memory; the terms are
  # in docs/developer/performance.md, "Memory, what one request costs".
  multipart_short_part_buffer_size: 67108864  # default 64MB, minimum 5MB
  multipart_session_cleanup_interval: 300  # default, seconds; 0 disables the sweeper
  # Measured from the start of the upload, not from its last part.
  multipart_session_max_age: 3600          # default, seconds
```

> **Body decoding carries no configuration.** aws-chunked framing is always
> decoded — the only thing switching it off could do is store chunk framing as
> object content — and nothing else reaches a handler still framed, because
> `net/http` strips `Transfer-Encoding` before the request is dispatched.

> **`optimizations.streaming_segment_size` must be a multiple of 64 KiB.** It is
> the plaintext one backend part carries, and a part that does not cover whole
> segments cannot sit in the middle of the chain. The default 12582912 (12 MiB)
> is a multiple; a value like `6000000` is not and the proxy refuses to start
> with `optimizations.streaming_segment_size: must be a multiple of 65536 bytes
> (64 KiB)`, rather than accepting it and failing every upload larger than one
> part ([ADR 0011](./docs/adr/0011-the-proxy-owns-the-part-layout.md)).

> **Session expiry drops the proxy's state, not the backend's upload.** A
> client-driven multipart upload whose session is older than
> `multipart_session_max_age` is forgotten by the sweeper — with its buffered
> final part and its data key — and a `CompleteMultipartUpload` afterwards
> answers `404 NoSuchUpload`. The backend upload it belonged to is not aborted,
> so its parts stay until a bucket lifecycle rule removes them. Raise the value
> for clients that hold an upload open for longer than an hour.

### Metrics

With `monitoring.enabled: true` the listener serves `metrics_path` in Prometheus
format. What it actually exports today:

| Metric | Type | Labels |
|---|---|---|
| `s3ep_requests_total` | counter | `method`, `endpoint`, `status_code` |
| `s3ep_request_duration_seconds` | histogram | `method`, `endpoint` |
| `s3ep_server_info` | gauge | `version`, `commit`, `build_time` |
| `s3ep_active_connections` | gauge | — |
| `s3ep_license_info` | gauge | `licensed_to`, `company`, `expires_at` |
| `s3ep_license_expiry_timestamp` | gauge | — |
| `s3ep_license_days_remaining` | gauge | — |

Every series carries `kubernetes_namespace`, `kubernetes_pod_name`,
`helm_release` and `helm_chart_version` when those are present in the
environment; the chart sets them. The three license gauges appear once a valid
license is loaded.

`endpoint` is the **route template** — `/{bucket}/{key:.*}`, not the path the
client requested — so no bucket or key name reaches a scrape.

The Go runtime and process collectors (`go_*`, `process_*`) are served as well.

> **Until 5.0.0 the two request metrics reached no scrape at all.** They were
> registered on the proxy's own registry while the endpoint served Prometheus's
> default one, so a proxy whose second goal is throughput exported no request
> rate and no latency; and the collectors that *were* served carried none of the
> Kubernetes labels, because those are attached only by the wrapper around that
> other registry. Labelled series were not exported, exported series were not
> labelled. There is one registry now.

Anything else an older dashboard charts — S3 operation counters, encryption or
HMAC timings, throughput gauges, provider info — no longer exists: those metrics
were removed together with the code that never observed them.

### Upgrading from 3.x or 4.x

Two breaks, both deliberate ([ADR 0017](./docs/adr/0017-stored-data-compatibility-is-not-owed.md)):

- **Objects written by an earlier release cannot be read.** They carry a
  different format id, so every `GET`, `HEAD` and ranged `GET` answers `403
  InvalidObjectState` rather than handing out bytes the proxy cannot
  authenticate. Copy the data out with the old version before upgrading.
- **`type: "none"` is gone; that provider is now `exit`.** A file that still
  says `none` is refused at startup by name. It is not a rename: the exit
  provider passes writes through on *every* write path, not only on a
  single-request `PUT`, and it keeps decrypting objects this proxy encrypted
  earlier — so the `aes` provider holding their key has to stay listed beside it
  ([Exit Provider](#2-exit-provider-type-exit)).
- **Configuration keys that no code read are gone, and a key the proxy does not
  define now refuses the start instead of being ignored.** That second half is
  what makes the first one safe: a removed key used to be dropped in silence, so
  a setting an operator believed was in force was not. Removed:
  `encryption.integrity_verification` and the four HMAC modes behind it,
  `optimizations.streaming_threshold`, `streaming_buffer_size` and
  `enable_adaptive_buffering`, `s3_backend.use_tls`, and every `s3_security` key
  except `max_clock_skew_seconds`. Integrity is no longer a setting: it is the
  storage format, on every read
  ([ADR 0013](./docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md)).
  The legacy top-level backend block — `target_endpoint`, `region`,
  `access_key_id`, `secret_key`, `use_tls`, `skip_ssl_verification` — is no
  longer migrated into `s3_backend`, and it is now named in the refusal rather
  than producing only `s3_backend.target_endpoint is required`.
  **Go through your configuration before upgrading:** a leftover key, or a
  misspelled one, stops the proxy at startup, and the error names it.
- **New refusals at startup, each naming the key.** A `target_endpoint` with no
  scheme, or `http://` under a provider that encrypts; an
  `encryption.metadata_key_prefix` shorter than four characters, not starting
  with a letter or digit, or not ending in `-`; a `max_clock_skew_seconds` or a
  `max_presign_expiry_seconds` of `0`; a `read_header_timeout` or `idle_timeout`
  of `0`.
- **`max_clock_skew_seconds` now governs both authentication forms.** It used to
  reach pre-signed URLs only, while the `Authorization`-header path — the one
  every AWS SDK client takes — compared against a fixed 900 seconds. If your
  configuration narrows the window, it now narrows for every request. **A client
  whose clock is off by more than the configured window starts being refused**,
  and every shipped example sets 300 seconds where the header path used to allow
  900. Check client clocks before upgrading.
- **Pre-signed URLs are bounded to one hour by default**
  (`s3_security.max_presign_expiry_seconds`), not to the S3 maximum of seven
  days. A client that mints longer URLs needs the setting raised.

### Environment Variable References

Configuration values can reference environment variables using the `${VAR_NAME}` syntax. This avoids storing secrets directly in config files.

**Supported fields:**
- `s3_backend.access_key_id`, `s3_backend.secret_key`
- `s3_clients[].access_key_id`, `s3_clients[].secret_key`
- All string values in `encryption.providers[].config` — for the `aes` provider that is `aes_key`

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
        aes_key: "${S3EP_AES_KEY}"
```

**Setting the variables:**
```bash
# S3 Backend credentials
export S3_ACCESS_KEY_ID="your-access-key"
export S3_SECRET_KEY="your-secret-key"

# AES key. s3ep-keygen prints a banner around the key, so take the key line only.
export S3EP_AES_KEY="$(./build/s3ep-keygen | sed -n 2p)"
```

### Configuration Examples

Complete files live in the `config/` directory: `aes-example.yaml` and
`aes-tls-example.yaml` (the same setup with the proxy's own TLS listener),
`multi-example.yaml` for key rotation, and `exit-example.yaml` for the exit
provider. The encryption block of each:

#### AES Envelope Configuration (`config/aes-example.yaml`)
```yaml
encryption:
  encryption_method_alias: "aes-envelope"
  providers:
    - alias: "aes-envelope"
      type: "aes"
      description: "AES envelope encryption"
      config:
        aes_key: "${S3EP_AES_KEY}"
```

#### Multi-Provider Configuration (`config/multi-example.yaml`)
```yaml
encryption:
  encryption_method_alias: "aes-current"
  providers:
    # Current encryption for new objects
    - alias: "aes-current"
      type: "aes"
      description: "Current AES envelope encryption"
      config:
        aes_key: "${S3EP_AES_KEY}"

    # The retired key, still able to read what it wrote
    - alias: "aes-previous"
      type: "aes"
      description: "Retired key, kept so objects written under it stay readable"
      config:
        aes_key: "${S3EP_AES_KEY_RETIRED}"
```

#### Exit Provider Configuration (`config/exit-example.yaml`)
```yaml
encryption:
  # Active: stores what the client sends, no data key, no s3ep-* metadata
  encryption_method_alias: "exit"
  providers:
    - alias: "exit"
      type: "exit"
      description: "Stores what the client sends; holds no key material"

    # Not active, never writes. Registered so that objects encrypted before the
    # switch are still decrypted: an object names the key that wrapped it in its
    # own s3ep-kek-fingerprint metadata.
    - alias: "aes-previous"
      type: "aes"
      description: "The key the objects already in the bucket were written with"
      config:
        aes_key: "${S3EP_AES_KEY}"
```

The exit provider is the one type the startup license gate admits without a
license, because the gate looks only at the active provider. That is the point:
getting the data out must not depend on a valid license.

> No usable key is tracked in this repository (ADR 0021). Every example above
> references `${S3EP_AES_KEY}`; `scripts/gen-keys.sh` generates one into the
> ignored `.env` file, and `./start-demo.sh` calls it. An unset variable fails
> the configuration load and the proxy refuses to start — there is no default
> key and no fallback.

## Documentation

| Document | What it covers |
|---|---|
| **[SECURITY_ARCHITECTURE.md](./SECURITY_ARCHITECTURE.md)** | Trust boundaries, where keys and secrets live, what the proxy defends against and what it does not, residual risks and how to report a vulnerability |
| **[docs/developer/](./docs/developer/)** | Working on the code: package map, the storage format and its invariants, the request paths, multipart, error conventions, the test layers and how to measure performance |
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
# Build. The build file is named Containerfile, so it has to be named too.
docker build -f Containerfile -t s3-encryption-proxy .

# Run with config file
docker run -d \
  -p 8080:8080 \
  -e S3EP_LICENSE_TOKEN="$S3EP_LICENSE_TOKEN" \
  -v $(pwd)/config:/config:ro \
  s3-encryption-proxy --config /config/aes-example.yaml
```

#### With Environment Variables
```bash
# AES Envelope
docker run -d \
  -p 8080:8080 \
  -e S3EP_LICENSE_TOKEN="$S3EP_LICENSE_TOKEN" \
  -e S3EP_AES_KEY="$(./build/s3ep-keygen | sed -n 2p)" \
  -v $(pwd)/config:/config:ro \
  s3-encryption-proxy --config /config/aes-example.yaml
```

> The shipped example configs reference `${S3EP_AES_KEY}` and carry no key of
> their own, so this variable is what makes them work (see
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
      - S3EP_LICENSE_TOKEN=${S3EP_LICENSE_TOKEN}
      - S3EP_AES_KEY=${S3EP_AES_KEY}
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
> through the chart's `env` list with a `secretKeyRef` — the shipped
> `values-production.yaml` is written that way and only the secret name has to
> change. The license is different: `license.existingSecret` (or `license.jwt`)
> mounts it and points `license_file` at the mount. See the chart's own
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

A ranged read fetches only the segments its window covers — at most one segment
of over-read at each end — and opens each of them under its own tag, so a partial
read is authenticated exactly like a whole one. An object this proxy did not
write is refused rather than passed through; see
[Objects this proxy did not write](#objects-this-proxy-did-not-write).

The response is a normal `206 Partial Content` whose `Content-Range` describes
**plaintext** offsets and the plaintext total, so a client never has to know the
object is stored encrypted.

An explicit `bytes=a-b` costs one backend request. A suffix range (`bytes=-500`)
and an open-ended one (`bytes=100-`) are relative to the end of the object, so
the proxy needs its length first and they cost one `HEAD` ahead of the `GET`.

**Under the exit provider every range costs one extra `HEAD`**, whatever its
form. The stored window a range translates to depends on whether the object is
one this proxy encrypted, and under that provider a bucket holds both kinds, so
the proxy has to ask before it can request the window. Under an encrypting
provider it never asks: every readable object is a sealed one, the window follows
from the request, and an object that turns out to be foreign is refused when its
metadata arrives with the `GET`.

A range carries no `x-amz-checksum-*` header: the object's sealed checksum
describes the whole plaintext, and a checksum over part of it is a different
value the proxy does not compute. A whole-object `GET` and a `HEAD` do carry it —
see [What a read costs](#what-a-read-costs) below.

### What a read costs

A **whole-object `GET`** reads the object's **end first**: one request for the
last 64 KiB and the trailer, then — only if the object is larger than that — a
second for the remainder, carrying `If-Match` on the first answer's `ETag`. Every
stored byte is fetched exactly once, an object of at most 64 KiB costs one backend
request, and anything larger costs two.

What the order buys is what the proxy can say before it answers: the
`Content-Length` of a whole-object `GET` and of a `HEAD` is the plaintext length
**the object's own trailer authenticates**, not a number the backend reported
about itself, and both verbs answer with `x-amz-checksum-crc32c` over the
plaintext. It also moves three failures from the middle of a download to before
it starts — a damaged trailer, a truncated object, and a stored length the trailer
contradicts are `403 InvalidObjectState` with nothing written, where they used to
arrive as a body that stopped early. A fault inside a segment is still found while
the body is flowing, and there the body is cut off: a response that has already
answered `200` cannot un-answer it.

A **`HEAD`** costs one backend request, as it always did — it reads the object's
last 40 bytes rather than asking for its metadata.

**Under the exit provider a whole-object read stays a single forward pass**, and
carries neither the authenticated length nor the checksum header. A bucket on the
way out holds objects this proxy never encrypted, those have no trailer at all,
and telling the two apart would cost a `HEAD` on every read of the provider whose
job is getting the data out
([ADR 0025](./docs/adr/0025-leaving-is-a-supported-mode.md)).

### Storage format (`s3ep-gcm-seg-v2`)

Every object this proxy encrypts is stored in one format, whichever write path
produced it. The plaintext is cut into 64 KiB segments; each segment is sealed
on its own with AES-256-GCM under a 12-byte nonce and a 16-byte tag, and the
object ends with a 40-byte trailer carrying the plaintext length and a CRC32C
over the plaintext, sealed the same way.

Each seal's additional data binds the segment to **its index within the object**
and to **the object key the client used**. A segment therefore cannot be moved
within an object, swapped between objects, duplicated, dropped or reordered
without the read failing, and an object copied to another name inside the
backend is undecryptable under that name — which is why server-side copy is
refused rather than forwarded.

The stored length is a pure function of the plaintext length, so the proxy
reports plaintext sizes on `HEAD` and `GET` and finds any segment arithmetically,
with nothing about the layout stored where a backend could edit it:

```
stored = plaintext + ceil(plaintext / 65536) * 28 + 40
```

What a client sees when a stored object has been modified: the proxy has already
answered `200 OK` by the time it opens the first segment, so it aborts the
response body, and the client's HTTP stack reports an unexpected EOF on a body
cut short at a segment boundary. Every byte it did receive carried its own tag.
A modified object is never delivered whole.

### Object metadata

Four keys are written, and they describe how the data key was wrapped — never
the data itself, which is sealed inside the object where the backend cannot edit
it:

| Key | Value |
|---|---|
| `s3ep-dek-algorithm` | Always `s3ep-gcm-seg-v2`, the format id |
| `s3ep-encrypted-dek` | The object's data key, wrapped under the KEK |
| `s3ep-kek-algorithm` | The key provider type that wrapped it, e.g. `aes` |
| `s3ep-kek-fingerprint` | Which key wrapped it, so a retired key still reads what it wrote |

The prefix is `encryption.metadata_key_prefix`; the four names after it are
fixed. No nonce and no HMAC is stored beside the object: the nonces live in the
segments, and the integrity value is the tag on each of them. That namespace
belongs to the proxy alone — an `x-amz-meta-` header a client sends inside it is
**refused** with `400 InvalidArgument` naming the key, on `PUT` and on
`CreateMultipartUpload` alike, and every key carrying the prefix is stripped from
`GET` and `HEAD` responses on the way out. Nothing is stored by a refused
request, and a client that legitimately uses such a key renames it.

All four exist before the first backend byte is sent on every write path, so a
completed object is never rewritten afterwards to attach metadata.

### Objects this proxy did not write

Under an encrypting provider, an object that carries no proxy metadata, or whose
`s3ep-dek-algorithm` names another format, is **refused** — on `GET`, `HEAD` and
ranged `GET` alike. Objects written by an earlier release of this proxy fall
under exactly that rule: their algorithm is `aes-gcm` or `aes-ctr`, not
`s3ep-gcm-seg-v2`, and they are refused rather than served
([Upgrading from 3.x or 4.x](#upgrading-from-3x-or-4x)).

| Condition | Answer |
|---|---|
| No proxy metadata, or a foreign format id | `403` `InvalidObjectState`, *Object is not encrypted by this proxy* |
| The wrapped data key fails its authentication tag | `403` `InvalidObjectState`, *Object key material failed authentication* |
| `s3ep-kek-fingerprint` names a key this proxy does not have configured | `500` `DecryptionError` — the object is intact, the key is missing |

Under an encrypting provider there is no mode in which such an object is handed
to a client.

**Under the exit provider only the first row changes.** The decision is taken per
object, from that object's own metadata: an object carrying no proxy metadata, or
naming a format this proxy does not read, is not one of its own and is served
verbatim — that is what the provider is for. An object that does carry the
current format's metadata is decrypted, and the other two rows still refuse it:
a wrapped data key that fails its authentication tag is refused, and a
fingerprint naming a key that is no longer configured is an error, not a
pass-through. A backend cannot talk its way past the key by relabelling an object
([ADR 0001](./docs/adr/0001-the-backend-is-hostile.md)).

The third row is the one an operator causes: dropping a retired key from
`encryption.providers` makes every object written under it unreadable while it
is still there. Keep the key listed as long as its objects exist.

The two refusals are `4xx` deliberately: the state is permanent, and a `5xx`
would have a client SDK retry a read that cannot succeed and let a client file a
corrupted object as a passing outage.

### Write paths

All three write paths produce identical bytes, so nothing about a stored object
says how it was uploaded:

| Upload | Path |
|---|---|
| `PUT` with a declared length at or below `optimizations.streaming_segment_size` | One `PutObject`; the body seals as the backend reads it |
| `PUT` with no declared length, or above that size | An internal multipart upload with parts of that size, sent while the body is still arriving |
| A client's own multipart upload | One client part becomes one backend part; the object's closing record is written at `CompleteMultipartUpload` |

**Under the exit provider all three store what the client sent.** The routing is
unchanged — a large or undeclared `PUT` still becomes an internal multipart
upload — but no path seals anything, none draws a data key, and none writes
`s3ep-*` metadata. On a client's own upload the proxy keeps no part table either:
the list the client sends at `CompleteMultipartUpload` is the object, and the
backend is what checks it, so the part-size rule below does not apply and the
backend's own rules are the ones a client meets.

**A client-driven multipart upload sizes its parts, within one rule:** every
part except the last has to cover whole 64 KiB segments and clear S3's own 5 MiB
minimum. The usual part sizes satisfy it — 5 MiB, 8 MiB and 16 MiB are all
multiples of 64 KiB — but a client that picks something like 5,000,000 bytes
gets `400 EntityTooSmall` on its second part. The last part may be any size: it
is held until `CompleteMultipartUpload`, which uploads it with the trailer
behind it, so that one part sits in the proxy's memory until then, and a client
holding more than `optimizations.multipart_short_part_buffer_size` there is
answered `503 SlowDown` and retries. A completion list that disagrees with what was uploaded is answered
`400 InvalidPart`, and the upload stays open. **Part numbers run 1 to 9999**, not
to S3's 10000: the object's closing record needs a part number of its own
whenever the client's last part is one the proxy stored where it arrived, and
part 10000 is refused with `400 InvalidArgument` when it is sent rather than at
completion, after every byte has been transferred
([ADR 0011](./docs/adr/0011-the-proxy-owns-the-part-layout.md)).

### Pre-signed URLs

Query-string AWS Signature V4 is validated alongside the `Authorization` header
form, so URLs minted with `PresignGetObject` and friends work through the proxy.
`X-Amz-Expires` is mandatory and is bounded by
`s3_security.max_presign_expiry_seconds`, **one hour by default**. That is a
deliberate deviation from the S3 maximum of seven days, which remains the ceiling
the setting may not exceed: a pre-signed URL is a bearer credential for exactly
as long as it claims, so the shipped default is the shortest window that serves
the clients this proxy is tested against. Raise it if yours mint longer URLs.

The signing time is subject to `s3_security.max_clock_skew_seconds`, so a URL
cannot extend its own lifetime by claiming to have been signed in the future.
That same tolerance is added to the end of the window, so a URL is accepted for
`X-Amz-Expires` plus the skew — and that tolerance now governs the
`Authorization`-header form as well, which used to use a fixed 900 seconds
whatever the configuration said.

### Object size

`HEAD` and `GET` report the **plaintext** size. The stored object is larger by
28 bytes per 64 KiB segment plus the 40-byte trailer, and reading it back
directly from the backend will show that difference.

**Listings report the plaintext size too.** `ListObjectsV2` and `ListObjects`
compute it from the stored size, which is arithmetic the proxy controls: no
metadata is read and no extra request is made, so a listing of a thousand keys
costs a thousand divisions and nothing else
([ADR 0010](./docs/adr/0010-sizes-and-listings-describe-the-plaintext.md)).
`HEAD`, `GET` and a listing therefore agree.

**Under the exit provider a listing reports the stored size verbatim**, for every
entry, and does not invert the arithmetic. Such a bucket holds both kinds of
object and a listing has no metadata to tell them apart; inverting would be exact
for the encrypted ones and would *under*-report every plain object whose stored
size happens to look like one this proxy could have written. Over-reporting a
size costs a re-transfer. Under-reporting one tells a sync client the remote copy
is shorter than its local file, and it uploads over the remote — so the error is
kept deliberately on the harmless side. `HEAD` is exact either way: it reads the
object's metadata and reports the plaintext size for an encrypted object and the
stored size for a plain one.

**One deliberate inexactness.** In a bucket that also holds objects this proxy
did not write — foreign objects, or content uploaded straight to the backend —
a listing entry for such an object is short by the segment overhead whenever its
stored size happens to look like one the proxy could have written: 40 bytes plus
28 per 64 KiB. The listing cannot tell those entries apart without a `HEAD` per
key, and that round trip is the thing this design exists to avoid. It costs
nothing in practice: such an object is refused on read anyway (see
[Objects this proxy did not write](#objects-this-proxy-did-not-write)), so a
client cannot act on the size it read.

### Listing parameters

| Parameter | Behaviour |
|---|---|
| `prefix`, `delimiter`, `marker`, `continuation-token` | forwarded |
| `start-after`, `fetch-owner` | forwarded (V2) |
| `encoding-type` | the proxy always requests URL encoding from the backend and decodes it; `encoding-type=url` re-encodes the answer and echoes `<EncodingType>url</EncodingType>` |
| `max-keys` absent | the backend default applies |
| `max-keys` 0 to 1000 | forwarded verbatim, `0` included |
| `max-keys` above 1000 | clamped to 1000 |
| `max-keys` negative or not an integer | `400 InvalidArgument` |

The clamp is the proxy's own: MinIO does not clamp, so the same request answers
at most 1000 keys through the proxy and possibly more straight from the backend.

`<Owner>` names the client that made the request — the access key it
authenticated with — never the account the proxy uses against the backend
([ADR 0008](./docs/adr/0008-every-response-describes-the-proxy.md)). It appears
on a V2 listing only when `fetch-owner=true` is set, and on a V1 listing always.

No `<ChecksumAlgorithm>` or `<ChecksumType>` element is ever emitted: a backend
checksum describes the ciphertext, and the object's own sealed checksum can only
be read by opening its trailer, which a listing will not do per entry. A `GET` or
a `HEAD` of one object does report it, as `x-amz-checksum-crc32c`.

`<ETag>` is the backend's, which is an entity tag over the ciphertext and
therefore not a plaintext MD5. That is consistent across `GET`, `HEAD` and the
listing, and it is a property of the storage format rather than of the listing.

### `HeadBucket`

`HEAD /{bucket}` calls the backend's `HeadBucket`. It answers `x-amz-bucket-region`
from the backend when the backend sends one, and otherwise with the configured
`s3_backend.region` — **the region a client reads here is the proxy's statement,
not the backend's**, because MinIO sends no region header at all.

### Storage headers on upload

The proxy's mandate is the confidentiality of object **content**. A header that
does not touch content is the client's business and is carried to the backend
unchanged, on all three upload paths — a single-request `PUT`, the proxy's
internal multipart producer and client-driven `CreateMultipartUpload`
([ADR 0007](./docs/adr/0007-forward-it-or-refuse-it.md) D3). They used to be
accepted, discarded and answered `200 OK`.

| Header | Behaviour | What it means through this proxy |
|---|---|---|
| `x-amz-server-side-encryption`, `...-aws-kms-key-id` | forwarded | the **backend** encrypts its own copy of the ciphertext. It is not the proxy's encryption, and the response header the backend produces is not a statement about it |
| `x-amz-server-side-encryption-customer-*` (SSE-C) | `501 NotImplemented`, naming the header | no read path carries the customer key, so an object written this way could never be read back. Refused on every verb until the key travels on all of them ([ADR 0007](./docs/adr/0007-forward-it-or-refuse-it.md) D6) |
| `x-amz-tagging` | forwarded | tag keys and values are stored **in the clear** on the ciphertext object. For a backup bucket that is a labelled index of what each object is |
| `x-amz-storage-class` | forwarded | a tier the backend applies. An object written into an archive tier still appears in a listing and then fails on `GET` |
| `x-amz-acl`, `x-amz-grant-*` | forwarded | the grant acts on the **ciphertext** object. `public-read` exposes its bytes, its size, its timing and its `s3ep-*` metadata to everyone the grant names |
| `x-amz-object-lock-mode`, `-retain-until-date`, `-legal-hold` | forwarded | WORM on the ciphertext object. It defends against a **compromised credential**, which is the common ransomware path for a backup bucket. It defends against nothing at a compromised backend, which can ignore its own lock |
| `x-amz-website-redirect-location` | forwarded | stored as the backend stores it |
| `Content-Type`, `Cache-Control`, `Content-Disposition`, `Content-Encoding`, `Content-Language`, `Expires` | forwarded | they describe the plaintext, so they survive encryption unchanged and `GET` and `HEAD` return them |
| `x-amz-expected-bucket-owner` | forwarded, **on every verb** | the guard acts where it can be answered: the backend fails the call `403 AccessDenied` when the bucket belongs to another account. Not limited to uploads — every backend call the proxy makes carries it ([ADR 0007](./docs/adr/0007-forward-it-or-refuse-it.md) D14) |
| `x-amz-bypass-governance-retention`, `x-amz-mfa` | **dropped** | still not forwarded on the delete paths. Without them the backend refuses the delete, so a delete that needs one fails rather than succeeding unguarded |

**`x-amz-expected-bucket-owner` before 5.0.0.** Only `DeleteBucket` honoured it.
Every other verb read it, dropped it and answered success — so a client that set
it on `PUT`, `DeleteObject` or `DeleteObjects` believed the bucket ownership had
been checked and it had not. If a deployment relies on that header, the guard now
takes effect: a request against a bucket owned by a different account starts
answering `403 AccessDenied` where it used to succeed. That is the intended
behaviour and the reason the change is in a major.

`x-amz-object-lock-retain-until-date` that is not an RFC 3339 timestamp, and an
`Expires` that is not an HTTP-date, answer `400 InvalidArgument` naming the
header. Storing the object without the header the client asked for is the silent
success the decision exists to forbid.

`Content-Encoding` loses an `aws-chunked` token: that describes the request
framing, which the proxy has already decoded, so storing it would mislabel the
object. A `PUT` with no `Content-Type` leaves the field unset rather than storing
an empty one, so the backend applies its own default.

None of this changes the proxy's own encryption. The object body is an
authenticated segment chain either way.

### `<Location>` in a completed multipart upload

`CompleteMultipartUploadResult` carries a `<Location>` naming **the proxy**, never
the backend: the backend's own value names the internal storage endpoint and is
text that endpoint controls. It is built from `X-Forwarded-Proto` and
`X-Forwarded-Host` when they are present — the first value of each — and
otherwise from the connection the proxy sees and the `Host` header. Behind a
TLS-terminating ingress that is the difference between `https://` and a
`http://` the client never used.

No trusted-proxy list guards those two headers, deliberately: the element is
reflected only to the sender of the request and drives no decision inside the
proxy, so a client that forges them misleads only itself.

### Conditional requests

`If-Match`, `If-None-Match`, `If-Modified-Since` and `If-Unmodified-Since` are
forwarded to the backend on `GET`, ranged `GET` and `HEAD`, and `If-Match` and
`If-None-Match` on `PUT` and `CompleteMultipartUpload`
([ADR 0007](./docs/adr/0007-forward-it-or-refuse-it.md) D7). `GET` and `HEAD`
give the same answer to the same precondition, and `If-None-Match: *` against an
existing key answers `412 PreconditionFailed` instead of overwriting the object.

Until 5.0.0 only the two entity-tag headers were carried, and only on a `GET`:
`HEAD` carried none, so it answered `200` where `GET` answered `304`; a
revalidating `GET` with `If-Modified-Since` fetched, decrypted and transferred
the whole object; and a create-if-absent `PUT` overwrote what it was written to
protect.

A date the proxy cannot parse is ignored rather than refused, which is what
RFC 9110 asks of a recipient. **The ETag a precondition is compared against is
the stored ciphertext's**, not a digest of the plaintext — send back the value
the proxy gave you and revalidation works; compute an MD5 of your own file and
it will not.

### Operations the proxy does not implement

A sub-resource the proxy does not implement is answered with
`501 NotImplemented`. It used to fall through to the base operation for its HTTP
method instead, which is how `DELETE /bucket?encryption` **deleted the bucket**.
Only query parameters on an allowlist now reach the base bucket and object
operations; any other parameter is refused by name.

What that means for a client today:

- **Object sub-resources: three are passthrough, the rest are refused.**
  `?tagging` (`GET`, `PUT`, `DELETE`), `?retention` (`GET`, `PUT`) and
  `?legal-hold` (`GET`, `PUT`) reach the backend and answer with its document —
  they carry no plaintext of the object and the proxy has nothing to add to them
  ([ADR 0007](./docs/adr/0007-forward-it-or-refuse-it.md) D4). `?torrent` is
  forwarded too. `?acl`, `?attributes` and S3 Select answer `501`, and so does a
  verb none of the three defines. A request document that does not parse answers
  `400 MalformedXML`, through the proxy's own error document.
- **Bucket sub-resources read but mostly do not write.** `GET` is forwarded for
  all of them, and so is `DELETE` for `?cors`, `?policy`, `?tagging`,
  `?lifecycle`, `?replication` and `?website` — each answering `204` with no
  body, as S3 does. Of the `PUT`s only `?acl`, `?cors`, `?policy` and `?logging`
  reach the backend, and they carry the client's document **in full**, grant for
  grant and rule for rule ([ADR 0007](./docs/adr/0007-forward-it-or-refuse-it.md)
  D5); a body that does not parse answers `400 MalformedXML` through the proxy's
  own error document. `?versioning`, `?tagging`, `?notification` and
  `?lifecycle` parse no body and answer `501` whenever one is present — which it
  always is — and `?replication`, `?website`, `?accelerate` and
  `?requestPayment` answer `501` outright. **Enable versioning on the bucket
  directly at the backend**, not through the proxy.
- **Every sub-resource answers a real S3 document.** Each `GET` returns the
  document S3 defines, under the S3 namespace, with the XML declaration in front
  of it — `<CORSConfiguration><CORSRule><AllowedMethod>`, not the Go field names
  of an SDK struct. Until 5.0.0 these responses were the `aws-sdk-go-v2` output
  struct XML-encoded, so the root element was its Go type name, the element names
  were its field names, there was no namespace, and an internal
  `<ResultMetadata>` element was part of every one of them. No S3 client could
  parse any of them.
- **Multipart listing works**: `ListParts` answers from the proxy's own part
  table, with the plaintext size and the `ETag` this proxy answered per part —
  the object's last part included, which the proxy holds until
  `CompleteMultipartUpload` and which the backend therefore does not know about.
  `part-number-marker` and `max-parts` are honoured, and an upload id the proxy
  has no session for is `404 NoSuchUpload`. `ListMultipartUploads` is forwarded to
  the backend.

Five object sub-resources used to answer `200` for work they did wrongly or not
at all. Two of them are now real, and three are refused:

| Request | What it used to do | Today |
|---|---|---|
| `PUT /bucket/key?legal-hold` | Always set the hold **on**, whatever the body asked for, so a request to release one applied one | passthrough: the status in the body is the one that reaches the backend |
| `GET /bucket/key?legal-hold` | Empty `200` with no document | passthrough: a `<LegalHold>` document |
| `PUT`/`GET /bucket/key?retention` | Sent `Mode=Governance` with no retain-until date, or answered an empty `200` | passthrough: the mode and date in the body reach the backend, `x-amz-bypass-governance-retention` with them |
| `POST /bucket/key?select&select-type=2` | Ran a fabricated query, discarded the event stream, answered an empty `200` | `501 NotImplemented` |
| `GET /bucket/key?attributes` | Returned the object **bytes** where `GetObjectAttributes` expects an XML document | `501 NotImplemented` |

**A query string containing a `;` is refused with `400 InvalidArgument`**, after
authentication and before any routing decision
([ADR 0007](./docs/adr/0007-forward-it-or-refuse-it.md) D13). S3 never uses `;`
as a query separator, and Go's query parser silently discards every
`&`-separated segment that contains one while the router splits on both
characters — so such a request would otherwise be routed by one reading of its
query and handled by another. A percent-encoded `%3B` is a value byte and is
unaffected.

`CopyObject` (`PUT` with `x-amz-copy-source`) and `UploadPartCopy` answer
`422 NotSupportedWithEncryption`: a server-side copy runs inside the backend,
where the proxy cannot decrypt and re-encrypt. `UploadPartCopy` used to be
unreachable and its request stored an empty part; it is now routed and refused.

### Checksums

**Every checksum you declare on an upload is verified against your plaintext**
([ADR 0012](./docs/adr/0012-client-checksums-are-verified-never-forwarded.md)).
The value may arrive as a request header or as an aws-chunked trailer, and the
check runs on every write path: single-request `PUT`, large uploads the proxy
splits into parts internally, `UploadPart`, the bucket configuration writes and
`DeleteObjects`.

| Declaration | Algorithm | Where it may arrive |
|---|---|---|
| `Content-MD5` | MD5 | request header |
| `x-amz-checksum-crc32` | CRC-32/IEEE | header or `X-Amz-Trailer` |
| `x-amz-checksum-crc32c` | CRC-32C | header or `X-Amz-Trailer` |
| `x-amz-checksum-crc64nvme` | CRC-64/NVME | header or `X-Amz-Trailer` |
| `x-amz-checksum-sha1` | SHA-1 | header or `X-Amz-Trailer` |
| `x-amz-checksum-sha256` | SHA-256 | header or `X-Amz-Trailer` |
| `x-amz-checksum-sha512` | SHA-512 | header or `X-Amz-Trailer` |
| `x-amz-checksum-md5` | MD5 | header or `X-Amz-Trailer` |

- A value that does not match your payload → **`400 BadDigest`**.
- A value that is not base64, or decodes to the wrong length → **`400 InvalidDigest`**.
- A trailer named in `X-Amz-Trailer` that never arrives → **`400 BadDigest`**. Naming
  it is how you ask for the check; omitting the value is not a way out of it.
- **Nothing is stored on a failure.** The verdict lands before the object is
  committed, no part reaches the backend, and no multipart upload is left behind.
- `DeleteObjects` **requires** a digest, as S3 does, and a request without one is
  refused with `400 InvalidRequest`. The digest is checked before the document is
  parsed, so a refused request deletes nothing.
- An algorithm the proxy does not compute → **`501 NotImplemented`**, naming the
  header. The `x-amz-checksum-xxhash3`, `-xxhash64` and `-xxhash128` families are
  the ones this affects: none has a Go standard-library hash and the proxy takes
  no dependency for one. It refuses them rather than accepting a check it cannot
  run. `x-amz-checksum-algorithm`, `-mode` and `-type` carry no digest and are
  unaffected.
- **`CompleteMultipartUpload` is the exception.** There `x-amz-checksum-*` is the
  digest of the *completed object*, not of the completion document, so it is not
  checked against that document — it is dropped, because the proxy no longer
  holds the plaintext object it would have to hash and the backend holds only
  ciphertext.

**What a checksum costs you.** Only the algorithm you declare is computed, and
declaring none costs nothing at all. Per-byte throughput on one core of an Apple
M5 Pro, 128 KiB blocks, Go 1.27.1:

| Algorithm | Throughput | Hardware |
|---|---|---|
| CRC-32 | 12.1 GB/s | dedicated instructions on amd64 and arm64 |
| CRC-32C | 12.1 GB/s | dedicated instructions on amd64 and arm64 |
| SHA-1 | 3.5 GB/s | ARMv8 SHA1 / x86 SHA-NI where the CPU has them |
| SHA-256 | 3.4 GB/s | ARMv8 SHA2 / x86 SHA-NI where the CPU has them |
| SHA-512 | not measured | ARMv8 / x86 where the CPU has them |
| CRC-64/NVME | 2.4 GB/s | none, software only |
| MD5 | 0.94 GB/s | none on either architecture |

End to end the difference is much smaller, because the hash runs while the
request is bound by the write to the backend: measured over the development
stack at 8 MiB and 20 MiB, every algorithm but MD5 was inseparable from an
upload declaring nothing, and MD5 cost about three percent. Pick CRC-32 or
CRC-32C if your client lets you choose; the AWS SDKs send CRC-32 by default.

**A CRC is a transmission-corruption check, not an integrity guarantee.** It
catches a byte damaged on the way to the proxy, which is what it is for. It does
not detect a deliberate modification, and nothing here claims it does — see
[SECURITY_ARCHITECTURE.md](./SECURITY_ARCHITECTURE.md) § 6.4.

**Your value is never forwarded and never stored.** It describes the plaintext
while the body the proxy uploads is ciphertext, so a digest-checking backend
would answer `BadDigest` for a perfectly good upload; and a plaintext checksum
sitting in cleartext next to the ciphertext would hand a hostile backend a way to
confirm a guessed plaintext. Responses carry no backend checksum header either,
for the mirror-image reason: it would describe the stored ciphertext, not the
plaintext delivered.

Object integrity at rest is covered by the per-segment tags of the
[storage format](#storage-format-s3ep-gcm-seg-v2), which refuse a modified object
outright. The format also seals a CRC32C over the plaintext in its trailer, the
proxy checks it on every whole-object read, and **it serves it back to you**: a
whole-object `GET` and a `HEAD` answer with `x-amz-checksum-crc32c` over the
plaintext, recorded when the object was written and never computed from the bytes
about to be sent. There is no configuration key for it, and a ranged read carries
none.

### Versioned buckets

`versionId` is forwarded to the backend on `GET`, ranged `GET`, `HEAD` and
`DELETE`, so a client addressing one specific version gets that version rather
than the current one. `x-amz-version-id` is returned on `GET`, `HEAD`, `PUT`,
`DELETE` and `CompleteMultipartUpload`, and `x-amz-delete-marker` on a `DELETE`
that created one. An encrypted multipart upload writes exactly one
version: every metadata value exists before the first backend byte is sent, so
nothing rewrites the finished object to attach it.

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
- The three gaps that used to make this depend on a trusted backend are closed
  by the storage format: kopia's ranged reads of its pack blobs are verified
  segment by segment, a modified object is never delivered whole, and an object
  whose `s3ep-*` metadata has been stripped is refused rather than served.

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
> secrets: without it, existing repositories cannot be read.

## Security

- **🔐 Authenticated Encryption**: AES-256-GCM per 64 KiB segment, each seal bound to its segment index and to the object key ([storage format](#storage-format-s3ep-gcm-seg-v2))
- **🔑 Envelope Encryption**: KEK/DEK separation, with an authenticated key wrap that fails closed
- **🔒 Client Authentication**: AWS Signature V4 validation, both the `Authorization` header and the pre-signed query form
- **⚠️ No rate limiting**: the proxy does **not** throttle requests, and it counts nothing per caller. There is no setting for it: the keys that suggested one are gone. An unauthenticated caller is limited only by what sits in front of the proxy, so put a real limiter there if you need one — shipping none is a decision ([ADR 0014](./docs/adr/0014-authentication-is-sigv4-no-rate-limiting.md))
- **🔒 Objects this proxy did not write are refused**: no `s3ep-*` metadata, a foreign format id, or a wrapped key that fails its tag answers `403 InvalidObjectState` on `GET`, `HEAD` and ranged `GET` — never the stored bytes. See [Objects this proxy did not write](#objects-this-proxy-did-not-write)
- **⚠️ Object key names are stored in the clear**: every byte of an object is encrypted and authenticated, its name is not. Whoever holds the bucket reads the key names, and backup layouts put namespaces, backup names and schedules there. Encrypting them is specified and **not implemented** ([ADR 0023](./docs/adr/0023-filename-encryption-encrypts-directory-segments.md))
- **🔒 A response describes the proxy, not the backend**: `<Owner>` in a listing is the client's own access key, the completed-multipart `<Location>` names the proxy, and no backend account id, endpoint or checksum reaches a client ([ADR 0008](./docs/adr/0008-every-response-describes-the-proxy.md))

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

`make help` lists the common targets; the Makefile has more. `make quality` runs
the formatter first, then `go vet`, then the linter — in that order, because make
stops at the first failing prerequisite and an unformatted tree would otherwise
never reach the target that fixes it.

**`staticcheck` here means the linter inside golangci-lint**, configured in
[.golangci.yml](./.golangci.yml), not a separately installed binary. A standalone
`staticcheck` has to be built with this module's Go version or it cannot analyze
the tree at all; `make lint` is the way in, and `make tools` installs the same
pinned golangci-lint coordinate CI uses.

Before changing a subsystem, read the page for it in
[docs/developer/](./docs/developer/) — it carries the invariants and the
hard-won details that the code cannot state on its own.

## License

The proxy is a licensed product and the license is a startup gate: with an active
provider of type `aes` and no valid license, it refuses to start and names the
missing license ([ADR 0016](./docs/adr/0016-the-license-is-a-startup-gate.md)).

**The exit provider needs no license, and that is deliberate.** The gate looks at
the *active* provider only, so `encryption_method_alias` pointing at an `exit`
provider starts without a valid license while the `aes` provider stays listed
beside it and keeps unwrapping the data keys of everything written under it. A
license that has expired, or one you no longer hold, must never be the reason you
cannot read your own data. What stops is new encryption: from that point objects
are stored as the client sends them
([Exit Provider](#2-exit-provider-type-exit)).

The token is read from `S3EP_LICENSE`, `S3EP_LICENSE_TOKEN` or
`S3_ENCRYPTION_PROXY_LICENSE`, and otherwise from `license_file` — by default
`config/license.jwt`, with `/etc/s3ep/license.jwt` and `/app/license.jwt` among
the fallbacks searched afterwards. It is never committed to this repository, so
`./start-demo.sh` and the Velero e2e suite need it supplied out of band.

Source code terms: see [LICENSE](./LICENSE).
