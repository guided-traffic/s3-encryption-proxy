# Contributing to S3 Encryption Proxy

We welcome contributions to the S3 Encryption Proxy project! Please read this guide to understand how to contribute effectively.

## Development Setup

### Prerequisites

- Go 1.27.1 — the version is spelled out in [go.mod](go.mod) and in the
  [Containerfile](Containerfile), and the two must always agree. The go command
  downloads that toolchain for you if your local Go is older
- Docker and Docker Compose — for the demo stack the integration suites run against
- Make
- A license token for the integration and end-to-end suites. Any active provider
  other than `none` fails startup without a valid license (ADR
  [0016](docs/adr/0016-the-license-is-a-startup-gate.md)). It is supplied out of
  band as `S3EP_LICENSE_TOKEN` or as `config/license.jwt`, which is gitignored
- Only for the Velero end-to-end suite: `kind`, `kubectl`, `helm`, `velero`,
  `openssl`

### Setup

1. Clone the repository:
```bash
git clone https://github.com/guided-traffic/s3-encryption-proxy.git
cd s3-encryption-proxy
```

2. Install dependencies:
```bash
make deps
```

3. Install development tools:
```bash
make tools
```

`make tools` installs `air` (live reload) and `golangci-lint`. **It installs the
wrong linter major version**: it uses the pre-v2 module path, which resolves to
the last v1 release, while [.golangci.yml](.golangci.yml) declares `version: "2"`
and a v1 binary refuses that file outright. Until the target is fixed, install
the version CI pins:

```bash
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.1
```

## Development Workflow

### Building

```bash
make build         # build/s3-encryption-proxy
make build-keygen  # build/s3ep-keygen, generates an AES-256 key
make license-tool  # build/license-tool, needs a key pair that is not in the repository
make build-all     # all three
```

### Running Tests

```bash
# Unit tests (-short)
make test-unit

# The same packages without -short. This does NOT run the integration suites:
# they are behind the `integration` build tag and are invisible to ./...
make test

# Integration tests against the plain-HTTP proxy (requires the demo stack, below)
make test-integration

# The same suites against the TLS listener. Not redundant: aws-sdk-go-v2 emits
# STREAMING-UNSIGNED-PAYLOAD-TRAILER framing only over HTTPS, so the trailer
# decoder is reached by no other run
make test-integration-tls

# Throughput of the proxy against direct MinIO. Run alone, on purpose: alongside
# the other suites it competes for the same backend and reports a lower number
make test-integration-performance

# Velero end-to-end in a kind cluster (build tag `e2e`)
make e2e-up && make test-e2e-velero
```

The integration suites need the demo stack, which takes about 30 seconds:

```bash
S3EP_LICENSE_TOKEN="$(cat config/license.jwt)" ./start-demo.sh
```

The container runs the built binary, not your working tree, so rebuild after
changing proxy code: `./start-demo.sh rebuild`. `docker logs proxy | tail -50`
for the plain listener, `proxy-tls` for the TLS one.

```bash
# Unit-test coverage report (coverage/coverage.html)
make coverage

# Combined unit + integration coverage: the proxy containers must be built
# instrumented, then their counters are collected after the suite ran
GOCOVER=1 ./start-demo.sh
make test-unit-coverage test-integration test-integration-tls
make coverage-integration-collect coverage-report

# Per-package table with unit, integration and combined columns, the same
# one the pull request comment shows
python3 .github/scripts/coverage-summary.py coverage
```

Every coverage input has to come from the same Go toolchain — the coverage
targets pin it for you — because Go's block layout changes between releases and
mixed data double counts the denominator instead of failing.

### Code Quality

```bash
make fmt         # gofmt -s -w .
make lint        # go vet, a gofmt check that actually fails, then golangci-lint
make gosec       # pinned gosec, built by the toolchain that compiles the code
make vuln        # pinned govulncheck, same reason
make all-checks  # quality + security
```

### Development Server

```bash
# Run with live reload (air, configured in .air.toml)
make dev
```

## Testing

Four layers, and they are not interchangeable. [docs/developer/testing.md](docs/developer/testing.md)
is the full picture; what matters before you write a test:

| Layer | Command | Build tag |
|---|---|---|
| Unit | `make test-unit` | none (`-short`) |
| Integration | `make test-integration` | `integration` |
| Integration over TLS | `make test-integration-tls` | `integration` |
| Velero end-to-end | `make test-e2e-velero` | `e2e` |

### Unit Tests

- Place unit tests in `*_test.go` files alongside the code they test
- `*_coverage_test.go` files are ordinary unit tests from a coverage round
- Use table-driven tests where appropriate
- Mock external dependencies. The handlers compile against
  `internal/proxy/interfaces/s3_backend.go`, which is what makes them mockable

### Integration Tests

- Under `test/integration/<package>/`; `test/integration/` itself holds the
  helpers. `minio_test_helper.go` builds a `TestContext` with both a proxy client
  and a direct MinIO client, which is what lets a test compare what a client sees
  against what is actually stored
- They need the demo stack running. Endpoints are overridable
  (`S3EP_TEST_PROXY_ENDPOINT`, `S3EP_TEST_MINIO_ENDPOINT`); with nothing running,
  the suites skip rather than fail
- **MinIO is the oracle, the AWS documentation is the specification.** Where the
  proxy and MinIO disagree, a test asserts the *actual* behaviour and a comment
  above it names the deviation. Search for `DEVIATION`
- Four `bucket_*_test.go` files in `s3-methods` carry no build tag — they are
  offline XML and validation tests — so they also run under `make test-unit`

### The suites are not optional

The integration and end-to-end suites are the product's behaviour, so they are
never skipped, disabled or deleted to make a change land (ADR
[0019](docs/adr/0019-integration-and-e2e-tests-are-the-product.md)). If one of
them fails, the change is not finished.

## Code Style

- Follow standard Go conventions; `gofmt -s` is enforced by `make lint`, not just
  reported
- `make lint` runs golangci-lint v2 with errcheck, gosec, govet, ineffassign,
  misspell, revive, staticcheck and unused
- Code, comments, commit messages and documentation are English
- Keep functions small and focused, and use descriptive variable names
- Comment what the reader cannot derive from the line itself: a non-default value
  and its default, a workaround and the defect behind it, a constraint that bites
  elsewhere. Do not restate what the name already says

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes
4. Add tests for new functionality
5. Ensure the suites pass: `make test-unit`, then `make test-integration` and
   `make test-integration-tls` against the demo stack
6. Run linting: `make lint`
7. Commit your changes using [Conventional Commits](https://www.conventionalcommits.org/)
8. Push to your fork
9. Create a pull request

### Commits drive the release

Releases are cut automatically from `main`, and the version is computed from the
commit headers and footers that reach it. `feat` produces a minor; `fix`, `perf`,
`refactor` and `revert` a patch; `docs`, `style`, `chore`, `test`, `build` and
`ci` produce no release at all.

A breaking change is **declared, never discovered**: `feat!`, `fix!` or a
`BREAKING CHANGE:` footer requires the `release:major` label on the pull request,
and a guard check fails the pull request without it (ADR
[0018](docs/adr/0018-a-major-release-is-declared-by-a-label.md)). The guard reads
the commits, the pull-request title *and* the body, because a merge commit and a
squash merge hand the release tool different text. A second check dry-runs the
release tool and fails when the computed bump and the label disagree.

### Pull Request Requirements

- Every CI job green: malware scan, unit tests, gosec, govulncheck, lint,
  integration tests over both the plain-HTTP and the TLS endpoint, the combined
  coverage report and the Velero end-to-end suite
- New features must include tests
- Coverage is reported per pull request as a per-package table. It is a signal,
  not a gate — no threshold fails the build — so a drop needs a reason, not a
  waiver
- Documentation updated in the same change, in the right place:

| Kind | Home |
|---|---|
| A decision — what the product does and why, what was rejected | an [ADR](docs/adr/), carrying no references into the code |
| How a subsystem works, an invariant, a hard-won detail | [docs/developer/](docs/developer/) |
| What an operator or a client needs | [README.md](README.md) |
| The threat model and residual risks | [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md) |

Work still outstanding lives in a work list that is deleted when the work lands,
and nothing outside that directory may reference one — cite the ADR instead (ADR
[0022](docs/adr/0022-tickets-are-work-lists-that-get-deleted.md)).

## Architecture

### Overview

```
cmd/
├── s3-encryption-proxy/  # the binary: config load, license gate, server lifecycle, shutdown
├── keygen/               # AES-256 key generator
└── license-tool/         # license JWT generator
internal/
├── config/               # Viper configuration: defaults, validation, ${ENV} expansion
├── license/              # license JWT validation and the startup gate
├── monitoring/           # Prometheus metrics server and middleware, pprof on its own loopback listener
├── orchestration/        # the encryption facade the handlers call
└── proxy/                # the HTTP surface
    ├── handlers/         # object, multipart, bucket, root, health
    ├── interfaces/       # the slice of the AWS S3 SDK the handlers compile against
    ├── middleware/       # SigV4 (header and pre-signed), CORS, logging, request tracking
    ├── request/          # request parsing, aws-chunked and HTTP-chunked decoding, query parameters
    ├── response/         # S3 error documents, backend error mapping, XML helpers
    └── utils/            # shared error handling and request-context helpers
pkg/
└── encryption/           # crypto primitives, no business logic
    ├── dataencryption/   # the segmented AES-256-GCM storage format: codec, sealing and opening IO, range planner
    ├── keyencryption/    # key-encryption-key providers: aes, none
    └── factory/          # builds a key encryptor from configuration; fingerprint to provider registry
test/
├── integration/          # build tag `integration`, against the demo stack
├── e2e/velero/           # build tag `e2e`, in a kind cluster
├── perf/                 # build tag `perf`, the local before/after baseline
└── ssl-setup/            # the test PKI generator; the PKI itself is generated, never committed
docs/
├── adr/                  # decisions
└── developer/            # how the subsystems work
```

File-level detail is in [docs/developer/package-map.md](docs/developer/package-map.md).

### Key Components

1. **Storage format** (`pkg/encryption/dataencryption/`): an object is an
   authenticated AES-256-GCM segment chain plus a trailer. Each segment carries
   its own nonce and tag, and its associated data binds the format id, the object
   key and the segment index, so a segment cannot be moved between objects or
   between positions (ADR [0003](docs/adr/0003-objects-are-an-authenticated-segment-chain.md))
2. **Key providers** (`pkg/encryption/keyencryption/`): the key-encryption-key
   layer. `aes` is the one provider that encrypts — HKDF-SHA256 derivation, an
   authenticated 76-byte data-key wrap, and the fingerprint that selects it again
   on read (ADR [0004](docs/adr/0004-one-local-key-provider.md)). `none` is
   pass-through. There is no KMS-backed provider; a configuration that asks for
   `tink` is refused at startup (ADR [0005](docs/adr/0005-a-kms-key-is-a-provider.md))
3. **Orchestration** (`internal/orchestration/`): the facade the handlers call —
   one object write or read, the client-driven multipart session and its part
   table, the data-key wrap and its cache, and the `s3ep-*` metadata
4. **Configuration** (`internal/config/`): YAML through Viper, with `${VAR}`
   expansion and validation that refuses a bad configuration at startup rather
   than at the first request. A key exists only if code reads it (ADR
   [0013](docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md))
5. **Proxy server** (`internal/proxy/`): the HTTP and optional TLS listener, the
   SigV4 middleware, and the S3 handlers that talk to the backend through
   `aws-sdk-go-v2`. An S3 feature the proxy cannot serve correctly under
   encryption is refused, not faked (ADR
   [0007](docs/adr/0007-forward-it-or-refuse-it.md))

## Security Considerations

- The backend is treated as hostile: it sees ciphertext and the `s3ep-*` metadata,
  never a data key or a plaintext byte (ADR
  [0001](docs/adr/0001-the-backend-is-hostile.md))
- Envelope encryption throughout — one fresh data key per object (ADR
  [0002](docs/adr/0002-one-data-key-per-object.md)), wrapped under the configured
  key-encryption key. No plaintext key is stored or transmitted
- Integrity is inseparable from decryption: every segment is opened with its tag
  and its associated data, so a modified object is never delivered whole. There
  is no mode that turns this off
- **Key material and license tokens are never committed** — a key is generated
  with `build/s3ep-keygen` (`make build-keygen`), the test PKI by
  `test/ssl-setup/gen-certs.sh`, and both are gitignored (ADR
  [0021](docs/adr/0021-key-material-is-generated-never-committed.md))
- Do not report a vulnerability in a public issue or a pull request. Use the
  private route in
  [SECURITY_ARCHITECTURE.md § Reporting a vulnerability](SECURITY_ARCHITECTURE.md#9-reporting-a-vulnerability)

## Debugging

The log level comes from the configuration file, not from a flag — the binary
takes only `--config`, `--monitoring` and `--monitoring-port`:

```yaml
log_level: "debug"  # example; default is "info"
```

```bash
./build/s3-encryption-proxy --config config/aes-example.yaml
```

For the demo stack, `docker logs proxy | tail -50` (`proxy-tls` for the TLS
listener). [docs/developer/](docs/developer/) explains what you are looking at:
the request paths, the storage format and its invariants, and the error
conventions.

## Getting Help

- Read [docs/developer/README.md](docs/developer/README.md) first — it is the map
- [docs/adr/README.md](docs/adr/README.md) for why something is the way it is
- Check existing issues on GitHub, and ask questions in discussions — both are
  public, so keep security reports out of them (see above)

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.
