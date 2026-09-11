# Developer guide

For people changing this code. [README.md](README.md) is for operators and
clients, [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md) is the threat model
and the residual risks, and this page is the contributor's entry point: where
things live, how to build and test them, what continuous integration gates, and
the conventions that are not obvious from the tree.

**Per-subsystem depth is in [docs/developer/](docs/developer/), and this page
never repeats it.** Read the page for a subsystem before you change it, and
update it in the same change — unlike an ADR, those pages point at files and
functions on purpose, so they go stale when the tree moves.

| Page | Read it when |
|---|---|
| [package-map.md](docs/developer/package-map.md) | You are new, or you are looking for where something lives |
| [storage-format.md](docs/developer/storage-format.md) | You touch the codec — one stored format, `s3ep-gcm-seg-v2` — or anything that computes a size or an offset |
| [request-paths.md](docs/developer/request-paths.md) | You touch a handler: what happens on a PUT, a GET, a ranged GET, a HEAD |
| [multipart.md](docs/developer/multipart.md) | You touch multipart upload, the part table, or the trailer |
| [errors.md](docs/developer/errors.md) | You are choosing a status code or an S3 error code |
| [testing.md](docs/developer/testing.md) | You are adding a test, or a suite is failing and you need to know what it is for |
| [performance.md](docs/developer/performance.md) | You are changing a hot path, or you need a before/after number |

## What has to be in your head first

- **One stored format**, `s3ep-gcm-seg-v2`: an AES-256-GCM segment chain closed
  by a sealed trailer, under one random data key per object wrapped by the
  configured key encryption key. No second cipher, no configurable integrity, no
  format switch ([ADR 0001](docs/adr/0001-the-backend-is-hostile.md),
  [0002](docs/adr/0002-one-data-key-per-object.md),
  [0003](docs/adr/0003-objects-are-an-authenticated-segment-chain.md)).
- **Exactly four metadata keys** under `metadata_key_prefix` (`s3ep-` by
  default): `dek-algorithm`, `encrypted-dek`, `kek-algorithm`,
  `kek-fingerprint`. Nothing else is written, nothing unprefixed is read, and a
  client key inside the prefix is refused
  ([ADR 0009](docs/adr/0009-the-metadata-prefix-is-the-proxys-namespace.md)).
- **Two key providers**, `aes` and `exit`. `exit` holds no key material, stores
  what the client sent on every write path, and still decrypts per object what
  `aes` wrote — so the `aes` provider has to stay configured beside it
  ([ADR 0004](docs/adr/0004-one-local-key-provider.md),
  [0025](docs/adr/0025-leaving-is-a-supported-mode.md)).
- **Encryption happens exactly once**, in the handler's call into
  `orchestration.Manager`. There is no second layer.

## Repository layout

```
cmd/
  s3-encryption-proxy/   the binary: config, licence gate, server lifecycle, shutdown
  keygen/                AES-256 key generator, built as build/s3ep-keygen
  license-tool/          licence JWT generator (needs key files that are not in the repo)
internal/
  config/                Viper loading, defaults, and every startup refusal
  license/               licence validation and the startup gate
  monitoring/            Prometheus registry and listener, pprof on its own loopback listener
  orchestration/         the facade the handlers call: providers, metadata, segmented read/write,
                         the client-driven multipart session table
  proxy/
    handlers/            root, bucket, object, multipart, health
    interfaces/          the slice of the AWS SDK the handlers compile against (mocked in tests)
    middleware/          SigV4 in both forms, CORS, logging, request tracking
    request/             body parsing, aws-chunked decoding, upload checksum verification
    response/            S3 error documents, backend error mapping, XML helpers
    utils/               a second S3-error writer, and the detached context an abort needs
pkg/encryption/
  dataencryption/        the codec: segments, trailer, range planner. No business logic
  keyencryption/         the KEK providers, one file each
  factory/               the KEK registry, keyed by fingerprint
deploy/helm/s3-encryption-proxy/   the supported way to run it in Kubernetes
test/
  integration/           against a running demo stack, build tag `integration`
  e2e/velero/            Velero in a kind cluster, build tag `e2e`
  perf/                  the local baseline suite, build tag `perf`
  ssl-setup/             the test PKI generator
docs/
  adr/                   every decision, permanent, with no references into the code
  developer/             the pages above
  tickets/               work lists, deleted when the work lands
```

File-level detail is [package-map.md](docs/developer/package-map.md).

## Core flows, one fact each

- **A `PUT` routes on `DecodedContentLength` against
  `optimizations.streaming_segment_size` and on nothing else.** Above it, or with
  an undeclared length, it becomes the internal multipart producer.
- **The producer overlaps receive with send**
  ([ADR 0024](docs/adr/0024-an-upload-forwards-while-it-receives.md)) and holds a
  bounded pool of `concurrency + 1` buffers. Nothing runs after
  `CompleteMultipartUpload`: every metadata value exists before the first backend
  byte, so a finished object is never rewritten.
- **A whole-object `GET` is tail-first**: `bytes=-65604` first, then the
  remainder under `If-Match` on the first answer's entity tag. The length served
  and the `x-amz-checksum-crc32c` come from the **trailer**, not from what the
  backend says about itself
  ([ADR 0003](docs/adr/0003-objects-are-an-authenticated-segment-chain.md) D14).
- **A ranged read plans without a key.** `PlanRange` maps the plaintext range
  onto stored bytes, so the backend request can be issued before anything is
  unwrapped. An explicit `bytes=a-b` costs one backend request; a suffix or an
  open-ended range costs a `HEAD` first, because both are relative to the end.
- **The proxy owns the part layout** of a client-driven multipart upload
  ([ADR 0011](docs/adr/0011-the-proxy-owns-the-part-layout.md)). The session's
  part table is the authority at `Complete`, not the list the client sends.
- **Every client checksum is verified against the decoded plaintext and then
  dropped** ([ADR 0012](docs/adr/0012-client-checksums-are-verified-never-forwarded.md)).
  None reaches the backend and none is stored.

## Build, test and lint

Everything goes through the Makefile. `make help` is not the authority; this
table is.

**Build**

| Target | What it does |
|---|---|
| `build` | the proxy into `build/s3-encryption-proxy` |
| `build-keygen` | the AES key generator into `build/s3ep-keygen` |
| `license-tool` | the licence generator; needs `license_private_key.pem` / `license_public_key.pem` beside the binary, which are not in the repository ([ADR 0021](docs/adr/0021-key-material-is-generated-never-committed.md)) |
| `build-all` | all three |

**Test**

| Target | What it does |
|---|---|
| `test-unit` | `-short`, no stack needed |
| `test-integration` | the full suite against the plain-HTTP proxy; needs `./start-demo.sh` first |
| `test-integration-tls` | the same suites against the TLS endpoint. **Only this run reaches the trailer decoder**: aws-sdk-go-v2 emits `STREAMING-UNSIGNED-PAYLOAD-TRAILER` framing over HTTPS only |
| `test-integration-performance` | proxy-vs-backend throughput; run alone, the other packages would compete for the backend |
| `e2e-up` / `test-e2e-velero` / `e2e-down` | the Velero suite in a kind cluster. `e2e-up` is idempotent and reloads a freshly built image, so retest a code change with `make e2e-up && make test-e2e-velero` rather than recreating the cluster |

**Performance** — [performance.md](docs/developer/performance.md) has the rules.

| Target | What it does |
|---|---|
| `perf-baseline` | the full instrument set; needs the demo stack, and `S3EP_PERF_ALT_PROXY` for the upload-path comparison |
| `perf-baseline-quick` | fewer repetitions, throughput sizes to 8 MiB. Short, not small |
| `perf-baseline-offline` | only the instruments that need no stack |
| `perf-compare BEFORE= AFTER=` | compares two recorded runs and prints a verdict per row |

**Quality and security**

| Target | What it does |
|---|---|
| `fmt` / `lint` / `static` | formatting, golangci-lint (pinned, v2 module path), `go vet` |
| `quality` | `fmt static lint`, in that order |
| `gosec` / `vuln` | security scan, vulnerability check |
| `all-checks` | `quality security` |
| `helm-test` | `helm lint`, a render of **every** values file including the Velero e2e values, and `helm unittest` |

**Coverage**

| Target | What it does |
|---|---|
| `coverage` | unit-test coverage report |
| `test-unit-coverage`, `coverage-integration-collect`, `coverage-report` | the combined unit + integration flow, with `GOCOVER=1` on the stack |

Three rules that are not obvious and have each cost a day:

- **`make lint` compiles no tagged tree.** The integration, e2e and perf suites
  carry build tags, so they need their own `go vet -tags=integration`, `-tags=e2e`
  and `-tags=perf`. A change that breaks only a tagged tree passes `lint`.
- **`quality` runs `fmt` first on purpose.** `make` stops at the first failing
  prerequisite, so with `lint` ahead of it an unformatted tree never reached the
  target that would have fixed it.
- **The coverage targets pin the toolchain** to the version the shipped image is
  built with. Go coverage data only merges across identical toolchains; a 1.26
  and 1.27 mix once reported a package at 25.9 % that was really at 62.8 %.

## The Go toolchain version

Spelled out in exactly two files, which must always agree: `Containerfile`
(`FROM golang:<version>-alpine`, the source of truth for the shipped image, which
the Makefile parses into `GO_VERSION`) and `go.mod` (`go <version>`, which every
`setup-go` step reads through `go-version-file`). Everything else derives it.
Renovate bumps both in one pull request under the group "Go version". Never add a
third literal.

## Continuous integration and the release

`release.yml` runs on every push to `main` and on every pull request into it.

| Job | Gates |
|---|---|
| Malware Scan | ClamAV over the source |
| Unit Tests | `make test-unit` with coverage data |
| GoSec / Vulnerability Check / Code Linting | the three static gates |
| Helm Chart | `make helm-test`: lint, render every values file, `helm unittest` |
| Integration Tests | the demo stack, both transports, against an instrumented proxy |
| Coverage Report | merges unit and integration data. **Advisory: no threshold fails a build** |
| Velero E2E (kind) | the 13 scenarios. A deliberate release gate ([ADR 0019](docs/adr/0019-integration-and-e2e-tests-are-the-product.md)) |
| Semantic Release | runs only when all of the above pass |

The other workflows:

| Workflow | Trigger | Effect |
|---|---|---|
| `semantic-release-dry-run.yml` | pull requests into `main`, including label and title/body edits | The single release gate ([ADR 0018](docs/adr/0018-a-major-release-is-declared-by-a-label.md)). Runs semantic-release in dry-run mode to print the version it would cut — so a broken release configuration is found on the pull request that broke it — and inspects the commits, the title and the body for breaking markers, failing when one is present without `release:major`. The dry run reads only commits; the title and body are what a squash merge puts on `main`, which is why both checks are in the job |
| `push.yml` | **after a release is published** | builds and pushes the image, packages the chart. A green pull request therefore proves nothing about the image or the chart |
| `renovate.yml` | daily at 02:00 Europe/Berlin, or manually | dependency updates |
| `renovate-assign-on-failure.yml` | after "Test and Release" completes | assigns a failing Renovate pull request |

## Adding things

**A KEK provider.** Implement `KeyEncryptor` in
`pkg/encryption/keyencryption/{name}.go`; add the type to `KeyEncryptionType` and
`CreateKeyEncryptorFromConfig` in the factory; extend `isValidProviderType` and
`validateProvider` in the config loader and the provider switch in
`NewProviderManager`; add `config/{name}-example.yaml`; add an integration test.
`Fingerprint()` must identify the key without revealing anything about it and
must be **stable** — it is what a stored object names, so a provider that changes
its fingerprint stops reading its own objects.

**There is no DEK provider extension point.** The data layer is the segment
chain; changing it is a storage format change
([ADR 0003](docs/adr/0003-objects-are-an-authenticated-segment-chain.md),
[ADR 0017](docs/adr/0017-stored-data-compatibility-is-not-owed.md)).

**A configuration key.** It exists only if code reads it, and only if some value
an operator may set is one the product would accept
([ADR 0013](docs/adr/0013-a-configuration-key-exists-only-if-code-reads-it.md)).
Add it to the struct, to `setDefaults`, to its validation, to the shipped
examples and to `README.md` in the same change: an unknown key refuses the start
and names itself, so a key in the struct that nobody documented is a startup
failure for anyone whose configuration carries it.

**A chart value.** Add it to `values.yaml`, to the chart README's parameter
table, and to `tests/deployment_test.yaml`. Then revert your template change and
confirm the test goes red — an assertion that passes against both the fixed and
the broken chart is not a test.

## Conventions

- **Decisions are ADRs.** Every design decision of this project is recorded in
  [docs/adr/](docs/adr/), written in the session the decision is taken. An ADR
  says what the product does and why, and carries **no references into the code**
  — no file paths, no function names — so it stays true when the tree moves. The
  product's own vocabulary (configuration keys, `s3ep-*` metadata keys, S3 error
  codes) is not a code reference and must be exact.
- **A ticket is a work list and nothing else.** It lives in
  [docs/tickets/](docs/tickets/) while work is outstanding and is closed by
  **deleting the file**. Move anything durable out of it first: the decision into
  an ADR, the user-facing consequence into `README.md` or
  `SECURITY_ARCHITECTURE.md`.
- **Nothing outside `docs/tickets/` may reference a ticket** — not a code
  comment, not a commit message, not a pull request. Cite the ADR instead. `git
  grep` the number before deleting a ticket.
- **English everywhere**: code, comments, documentation, commit messages.
- **Never reflect a raw error string into a response body.** The client-facing
  wording per S3 error code is fixed; see [errors.md](docs/developer/errors.md).
- **Integration and e2e tests are the product** and may not be skipped, disabled
  or removed ([ADR 0019](docs/adr/0019-integration-and-e2e-tests-are-the-product.md)).
- **No performance claim without a before and an after** on the same machine
  ([ADR 0020](docs/adr/0020-performance-is-measured-before-and-after.md)).
- **No key material in the repository.** Keys are generated at bring-up
  ([ADR 0021](docs/adr/0021-key-material-is-generated-never-committed.md)).

## The knowledge graph

`graphify-out/` holds a committed knowledge graph of this repository — start at
`graphify-out/wiki/index.md`. It is the fastest way to see how the pieces hang
together, but **it lags the code**: the build date is the first line of
`GRAPH_REPORT.md`. Treat a hit as a pointer and verify it in the tree before
citing it. Rebuilding it is a manual step that is committed as its own change.
