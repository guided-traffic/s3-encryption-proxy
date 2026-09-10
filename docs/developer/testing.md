# Testing

Four layers, and they are not interchangeable. The rule that governs all of them
is [ADR 0019](../adr/0019-integration-and-e2e-tests-are-the-product.md): the
integration and end-to-end suites *are* the product's behaviour, so they are
never skipped, disabled or deleted to make a change land.

## The layers

| Layer | Command | Build tag | What it is for |
|---|---|---|---|
| Unit | `make test-unit` | none | Logic and edge cases against mocks. Fast enough to run on every save |
| Integration | `make test-integration` | `integration` | The real proxy against a real MinIO. This is where behaviour is decided |
| Integration over TLS | `make test-integration-tls` | `integration` | The same suites against the TLS listener |
| Velero end-to-end | `make test-e2e-velero` | `e2e` | One supported client, exercised whole, in a kind cluster |

**The build tag is what separates them, not `-short`.** `make test-unit` is
`go test -v -short ./...`, and `-short` today gates exactly two tests, both of
them behind the `integration` tag. What keeps the integration tree out of the
unit round is the tag on every file, nothing else.

That has one consequence worth knowing: four files in `test/integration/s3-methods`
carry **no** tag — `bucket_acl_test.go`, `bucket_cors_test.go`,
`bucket_location_test.go`, `bucket_logging_test.go`. They are offline XML and
validation tests that need no stack, so they compile into the unit round and
`make test-unit` runs them. A new file in that package needs the tag unless you
mean that.

Unit tests sit next to the code. `*_coverage_test.go` files are ordinary unit
tests from a coverage round.

**`make lint` compiles none of the tagged trees.** Its `go vet ./...` passes no
tag and `.golangci.yml` sets none, so a tagged file that does not compile passes
lint and fails later, in a suite. Check what you touched yourself:

```bash
go vet -tags=integration ./test/integration/...
go vet -tags=e2e ./test/e2e/...
go vet -tags=perf ./test/perf/...
```

## Why the TLS run exists

It is not redundant. The AWS SDK emits its `STREAMING-UNSIGNED-PAYLOAD-TRAILER`
framing **only over HTTPS**, so the trailer decoder is reached by no other run. A
change to request parsing that passes `make test-integration` and is never run
over TLS is a change nobody tested.

The mechanism is one variable: `make test-integration-tls` runs the same packages
with `S3EP_TEST_PROXY_ENDPOINT` pointed at the TLS listener (the Makefile's
`PROXY_TLS_ENDPOINT`, `https://127.0.0.1:8443`). A suite that builds its own
listener never sees it — see *Two suites start the proxy in process*.

## Integration suites

Under `test/integration/<package>/`.

| Suite | Subject |
|---|---|
| `s3-methods` | The S3 API surface, verb by verb, against MinIO as the oracle. The largest suite, and where the deviations are recorded |
| `360-degree-variants` | Round trips in every shape: single part, client-driven multipart, aws-chunked framing, ranged reads, the DEK cache after a re-upload, and what a hostile backend gets by tampering with a stored object |
| `180-degree-variants` | One 500 MB client-driven multipart round trip through the proxy alone, checked by SHA-256 |
| `encryption-modes` | The `aes` and `exit` providers, each against a proxy the test starts in process |
| `authentication` | Header SigV4: credentials, malformed and oversized headers, clock skew |
| `performance-test` | Proxy against MinIO throughput. `make test-integration-performance`, on its own, because the others would compete for the backend |

`test/integration/` itself is a package too, and it is in the list the Makefile
runs. It holds the helpers:

| File | What it gives you |
|---|---|
| `minio_test_helper.go` | `TestContext`, with a proxy client and a direct MinIO client — what lets a test compare what a client sees against what is actually stored |
| `encryption_validation_helper.go` | Entropy and readable-string checks that assert stored bytes are ciphertext |
| `s3_signing_helper.go` | Hand-rolled SigV4, for the requests the SDK will not emit: raw aws-chunked bodies, a malformed `Range`, an unrouted sub-resource. `s3_signing_test.go` is its own test |

The pre-signed form of SigV4 is not in the `authentication` suite. It is covered
by `TestSubrefPresignedGetIsNotRefusedAsASubResource` in `s3-methods` and by
`TestV10_PresignedLogAccess` in the Velero suite.

**MinIO is the oracle, the AWS documentation is the specification.** Where the
proxy and MinIO disagree, or both disagree with AWS, a test asserts the *actual*
behaviour and a comment above it names the deviation. That keeps the suite green
and the gap visible. Search for `DEVIATION` to find them; when one is closed, the
test flips to the correct behaviour and the deviation note goes.

## Two suites start the proxy in process

`encryption-modes` never talks to the containers. Each of its tests loads
`config/aes-example.yaml` or `config/exit-example.yaml`, calls `proxy.NewServer`,
binds a free port and drives that. Three consequences:

- it exercises your working tree, so it is the one suite a container rebuild does
  not affect — and the one that catches a config example the code no longer
  accepts, which is what a removed configuration key breaks first;
- it needs MinIO reachable at `https://localhost:9000` and, for the `aes` half, a
  license in `S3EP_LICENSE_TOKEN` or at `config/license.jwt`;
- it ignores `S3EP_TEST_PROXY_ENDPOINT`, so the TLS run repeats it over plain
  HTTP unchanged.

## Running them

Integration needs the demo stack, which takes about 30 seconds:

```bash
S3EP_LICENSE_TOKEN="$(cat config/license.jwt)" ./start-demo.sh
```

The stack reads the token from the environment, and the proxy will not start
without one. After changing proxy code, rebuild before you retest — the container
runs the built binary, not your working tree:

```bash
S3EP_LICENSE_TOKEN="$(cat config/license.jwt)" ./start-demo.sh rebuild
```

`docker logs proxy | tail -50` for the plain listener, `proxy-tls` for the other.

The Velero suite costs much more: `make e2e-up` generates the test PKI when it is
missing, creates a kind cluster, installs MinIO over TLS, the CSI hostpath driver
and snapshotter, the proxy chart and Velero, and waits for the
BackupStorageLocation to go Available. It needs a license the same way, and
aborts up front if neither `S3EP_LICENSE_TOKEN` nor `config/license.jwt` exists.
It is idempotent and reloads a freshly built image, so retest a change with
`make e2e-up && make test-e2e-velero` rather than recreating the cluster. Thirteen
tests: a preflight and the V1–V10 scenarios, V1b and V8b included.

## Coverage

Coverage has two sources in two processes — the unit tests, and the proxy binary
the integration suite talks to over HTTP. Both write Go's binary coverage format
into `coverage/`, and `coverage-report` merges every directory it finds there:

```bash
make test-unit-coverage                        # -> coverage/unit
GOCOVER=1 ./start-demo.sh                      # instrumented proxy containers
make test-integration test-integration-tls
make coverage-integration-collect              # -> coverage/integration-http, -tls
make coverage-report                           # -> coverage/coverage.txt, .html, merged.out
```

`make coverage` is the unit-only shortcut. Collecting from the containers stops
them first — a clean exit is what flushes the counters — and fails loudly if they
were not built with `GOCOVER=1`.

Every input has to come from one Go toolchain, which is why these targets pin the
version parsed out of the `Containerfile`. Mixed data does not fail; it
under-reports, because `covdata` keeps both variants of a package and doubles the
denominator.

## Not a layer: the performance baseline

`test/perf` carries its own `perf` tag and **asserts nothing**. It records, and a
person compares two records ([ADR 0020](../adr/0020-performance-is-measured-before-and-after.md)).
It is local by design and referenced by no workflow. The commands and the traps
are in [`test/perf/README.md`](../../test/perf/README.md); what is easy to get
wrong about a comparison is in [performance.md](performance.md).

One trap belongs here, because it looks like a broken suite and is not:
`go build -tags=perf ./test/perf/...` fails with three undefined endpoint
constants. `client.go` is a non-test file that uses constants declared in
`main_test.go`, which `go build` does not compile. `go vet -tags=perf` and
`go test -tags=perf` both see the test files and pass — they are the real gate.

## What CI runs

`.github/workflows/release.yml` runs all four layers plus the performance package
on every pull request to `main` and every push to it. `semantic-release` needs
the malware scan, gosec, govulncheck, the linter, the unit tests, the integration
tests, the coverage report **and** the Velero suite, so a red suite blocks a
release instead of warning about one. The e2e job budgets 45 minutes for bring-up,
run and teardown, and CI runs the same `e2e-up.sh` / `e2e-down.sh` a workstation
does, so the two cannot drift apart.

## Writing a test that is worth having

**Assert what is stored, not only what round-trips.** A round trip proves the
proxy is self-consistent; it does not prove the bytes at rest are ciphertext, nor
that they are the length the format prescribes. The 360-degree suite recomputes
the exact stored length from the plaintext length (`segStoredSize`) precisely
because it is a pure function of it, and an off-by-one in the size arithmetic
would round-trip fine.

**Compare payloads by SHA-256, never by dumping them.**

**A test that pins a defect says so.** If the behaviour under test is wrong but
not yet fixed, the assertion still asserts the truth and its message says what
would have changed if it starts failing — the `ListParts` stub is asserted as
`deviation D5 may be fixed; ListParts now reports %d parts`, so the day the stub
goes, the test tells you it is your turn to fix the assertion. A test that
quietly encodes a bug as intended behaviour is worse than no test.

**For crypto, a green suite is not evidence.** See the mutation-round convention
in [storage-format.md](storage-format.md).
