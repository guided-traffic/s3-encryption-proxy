# Testing

Five layers, and they are not interchangeable. The rule that governs all of them
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
| Conformance | `make test-conformance` | `conformance` | What S3 specifies, against any backend. Free locally; the same binary runs weekly against a paid one, and the difference is the finding ([ADR 0027](../adr/0027-conformance-is-asserted-against-a-backend-that-is-not-minio.md)) |

**The build tag is what separates them, not `-short`.** `make test-unit` is
`go test -v -short ./...`, and `-short` today gates exactly two tests, both of
them behind the `integration` tag. What keeps the integration tree out of the
unit round is the tag on every file, nothing else.

Every file in the integration tree carries a build tag — `integration`, and
`conformance` in `test/integration/conformance/`. Four once carried none —
`bucket_acl_test.go`, `bucket_cors_test.go`, `bucket_location_test.go`,
`bucket_logging_test.go` — and they were deleted on 2026-09-12: 129 test cases
that imported no package of this project, asserting the test file's own helpers
and SDK constants against each other. One of them pinned a canned-ACL validation
the proxy does not perform at all. What the four names suggest is covered where
the code is, in `internal/proxy/handlers/bucket`. A new file in the integration
tree needs the tag its package uses.

Unit tests sit next to the code. `*_coverage_test.go` files are ordinary unit
tests from a coverage round.

**`make lint` compiles none of the tagged trees.** Its `go vet ./...` passes no
tag and `.golangci.yml` sets none, so a tagged file that does not compile passes
lint and fails later, in a suite. Check what you touched yourself:

```bash
go vet -tags=integration ./test/integration/...
go vet -tags=e2e ./test/e2e/...
go vet -tags=perf ./test/perf/...
go vet -tags=conformance ./test/integration/conformance/...
```

## The conformance suite, and the one rule that keeps it cheap

`test/integration/conformance/`, build tag `conformance`, [ADR 0027](../adr/0027-conformance-is-asserted-against-a-backend-that-is-not-minio.md).
It asserts what S3 specifies, takes its endpoints from the environment, and has
no branch on which backend is behind the proxy, so one binary serves them all.

One script drives every backend — `scripts/conformance-run.sh <backend> [--seed|--clean]`
— and it is the same script CI runs, so a runner and a laptop cannot drift apart.
Each backend gets its own container, its own bucket and **its own proxy port**,
which is what lets them run at once.

| Backend | What it is | Cost | When |
|---|---|---|---|
| `minio` | a standalone MinIO over the test PKI, started by the script | free | every change, in CI |
| `localstack` | LocalStack community, pinned to a tag — `:latest` now needs a licence | free | every change, in CI |
| `wasabi` | a paid third-party backend | **billed** | weekly, `conformance-paid.yml` |

```bash
make test-conformance            # both free backends, one after the other
make test-conformance-parallel   # both at once, which is what CI does
make test-conformance-wasabi     # read only against the paid backend
```

**They run in parallel, one runner per backend.** `fail-fast` is off on purpose:
when one backend disagrees, what the others did is the interesting half, and
cancelling them throws it away.

**The difference between the runs is the point.** MinIO is not S3: it accepts
`x-amz-expected-bucket-owner` and ignores it, so against MinIO alone a proxy that
forwards the header and one that drops it look identical. That is how the header
came to be dropped on 63 of 64 backend calls while the whole integration suite
stayed green. A test that cannot prove its point against the backend it is running
on logs `BACKEND DEVIATION` and says what it did prove instead — it does not skip,
because a suite that quietly stops asserting is worse than one that stops.

**What the deviations have found so far**, all three probed on 2026-09-11:

| | `x-amz-expected-bucket-owner` |
|---|---|
| MinIO | accepted and ignored |
| LocalStack 3.8 | accepted and ignored |
| Wasabi | accepted and ignored |

Three implementations, one answer, and it is worth knowing why rather than
treating it as three coincidences: the header checks an **AWS account id**, and an
S3-compatible implementation with no AWS account model has nothing to check it
against. LocalStack is the sharpest case — it does model account ids and still
does not enforce it. So the guard is, for these three backends, something the
client believes in and nothing downstream honours, which is the backend's gap
rather than the proxy's. Forwarding stays correct: a client pointed at AWS gets a
working guard, and one pointed at these three is no worse off than talking to
them directly.

**If you add a backend, use a wrong owner id that is owned by nobody.** The test
uses `999999999999` and not `000000000000`, because the latter is LocalStack's
default account id — against that backend it would be the *correct* owner, and the
success would be misread as the header being ignored.

**The cost rule, if you touch this suite:** the paid backend bills every written
byte for a minimum of ninety days and refunds nothing when the object is deleted.
So writing is confined to one place.

- Only `TestSeed` writes, only when `S3EP_CONFORMANCE_SEED=1`, and only through
  `Budget.Authorize`, which reserves against a ceiling **before** the request
  leaves. Every other test runs with a budget of zero and fails on its first byte.
- The seed is idempotent against the plaintext length, so a second run writes
  nothing. Steady state is zero.
- Deleting does not help and re-seeding does. That is why the corpus is a fixed
  set of keys rather than a fresh bucket per run — the inverse of every other
  suite here.

**Why it is small at all**: the stored format seals 64 KiB per segment, and the
segment size is a constant, not a setting — so boundaries, multi-segment reads
and cross-segment ranges cost kilobytes. A refused request stores nothing, so
every refusal is free to assert. The only expensive surface is a real multi-part
layout, because S3 refuses a part below 5 MiB unless it is the object's last. Two
paths need one each, and that is the whole ~10 MiB corpus.

Adding a corpus object means adding a recurring charge. The `Why` field on the
entry is where you justify it.

### The bucket policy the paid run needs

The credential is a **dedicated sub-user scoped to the one test bucket**, never
an account root key: if it leaks, the blast radius is a throwaway bucket. That is
also why the policy is written out here rather than left to whoever sets it up —
a permission granted "to make it work" tends to be `s3:*`.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:ListBucketMultipartUploads",
        "s3:GetBucketLocation"
      ],
      "Resource": "arn:aws:s3:::<bucket>"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:AbortMultipartUpload",
        "s3:ListMultipartUploadParts"
      ],
      "Resource": "arn:aws:s3:::<bucket>/*"
    }
  ]
}
```

**The three multipart actions are not optional, and leaving them out is a money
bug rather than a test failure.** The first run against Wasabi was made with a
policy that had the other five, and it found this:

| Missing action | What breaks | Why it costs |
|---|---|---|
| `s3:ListBucketMultipartUploads` | `TestNoDanglingMultipartUploads` answers `403` | An incomplete upload appears in **no object listing**. Without this action there is no way to find out one is open |
| `s3:AbortMultipartUpload` | every `t.Cleanup` abort answers `403` | The parts of an upload that was never completed are stored and billed. Without this action they cannot be removed with this credential at all |
| `s3:ListMultipartUploadParts` | `ListParts` cannot be verified against the backend | No cost, but the proxy's own part table is then asserted against nothing |

The failure mode the first two produce together is the bad one: a seed that dies
halfway through its 5 MiB multipart leaves those parts billed for the backend's
minimum storage period, invisible to a listing, and unremovable. **Grant them
before the first seed, not after.**

There is deliberately no `s3:CreateBucket` or `s3:DeleteBucket`: the operator
creates the bucket once, and a suite that could delete it could delete the wrong
one ([ADR 0027](../adr/0027-conformance-is-asserted-against-a-backend-that-is-not-minio.md) D9).

## Why the TLS run exists

It is not redundant. The AWS SDK emits its `STREAMING-UNSIGNED-PAYLOAD-TRAILER`
framing **only over HTTPS**, so the trailer decoder is reached by no other run. A
change to request parsing that passes `make test-integration` and is never run
over TLS is a change nobody tested.

The mechanism is one variable: `make test-integration-tls` runs the same packages
with `S3EP_TEST_PROXY_ENDPOINT` pointed at the TLS listener (the Makefile's
`PROXY_TLS_ENDPOINT`, `https://127.0.0.1:8443`). A suite that builds its own
listener never sees it — see *One suite starts the proxy in process*.

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

`conformance` is the seventh directory under the same path and is deliberately
not one of these: it carries the `conformance` tag, is driven by
`scripts/conformance-run.sh`, and is outside the Makefile's `INTEGRATION_PKGS`,
so neither `make test-integration` nor the TLS run touches it — see *The
conformance suite, and the one rule that keeps it cheap*.

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

## One suite starts the proxy in process

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

`test/perf` carries its own `perf` tag and **asserts nothing about throughput**:
it records, and a person compares two records
([ADR 0020](../adr/0020-performance-is-measured-before-and-after.md)). The one
carve-out is memory — the instrument samples the proxy's own resident memory and
fails on peak-minus-idle, against the bound the configuration budgets and against
the object size, because a proxy that buffered a whole object would show it there
(ADR 0020 D14). It is local by design and referenced by no workflow. The
commands and the traps are in [`test/perf/README.md`](../../test/perf/README.md);
what is easy to get wrong about a comparison is in [performance.md](performance.md).

One trap belongs here, because it looks like a broken suite and is not:
`go build -tags=perf ./test/perf/...` fails with three undefined endpoint
constants. `client.go` is a non-test file that uses constants declared in
`main_test.go`, which `go build` does not compile. `go vet -tags=perf` and
`go test -tags=perf` both see the test files and pass — they are the real gate.

## What CI runs

`.github/workflows/test-pipeline.yml` runs all five layers plus the performance package
on every pull request to `main` and every push to it. `semantic-release` needs
the malware scan, gosec, govulncheck, the linter, the unit tests, the race round,
the integration tests, the coverage report, the Helm chart job, both conformance
backends **and** the Velero suite, so a red suite blocks a release instead of
warning about one. The e2e job budgets 45 minutes for bring-up,
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
would have changed if it starts failing — the out-of-order
`CompleteMultipartUpload` the proxy sorts instead of refusing is asserted as
`deviation D1 may be fixed; the proxy now refuses: %s`, so the day the sort goes,
the test tells you it is your turn to fix the assertion. A test that quietly
encodes a bug as intended behaviour is worse than no test.

**For crypto, a green suite is not evidence.** See the mutation-round convention
in [storage-format.md](storage-format.md).

**When the defect is an omission, test the source, not the behaviour.** Some gaps
cannot be caught by a behavioural test, because the thing that goes wrong is a
call site nobody wrote a test for. `x-amz-expected-bucket-owner` was dropped on 63
of 64 backend calls while every one of those verbs had passing tests of its own
behaviour: each test asserted what its handler did, and none could assert what the
handler forgot. `TestEveryBackendCallCarriesTheOwnerGuard`
([bucketowner_guard_test.go](../../internal/proxy/request/bucketowner_guard_test.go))
parses the handler packages with `go/ast` and fails on an `s3.*Input` literal that
does not set the field.

Two things make that kind of test worth its weight rather than a maintenance tax.
It carries **no fixture to update** — it asserts a floor on how many call sites it
found, not a list of them, so adding a verb does not edit the test. And it was
**proven to bite**: one call site's line was removed, the test named the file and
the line, and the line was put back. A guard test nobody has watched fail is a
guard test nobody knows works.
