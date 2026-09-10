# Testing

Four layers, and they are not interchangeable. The rule that governs all of them
is [ADR 0019](../adr/0019-integration-and-e2e-tests-are-the-product.md): the
integration and end-to-end suites *are* the product's behaviour, so they are
never skipped, disabled or deleted to make a change land.

## The layers

| Layer | Command | Build tag | What it is for |
|---|---|---|---|
| Unit | `make test-unit` | none (`-short`) | Logic and edge cases against mocks. Fast enough to run on every save |
| Integration | `make test-integration` | `integration` | The real proxy against a real MinIO. This is where behaviour is decided |
| Integration over TLS | `make test-integration-tls` | `integration` | The same suites against the TLS listener |
| Velero end-to-end | `make test-e2e-velero` | `e2e` | One supported client, exercised whole, in a kind cluster |

Unit tests sit next to the code. `*_coverage_test.go` files are ordinary unit
tests from a coverage round.

## Why the TLS run exists

It is not redundant. The AWS SDK emits its `STREAMING-UNSIGNED-PAYLOAD-TRAILER`
framing **only over HTTPS**, so the trailer decoder is reached by no other run. A
change to request parsing that passes `make test-integration` and is never run
over TLS is a change nobody tested.

## Integration suites

Under `test/integration/<package>/`. `test/integration/` itself holds the helpers
— `minio_test_helper.go` builds a `TestContext` with both a proxy client and a
direct MinIO client, which is what lets a test compare what a client sees against
what is actually stored.

| Suite | Subject |
|---|---|
| `s3-methods` | The S3 API surface, verb by verb, against MinIO as the oracle |
| `360-degree-variants` | Round trips at many sizes, and what tampering with a stored object costs |
| `180-degree-variants` | Proxy-side behaviour without the backend comparison |
| `encryption-modes` | Provider configurations |
| `authentication` | SigV4 in both forms |
| `performance-test` | Proxy against MinIO throughput. Run alone, because the others would compete for the backend |

**MinIO is the oracle, the AWS documentation is the specification.** Where the
proxy and MinIO disagree, or both disagree with AWS, a test asserts the *actual*
behaviour and a comment above it names the deviation. That keeps the suite green
and the gap visible. Search for `DEVIATION` to find them; when one is closed, the
test flips to the correct behaviour and the deviation note goes.

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

The Velero suite costs much more: `make e2e-up` builds an image, creates a kind
cluster, installs MinIO over TLS, the CSI hostpath driver, the proxy chart and
Velero. It is idempotent and reloads a freshly built image, so retest a change
with `make e2e-up && make test-e2e-velero` rather than recreating the cluster.

## Writing a test that is worth having

**Assert what is stored, not only what round-trips.** A round trip proves the
proxy is self-consistent; it does not prove the bytes at rest are ciphertext, nor
that they are the length the format prescribes. The 360-degree suite checks the
exact stored length precisely because it is a pure function of the plaintext
length, and an off-by-one in the size arithmetic would round-trip fine.

**Compare payloads by SHA-256, never by dumping them.**

**A test that pins a defect says so.** If the behaviour under test is wrong but
not yet fixed, the assertion still asserts the truth and the comment says what
the right answer would be. A test that quietly encodes a bug as intended
behaviour is worse than no test — one of these got written during this work
("part 3 is missing from the list") and had to be caught in review.

**For crypto, a green suite is not evidence.** See the mutation-round convention
in [storage-format.md](storage-format.md).
