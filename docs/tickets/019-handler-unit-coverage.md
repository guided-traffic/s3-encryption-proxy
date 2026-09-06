# Ticket 019: Handler-level unit coverage

## Status (2026-09-06)

**Open, and deliberately blocked on ticket 013 (storage format v2).** Do not start
this work before v2 has landed. Half the code these tests would pin is code v2
deletes: the GCM/CTR split in the PUT and GET paths, the early-HMAC machinery
(`shouldValidateHMACEarly`, `validateHMACEarly`), the ranged-read fork and
`serveRangeByFullDecryption` in
[range.go](../../internal/proxy/handlers/object/range.go) with the CTR reader behind
them in [rangeread.go](../../internal/orchestration/rangeread.go), the post-Complete
self-`CopyObject`, and the whole `integrity_verification` branch set. A test
suite written now would be rewritten line for line, and worse, it would make the
v2 change look like a regression because the tests encode today's behaviour as
the contract. This is exactly what D-17 decided: *"Own ticket, scheduled after
v2. Handler tests written now would test code v2 deletes."*

Source of the decision: the Velero path review, D-17 — defined in the
[label index](README.md#decisions-d-1-to-d-19) — together with the coverage gaps
that round left open, which this ticket carries in the sections below.

---

## Context

`internal/proxy/handlers/object` is the layer where every client-visible
decision is made — which PUT path an object takes, which headers reach the
backend, which headers reach the client, what is filtered out of the metadata
map. It is at **43.6 % of statements**. Measured with
`go test -short -cover ./internal/proxy/...` on `087f739`, which is the number
this ticket starts from; the **9.1 %** the ticket was written against
(`bc6a37a`) is the figure before the pre-merge fix round, and it is quoted below
only to say what moved and why.

| Package | Now (`087f739`) | When this ticket was written (`bc6a37a`) |
|---|---|---|
| `internal/proxy` | 44.2 % | 38.4 %, including 172 uncovered statements of a dead mock, see below |
| `internal/proxy/handlers/object` | **43.6 %** | **9.1 %** — the subject of this ticket |
| `internal/proxy/handlers/bucket` | 62.8 % | 59.5 % |
| `internal/proxy/handlers/multipart` | 64.7 % | 53.2 % |
| `internal/proxy/handlers/root` | 9.4 % | 9.7 %, 248 uncovered statements of a mock, see below |
| `internal/proxy/handlers/health` | 0.0 % | 0.0 %, no test files at all |
| `internal/proxy/middleware` | 77.0 % | 77.0 % |
| `internal/proxy/request` | 53.8 % | 56.8 % |
| `internal/proxy/response` | 65.5 % | 47.9 % |
| `internal/proxy/utils` | 88.1 % | 85.9 % |

**Read the jump correctly, because it is the reason this ticket is still open.**
Every fix of the pre-merge round landed with a handler test, so what the object
package now has is coverage of the specific defects that round closed — not of
the paths as a whole. A number that quadrupled without anyone writing a test
*for coverage* is exactly the case where the number stops being informative.
D-17 was decided after that jump was known, and it still says: own ticket, after
v2.

Inside the object package, per file (`go tool cover -func` over the same
profile), with the pre-round figures beside them:

| File | Statements | Covered | Was |
|---|---|---|---|
| [operations.go](../../internal/proxy/handlers/object/operations.go) | 522 | **49.8 %** | 2.1 % |
| `test_helpers.go` (the mock) | 248 | 12.9 % | 1.6 % |
| [range.go](../../internal/proxy/handlers/object/range.go) | 143 | 65.0 % | 33.3 % |
| [helpers.go](../../internal/proxy/handlers/object/helpers.go) | 62 | 74.2 % | 40.4 % |
| [handler.go](../../internal/proxy/handlers/object/handler.go) | 54 | 42.6 % | 11.8 % |
| [tagging.go](../../internal/proxy/handlers/object/tagging.go) | 13 | 7.7 % | 0 % |
| [acl.go](../../internal/proxy/handlers/object/acl.go) | 11 | 9.1 % | 0 % |
| [metadata.go](../../internal/proxy/handlers/object/metadata.go) | 9 | 11.1 % | 0 % |
| [content_encoding.go](../../internal/proxy/handlers/object/content_encoding.go) | 10 | 100 % | 100 % |

The six functions this ticket names were all at **0.0 %** when it was written.
They are not any more, and the per-function figures are what the work items
below have to improve on rather than start from: `handleGetObject` 40.6 %,
`handleHeadObject` 59.3 %, `putObjectDirect` **0.0 %**,
`putObjectStreamingReader` 58.8 %, `putObjectAutoMultipart` 77.4 %,
`handleDeleteObjects` 59.6 %, plus `handleGetObjectRange` 34.9 %
([range.go:115](../../internal/proxy/handlers/object/range.go#L115)) and
`handlePutObject` still 13.5 % at the routing head.
`handleGetObjectStreamingDecryption` and `handleGetObjectMemoryDecryption`
([operations.go:110](../../internal/proxy/handlers/object/operations.go#L110),
[:249](../../internal/proxy/handlers/object/operations.go#L249)) are at 0.0 %,
and `putObjectDirect` — the small-object PUT path, the one BUG-001 broke — is
the only one of the six that no test reaches at all.

**Why this matters beyond a number.** The integration and e2e suites do cover
these paths end to end — that is why the defects F-1 to F-9 were found at all.
But they need Docker, they take minutes, and the e2e needs a kind cluster. A
regression in header handling or routing therefore surfaces long after the edit
that caused it, in a suite whose failure mode is a Velero backup that does not
complete rather than an assertion naming the header. Under the project threat
model (the backend is hostile; see
[SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md#11-the-s3-backend-is-hostile))
the header layer is not cosmetic: it is where the response is composed from an
allowlist rather than proxied, so nothing about the stored ciphertext — a
backend `x-amz-checksum-*` among it — can reach the client by being carried
along (that is the refutation of N-6 d, and it is a property worth a test even
though it was never a defect), where it filters `s3ep-*` metadata out of a
client response, and
after v2 it is where the fail-closed rule from N-1 lives — an object without the
proxy metadata must be an error under an encrypting provider, not a
pass-through. Those are one-line decisions that a second-long unit test can pin
and a ten-minute e2e should not have to.

The second, unglamorous half of the problem: **four of the five S3 backend
mocks in this repository are ordinary source files, not `_test.go` files**, so
their uncovered statements are counted as production code. That is also the whole
of the `handlers/root` number below.

---

## Scope

**In scope**

- D-17: handler unit tests against a mock backend for `handleGetObject`,
  `handleHeadObject`, `putObjectDirect`, `putObjectStreamingReader`,
  `putObjectAutoMultipart` and `handleDeleteObjects`.
- Coverage gap 4: an explicit part-size table test for `UploadPart` via
  aws-chunked.
- Cross-path header consistency: the entity-header drop on the auto-multipart
  path is already fixed (F-16/F-19), so what is in scope is folding the four
  duplicated header blocks into one source and the cross-path test that keeps a
  fifth copy from drifting.
- Conditional requests on PUT and on the multipart paths.
- `internal/proxy/middleware` coverage of what the SigV4 work on this branch did
  not reach.
- Mock hygiene: one mock, in `_test.go` files, asserted against the interface;
  delete the dead one.

**Out of scope, named so nobody assumes otherwise**

- D-11 / P-4, the `ListObjectsV2` document rewrite — its own ticket after v2.
- D-16 / P-5, bucket-configuration handlers with aws-chunked bodies — goes with
  the upload-checksum ticket (D-9), same parser, same test shape.
- `TestListBucketsOperation` counting buckets endpoint-wide and failing when
  another package creates one concurrently. Listed in the same findings section,
  but it is an integration-suite isolation bug (give the suite a per-package
  bucket namespace), not handler unit coverage. Fix it wherever the integration
  suite is next touched.
- Anything that requires a real backend to be meaningful: ciphertext
  round-trips, HMAC/AEAD verification, decryptability. Those stay in
  `test/integration` and `test/e2e/velero` and must not be weakened here.

---

## The mock situation (do this first)

Five `MockS3Backend` types exist:

| Where | Kind | Statements in the coverage denominator | Users |
|---|---|---|---|
| [internal/proxy/mock_s3_backend.go:15](../../internal/proxy/mock_s3_backend.go#L15) | hand-written stubs, **non-test file** | 172, **0 covered** | **none** |
| [internal/proxy/handlers/bucket/test_helpers.go:17](../../internal/proxy/handlers/bucket/test_helpers.go#L17) | testify, **non-test file** | 297, 126 covered | the bucket tests |
| [internal/proxy/handlers/object/test_helpers.go:12](../../internal/proxy/handlers/object/test_helpers.go#L12) | testify, **non-test file** | 248, 4 covered | one test file |
| [internal/proxy/handlers/root/test_helpers.go:12](../../internal/proxy/handlers/root/test_helpers.go#L12) | testify, **non-test file** | 248, 4 covered | one test file |
| [internal/proxy/handlers/multipart/multipart_test.go:29](../../internal/proxy/handlers/multipart/multipart_test.go#L29) | testify, in a `_test.go` file | 0 (correct) | the multipart tests |

The object and root copies are the same 524-line file twice: `diff` over the two,
package clause aside, reports only that one renamed an unused parameter from
`optFns` to `_` in eighteen methods. They have already drifted, cosmetically.

Two verified facts about the first one:

- Nothing references it. `grep -rn "proxy.MockS3Backend\|proxy.NewMockS3Backend"`
  over the tree returns nothing, and no file in `internal/proxy` outside
  `mock_s3_backend.go` mentions the type.
- It does not implement the interface it claims to mock. Adding
  `var _ interfaces.S3BackendInterface = (*MockS3Backend)(nil)` to package
  `proxy` fails to compile: *"missing method DeleteBucketPolicy"*. It also
  carries `GetBucketReplicationConfiguration` where
  [interfaces/s3_backend.go](../../internal/proxy/interfaces/s3_backend.go) declares
  `GetBucketReplication`. It is 533 lines of code that has drifted away from the
  interface without anyone noticing, because nothing compiles it against
  anything. Delete it (project rule: no backward compatibility, delete dead
  code).

The object-package mock **does** satisfy the interface (the same assertion
compiles in package `object`, and in `bucket` and `root` too), so it is a usable
base; it only needs to move into a `_test.go` file and gain the assertion so it
cannot drift the same way.

Effect on the reported numbers, computed from the coverage profiles rather than
guessed:

| Package | Today (`087f739`) | After the mock leaves the denominator |
|---|---|---|
| `internal/proxy` | 44.2 % | **88.4 %** (deleting the dead `mock_s3_backend.go`, 172 statements at 0 %) |
| `handlers/object` | 43.6 % | **52.8 %** (renaming `test_helpers.go`, 248 statements at 12.9 %) |
| `handlers/bucket` | 62.8 % | **72.1 %** (renaming `test_helpers.go`, 297 statements at 43.4 %) |
| `handlers/root` | 9.4 % | **73.3 %** (renaming `test_helpers.go`, 248 statements at 1.6 %) |

(Recomputed on `087f739` from the current profiles, not carried over: the mocks
have picked up incidental coverage since this table was first written, which is
why three of the four "after" numbers moved.)

**Say this plainly in the commit message: that is a denominator correction, not
new testing.** It removes untested non-test code from the measurement; it does
not test one additional line of the proxy. The real target is further down.

---

## What the handler tests look like

The wiring already exists and needs no new abstraction. `Handler` holds the
backend as an interface
([handler.go:17](../../internal/proxy/handlers/object/handler.go#L17),
field `s3Backend interfaces.S3BackendInterface`, taken by `NewHandler` at
[:33](../../internal/proxy/handlers/object/handler.go#L33)), and the encryption manager as a
concrete `*orchestration.Manager`. A real manager is cheap to build in a unit
test: `orchestration.NewManager` takes a `*config.Config` built in code and does
**no** license validation — that lives in `config.LoadAndStartLicense`
([config.go:246](../../internal/config/config.go#L246)) and the config validation
path, neither of which a handler test touches. The multipart package already
does exactly this in
[multipart_test.go:347](../../internal/proxy/handlers/multipart/multipart_test.go#L347)
(`setupMultipartTestEnv`, AES provider, base64 key inline). Copy that shape.

Two existing tests show the two ends of the range: the pure-passthrough style in
[delete_object_test.go](../../internal/proxy/handlers/object/delete_object_test.go)
(construct `&Handler{}` with only the fields the function uses) and the
full-environment style in `setupMultipartTestEnv`. GET/PUT need the second.

Per handler, the assertions that earn their place — all of them on the *captured
input struct* or the *recorder*, never on stored bytes:

**`handleGetObject`** ([operations.go:26](../../internal/proxy/handlers/object/operations.go#L26))
— `If-Match` / `If-None-Match` are forwarded onto `GetObjectInput`
([:45](../../internal/proxy/handlers/object/operations.go#L45)); the response
`Content-Length` is the plaintext length, not the stored length; `s3ep-*` keys
never appear as `x-amz-meta-*` on the response; backend `x-amz-checksum-*`
values are **not** forwarded on a decrypted body. On that last one, do not
write the test as the lock on a fix: **N-6 (d) was refuted, not fixed** — no
response path ever emitted such a header. `writeGetObjectResponse`
([:295](../../internal/proxy/handlers/object/operations.go#L295)) sets the
headers it names and nothing else, and the backend client runs with
`ResponseChecksumValidation = WhenRequired`
([server.go:172](../../internal/proxy/server.go#L172)). The assertion already
exists as `assertNoChecksumHeaders`
([object_test.go:272](../../internal/proxy/handlers/object/object_test.go#L272),
three call sites); what is wanted here is that it keeps being called from every
new response test, not a new fix. N-1
fail-closed is **not** tested here: ticket 013 item 4 owns both that change and
its per-verb unit tests, and duplicating them would leave two suites asserting
one contract.

**`handleHeadObject`** ([operations.go:722](../../internal/proxy/handlers/object/operations.go#L722))
— `Accept-Ranges: bytes` is set; the four entity headers at
[:803](../../internal/proxy/handlers/object/operations.go#L803) survive;
`Content-Length` matches what GET would deliver (this is F-7 and it has no unit
test); metadata filtering as above.

**`putObjectDirect`** ([operations.go:501](../../internal/proxy/handlers/object/operations.go#L501))
— `PutObjectInput.ContentLength` equals `ComputeCiphertextSize(len, algorithm)`
and not the plaintext length (the `none` provider is the one exception: empty
metadata takes the plaintext branch at
[:578-582](../../internal/proxy/handlers/object/operations.go#L578));
`Content-Encoding: aws-chunked` is stripped and a
genuine `gzip` survives (F-8; `StripAWSChunked` is unit-tested, its call site is
not); the four entity headers reach the input via
[`addRequestHeaders`](../../internal/proxy/handlers/object/helpers.go#L109), called
at [:573](../../internal/proxy/handlers/object/operations.go#L573).

**`putObjectStreamingReader`** ([operations.go:574](../../internal/proxy/handlers/object/operations.go#L574))
— the same header set, built by a **second, inline copy** of that logic at
[:691](../../internal/proxy/handlers/object/operations.go#L691); a body with no
usable length answers `411 MissingContentLength` rather than buffering; the
client `Content-MD5` is **not** forwarded with the ciphertext
([:670](../../internal/proxy/handlers/object/operations.go#L670) — N-6 b, fixed
before merge, locked here).

**`putObjectAutoMultipart`** ([operations.go:1017](../../internal/proxy/handlers/object/operations.go#L1017))
— the part table it builds; abort on a mid-stream `UploadPart` failure; and the
cross-path header item below.

**`handleDeleteObjects`** ([operations.go:797](../../internal/proxy/handlers/object/operations.go#L797))
— `VersionId` is forwarded per object; a malformed body answers `MalformedXML`
and not 500; a key containing `&` and `<` survives an `encoding/xml` round trip
of the response. That last one is a lock, not a fix: the handler already marshals
its `DeleteResult` with `encoding/xml`
([:950](../../internal/proxy/handlers/object/operations.go#L950)), so it is **not**
one of the P-6 string-concatenation sites. Note that it reads the body with a
raw `io.ReadAll` at
[:834](../../internal/proxy/handlers/object/operations.go#L834) rather than through
`Parser.ReadBody` — that is P-5 and belongs to the D-9 ticket, but this test
will fail the moment someone frames that body as aws-chunked, which is the point.

---

## Cross-path header consistency (defect closed, drift risk open)

**The defect is fixed; do not re-fix it.** This section used to report a verified
bug: `putObjectAutoMultipart` built `CreateMultipartUploadInput` with `Bucket`,
`Key`, `ContentType` and the `x-amz-meta-*` map only, so the same PUT with the
same headers stored different object metadata depending on nothing but whether
the body crossed `streaming_threshold`. F-16 and F-19 of the 2026-09-06 fix round
(`c359091`, `ae1c828`, `d4553d4`, `087f739`) closed exactly that, and this ticket
is now the only place that records the overtake. Without this note somebody
starts here, writes the four-line fix a second time, and writes a regression test
for a bug that is no longer in the tree.

Verified against `087f739`. Every path sets `Cache-Control`,
`Content-Disposition`, `Content-Encoding` (with `aws-chunked` removed by
`StripAWSChunked`) and `Content-Language`:

| Path | Where the four headers are set |
|---|---|
| `putObjectDirect` | [`addRequestHeaders`](../../internal/proxy/handlers/object/helpers.go#L150), called at [operations.go:537](../../internal/proxy/handlers/object/operations.go#L537) |
| `putObjectStreamingReader` | inline copy, [operations.go:655-669](../../internal/proxy/handlers/object/operations.go#L655) |
| `putObjectAutoMultipart` | inline copy on the create input, [operations.go:1035-1047](../../internal/proxy/handlers/object/operations.go#L1035); the self-copy restates them from that same struct at [operations.go:1351-1354](../../internal/proxy/handlers/object/operations.go#L1351), because `MetadataDirective: REPLACE` drops whatever the copy does not restate |
| client-driven `CreateMultipartUpload` | inline copy, [create.go:77-93](../../internal/proxy/handlers/multipart/create.go#L77) |
| client-driven `CompleteMultipartUpload` | [`restateStoredAttributes`](../../internal/proxy/handlers/multipart/complete.go#L323) reads them back off the stored object with a `HeadObject`, since the create-time headers are not on that request |

`Expires` is the one entity header no path forwards; it needs time parsing and is
dropped consistently everywhere, which is a gap but not an inconsistency, and not
in scope here.

**What remains open is the shape and the test, not the behaviour.**

*The shape.* There are now four independent copies of the same four `if` blocks,
one per input type, plus the two copy-side restatements. `addRequestHeaders` still
has exactly one call site, so it is a helper in name only. Nothing makes a fifth
path, or a fifth header, break the build — and the closed defect is precisely what
that looks like when it happens. The input structs differ (`PutObjectInput`,
`CreateMultipartUploadInput`, `CopyObjectInput`), so the single source has to be
the *header set* rather than the assignment: one function that resolves the four
request headers into a small value, and one short applier per input type. That is
a consolidation, not a new layer — it deletes three copies and leaves one list of
which headers count.

*The test.* Nothing asserts that the paths agree. Two paths have a per-path
assertion —
`TestPutObjectAutoMultipart_SelfCopyOutlivesRequestAndOwnsETag`
([object_test.go:602](../../internal/proxy/handlers/object/object_test.go#L602),
which checks the create input and the copy input) and
`TestCreateHandler_ForwardsUserMetadata`
([multipart_test.go:955](../../internal/proxy/handlers/multipart/multipart_test.go#L955))
— while `putObjectDirect` and `putObjectStreamingReader` have no entity-header
test at all, and no test anywhere drives one request through more than one path.
Neither do the suites below: `grep -rn "Cache-Control\|Content-Disposition\|Content-Language" test/`
returns nothing, so the integration and e2e runs never look at these headers. The
three PUT paths agree by inspection today, and only by inspection.

The assertion to write is one table over three captures, not three separate
tests: a single request carrying all four headers with
`Content-Encoding: aws-chunked,gzip`, driven through `putObjectDirect`,
`putObjectStreamingReader` and `putObjectAutoMultipart` against the mock backend,
asserting the captured inputs carry the *same* four values. After ticket 013
item 6 collapses the first two into one writer the table has two rows in the
object package, and the client-driven create in `handlers/multipart` is the third
site that must not drift away from them. The two copy-side restatements go away
with v2, which removes the self-copy.

---

## Conditional requests

Covered today on GET only, and only end to end:
`test/integration/s3-methods/error_mapping_test.go:159-174` asserts a failed
`If-Match` is 412 and a matching `If-None-Match` is 304. The forwarding code is
[operations.go:45-50](../../internal/proxy/handlers/object/operations.go#L45) for
the whole-object path and
[range.go:127-132](../../internal/proxy/handlers/object/range.go#L127) for the
ranged path.

Not forwarded anywhere else, verified by grep — the only `IfMatch`/`IfNoneMatch`
occurrences in the tree are those two sites:

- `PutObjectInput` on both single-part paths: the SDK carries `IfMatch` and
  `IfNoneMatch` (`api_op_PutObject.go:497,513`), the proxy sets neither. A client
  using `If-None-Match: *` for a compare-and-swap create gets a **silent
  unconditional overwrite** instead of a 412. That is a correctness gap with a
  data-loss shape, not merely a missing test.
- `CompleteMultipartUploadInput` likewise (`api_op_CompleteMultipartUpload.go:323,339`).
- `HeadObjectInput` likewise (`api_op_HeadObject.go:239,273`); `handleHeadObject`
  builds the input with `Bucket` and `Key` only
  ([operations.go:760](../../internal/proxy/handlers/object/operations.go#L760)).

Forward them on all four inputs, unit-test the forwarding against the mock, and
add one integration assertion for the PUT case so the backend semantics are
exercised at least once.

---

## Gap 4: part-size table for `UploadPart` via aws-chunked

Status in the findings doc: *partly closed* — the path is reached over HTTPS and
by e2e V1b, but no test varies the part size. Verified: every multipart client in
`test/integration` uses a single 5 MiB `PartSize`
(`performance-test/performance_test.go:172,314,631`,
`360-degree-variants/hmac_validation_test.go:100,173,223,385,431,553`,
`180-degree-variants/test_constants.go:12`, used by
`180-degree-variants/large_multipart_upload_test.go`). Every `PartSize` in the
suite is 5 MiB. One size, forever.

That is precisely the dimension storage format v2 makes load-bearing: v2 requires
that every part except the last has the same size, that the size is a multiple of
the 65536-byte segment, and that the recorded offsets agree — checked at Complete,
with `InvalidPart` and an abort on violation. A table test is the cheapest way to
prove the rule holds and that a violation fails loudly instead of creating an
unverifiable object.

Table dimensions, driving `UploadHandler.Handle`
([upload.go:50](../../internal/proxy/handlers/multipart/upload.go#L50)) with
aws-chunked bodies against the mock backend:

- 5 MiB (aws-sdk-go-v2 `manager.Uploader` default, the Velero path), 8 MiB
  (aws-cli), 16 MiB (minio-go rounding), and the configured
  `streaming_segment_size` of 12 MiB;
- a short last part, a single-part upload, and a part of exactly one segment;
- one part size that is **not** a multiple of 65536 — must fail at Complete
  after v2, not at UploadPart;
- both aws-chunked framings (signed chunks and
  `STREAMING-UNSIGNED-PAYLOAD-TRAILER`), reusing the body builders already in
  [parser_test.go](../../internal/proxy/request/parser_test.go) and
  [streaming_aws_decoder_test.go](../../internal/proxy/request/streaming_aws_decoder_test.go).

While in that handler: it still calls `Parser.ReadBody`
([upload.go:77](../../internal/proxy/handlers/multipart/upload.go#L77)) **before**
validating `uploadId` and `partNumber`
([upload.go:87](../../internal/proxy/handlers/multipart/upload.go#L87)), and still
`io.ReadAll`s the ciphertext at
[upload.go:203](../../internal/proxy/handlers/multipart/upload.go#L203). That is
ticket 012 item 2.1, unfixed on this branch. v2 rewrites this handler; add a test
that a request with a bad `partNumber` is rejected without the body being read,
so the rewrite cannot quietly keep the old order.

---

## Middleware

The findings doc says the SigV4 header path is untested. **That is stale** —
[s3auth_header_test.go](../../internal/proxy/middleware/s3auth_header_test.go) was
added on this branch (`52e948b`) with four tests (SDK-signed headers, tampering,
malformed headers, clock skew), and the package is at 77.0 %. What is actually
left, from `go tool cover -func`:

| Symbol | Coverage |
|---|---|
| [cors.go:15,22](../../internal/proxy/middleware/cors.go#L15) `NewCORS`, `Middleware` | 0 % |
| [logging.go:17,25,61](../../internal/proxy/middleware/logging.go#L17) `NewLogger`, `Middleware`, `WriteHeader` | 0 % |
| [tracking.go:17,24,30](../../internal/proxy/middleware/tracking.go#L17) `NewRequestTracker`, `SetHandlers`, `Middleware` | 0 % |
| [s3auth_robust.go:447](../../internal/proxy/middleware/s3auth_robust.go#L447) `getClientIP` | 50 % |
| [s3auth_robust.go:267](../../internal/proxy/middleware/s3auth_robust.go#L267) `validateSignature` | 58.8 % |
| [s3auth_robust.go:222](../../internal/proxy/middleware/s3auth_robust.go#L222) `validateTimestamp` | 60.9 % |
| [s3auth_robust.go:303](../../internal/proxy/middleware/s3auth_robust.go#L303) `buildCanonicalRequest` | 71.4 % |
| [s3auth_robust.go:465,470](../../internal/proxy/middleware/s3auth_robust.go#L465) `GetSecurityMetrics`, `ResetSecurityMetrics` | 0 % |

The last row is listed only for completeness: both are accessors on the
`FailedAttempts` map that N-5 deletes, so they should disappear rather than gain
a test.

`getClientIP` is the one with a security edge: it reads the first
`X-Forwarded-For` value, an attacker-chosen string, and that value keys the
failed-attempt map that N-5 says is unbounded. The configuration-hygiene ticket
(D-6, D-7, N-5) deletes that map; this ticket only has to cover what survives,
so **sequence this item after that ticket or skip the map entirely**. Cover all
four branches (`X-Forwarded-For` present / multi-valued, `X-Real-IP`, and the
`RemoteAddr` fallback) and the residual signature and timestamp branches.
`cors`, `logging` and `tracking` are three small middlewares; one table test
each.

---

## Work breakdown

Ordered. Items 1 and 2 are mechanical and land first because everything after
them is measured against the corrected denominator.

- [ ] 1. Delete [internal/proxy/mock_s3_backend.go](../../internal/proxy/mock_s3_backend.go)
      (533 lines, no users, does not satisfy `S3BackendInterface`). `go build ./...`
      and `make test-unit` prove it.
- [ ] 2. Rename `internal/proxy/handlers/object/test_helpers.go`,
      `internal/proxy/handlers/bucket/test_helpers.go` and
      `internal/proxy/handlers/root/test_helpers.go` to `*_test.go` files and add
      `var _ interfaces.S3BackendInterface = (*MockS3Backend)(nil)` to each, so a
      future interface change breaks the build instead of the mock drifting.
      Commit message states explicitly that the resulting percentage jump is a
      denominator correction, not coverage.
- [ ] 3. Decide and record: one shared testify mock (proposal:
      `internal/proxy/testmock`, imported by the four handler packages that need
      one) versus four per-package copies. The object and root copies are already
      the same file twice, and the dead one in `internal/proxy` drifted off the
      interface entirely; a shared mock costs an import and gains one interface
      assertion. If shared, do the move here, before any test is written against
      a copy.
- [ ] 4. Object-package test scaffolding: a `setupObjectTestEnv` mirroring
      [multipart_test.go:347](../../internal/proxy/handlers/multipart/multipart_test.go#L347)
      (AES provider config in code, real `orchestration.Manager`, mock backend,
      `httptest` recorder, `mux.SetURLVars`), plus a `none`-provider variant.
- [ ] 5. `handleGetObject` tests: conditional-header forwarding, plaintext
      `Content-Length`, `s3ep-*` metadata filtered from the response, and backend
      `x-amz-checksum-*` not forwarded. N-1 fail-closed is ticket 013 item 4, not
      this item.
- [ ] 6. `handleHeadObject` tests: `Accept-Ranges`, the four entity headers,
      plaintext `Content-Length` agreeing with GET, metadata filtering.
- [ ] 7. `putObjectDirect` tests: ciphertext `ContentLength` (plaintext length
      under the `none` provider), aws-chunked stripped from `Content-Encoding`
      while `gzip` survives, entity headers forwarded.
- [ ] 8. `putObjectStreamingReader` tests: same header set, `411` on unknown
      length, client `Content-MD5` not forwarded with ciphertext.
      **Items 7 and 8 collapse into one after v2.** Ticket 013 item 6 replaces
      both functions with a single segmented writer and removes the size-based
      routing, so there is one PUT path left to test and its name is whatever v2
      gives it. Re-read the six function names in Context and in the success
      criteria against the post-v2 code before starting.
- [ ] 9. Consolidate the entity-header logic. The auto-multipart drop is already
      fixed, so this is not a behaviour change: replace the four copies of the same
      four `if` blocks with one resolver plus a short applier per input type
      (`PutObjectInput`, `CreateMultipartUploadInput`, `CopyObjectInput`), then a
      table test asserting the *same* stored headers for the same request across
      all three PUT paths — that is the assertion, not three separate ones. See the
      cross-path section above for the verified per-path sites.
- [ ] 10. `putObjectAutoMultipart` tests: part table, and abort called on a
      mid-stream `UploadPart` failure with a context that is not the (possibly
      cancelled) request context (P-8).
- [ ] 11. `handleDeleteObjects` tests: `VersionId` forwarded, `MalformedXML` on a
      bad body, `&` and `<` in a key surviving an `encoding/xml` round trip.
- [ ] 12. Conditional requests on writes: forward `If-Match`/`If-None-Match` onto
      `PutObjectInput` (both paths), `CompleteMultipartUploadInput` and
      `HeadObjectInput`; unit tests for the forwarding; one integration assertion
      that `If-None-Match: *` on an existing key answers 412.
- [ ] 13. Gap 4: the `UploadPart` part-size table over both aws-chunked framings,
      including the non-multiple-of-segment case that must fail at Complete, and
      the "bad partNumber rejected before the body is read" case.
- [ ] 14. Middleware: table tests for `cors`, `logging`, `tracking`; residual
      branches of `validateSignature`, `validateTimestamp`, `buildCanonicalRequest`;
      `getClientIP` branch selection **only after** the N-5 deletion has landed.
- [ ] 15. Re-measure, record the per-package numbers in this ticket, and delete
      any test that turned out to assert nothing beyond "the mock was called".

---

## Success criteria

Verified, not asserted. Every number below is measured with the same command as
the baseline in Context, so the two are comparable.

- [ ] `go test -short -cover ./internal/proxy/...` reports:
      `handlers/object` **≥ 65 %**, `handlers/multipart` **≥ 70 %**,
      `middleware` **≥ 85 %**, `internal/proxy` **≥ 85 %**, `handlers/root`
      **≥ 73 %** (item 2 alone reaches that), and no package in the tree below
      its baseline number above. These floors were raised on `087f739` to stay
      above the coverage the pre-merge fix round already brought in — the old
      ones (55 / 65 / 85 / 75 / 74) were set against a 9.1 % object package and
      three of them are satisfied by doing nothing.
- [ ] `go tool cover -func` on the object package shows **no 0.0 %** entry for
      `handleGetObject`, `handleHeadObject`, `putObjectAutoMultipart`,
      `handleDeleteObjects` and the single PUT writer that ticket 013 item 6 puts
      in place of `putObjectDirect` and `putObjectStreamingReader`, and each is at
      **≥ 70 %** of its own statements. The percentage is a floor; the named test
      list is the actual criterion.
- [ ] These tests exist and fail against the pre-fix code (state the commit they
      were checked against): the conditional-write forwarding tests (item 12) and
      the part-size table (item 13). The cross-path header equality test (item 9)
      is the exception and must be stated as one: the defect it describes is
      already fixed, so it passes on `087f739` by construction — it exists to fail
      on the *next* divergence, and it is proven by deleting one of the four header
      blocks locally and watching it fail.
- [ ] `make test-unit` is green and `go test -short ./internal/proxy/handlers/object/`
      completes in **under 10 s** on a laptop with no Docker running. Baseline on
      this branch, `-count=1` after `go clean -testcache`: 0.45 s of package time,
      1.2 s wall clock including the build (M-series, warm build cache). If the
      suite needs a container, it is in the wrong package.
- [ ] `make test-integration` and `make test-integration-tls` green against a
      fresh stack from `./start-demo.sh`. No integration test is deleted, skipped
      or weakened by this ticket — a handler test never replaces one.
- [ ] `make test-integration-performance` green, and its numbers unchanged: this
      ticket adds no production code beyond the header-logic consolidation and the
      conditional-header forwarding, so any movement is a signal, not noise.
- [ ] `make e2e-velero` green (all 13 scenarios in `test/e2e/velero`).
- [ ] `make lint` green, including on the renamed mock files.
- [ ] The four percentage jumps that come from removing mock statements from the
      denominator (`internal/proxy`, `handlers/object`, `handlers/bucket`,
      `handlers/root`) are labelled as such in the commit message and in the
      closing note of this ticket.

---

## Risks and open questions

- **The v2 dependency is the whole risk.** If this is started before ticket 013
  merges, items 5 to 10 test code that no longer exists. If v2 slips more than a
  release, the parts of this ticket that do not depend on the storage format —
  items 1, 2, 3, 9, 11, 12 and 14 — can be
  pulled forward on their own. Items 5, 6, 7, 8, 10 and 13 cannot.
- **A mock proves plumbing, not cryptography.** These tests assert on captured
  `*s3.PutObjectInput` / `*s3.UploadPartInput` values and on the recorder. They
  cannot show that what was stored decrypts, that an HMAC verifies, or that a
  real SDK client accepts the response. The moment somebody argues an integration
  test is redundant because "the handler is unit-tested", this ticket has done
  harm. Say so in `DEVELOPER.md` when the suite lands.
- **`*orchestration.Manager` is concrete in the `Handler` struct**
  ([handler.go:16-29](../../internal/proxy/handlers/object/handler.go#L16)), so
  every handler test constructs a real manager with real AES keys. That is
  workable today and is what the multipart tests already do, but it couples the
  handler suite to the orchestration API. Introducing an interface just for
  testability would be a speculative layer (project rule 2) — do not, unless v2
  makes the manager expensive to construct. Open question for whoever does v2:
  does `NewManager` stay cheap and side-effect-free? It starts a background
  cleanup goroutine when `MultipartSessionCleanupInterval > 0`
  ([manager.go:88](../../internal/orchestration/manager.go#L88)); the config default
  is 300, so a hand-built test config must leave the field at zero or the suite
  leaks goroutines.
- **Coverage percentages are gameable and this ticket names four ways to move
  them without testing anything.** Reviewers should check the named test list
  first and the number second.
- **Unverified:** that the auto-multipart header drop was ever hit by a real
  client before F-16 closed it. It was verified in the code and no bug report was
  ever attached to it, which is the argument for item 9: a defect that only code
  reading found, in logic that is still copied four times, will be found the same
  way the next time or not at all.
- **Unverified:** whether any client in scope actually uses conditional PUT
  against this proxy. Velero and kopia do not, as far as the e2e shows. The gap
  is still worth closing because the failure mode is a silent overwrite rather
  than an error, which is the wrong direction under this threat model.
- The `handlers/health` package has no test file at all (0.0 %). `handlers/root`
  reads 9.7 % only because its 248-statement mock sits in the denominator —
  item 2 moves it out and the package reports 74.2 % without a line of new
  testing, which is the same denominator correction as everywhere else and must
  be labelled as one. Neither package is otherwise in scope here; if the numbers
  are being looked at anyway, `handlers/health` is the cheapest one left.
