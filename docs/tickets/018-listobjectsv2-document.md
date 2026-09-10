# Ticket 018: ListObjectsV2 — a real S3 document and plaintext sizes

## Status (2026-09-10) — **the work landed; two items left**

**Implemented on `feat/major-v5` in d696763.** Both object listings and
`ListBuckets` build an S3 document, the dropped parameters are forwarded,
`max-keys` is honoured, `<Size>` is the plaintext size and `HEAD /{bucket}` calls
the backend's `HeadBucket`.
[ADR 0010](../adr/0010-sizes-and-listings-describe-the-plaintext.md) records the
decision; `README.md` carries the client-facing rules.

Gates when it landed: `go build`, `go vet`, `gofmt` and `go test -short` clean;
`make test-integration` and `make test-integration-tls` green against a rebuilt
demo stack; `gosec` 0 issues.

**Nothing below is a plan.** What is left is two items; the rest of the file is
the measurement record and four things found and not fixed. **Delete this file
once those two are done** — the decision is in ADR 0010 and the operator-facing
consequence is in `README.md`, so nothing needs moving out first.

---

## Still to do

- **The listing benchmark.** Record the wall time of the 2500-key paginated
  listing against the same listing issued straight to MinIO. A recorded number,
  not a gate — [ADR 0020](../adr/0020-performance-is-measured-before-and-after.md).
  The instrument does not exist:
  [performance_test.go](../../test/integration/performance-test/performance_test.go)
  calls `ListObjectsV2` only to empty a bucket between runs
  ([:245](../../test/integration/performance-test/performance_test.go#L245) and
  [:430](../../test/integration/performance-test/performance_test.go#L430)), and
  nothing in the package times a listing. The expectation is a small constant
  factor from building the document; a per-key backend round trip would show up
  as an order of magnitude, and that is the thing the number is watching for.
- **The Velero end-to-end suite.** `make e2e-velero` (or `make e2e-up` then
  `make test-e2e-velero`), all 13 scenarios. It has not been run since this
  landed — nor since the storage format did. Velero lists `backups/` and
  `restores/` with a delimiter on every reconcile and kopia lists blob prefixes
  constantly, so a broken listing shows up there as a backup that never appears
  rather than as an error.

---

## Found while doing it, not fixed

Each re-verified against the tree on 2026-09-10.

- **`handleHeadBucket` drops `x-amz-expected-bucket-owner`.** The header reaches
  the handler and never reaches the backend input:
  [bucket/operations.go:116-121](../../internal/proxy/handlers/bucket/operations.go#L116-L121)
  builds `HeadBucketInput` with `Bucket` alone, while `handleDeleteBucket` two
  functions above it does forward the header
  ([:93-94](../../internal/proxy/handlers/bucket/operations.go#L93-L94)). A client
  using it as a guard against a re-created bucket is not guarded. Pinned by a
  handler test that says so, `expected_bucket_owner_is_not_forwarded`
  ([operations_coverage_test.go:1311](../../internal/proxy/handlers/bucket/operations_coverage_test.go#L1311)).
- **`ListBuckets` serialises a missing creation date as the Go zero time**,
  `0001-01-01T00:00:00Z`, instead of omitting the element: `CreationDate` is a
  non-pointer `time.Time` with no `omitempty`
  ([root/handler.go:41](../../internal/proxy/handlers/root/handler.go#L41)) and
  stays zero when the backend sends nil
  ([:132-133](../../internal/proxy/handlers/root/handler.go#L132-L133)).
  Pre-existing.
- **`KeyCount` is forwarded from the backend** rather than recomputed from
  `Contents` plus `CommonPrefixes`
  ([bucket/listing.go:111](../../internal/proxy/handlers/bucket/listing.go#L111)).
  Against a backend that miscounts, the proxy repeats the miscount.
- **The element order of `ListAllMyBucketsResult` was never measured** — only the
  object listings were. The assertion at
  [listobjects_conformance_test.go:955-957](../../test/integration/s3-methods/listobjects_conformance_test.go#L955-L957)
  pins `Owner, Buckets, Prefix, ContinuationToken`, which is the proxy's own
  choice; the V2 and V1 orders next to it carry a "measured against the demo
  MinIO" note ([:50](../../test/integration/s3-methods/listobjects_conformance_test.go#L50),
  [:66](../../test/integration/s3-methods/listobjects_conformance_test.go#L66)) and
  this one cannot. A strict client would notice if it differs.

---

## What shipped

One line per closed work item, with where it now lives. Kept so the next reader
can find the pieces, not as instructions.

- **The document.** Both listings are built from explicit types in
  [bucket/listing_document.go](../../internal/proxy/handlers/bucket/listing_document.go):
  root `ListBucketResult` under the S3 namespace for V2 *and* V1, elements in the
  order MinIO emits (captured, see below), `LastModified` formatted to `.000Z`,
  and no `<ChecksumAlgorithm>`, `<ChecksumType>`, `<RequestCharged>` or
  `<ResultMetadata>` — a backend checksum describes ciphertext, so the honest
  answer is to emit none. The two `xml.NewEncoder(w).Encode(output)` calls over the
  SDK output struct are gone; `grep -rn "Encode(output)" internal/proxy/handlers`
  is empty.
- **The XML declaration** is written by
  [`XMLWriter.WriteS3Document`](../../internal/proxy/response/xml.go#L45), which
  marshals before it commits a status, so a marshalling failure answers 500 rather
  than a truncated body behind a 200 that already went out. `HandleListBuckets`
  uses it too; its hand-written declaration is gone.
- **The size.** [`Handler.reportedSize`](../../internal/proxy/handlers/bucket/listing.go#L31)
  calls [`dataencryption.PlaintextSize`](../../pkg/encryption/dataencryption/segmented_gcm.go#L208)
  per entry — one division, no metadata read, no extra request. **Two corrections
  against this ticket's original design:** the function returns `(int64, error)`,
  not the planned `-1` sentinel, and a rejected length is reported as the stored
  size verbatim; and the gate is
  [`Manager.IsExitProvider()`](../../internal/orchestration/manager.go#L81), not
  `IsNoneProvider` — [ADR 0025](../adr/0025-leaving-is-a-supported-mode.md)
  replaced the `none` provider with the exit provider and D8 there says a listing
  reports the stored size verbatim under it. The exactness of the inversion is a
  property of the format, argued and guarded in
  [segmented_gcm.go:205-230](../../pkg/encryption/dataencryption/segmented_gcm.go#L205-L230)
  ([ADR 0003](../adr/0003-objects-are-an-authenticated-segment-chain.md) D12a).
- **The mixed-bucket under-report is deliberate and pinned.** A foreign object
  whose stored length happens to be one a chain could have is reported short by
  the framing overhead; the alternative is a `HeadObject` per key, which is the
  round trip this whole design exists to avoid.
  [`TestLstListingUnderReportsForeignObjects`](../../test/integration/s3-methods/listobjects_conformance_test.go#L795)
  asserts both halves so nobody later "fixes" it with a per-key HEAD.
- **Parameters.** `start-after`, `fetch-owner` and `encoding-type` are forwarded
  and echoed ([bucket/listing.go:60](../../internal/proxy/handlers/bucket/listing.go#L60)
  for V2, [:147](../../internal/proxy/handlers/bucket/listing.go#L147) for V1, which
  also gained `max-keys` — it had none).
- **`max-keys`.** [`parseMaxKeys`](../../internal/proxy/handlers/bucket/listing_params.go#L23):
  absent means the backend default, `0`–`1000` is forwarded verbatim with `0`
  included, above `1000` is clamped, negative or non-integer is refused with
  `400 InvalidArgument`. The clamp is the proxy's own behaviour, not the
  backend's — measured, see below.
- **`encoding-type`.** The proxy always asks the backend for URL encoding so the
  backend→proxy XML is well formed whatever a key contains, decodes with
  `url.QueryUnescape` (the demo backend encodes a space as `+`, which
  `PathUnescape` would leave alone) and re-encodes only when the client asked
  ([listing_params.go:44](../../internal/proxy/handlers/bucket/listing_params.go#L44)
  and [:57](../../internal/proxy/handlers/bucket/listing_params.go#L57)).
  Round-tripped over `+`, a space, `&`, `<`, `%`, `%2B` and a non-ASCII character by
  [`TestLstListingEncodingTypeRoundTrip`](../../test/integration/s3-methods/listobjects_conformance_test.go#L1001).
- **`<Owner>` is the caller**, never the backend account — the access key that
  authenticated the request, on object listings
  ([`callerOwner`](../../internal/proxy/handlers/bucket/listing.go#L52)) and on
  `ListBuckets` ([root/handler.go:115-120](../../internal/proxy/handlers/root/handler.go#L115-L120)),
  per [ADR 0008](../adr/0008-every-response-describes-the-proxy.md).
- **`HeadBucket`** is the real operation
  ([bucket/operations.go:116](../../internal/proxy/handlers/bucket/operations.go#L116)),
  added to `S3BackendInterface`
  ([s3_backend.go:65](../../internal/proxy/interfaces/s3_backend.go#L65)), so a
  bucket that does not exist answers 404 instead of 200. `x-amz-bucket-region`
  falls back to the configured `s3_backend.region`, which is the normal path
  against a backend that returns none. The `ListObjectsV2(MaxKeys: 0)` existence
  probe is gone.
- **`ListBuckets`** gained the namespace and forwards `prefix`, `max-buckets`,
  `continuation-token` and `bucket-region`, emitting `<Prefix>` and
  `<ContinuationToken>`
  ([root/handler.go:63-89](../../internal/proxy/handlers/root/handler.go#L63-L89)).
  MinIO returns every bucket in one response, so the pagination forwarding is
  covered only by handler unit tests with a mocked backend
  ([listbuckets_coverage_test.go](../../internal/proxy/handlers/root/listbuckets_coverage_test.go));
  no integration test can fail on it.
- **The constructor.** [`bucket.NewHandler`](../../internal/proxy/handlers/bucket/handler.go#L45)
  takes `(s3Backend, encryptionMgr *orchestration.Manager, logger, cfg)`; the
  ignored metadata-prefix parameter is gone, wired at
  [router.go:62](../../internal/proxy/router.go#L62).
- **Tests.** Handler level over the raw response body in
  [bucket/operations_coverage_test.go](../../internal/proxy/handlers/bucket/operations_coverage_test.go)
  (root element, namespace, element order, the `max-keys` table, `<Owner>`
  presence, sizes). Integration level in
  [listobjects_conformance_test.go](../../test/integration/s3-methods/listobjects_conformance_test.go),
  rewritten from the file that used to pin the wrong behaviour: the 2500-key
  paginated fixture, delimiter roll-up, `MaxKeys=1`, `StartAfter`, sizes agreeing
  with HEAD and GET, the document fetched with a plain signed `http.Client`
  ([:845](../../test/integration/s3-methods/listobjects_conformance_test.go#L845))
  because the SDK hides the root element and the namespace, and `HeadBucket`
  ([:1093](../../test/integration/s3-methods/listobjects_conformance_test.go#L1093)).
  That last one is also what the plan called the strict-client check: a
  namespace-aware parse of a captured V2, V1 and `ListBuckets` response, run every
  suite rather than filed as three documents.
- **The flaky `TestListBucketsOperation`** was fixed in d4553d4, 2026-09-06: the
  endpoint-wide `len(minioOutput.Buckets) == len(proxyOutput.Buckets)` assertion is
  gone, because `go test` runs packages in parallel and any other package creating
  or deleting a bucket between the two listings failed a test that had nothing to
  do with it. Both listing tests scope themselves to the bucket they created
  ([list_buckets_test.go:61-77](../../test/integration/s3-methods/list_buckets_test.go#L61-L77)
  and [:192](../../test/integration/s3-methods/list_buckets_test.go#L192)). Recorded
  so the count does not come back.
- **Docs.** The listing section of `README.md` (from "Listings report the
  plaintext size too", `README.md:849`) states the document, the forwarded
  parameters, the `max-keys` rule including the clamp deviation, the plaintext-size
  rule, the mixed-bucket under-report and the region a client reads on
  `HeadBucket`.

`<StorageClass>` is forwarded from the backend, which is right — it is a property
of the stored object — but unverified against Glacier: a restore-in-progress
object would list as readable and then fail on GET. Never observed here, no
backend in this project has the feature.

---

The record, kept verbatim. It reads as future tense and refers to "the design
section below": that plan is gone from this file, and what it planned is the code
linked above. The three corrections are the reason the section is worth keeping —
they were caught because the plan said to capture a real response before locking
the assertions down.

## Measured against MinIO, 2026-09-10

Captured with a hand-signed SigV4 probe straight against the demo backend, before
any assertion was written. **Three assumptions in this ticket were wrong** and the
text below them is corrected.

### Element order — the real one

`ListBucketResult` (V2), in the order MinIO emits:

```
Name, Prefix, [StartAfter], [NextContinuationToken], KeyCount, MaxKeys,
[Delimiter], IsTruncated, Contents*, CommonPrefixes*, [EncodingType]
```

`Contents`, in order: `Key, LastModified, ETag, Size, [Owner], StorageClass`.

Three corrections against the struct sketched in the design section below:
`NextContinuationToken` comes **before** `KeyCount`, not after it; `EncodingType`
is the **last** element of the document, after `CommonPrefixes`, not an early one;
and `Owner` sits **between `Size` and `StorageClass`**, not at the end of the entry.

V1 is the same document without `KeyCount` and with `Marker` in place of the
continuation token — `Name, Prefix, Marker, MaxKeys, [Delimiter], IsTruncated,
Contents*, CommonPrefixes*, [EncodingType]` — and MinIO emits `<Owner>` on every
V1 entry whether or not it was asked for. The root element of V1 is
`ListBucketResult`, not `ListObjectsResult`.

`KeyCount` counts `Contents` **plus** `CommonPrefixes`: the delimiter probe over
three top-level keys and two rolled-up prefixes reported `KeyCount` 5.

### `max-keys` — MinIO does not clamp

| Input | MinIO | What the proxy will do |
|---|---|---|
| absent | `MaxKeys` 1000 | do not set it; the backend default applies |
| `0` | `KeyCount` 0, `MaxKeys` 0, **`IsTruncated` false** | forward verbatim |
| `2` (bucket has more) | `IsTruncated` true, `NextContinuationToken` set | forward verbatim |
| `5000` | **not clamped** — echoes `MaxKeys` 5000 and returns everything | **clamp to 1000** |
| `-1` | `400 InvalidArgument`, "Argument maxKeys must be an integer between 0 and 2147483647" | `400 InvalidArgument` |
| `abc` | `400 InvalidArgument`, same message | `400 InvalidArgument` |

Two corrections. The design section predicted `IsTruncated` **true** for
`max-keys=0` on a non-empty bucket; MinIO answers **false**, and the proxy forwards
what the backend says rather than inventing a value. And MinIO does not clamp above
1000, so the clamp is the proxy's own behaviour, matching documented S3
("the response ... will never contain more" than 1000) and deviating from the
backend it runs against. That deviation is deliberate and belongs in the README:
a client asking for 5000 gets at most 1000 through the proxy and up to everything
straight from MinIO.

### `encoding-type` — the risk is real and the mitigation holds

With `encoding-type=url` MinIO encodes a space as `+` (`sp ace.txt` comes back as
`sp+ace.txt`) and a non-ASCII byte as a percent triplet (`umläut.txt` →
`uml%C3%A4ut.txt`). `url.QueryUnescape` handles both; `url.PathUnescape` would
leave the `+` as a literal plus. This confirms the choice recorded under "Settled"
and it confirms the sharp edge: a key containing a **literal** `+` is only
recoverable if the backend percent-encodes it, which is exactly what the
round-trip test has to prove.

### `HeadBucket` — no region header from MinIO

`HEAD` on an existing bucket answers `200` with **no `x-amz-bucket-region` header
at all**; on a missing bucket it answers `404`. The fallback to the configured
`s3_backend.region` is therefore not a corner case but the normal path against
this backend, which is why the README has to state that the region a client reads
is the proxy's, not the backend's.
