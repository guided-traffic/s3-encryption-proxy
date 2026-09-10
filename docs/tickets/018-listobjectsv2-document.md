# Ticket 018: ListObjectsV2 — a real S3 document and plaintext sizes

## Status (2026-09-10) — **the work landed; two items left**

**Implemented on `feat/major-v5`, 2026-09-10.** Both object listings and
`ListBuckets` build an S3 document, the parameters are forwarded, `max-keys` is
honoured, `<Size>` is the plaintext size and `HeadBucket` calls `HeadBucket`.
[ADR 0010](../adr/0010-sizes-and-listings-describe-the-plaintext.md) records what
shipped.

Gates when it landed: `go build`, `go vet`, `gofmt` and `go test -short` clean;
`make test-integration` and `make test-integration-tls` green against a rebuilt
demo stack; `gosec` 0 issues.

**What is left in this ticket:**

- **Item 4 of the success criteria** — record the wall time of the 2500-key
  paginated listing against the same listing issued straight to MinIO. A
  recorded number, not a gate. The instrument does not exist yet.
- **Item 5 of the success criteria** — the Velero end-to-end suite has not been
  run since this landed. Velero lists `backups/` and `restores/` with a delimiter
  on every reconcile and kopia lists blob prefixes constantly, so a broken
  listing shows up there as a backup that never appears rather than as an error.

Everything else is closed and verified. **Delete this file once those two are
done**, after moving nothing — the decision is in ADR 0010 and the
operator-facing consequence is in `README.md`.

### What the measurement changed

Three of this ticket's assumptions were wrong, and they were caught because the
plan said to capture a real response before locking the assertions down. They
are written out under "Measured against MinIO" below: the element order is wrong
in three places, MinIO does not clamp `max-keys` above 1000, and `max-keys=0`
answers `IsTruncated` false rather than true.

### Found while doing it, not fixed

- `handleHeadBucket` drops `x-amz-expected-bucket-owner`: the header reaches the
  handler and never reaches the backend input, so a client using it as a guard
  against a re-created bucket is not guarded. Pinned by a handler test that says
  so.
- `ListBuckets` serialises a bucket with no creation date as the Go zero time,
  `0001-01-01T00:00:00Z`, instead of omitting the element. Pre-existing.
- `KeyCount` is forwarded from the backend rather than recomputed from
  `Contents` plus `CommonPrefixes`. Against a backend that miscounts, the proxy
  repeats the miscount.
- The element order of `ListAllMyBucketsResult` was never measured — only the
  object listings were. A strict client would notice if it differs.

---

## Before you start

All of these are already corrected in the text below.

- The defect list was read before v4.0.0 shipped. The defects still read as
  described; nearly every line link has drifted — follow the symbol names.
- The ListBuckets `text/plain` `http.Error` is gone: the handler answers backend
  failures through the shared error writer. That sub-step of work item 9 is done;
  the namespace and the dropped parameters remain.
- Four mocks, not five (`internal/proxy/mock_s3_backend.go` is deleted, the
  `test_helpers.go` files are now `test_helpers_test.go`), and all four already
  implement `HeadBucket` — work item 10 needs zero mock edits. Work item 2 has 16
  `NewHandler` call sites, not nine.
- Both test levels already pin today's wrong behaviour and must be rewritten with
  the handler, not added to:
  [`bucket/operations_coverage_test.go`](../../internal/proxy/handlers/bucket/operations_coverage_test.go)
  and
  [`listobjects_conformance_test.go`](../../test/integration/s3-methods/listobjects_conformance_test.go),
  which also captures a MinIO reference document.
- MinIO encodes a space as `+`, not `%20`. `url.QueryUnescape` survives as the
  choice — it accepts both — but its justification does not; the key-set round
  trip decides the encoding step.
- `2006-03-01` no longer greps empty: production code still carries no namespace,
  the conformance and DeleteObjects tests name it.
- "Could land earlier" no longer means quietly. v4.0.0 shipped from main, and the
  document root, the `max-keys` refusal and a real `HeadBucket` are
  client-visible breaks, so landing them carries a major label under
  [ADR 0018](../adr/0018-a-major-release-is-declared-by-a-label.md).

## Settled

- A page size above the maximum is clamped; a negative one is refused with a 400.
- The proxy requests URL encoding from the backend and decodes with query
  unescaping, guarded by a round-trip test over a key set containing `+`, a
  space, `&`, `<`, `%`, `%2B` and a non-ASCII character.
- When the backend returns no region on a bucket existence check, the proxy
  answers with its configured region and the README says so.
- Element order is captured from a real backend response before the assertions
  are locked down.
- The pagination fixture is 2500 objects of one byte, created in parallel and
  reused across every subtest.
- The owner element never reflects the backend account: when a client asks for
  it, the proxy answers with the client's own access key identity, on bucket
  listings too.
- The entity tag stays the ciphertext one and is documented as a known deviation;
  changing it is a format question, not a listing question.
- The contract that an unknown plaintext size is reported as `-1` belongs in the
  storage-format work, not here.

---

## Context

The listing handler is the last S3 response in the proxy that is not an S3
response. [`handleListObjects`](../../internal/proxy/handlers/bucket/operations.go#L15)
XML-encodes the raw aws-sdk-go-v2 output struct
([operations.go:52](../../internal/proxy/handlers/bucket/operations.go#L52) for V2,
[operations.go:79](../../internal/proxy/handlers/bucket/operations.go#L79) for V1),
so the wire format is whatever `encoding/xml` makes of a Go struct that was
never meant to be marshalled. aws-sdk-go-v2 and minio-go tolerate it because
their deserializers match elements by local name and ignore the root; a strict
client, an XSD validator, or any implementation that checks the namespace does
not.

Three things follow from that one decision, and they are why this is a rewrite
rather than a patch:

1. **The document is wrong** — wrong root element, no namespace, elements S3
   never emits, elements S3 always emits missing.
2. **The parameters are wrong** — `start-after`, `fetch-owner` and
   `encoding-type` are silently dropped, and an out-of-range `max-keys` is
   dropped rather than honoured or rejected. A client that pages with
   `StartAfter` gets the same first page forever.
3. **The sizes are wrong** — `<Size>` is what the backend stores, so it
   disagrees with GET and (since F-7) with HEAD by 28 bytes for every AES-GCM
   object. `aws s3 sync` and rclone compare sizes from a listing and
   re-transfer every object whose size does not match.

**Threat-model framing.** The listing is one of the places where the proxy
speaks for a hostile backend, so what it does *not* forward matters as much as
what it does. Two rules apply here:

- The proxy must never present a backend checksum as if it described the bytes
  the client will receive. That is [N-6(d)](README.md#threat-model-findings-n-1-to-n-10)
  for GET and HEAD, and it is the same defect in a listing: `<ChecksumAlgorithm>`
  and `<ChecksumType>` from the backend describe ciphertext. Under
  [D-9](README.md#decisions-d-1-to-d-19)
  no plaintext checksum is stored either, so the honest answer is to emit no
  checksum elements at all.
- The size the proxy reports is computed by the proxy from arithmetic it
  controls, not read from anything the backend can choose. Under v2 that is
  possible; before v2 it is not, which is the scheduling dependency above.

Nothing in this ticket makes the proxy trust the backend more than it does
today. It does make the proxy stop passing the backend's words through unread.

---

## Scope

**In scope**

- `ListObjectsV2` (`GET /{bucket}?list-type=2`): document, parameters, sizes.
- `ListObjects` V1 (`GET /{bucket}`): same defect family, same handler, same fix.
- `ListBuckets` (`GET /`): namespace, dropped parameters, dropped pagination
  fields, non-XML error path.
- `HeadBucket` (`HEAD /{bucket}`): stop implementing it as a listing.
- Deleting the dead metadata-prefix parameter the bucket handler already ignores.
- Unit tests over the raw response body and integration tests over the SDK.
- README reference section for the listing, including the mixed-bucket
  under-report below.

**Out of scope**

- `ListObjectVersions` — not implemented today; `?versions` is refused with
  `NotImplemented` by the bucket handler, so there is nothing to correct here.
  Any S3 client that needs it hits a gap of its own, not a listing defect.
- `ListParts` / `ListMultipartUploads` — [P-7](README.md#parked-items-p-1-to-p-13),
  which goes with the v2 multipart rework in ticket 013.
- `<ETag>`. The listing forwards the backend ETag verbatim, exactly as HEAD does
  today ([operations.go:792](../../internal/proxy/handlers/object/operations.go#L792)).
  It is the ciphertext ETag and therefore not a plaintext MD5; that is a
  pre-existing, consistent property of every path, and changing it is a format
  question, not a listing question.
- `RestoreStatus` and Glacier semantics.
- Per-key `HeadObject` in a listing, under any circumstances. If someone later
  proposes it to "fix" the mixed-bucket case below, that is the thing this
  ticket exists to avoid.

**Closes:** D-11 and P-4. **Depends on:** ticket 013 (storage format v2) for
the size function. **Related:** N-1 (which is what makes the mixed-bucket
under-report acceptable), N-6(d) and D-9 (which is why no checksum elements are
emitted).

---

## The defects, verified

Every line below was read before v4.0.0. The defects are unchanged; the line
numbers have drifted, so follow the symbol names rather than the line links.

### 1. Dropped request parameters — V2

[operations.go:23-43](../../internal/proxy/handlers/bucket/operations.go#L23-L43)
builds `ListObjectsV2Input` from exactly four query parameters: `prefix`,
`delimiter`, `max-keys` and `continuation-token`. The SDK input struct also
carries `StartAfter`, `FetchOwner` and `EncodingType`, and none of them is ever
set. Consequences:

- **`start-after`**: a client paging by key gets the same first page on every
  request. Velero's plugin does not use it; `aws s3api list-objects-v2
  --start-after` and several backup tools do.
- **`fetch-owner`**: `Owner` comes back nil from the backend, so `<Owner>` never
  appears in the response — see defect 3.
- **`encoding-type`**: a client that asks for URL-encoded keys because its keys
  may contain XML-hostile bytes gets raw keys and no `<EncodingType>` echo.

### 2. `max-keys` outside 1..1000 is silently dropped

[operations.go:36](../../internal/proxy/handlers/bucket/operations.go#L36):

```go
if maxKeysInt, err := strconv.Atoi(maxKeys); err == nil && maxKeysInt > 0 && maxKeysInt <= 1000 {
```

Every other value — `0`, negative, `5000`, `abc` — falls through with `MaxKeys`
unset, so the backend applies its default and the client receives **up to 1000
keys after asking for none, or for more than the proxy is willing to pass on**.
`max-keys=0` returning 1000 keys is the sharpest case: it is the one value where
the client's intent and the proxy's answer are maximally far apart, and it is
also, not coincidentally, how `handleHeadBucket` is implemented (defect 5).

### 3. The response document is the SDK struct

[operations.go:51-54](../../internal/proxy/handlers/bucket/operations.go#L51-L54):

```go
w.Header().Set("Content-Type", "application/xml")
if err := xml.NewEncoder(w).Encode(output); err != nil {
```

Encoding `*s3.ListObjectsV2Output` with `encoding/xml` produces, verified by
running the encoder against this SDK version (`service/s3 v1.111.0`, pinned in
[go.mod:10](../../go.mod#L10)):

```xml
<ListObjectsV2Output>
  <CommonPrefixes><Prefix>p/x/</Prefix></CommonPrefixes>
  <Contents>
    <ChecksumType></ChecksumType>
    <ETag>&#34;abc&#34;</ETag>
    <Key>p/a&amp;b&lt;c.txt</Key>
    <LastModified>2026-09-06T12:00:00Z</LastModified>
    <Size>1052</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
  <EncodingType></EncodingType>
  <IsTruncated>false</IsTruncated>
  <KeyCount>1</KeyCount>
  <MaxKeys>1000</MaxKeys>
  <Name>bucket</Name>
  <Prefix>p/</Prefix>
  <RequestCharged></RequestCharged>
  <ResultMetadata></ResultMetadata>
</ListObjectsV2Output>
```

Against S3's `ListBucketResult`, item by item:

| Defect | Cause |
|---|---|
| Root element `<ListObjectsV2Output>` | Go derives the root from the struct type name; the SDK type is named after the operation output, not the wire document. |
| No `xmlns` | The SDK struct carries no namespace; S3 emits `xmlns="http://s3.amazonaws.com/doc/2006-03-01/"`. |
| No XML declaration | The handler writes none. [`root.HandleListBuckets`](../../internal/proxy/handlers/root/handler.go#L101) does write one, so the proxy is not even self-consistent. |
| Empty `<ChecksumType>` | `types.Object.ChecksumType` is a non-pointer enum (`service/s3/types/types.go`, `type Object` in the pinned v1.111.0), so the zero value marshals as an empty element instead of being omitted. |
| Empty `<EncodingType>`, `<RequestCharged>` | Same reason, on the output struct. |
| `<ResultMetadata>` | `middleware.Metadata` is SDK plumbing that has no business on the wire; its only field is unexported, so it marshals as an empty element. |
| No `<Owner>` | `types.Object.Owner` is a pointer and stays nil because `fetch-owner` is never forwarded (defect 1). |
| Element order | Go emits struct field order (alphabetical here by accident); S3 has a defined order. Only schema-validating parsers care, but they are exactly the clients this ticket is for. |
| `LastModified` precision | Go's `time.Time` marshals as RFC 3339 without sub-second digits; S3 emits `.000Z`. |

Also note what the encoder gets *right* and must keep: `&` and `<` in a key are
escaped correctly, because this path uses `encoding/xml` rather than string
concatenation. That is the one thing the rewrite must not lose — it is the
defect [P-6](README.md#parked-items-p-1-to-p-13)
fixes elsewhere in the proxy, and building the document by hand is exactly how
it would come back.

### 4. `<Size>` is the ciphertext size

`Contents[i].Size` is forwarded from the backend untouched. GET has subtracted
the AES-GCM overhead since F-7 ([operations.go:284](../../internal/proxy/handlers/object/operations.go#L284))
and HEAD does the same through
[`encryption.ComputePlaintextSize`](../../pkg/encryption/ciphertext_size.go#L30) at
[operations.go:785](../../internal/proxy/handlers/object/operations.go#L785). The
listing cannot use that helper: it takes the `dek-algorithm` string, which comes
from per-object metadata that `ListObjectsV2` does not return. Hence the
dependency on v2.

### 5. `handleHeadBucket` is a listing in disguise

[operations.go:184-202](../../internal/proxy/handlers/bucket/operations.go#L184-L202)
issues `ListObjectsV2` with `MaxKeys: 0` and answers 200 on success. Four
problems:

- **It answers 200 for a bucket that does not exist. Measured 2026-09-09** against
  the demo stack: `HeadBucket` on a name no bucket has returns success through the
  proxy and `404 NotFound` against the same MinIO directly, and a `ListObjectsV2`
  on that same name through the proxy correctly returns `NoSuchBucket`. The
  difference is `MaxKeys: 0`: the backend short-circuits the listing before it
  checks that the bucket is there. A client that uses `HeadBucket` to decide
  whether to create a bucket gets the wrong answer, and the rewrite below fixes it
  by calling the real operation.
- **No `x-amz-bucket-region`.** Real S3 returns it on every `HeadBucket`,
  including on the 301 redirect for a wrong-region request. aws-sdk-go-v2's
  bucket-region resolution and several tools read it.
- **Wrong operation, wrong errors.** A backend that permits `s3:HeadBucket` but
  not `s3:ListBucket` answers 403 to an existence check that should have
  succeeded. The error surface of a listing is not the error surface of a HEAD.
- **It depends on the `max-keys=0` behaviour that defect 2 documents as broken.**
  The SDK path sets `MaxKeys` directly so it works today, but the handler is
  relying on a semantic the client-facing path gets wrong.

`HeadBucket` is not on `S3BackendInterface`
([s3_backend.go:69](../../internal/proxy/interfaces/s3_backend.go#L69) is the
nearest neighbour), so adding it touches the interface — and nothing else on the
test side: the four mocks that implement the interface
([handlers/bucket/test_helpers_test.go](../../internal/proxy/handlers/bucket/test_helpers_test.go),
[handlers/object/test_helpers_test.go](../../internal/proxy/handlers/object/test_helpers_test.go),
[handlers/root/test_helpers_test.go](../../internal/proxy/handlers/root/test_helpers_test.go),
[handlers/multipart/multipart_test.go](../../internal/proxy/handlers/multipart/multipart_test.go))
already carry a `HeadBucket` method.
The backend is a plain `*s3.Client` ([server.go:125](../../internal/proxy/server.go#L125)),
which already has the method, so no production wiring changes.

### 6. ListObjects V1 — same pattern, checked

[operations.go:55-82](../../internal/proxy/handlers/bucket/operations.go#L55-L82).
Verified by running the same encoder probe against `*s3.ListObjectsOutput`: root
element `<ListObjectsOutput>`, no `xmlns`, the same empty `<ChecksumType>`,
`<EncodingType>`, `<RequestCharged>` and `<ResultMetadata>` elements. On the
request side V1 forwards only `prefix`, `delimiter` and `marker`
([operations.go:61-70](../../internal/proxy/handlers/bucket/operations.go#L61-L70))
— it does not even attempt `max-keys`, so a V1 client can never ask for a page
size at all, and `encoding-type` is dropped as in V2. `<NextMarker>` is whatever
the backend returned, which is correct only by accident (S3 sets it only when a
delimiter is in play).

### 7. ListBuckets — a different pattern, still wrong

[`root.HandleListBuckets`](../../internal/proxy/handlers/root/handler.go#L49) is
better: it builds an explicit `ListAllMyBucketsResult`
([handler.go:14](../../internal/proxy/handlers/root/handler.go#L14)) and writes an
XML declaration ([handler.go:101](../../internal/proxy/handlers/root/handler.go#L101)).
Three defects remain, verified:

- **No `xmlns`** on `ListAllMyBucketsResult`. No response document in this proxy
  carries the S3 namespace; the only `2006-03-01` occurrences in the tree are in
  tests that record what S3 emits.
- **Every request parameter dropped.** The call is
  `ListBuckets(ctx, &s3.ListBucketsInput{})` ([handler.go:53](../../internal/proxy/handlers/root/handler.go#L53)),
  while the input struct in this SDK version carries `Prefix`, `MaxBuckets`,
  `ContinuationToken` and `BucketRegion`. The response document omits `<Prefix>`
  and `<ContinuationToken>` as well, so against real S3 — which caps a
  `ListBuckets` page and returns a continuation token — **a client cannot page
  past the first page through this proxy**. MinIO returns everything in one
  response, which is why no test has ever noticed.
- ~~**Non-XML error body.**~~ **Fixed already.**
  [`HandleListBuckets`](../../internal/proxy/handlers/root/handler.go#L52) answers
  a backend failure with `errorWriter.WriteS3Error`, so it goes through the shared
  mapper like every other backend error. Plain `http.Error` still survives on a
  handful of malformed-input paths
  ([bucket/cors.go:77](../../internal/proxy/handlers/bucket/cors.go#L77),
  [bucket/acl.go:87](../../internal/proxy/handlers/bucket/acl.go#L87),
  [multipart/upload.go:80](../../internal/proxy/handlers/multipart/upload.go#L80)),
  which is out of scope here.

### 8. Dead parameter in the bucket handler constructor

[`bucket.NewHandler`](../../internal/proxy/handlers/bucket/handler.go#L39) takes the
metadata key prefix as `_ string`
([handler.go:42](../../internal/proxy/handlers/bucket/handler.go#L42)) and ignores
it; the router passes `s.getMetadataPrefix()` into it
([router.go:40](../../internal/proxy/router.go#L40)). The listing rewrite needs a
different dependency in that slot anyway (below), so the dead parameter goes
with it rather than being left as a decoy.

---

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

---

## Design

### The size function, and why v2 is the gate

Ticket 013 stores every object as segments plus a trailer:

- segment = `nonce(12) ‖ AES-256-GCM(plaintext ≤ S) ‖ tag(16)`, so **28 bytes**
  per segment, with **S = 65536** a constant of the format;
- trailer = `nonce(12) ‖ AES-256-GCM(uint64 length ‖ uint32 crc32c) ‖ tag(16)` = **40 bytes**
  (since 2026-09-09, ADR 0003 D13),
  once per object.

So for plaintext `P` with `n = ceil(P / S)` segments, the stored size is
`C = 40 + 28·n + P`. Inverting, given only `C`:

```
n = ceil((C - 40) / (S + 28))
P = C - 40 - 28·n
```

The inversion is exact, not an approximation: from `C - 40 = 28n + P` and
`(n-1)·S < P ≤ n·S` it follows that `(n-1)·(S+28) < C - 40 ≤ n·(S+28)`, which is
the definition of `n = ceil((C-40)/(S+28))`. The empty object (`P = 0`, `n = 0`,
`C = 40`) and the exact-multiple case (`P = k·S` → `n = k`, no trailing empty
segment) both fall out correctly.

**This is the whole reason the ticket waits for 013.** No metadata, no round
trip, pure integer arithmetic on a number already in the listing — a listing of
1000 keys costs 1000 divisions.

Ticket 013 owns the constants and the function; this ticket consumes it. 013
puts it in the segment codec — `PlaintextSize(C)` / `CiphertextSize(P)` in
`pkg/encryption/dataencryption/segmented_gcm.go`, its work item 1 — and its work
item 11 replaces `ComputePlaintextSize` / `ComputeCiphertextSize`
([ciphertext_size.go:30](../../pkg/encryption/ciphertext_size.go#L30) and
[:13](../../pkg/encryption/ciphertext_size.go#L13) today). So there is nothing left
in `ciphertext_size.go` for this ticket to sit next to; it calls the codec. What
the signature should keep is the `-1`-means-unknown contract that the replaced
`ComputePlaintextSize` established:

```go
// PlaintextSize returns the plaintext length of a stored v2 object of the
// given size, or -1 when the size cannot be one this proxy wrote.
func PlaintextSize(storedSize int64) int64
```

`C < 36` returns `-1`: no object the proxy wrote can be smaller than its own
trailer. The listing then reports the stored size verbatim for such an entry
rather than inventing a negative number.

### Which objects get the computed size

The rule is one line and it must be stated in the README, because it has a
visible consequence:

> When the active provider encrypts, `<Size>` is `PlaintextSize(storedSize)`.
> When the active provider is `none`, `<Size>` is the stored size.

The handler asks [`Manager.IsNoneProvider()`](../../internal/orchestration/manager.go#L440),
which already exists and is already the switch every other path uses. That is
the dependency the dead `_ string` parameter is replaced with: `bucket.NewHandler`
takes the `*orchestration.Manager` the object handler already takes
([object/handler.go:35](../../internal/proxy/handlers/object/handler.go#L35)).

**Documented consequence, deliberate.** In a bucket that also holds
`none`-provider objects or foreign plaintext written outside the proxy, the
computed size under-reports those entries by `40 + 28·ceil((C-40)/65564)` bytes
— 36 B plus 28 B per 64 KiB. The listing cannot tell them apart without a
per-key `HeadObject`, which is the round trip this whole design exists to avoid.
It is acceptable because [N-1](README.md#threat-model-findings-n-1-to-n-10)
makes such a bucket unsupported for reads anyway: under v2 a GET, HEAD or ranged
GET of an object without the proxy's metadata is an error when the active
provider encrypts, so a client that trusts a size it read from such a listing
cannot then read the object regardless. A bucket with pre-existing plaintext is
migrated once through the proxy, not read in place. Pin this with a test rather
than only with prose — see the work breakdown — so nobody later "fixes" it with
a HEAD per key.

### The document

Build it explicitly. Namespace on the root via `xml.Name`, verified to emit once
and to be inherited by children without repetition:

```go
type listBucketResultV2 struct {
    XMLName               xml.Name       `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListBucketResult"`
    Name                  string         `xml:"Name"`
    Prefix                string         `xml:"Prefix"`
    Delimiter             string         `xml:"Delimiter,omitempty"`
    MaxKeys               int32          `xml:"MaxKeys"`
    CommonPrefixes        []commonPrefix `xml:"CommonPrefixes"`
    EncodingType          string         `xml:"EncodingType,omitempty"`
    KeyCount              int32          `xml:"KeyCount"`
    ContinuationToken     string         `xml:"ContinuationToken,omitempty"`
    NextContinuationToken string         `xml:"NextContinuationToken,omitempty"`
    StartAfter            string         `xml:"StartAfter,omitempty"`
    IsTruncated           bool           `xml:"IsTruncated"`
    Contents              []objectEntry  `xml:"Contents"`
}

type objectEntry struct {
    Key          string  `xml:"Key"`
    LastModified string  `xml:"LastModified"` // formatted 2006-01-02T15:04:05.000Z
    ETag         string  `xml:"ETag"`
    Size         int64   `xml:"Size"`
    StorageClass string  `xml:"StorageClass,omitempty"`
    Owner        *owner  `xml:"Owner,omitempty"`
}
```

Rules the struct encodes:

- **No checksum elements, ever.** `<ChecksumAlgorithm>` and `<ChecksumType>` do
  not appear in the type, so the backend's ciphertext checksums cannot leak into
  a listing that describes plaintext sizes. This is N-6(d) applied to the
  listing and it is a security rule, not a formatting one.
- **No `<RequestCharged>`, no `<ResultMetadata>`, no `<RestoreStatus>`.**
- `omitempty` everywhere S3 omits, so an absent value is an absent element
  rather than an empty one.
- `LastModified` is formatted, not marshalled as `time.Time`, so the `.000Z`
  precision matches S3.
- The XML declaration is written before the document. Add it once as a helper on
  [`response.XMLWriter`](../../internal/proxy/response/xml.go#L23) — `WriteXML`
  writes no declaration today — and use it from both listing handlers and from
  `HandleListBuckets`, which currently writes its own by hand
  ([root/handler.go:101](../../internal/proxy/handlers/root/handler.go#L101)).

V1 gets the same treatment with `<Marker>` / `<NextMarker>` in place of the
continuation token and no `<KeyCount>`.

### `encoding-type`

The proxy owns the document now, so it owns the encoding. Chosen design:

1. Always send `EncodingType: url` to the backend, so the backend→proxy XML is
   well formed no matter what bytes a key contains.
2. URL-decode the values the SDK hands back. **aws-sdk-go-v2 does not decode
   them** — verified: `grep -rn "QueryUnescape\|PathUnescape\|url.Unescape"` over
   `service/s3@v1.111.0` returns nothing. Keys, `Prefix`, `Delimiter`,
   `StartAfter` and the markers all come back percent-encoded, and every one of
   them has to be decoded before it is used, including for the size math's
   bookkeeping and for the `<CommonPrefixes>` comparison.
3. Re-encode on output only when the client asked, and echo
   `<EncodingType>url</EncodingType>` in that case.

The decode is the risky step; see "Risks and open questions".

### `max-keys`

| Input | Behaviour |
|---|---|
| absent | do not set `MaxKeys`; backend default applies |
| `0` ≤ n ≤ `1000` | forward verbatim, `0` included |
| n > `1000` | clamp to 1000 |
| negative, or not an integer | `400 InvalidArgument`, via the existing `errorWriter` |

`0` must reach the backend rather than being dropped, and it must produce
`<KeyCount>0</KeyCount>` with `<IsTruncated>true</IsTruncated>` when the bucket
is non-empty. V1 gains the same handling for its own `max-keys`.

### `HeadBucket`

Add `HeadBucket` to `S3BackendInterface` and to the five mocks. The handler
calls it, answers 200 with no body, and sets `x-amz-bucket-region` from
`HeadBucketOutput.BucketRegion`, falling back to the configured
`s3_backend.region` when the backend returns none. Errors go through
`errorWriter.WriteS3Error` as everywhere else. The `ListObjectsV2(MaxKeys: 0)`
call disappears.

---

## Work breakdown

- [ ] **1. Size function.** Confirm ticket 013's `PlaintextSize(C int64) int64`
      in `pkg/encryption/dataencryption/segmented_gcm.go` (013 work items 1 and
      11) carries the `-1`-for-unknown contract; if it does not, add it there,
      not to the `ciphertext_size.go` helpers 013 replaces. Unit
      tests: `P → C → P` round trip across `0`, `1`, `S-1`, `S`, `S+1`, `2S`,
      12 MiB, 5 GiB; `C < 36` → `-1`; the empty-object and exact-multiple
      boundaries.
- [ ] **2. Constructor.** Replace the ignored `_ string` at
      [bucket/handler.go:42](../../internal/proxy/handlers/bucket/handler.go#L42)
      with the `*orchestration.Manager`; update
      [router.go:62](../../internal/proxy/router.go#L62) and the 16 `NewHandler`
      call sites in the package's own tests
      ([test_helpers_test.go](../../internal/proxy/handlers/bucket/test_helpers_test.go),
      `acl_test.go`, `bucket_crud_test.go` (6), `cors_test.go`,
      `handlers_test.go`, `location_test.go`, `logging_test.go`,
      `policy_test.go`, `subresource_matrix_coverage_test.go` (2),
      `subresource_methods_coverage_test.go`). Compile-only step, reviewable on
      its own.
- [ ] **3. XML declaration helper** on
      [`response.XMLWriter`](../../internal/proxy/response/xml.go#L23); switch
      `HandleListBuckets` to it and delete its hand-written declaration.
- [ ] **4. V2 document.** New response types, explicit mapping from the SDK
      output, `xmlns`, S3 element order, formatted `LastModified`, no checksum /
      `RequestCharged` / `ResultMetadata` elements, `<Owner>` when requested.
      Sizes still passed through at this step so the diff is document-only.
- [ ] **5. V2 parameters.** Forward `start-after`, `fetch-owner`; implement the
      `max-keys` table; echo `ContinuationToken`, `StartAfter`, `Delimiter`,
      `Prefix`, `KeyCount`, `IsTruncated`, `NextContinuationToken`.
- [ ] **6. `encoding-type`.** Always request `url` from the backend, decode,
      re-encode on output when asked, echo `<EncodingType>`.
- [ ] **7. V2 sizes.** Apply `PlaintextSize` per entry, gated on
      [`Manager.IsNoneProvider()`](../../internal/orchestration/manager.go#L440);
      stored size verbatim when the function returns `-1`.
- [ ] **8. V1.** Same document, same `max-keys` rule, same encoding handling,
      `<Marker>` / `<NextMarker>`, same sizes.
- [ ] **9. ListBuckets.** Add the namespace; forward `prefix`, `max-buckets`,
      `continuation-token`, `bucket-region`; emit `<Prefix>` and
      `<ContinuationToken>`. The XML error path is already done — the handler
      uses the shared error writer.
- [ ] **10. `HeadBucket`.** Interface method, handler rewrite,
      `x-amz-bucket-region`. The four mocks already implement the method.
- [ ] **11. Delete what is now dead**: the two `xml.NewEncoder(w).Encode(output)`
      calls, the old `max-keys` guard, the `ListObjectsV2(MaxKeys: 0)` existence
      probe, and any metadata-prefix plumbing left unused by step 2.
- [ ] **12. Handler unit tests** (`internal/proxy/handlers/bucket/`, against the
      existing `MockS3Backend`), asserting on the **raw response body**, which
      is the only level where the document itself is visible:
      - root element is `ListBucketResult` and the `xmlns` attribute is present,
        for V2, V1, and `ListAllMyBucketsResult` for ListBuckets;
      - no `<ChecksumType>`, `<ChecksumAlgorithm>`, `<RequestCharged>`,
        `<ResultMetadata>`, `<EncodingType>` when the client did not ask;
      - `<Owner>` present with `fetch-owner=true`, absent without;
      - the `max-keys` table, including `0` and the `InvalidArgument` cases;
      - a key containing `&`, `<`, `"` and a non-ASCII character still parses
        with `encoding/xml` (the P-6 property, kept);
      - `<Size>` for a stored size that is and is not a valid v2 size.
- [ ] **13. Integration tests**, by rewriting the deviation tests in
      [listobjects_conformance_test.go](../../test/integration/s3-methods/listobjects_conformance_test.go)
      — which pin today's wrong behaviour against a MinIO oracle — and adding
      what they do not cover:
      - **2500 objects, paginated.** Written through the proxy, listed with
        `MaxKeys=1000`, following `NextContinuationToken` to exhaustion; assert
        3 pages, 2500 distinct keys, no duplicates, `IsTruncated` true then
        false, and that the key set matches what was written.
      - **`Delimiter="/"`** over a `a/`, `b/`, `c/x/` layout: assert
        `CommonPrefixes` and that no rolled-up key appears in `Contents`.
      - **`MaxKeys=1`**: exactly one key per page, and paging through all of
        them yields the full set in key order.
      - **`StartAfter`**: listing from the middle of the key set returns only
        greater keys, and `StartAfter` is echoed.
      - **Sizes agree**: for objects spanning the interesting sizes (0 B, 1 B,
        64 KiB − 1, 64 KiB, 64 KiB + 1, 12 MiB, and one multipart upload), the
        `<Size>` from the listing equals the HEAD `Content-Length` and the byte
        count actually read from GET. Compare content by SHA-256, per the work
        order in `CLAUDE.md`.
      - **Root element and namespace over the wire.** The SDK hides both, so
        fetch one listing with a plain `http.Client` and assert on the bytes.
        Sign it with the existing header-SigV4 helper
        [`integration.SignHTTPRequestForS3WithCredentials`](../../test/integration/s3_signing_helper.go#L232),
        already used that way in
        [comprehensive_chunked_test.go:270](../../test/integration/360-degree-variants/comprehensive_chunked_test.go#L270).
        Not a pre-signed URL: `s3.PresignClient` in this SDK version exposes
        only `PresignGetObject`, `PresignPutObject`, `PresignHeadObject`,
        `PresignHeadBucket`, `PresignDeleteObject`, `PresignDeleteBucket`,
        `PresignUploadPart` and `PresignPostObject` — there is no
        `PresignListObjectsV2`, so a listing cannot be presigned with it.
      - **The documented under-report.** A bucket holding both proxy-written and
        MinIO-written objects: assert the proxy-written sizes are exact and the
        foreign ones are short by exactly `40 + 28·ceil((C-40)/65564)`, with a
        comment naming N-1 and this ticket. This test exists to make the
        tradeoff deliberate and to fail loudly if someone adds a per-key HEAD.
      - **`HeadBucket`**: 200 plus `x-amz-bucket-region` for an existing bucket,
        404 for a missing one.
- [x] **14. Fix the flaky `TestListBucketsOperation`.** **Done in d4553d4,
      2026-09-06.** The endpoint-wide assertion
      `len(minioOutput.Buckets) == len(proxyOutput.Buckets)` is gone. `go test`
      runs packages in parallel, so any other package creating or deleting a
      bucket between the two listings failed a test that had nothing to do with
      it; it passed in isolation. `CreateBucket_ThenList` now searches MinIO for
      the one bucket it created
      ([list_buckets_test.go:66-77](../../test/integration/s3-methods/list_buckets_test.go#L66-L77))
      and the comment above it
      ([:61-65](../../test/integration/s3-methods/list_buckets_test.go#L61-L65))
      records why the count was the wrong assertion, so the next reader does not
      re-introduce it. `TestListBucketsPassthrough` scopes itself the same way
      and says so at
      [:192](../../test/integration/s3-methods/list_buckets_test.go#L192).
      Re-verified in the tree at the head of this branch: no endpoint-wide count
      assertion remains in the file, and the two surviving uses of the bucket
      count only log it
      ([:30](../../test/integration/s3-methods/list_buckets_test.go#L30),
      [:139](../../test/integration/s3-methods/list_buckets_test.go#L139)).
      Nothing in this item is left to do; it is listed here only so the rewrite
      does not put the count back.
- [ ] **15. Docs.** README full-reference section: the listing document, the
      forwarded parameters, the `max-keys` rule, the plaintext-size rule and the
      mixed-bucket under-report with its N-1 justification, and the ListBuckets
      pagination behaviour. Cross-link `SECURITY_ARCHITECTURE.md` for the
      no-checksum-elements rule.

---

## Success criteria

Verified, in this order:

1. `make test-unit` green, including the new handler tests and the size-function
   round trip. `make lint` clean (`go vet`, `gofmt -l .`, `golangci-lint`).
2. `./start-demo.sh`, then `make test-integration` green — the full plain-HTTP
   suite, not just the new file.
3. `make test-integration-tls` green. The listing path is not framing-sensitive,
   but this is the transport the SDK behaves differently on and the suite is the
   end-user contract on both.
4. `make test-integration-performance` shows no regression against the numbers
   recorded before the change. Listings are not in that benchmark today; record
   the wall time of the 2500-key paginated listing from step 13 against the same
   listing issued directly to MinIO, as a **recorded number, not a gate** —
   consistent with [D-14](README.md#decisions-d-1-to-d-19).
   The expectation is a small constant factor from building the document; a
   per-key backend round trip would show up as an order of magnitude and is the
   thing this measurement is watching for.
5. `make e2e-velero` (or `make e2e-up` then `make test-e2e-velero`) green, all
   13 scenarios. Velero lists `backups/` and `restores/` with a delimiter on
   every reconcile and kopia lists blob prefixes constantly, so a broken listing
   shows up here as a backup that never appears rather than as an error.
6. A strict-client check the SDK cannot give us: one `ListObjectsV2`, one
   `ListObjects` and one `ListBuckets` response captured from the running demo
   stack, each parsed by a namespace-aware XML parser and checked against the
   S3 element names. Record the three documents in the ticket folder.
7. `docker logs proxy | tail -50` shows no new error or warning lines during the
   integration run.

Done when: D-11 and P-4 are marked resolved in the
[label index](README.md#label-index) and the README
section exists.

---

## Risks and open questions

- **S3 element order is from the API reference, not from a captured response.**
  The order in the design section is what the AWS `ListObjectsV2` documentation
  specifies; it has not been checked against a real S3 or a MinIO response in
  this tree. Order matters only to schema-validating parsers, but those are the
  clients this ticket serves. **Verify** by capturing a real response before
  locking the assertions in step 12, and prefer MinIO's order if the two differ,
  since MinIO is what the suite runs against.
- **The `encoding-type` decode is the sharpest edge here.** `url.QueryUnescape`
  turns `+` into a space; `url.PathUnescape` does not. A key containing a
  literal `+` is only safe if the backend encoded it as `%2B`. AWS S3
  percent-encodes a space as `%20`, **MinIO encodes it as `+`** (recorded in the
  conformance suite), so `QueryUnescape` — which accepts both — is the only call
  that works against both, and a key containing a literal `+` depends entirely on
  the backend encoding it as `%2B`. Mitigate with an integration test
  over a key set containing `+`, a space, `&`, `<`, `%`, `%2B` and a non-ASCII
  character, round-tripped PUT → LIST → GET, and treat a failure as a reason to
  reconsider step 6 rather than to weaken the test. If it proves fragile, the
  fallback is to stop forwarding `encoding-type` to the backend and accept that
  a key with an XML-illegal byte breaks the backend→proxy parse — which is what
  happens today.
- **`max-keys` > 1000 and negative: clamp or reject?** The table above clamps
  above 1000 and rejects negatives, which is my reading of S3. Not verified
  against real S3. MinIO's behaviour should be captured before the test asserts
  it, and if the two disagree, match S3 and note the deviation.
- **`x-amz-bucket-region` from MinIO** may be absent, which is why the design
  falls back to the configured region. That fallback is a guess about the
  backend, not a fact from it: if the proxy and the backend disagree about the
  region, the proxy will state its own. Acceptable, since the proxy is the
  endpoint the client is talking to, but say so in the README rather than
  leaving it implicit.
- **The 2500-object test costs suite time.** 2500 tiny objects written through
  the proxy, even at concurrency 16, is the largest single fixture in the
  integration suite. Keep the objects at 1 byte, create them in parallel, reuse
  the same fixture across the pagination, delimiter, `MaxKeys=1` and
  `StartAfter` subtests, and measure the added wall time; if it dominates,
  reduce to 2100 (still three pages) rather than dropping the coverage.
- **This ticket assumes 013 landed as designed.** If v2 ships with a different
  segment size, a different trailer, or a per-object header, the size function
  changes and step 1 changes with it. Nothing else in the ticket does — the
  document rewrite, the parameters, `HeadBucket` and the flaky test are all
  independent of the format.
- **Storage classes and Glacier**: `<StorageClass>` is forwarded from the
  backend and is a property of the ciphertext object, which is correct, but a
  restore-in-progress object will list as readable and then fail on GET. Out of
  scope, unverified, worth a line in the README's known limits.
- **`ListBuckets` pagination has no test that can fail against MinIO**, because
  MinIO returns every bucket in one response. The continuation-token forwarding
  in step 9 is therefore covered only by a handler unit test with a mocked
  backend. Say so rather than implying end-to-end coverage.
