# Ticket 014: Verify client upload checksums

## Status (2026-09-10)

**Open, and untouched by the deletion round — but every route it names has been
rebuilt underneath it.** No line of the verification exists: `git grep -n
"X-Amz-Trailer\|Trailers()" internal/proxy/request` outside the tests returns
nothing, `BadDigest` and `InvalidDigest` appear only in the status-code table
([error_mapping.go:34](../../internal/proxy/response/error_mapping.go#L34),
[:40](../../internal/proxy/response/error_mapping.go#L40)) and are produced by
nothing, and a unit test pins the defect as it stands
(`TestObjPutClientChecksumsAreAcceptedAndDropped`,
[objectput_coverage_test.go:1498](../../internal/proxy/handlers/object/objectput_coverage_test.go#L1498)).

Carries **D-9**, **P-5**, **P-13**, **D-16** and **N-6 (a)** from the Velero path
review (the [label index](README.md#label-index) defines them). Its one hard
dependency, the before-merge N-6 (b)/(c)/(d) work, landed: `grep -rn
"ContentMD5\|ChecksumAlgorithm\|ChecksumCRC\|ChecksumSHA" internal/ --include='*.go'`
matches nothing outside tests and comments. It starts with no dependency.

**What moved under it (2026-09-10, the segment chain and the dead-code round):**

- The **PUT routing collapsed from four routes to two**, exactly as the last risk
  bullet of the earlier version predicted. `putObjectDirect` and
  `putObjectStreamingReader` no longer exist; `handlePutObject`
  ([operations.go:193](../../internal/proxy/handlers/object/operations.go#L193))
  now splits on plaintext length against `optimizations.streaming_segment_size`
  alone: `putObjectSegmented`
  ([:239](../../internal/proxy/handlers/object/operations.go#L239)) for a known
  length that fits one part, `putObjectAutoMultipart`
  ([:609](../../internal/proxy/handlers/object/operations.go#L609)) for an unknown
  or larger one. With client-driven `UploadPart` that is **three** routes to answer
  on, not four.
- **`encryption.integrity_verification` and `optimizations.streaming_threshold` are
  gone** (ADR 0013), together with the whole HMAC layer and the GCM/CTR split. Every
  sentence below that said "in `strict`" or "above `streaming_threshold`" has been
  rewritten; a size below or above 5 MiB no longer selects anything.
- **Every write path already computes a CRC32C over the plaintext** and seals it in
  the object trailer (ADR 0003 D13):
  [`dataencryption.NewChecksum`](../../pkg/encryption/dataencryption/segmented_gcm.go#L81)
  over `crc32.MakeTable(crc32.Castagnoli)`
  ([segmented_gcm.go:69](../../pkg/encryption/dataencryption/segmented_gcm.go#L69)),
  combined across parts with `Checksum.Append`. That is the same quantity as
  `x-amz-checksum-crc32c`. See [Algorithms, packages and
  hardware](#algorithms-packages-and-hardware).
- **`utils.ReadRequestBody` was deleted** in the same round. It was a second dead
  body reader, never the target of **P-5** — P-5 has always been about routing the
  three raw handlers through `Parser.ReadBody`, which is untouched
  ([parser.go:43](../../internal/proxy/request/parser.go#L43)).

**Decided 2026-09-09 (repository owner, ADR 0012 D3/D4/D14): the switch is gone before
it was built.** Every checksum a client declares is verified, `Content-MD5`, SHA-1 and
SHA-256 included; `encryption.verify_upload_digests` is not added anywhere and does not
exist in the tree. `DeleteObjects` requires a digest and verifies it always (D14). The
measurement stays as a published cost table, not as a gate. Measured 2026-09-09, Apple
M5 Pro, one core, 64 KiB blocks, Go 1.27: CRC32 and CRC32C 12 GB/s, AES-GCM seal
9.1 GB/s, SHA-1 3.5 GB/s, SHA-256 3.4 GB/s, MD5 0.95 GB/s. MD5 costs about ten times
the encryption pass per byte and lands on kopia's uploads; that number goes into the
README.

---

## Before you start

- **The prerequisite holds.** No `ContentMD5` and no `Checksum*` field is set on any
  backend input; comments mark the former forward sites
  ([upload.go:196](../../internal/proxy/handlers/multipart/upload.go#L196),
  [operations.go:144](../../internal/proxy/handlers/object/operations.go#L144)). Three
  unit tests already guard it —
  [object_test.go:504](../../internal/proxy/handlers/object/object_test.go#L504),
  [multipart_test.go:748](../../internal/proxy/handlers/multipart/multipart_test.go#L748),
  [deleteobjects_coverage_test.go:608](../../internal/proxy/handlers/object/deleteobjects_coverage_test.go#L608)
  — so the N-6 (b)/(c) regression guard is covered and needs no integration test of
  its own.
- The `ChecksumAlgorithm = SHA256` line on `DeleteObjects` and the
  `html.UnescapeString` call before `xml.Unmarshal` in `complete.go` are already
  deleted; both work items are ticked below. The reason the unescape had to go is
  kept as a comment at
  [complete.go:99](../../internal/proxy/handlers/multipart/complete.go#L99).
- `SECURITY_ARCHITECTURE.md` states that client checksums are dropped and not verified
  (§ Residual risks, "Client checksums") and carries the open hardening entry. The docs
  item is an edit of that text, not a new file. `README.md` § Checksums says the same.
- `handleObjectLegalHold` and `handleObjectRetention` are one-line refusals and read no
  body at all.
- Go is 1.27.1 (`go.mod`, `Containerfile`). The CRC64 slicing-by-8 rebuild on every
  write of 2 KiB or more is still there in that toolchain (`hash/crc64/crc64.go`,
  `else if len(p) >= 2048`).
- aws-sdk-go-v2 is v1.47.0, `service/s3` v1.113.0, `service/internal/checksum` v1.11.3.
  The two SDK line references below were re-checked against v1.11.3 and both still hold.
- Line numbers were re-located on 2026-09-10 and are correct as of that day. Re-locate
  by symbol after any change to the PUT handlers.

## Settled

- `DeleteObjects` verifies its mandatory body digest **always** and refuses a request
  that carries none: the cost argument that produced the withdrawn switch was about
  multi-megabyte uploads, not a delete document of a few kilobytes. Confirmed
  2026-09-09 as ADR 0012 D14. Today the request is parsed with no digest requirement
  ([operations.go:397](../../internal/proxy/handlers/object/operations.go#L397)), and a
  test records that as the current state
  ([deleteobjects_coverage_test.go:597](../../internal/proxy/handlers/object/deleteobjects_coverage_test.go#L597)).

---

## Context

Under the threat model recorded on 2026-09-06 the S3 endpoint is **hostile**: it can
read, change, swap, truncate and lie. Everything the proxy stores is defended by the
DEK layer and by the segment chain's own tags. Nothing defends the
**client-to-proxy leg**, and that leg is where the plaintext still exists. A byte
corrupted before the proxy encrypts is encrypted faithfully, authenticated faithfully,
and is from then on indistinguishable from correct data — every integrity mechanism the
product has confirms the corruption. The upload checksum is the only check that can
catch it, and it is the only one the proxy runs on that leg (per-chunk SigV4 signatures
stay unverified, deliberately: the adversary is on the other leg,
[ADR 0014](../adr/0014-authentication-is-sigv4-no-rate-limiting.md)).

What happens today:

- The aws-chunked trailer is read and thrown away. The decoder drains trailer lines in
  a loop and returns nil
  ([streaming_aws_decoder.go:108](../../internal/proxy/request/streaming_aws_decoder.go#L108)),
  which the type comment states outright
  ([streaming_aws_decoder.go:26](../../internal/proxy/request/streaming_aws_decoder.go#L26)).
  Every current aws-sdk-go-v2 client sends one: with `RequestChecksumCalculation` at its
  default `WhenSupported` the SDK picks CRC32 when the caller names no algorithm
  (`service/internal/checksum@v1.11.3/middleware_setup_context.go:59`), and frames it as
  a trailer over HTTPS.
- `Content-MD5` and `x-amz-checksum-*` are accepted and never checked. They no longer
  reach the backend on any route. A deliberately wrong digest gets **200** from the
  proxy — asserted as the current behaviour in
  [objectput_coverage_test.go:1498](../../internal/proxy/handlers/object/objectput_coverage_test.go#L1498),
  which is the test that has to flip when this lands. MinIO answers **400** to the same
  request. kopia sets `SendContentMd5: true` and therefore sends one on **every** blob
  it writes, so its integrity intent is dropped for all Velero volume data.

D-9 settles what to do: verify, never forward, never store. The performance-driven
exception it originally carried — CRC free on hardware, a second MD5 or SHA pass not —
was withdrawn on 2026-09-09 (ADR 0012 D4 struck). The measurement survives it as a
published cost table.

---

## Scope

**In scope — this ticket closes D-9, P-13, P-5, D-16 and N-6 (a):**

- Verification of `x-amz-checksum-crc32`, `-crc32c` and `-crc64nvme`, from a request
  header or from the aws-chunked trailer.
- Verification of `Content-MD5`, `x-amz-checksum-sha1` and `-sha256`.
- A mismatch answers `BadDigest`; a malformed digest value answers `InvalidDigest`. On
  every PUT route: `putObjectSegmented`, `putObjectAutoMultipart`, and client-driven
  `UploadPart`.
- `DeleteObjects` requires a body digest and verifies it (ADR 0012 D14).
- No client checksum value ever reaches the backend, and none is ever written to object
  metadata.
- **P-5**: the three handlers that read the body raw go through `Parser.ReadBody`.
- **D-16**: the eight bucket configuration handlers get an aws-chunked body test of the
  same shape.

**Out of scope:**

- Per-chunk and trailer **signature** verification — decided, leave, and say so in
  `SECURITY_ARCHITECTURE.md` ([ADR 0014](../adr/0014-authentication-is-sigv4-no-rate-limiting.md)).
- **Serving the proxy's own `x-amz-checksum-crc32c`** on GET and HEAD. Decided in
  ADR 0003 D14 and ADR 0012 D10, and owned by [ticket 013](013-storage-format-v2.md)
  item 2d, which also owns the tail-first read it needs. The write half is already
  built — see [Algorithms, packages and hardware](#algorithms-packages-and-hardware).
- Echoing the client's own verified value back on the PUT response (rationale below).
- `s3_security` knobs, presign lifetime — [ticket 015](015-configuration-hygiene.md).

---

## Design

### Where the hash goes: one pass, no extra copy

Every request body in the proxy funnels through exactly two functions — once P-5 below
closes the three handlers that still read `r.Body` raw:

| Entry point | Used by |
|---|---|
| [`Parser.ReadBody`](../../internal/proxy/request/parser.go#L43) | client-driven `UploadPart` ([upload.go:76](../../internal/proxy/handlers/multipart/upload.go#L76)), the eight bucket configuration handlers, and after P-5 `handleDeleteObjects`, `CompleteHandler.Handle` and `handleCreateBucket` |
| [`Parser.StreamingReader`](../../internal/proxy/request/parser.go#L108) | `putObjectSegmented` ([operations.go:242](../../internal/proxy/handlers/object/operations.go#L242)), `putObjectAutoMultipart` ([operations.go:673](../../internal/proxy/handlers/object/operations.go#L673)) |

Both already choose between the aws-chunked decoder and the raw body from headers alone
([parser.go:49](../../internal/proxy/request/parser.go#L49),
[:112](../../internal/proxy/request/parser.go#L112)). The verifier goes **around
whichever reader those two return** — a new `internal/proxy/request/checksum.go`:

```go
// verifyingReader hashes the decoded payload as it passes and compares at EOF.
type verifyingReader struct {
    src      io.Reader                 // chunked decoder or r.Body
    hashes   []namedHash               // only the algorithms this request declared
    header   map[string][]byte         // decoded expected values known up front
    declared []string                  // trailer names promised by X-Amz-Trailer
    trailers func() map[string]string  // nil when the body is not aws-chunked
    err      error                     // sticky verdict, readable by the handlers
}

func (v *verifyingReader) Read(p []byte) (int, error) {
    n, err := v.src.Read(p)
    for i := range v.hashes {
        v.hashes[i].Write(p[:n])   // the bytes are already in the caller's buffer
    }
    if err == io.EOF {
        if verr := v.finish(); verr != nil {
            v.err = verr
            return n, verr          // returned instead of io.EOF
        }
    }
    return n, err
}
```

Three properties that make this the right place and the cheap one:

1. **One pass, no copy.** The hash reads `p[:n]` — the destination buffer the caller
   already owns and is about to consume, still in L1/L2. No staging buffer, no second
   traversal, no allocation per `Read`. What bounds `n` is the *source*, not the
   destination: the aws-chunked decoder reads through a 128 KiB `bufio`
   ([streaming_aws_decoder.go:37](../../internal/proxy/request/streaming_aws_decoder.go#L37))
   and an identity body returns whatever the socket has. That matters because the
   auto-multipart producer no longer reads through a small window — it calls
   `io.ReadFull` straight into a part-sized buffer, 12 MiB by default
   ([operations.go:770](../../internal/proxy/handlers/object/operations.go#L770)) — so
   the cache-residency argument rests on the source's read granularity, not on the
   destination's size.
2. **Zero cost when nothing is declared.** If the request names no algorithm the parser
   returns the inner reader unwrapped — not even a `Read` indirection. Only algorithms
   the request actually declares get a hash, so a CRC32-trailered upload costs exactly
   one CRC32 pass and nothing else.
3. **It sees the plaintext payload, which is what the checksum covers.** The aws-chunked
   framing is stripped by the inner reader before the verifier sees a byte; the
   encryptor sits after it. Neither ciphertext nor framing is ever hashed.

Rejected alternatives, so they are not re-proposed: hashing **inside**
`streamingAWSChunkedReader.Read`
([streaming_aws_decoder.go:43](../../internal/proxy/request/streaming_aws_decoder.go#L43))
would miss every identity body — kopia's `Content-MD5` PUT, `DeleteObjects`,
`CompleteMultipartUpload` — and would need a second copy of the same logic. Hashing
inside the encryption manager would miss the `none` provider entirely.

### Trailer capture

Trailer values arrive **after** the last payload byte, which is exactly when the
verifier needs them. The decoder must keep them instead of draining them
([streaming_aws_decoder.go:105](../../internal/proxy/request/streaming_aws_decoder.go#L105),
the `size == 0` branch): parse each `name:value` line into a small map, expose it as
`Trailers()`, and keep ignoring `x-amz-trailer-signature` (ADR 0014). Two details the
current drain loop hides:

- `bufio.ReadString('\n')` returns **data together with `io.EOF`** when the last line
  has no terminator. The current code returns on the error and discards that line
  ([streaming_aws_decoder.go:110](../../internal/proxy/request/streaming_aws_decoder.go#L110));
  the capture must parse the partial line first. The
  `unsigned_trailer_without_final_crlf` framing already in the tests
  ([framing_test.go:119](../../internal/proxy/request/framing_test.go#L119)) is one CRLF
  away from this case.
- A trailer named in `X-Amz-Trailer` that never arrives is a **failed verification**,
  not a missing one. Otherwise omitting the trailer is a free opt-out from the check the
  client asked for.

### Algorithms, packages and hardware

Everything is stdlib. **No new dependency.** Verified against `go.mod`
(aws-sdk-go-v2 v1.47.0, service/s3 v1.113.0) and the Go 1.27.1 tree.

| Header | Algorithm | Package | Hardware |
|---|---|---|---|
| `x-amz-checksum-crc32` | CRC-32/IEEE | `hash/crc32`, `crc32.MakeTable(crc32.IEEE)` (stdlib caches this table) | amd64 PCLMULQDQ (`ieeeCLMUL`), arm64 ARMv8 CRC32 (`ieeeUpdate`, gated on `cpu.ARM64.HasCRC32`) |
| `x-amz-checksum-crc32c` | CRC-32C/Castagnoli | `hash/crc32`, `crc32.MakeTable(crc32.Castagnoli)` (cached) | amd64 SSE4.2 `castagnoliSSE42`, arm64 `castagnoliUpdate` |
| `x-amz-checksum-crc64nvme` | CRC-64/NVME | `hash/crc64`, reflected polynomial `0x9a6c9329ac4bc9b5` | **none** — software slicing-by-8 only |
| `Content-MD5` | MD5 | `crypto/md5` | no hardware instruction on either arch; hand-written scalar asm only |
| `x-amz-checksum-sha1` | SHA-1 | `crypto/sha1` | ARMv8 SHA1 / x86 SHA-NI when the CPU advertises them |
| `x-amz-checksum-sha256` | SHA-256 | `crypto/sha256` | ARMv8 SHA2 / x86 SHA-NI, otherwise AVX2 |

All values are base64 of the big-endian digest, which is what `hash.Hash.Sum` already
produces for `crc32`, `crc64`, MD5, SHA-1 and SHA-256.

**CRC32C already exists on the write path.** Since the segment chain landed, every write
computes a CRC32C over the whole plaintext and seals it in the object trailer
(ADR 0003 D13): [`NewChecksum`](../../pkg/encryption/dataencryption/segmented_gcm.go#L81)
per part, `Checksum.Append`
([segmented_gcm.go:86](../../pkg/encryption/dataencryption/segmented_gcm.go#L86)) across
them, over the same Castagnoli table
([segmented_gcm.go:69](../../pkg/encryption/dataencryption/segmented_gcm.go#L69)). It is
bit-for-bit the quantity a client declares as `x-amz-checksum-crc32c`, and on both PUT
routes it is complete before anything commits — `putObjectSegmented` seals the trailer
inside the body the SDK is pulling, and `putObjectAutoMultipart` has the combined `sum`
before `CompleteMultipartUpload`
([operations.go:797](../../internal/proxy/handlers/object/operations.go#L797)). Whether
to compare against it instead of running a second CRC32C pass is an implementation
choice for whoever does the work; this ticket does not settle it, and a declared
CRC32C on `UploadPart` or on a bucket configuration body has no such value to reuse.

The CRC64NVME polynomial is the same constant aws-sdk-go-v2 uses
(`service/internal/checksum@v1.11.3/algorithms.go:44` and `:106`, both re-checked
2026-09-10). That package sits under `github.com/aws/aws-sdk-go-v2/service/internal/`, so
Go's internal rule makes it unimportable from here; the constant is one line, copy it.

**CRC64NVME is a performance trap and must not be used naively.** `crc64.MakeTable`
caches only ISO and ECMA; for any other polynomial `crc64.update` rebuilds a 16 KiB
slicing-by-8 helper table **on every `Write` of 2048 bytes or more**
(`$GOROOT/src/hash/crc64/crc64.go`, the `else if len(p) >= 2048` branch, still present in
Go 1.27.1). At a 128 KiB read size that is one 16 KiB allocation and an 8×256 build loop
per 128 KiB of payload. This is the same `makeSlicingBy8Table` cost
[ticket 012](012-performance-audit-round2.md) item 1.1 measured at 1.16 % flat CPU when
the SDK was validating CRC64 responses. Build the slicing-by-8 table once into a
package-level `var` and run the update loop directly (about 25 lines), and benchmark it
against the naive form so the number is on record.

### What is verified, and what the client gets back

| Source | Known | Verified |
|---|---|---|
| `x-amz-checksum-*` request header | before the body | always, every algorithm |
| `Content-MD5` request header | before the body | always |
| aws-chunked trailer named in `X-Amz-Trailer` | after the last byte | always, per algorithm |
| `x-amz-trailer-signature` | after the last byte | never (ADR 0014) |

- Mismatch → **400 `BadDigest`**
  ([error_mapping.go:34](../../internal/proxy/response/error_mapping.go#L34)).
- Value that is not valid base64, or decodes to the wrong length → **400
  `InvalidDigest`** ([error_mapping.go:40](../../internal/proxy/response/error_mapping.go#L40)).

Comparison is on the decoded bytes with `bytes.Equal`. No secret is involved on either
side (the client knows the plaintext it just sent), so constant time buys nothing here;
note it rather than reaching for `crypto/subtle`.

### Failure behavior, per PUT route

The verdict must land before anything is committed. It does, on all three routes:

| Route | Body read at | Verdict lands | Result |
|---|---|---|---|
| `putObjectSegmented` | [operations.go:242](../../internal/proxy/handlers/object/operations.go#L242) | during the SDK's body read, surfacing as the `PutObject` error at [operations.go:273](../../internal/proxy/handlers/object/operations.go#L273) | request aborted mid-body, S3 commits nothing |
| `putObjectAutoMultipart` | [operations.go:673](../../internal/proxy/handlers/object/operations.go#L673) | `io.ReadFull` at [operations.go:770](../../internal/proxy/handlers/object/operations.go#L770) returns it, `producerErr` set at [:772](../../internal/proxy/handlers/object/operations.go#L772) | existing abort path at [:839](../../internal/proxy/handlers/object/operations.go#L839) aborts the S3 upload; **before** `CompleteMultipartUpload` |
| Client-driven `UploadPart` | [upload.go:76](../../internal/proxy/handlers/multipart/upload.go#L76) | inside `ReadBody`, before the backend `UploadPart` | 400, that part never reaches the backend |

Three details that decide the implementation:

- **Do not rely on `errors.Is` through the SDK.** On the `putObjectSegmented` route the
  reader error travels through `net/http`, `*url.Error` and smithy wrapping before the
  handler sees it. The handler must ask the verifier directly
  (`if verr := v.Err(); verr != nil { → BadDigest }`) *before* mapping the SDK error.
  Deterministic, and one field instead of a wrapping audit.
- **The auto-multipart route already has the shape for this.** The truncation guard at
  [operations.go:835](../../internal/proxy/handlers/object/operations.go#L835) asks
  `PlaintextContentLength` after the producer loop and sets `producerErr`, which the
  abort path then handles. A checksum verdict fits the same slot, and asking the verifier
  there is more direct than threading the error out of `io.ReadFull`.
- **The verdict always precedes Complete**, including when the object size is an exact
  multiple of the part size: there the last full `ReadFull` returns with `err == nil` and
  the EOF (and therefore the verdict) arrives on the next iteration, which still runs
  before `close(jobs)` and Complete. The `n == 0 && partNumber > 1` break at
  [operations.go:778](../../internal/proxy/handlers/object/operations.go#L778) is reached
  only on a *clean* EOF, so a mismatch cannot slip through it.

The error answers must change accordingly. A checksum verdict must not be reported as an
internal error: `putObjectAutoMultipart` answers a producer failure with 500
`UploadError` ([operations.go:841](../../internal/proxy/handlers/object/operations.go#L841))
and `putObjectSegmented` maps the SDK error through `WriteS3Error`
([:273](../../internal/proxy/handlers/object/operations.go#L273)) — both need
[`WriteGenericError`](../../internal/proxy/response/errors.go#L89) with `BadDigest` /
`InvalidDigest` for this case only. `UploadPart` needs one more step: it answers a read
failure with `http.Error` — a plain-text body, not an S3 error document
([upload.go:79](../../internal/proxy/handlers/multipart/upload.go#L79)), even though the
same handler answers its other failures through `errorWriter`
([upload.go:167](../../internal/proxy/handlers/multipart/upload.go#L167)).

### Never forwarded, never stored, never echoed

- **Never forwarded.** Already true in the tree: both `Content-MD5` forwards are gone,
  and so is the `ChecksumAlgorithm = SHA256` that `DeleteObjects` set merely because the
  client sent a `Content-MD5` — two unrelated quantities, and the client's MD5 was not
  consulted either way. With `RequestChecksumCalculationWhenRequired`
  ([server.go:147](../../internal/proxy/server.go#L147)) the SDK still supplies the
  checksum `DeleteObjects` mandates. Keep it that way.
- **Never stored.** No `s3ep-crc32`, no `s3ep-md5`, nothing. A checksum of the
  **plaintext** written in cleartext metadata next to the ciphertext hands the hostile
  backend a confirmation oracle: for a small or low-entropy object (a Velero
  `velero-backup.json`, a short manifest) it can guess a candidate plaintext offline and
  check it against 4 bytes of CRC. This is also why the format's own CRC32C lives
  *sealed in the trailer* rather than in metadata (ADR 0003 D13, amended 2026-09-09).
- **Never echoed.** Real S3 returns the checksum on the PutObject response. Neither SDK
  examined reads it (other clients unchecked): aws-sdk-go-v2 validates response checksums
  only on the GetObject-shaped operations (`middleware_validate_output.go`), minio-go
  does not validate a PutObject response digest, and the value is the client's own number
  anyway. This is about the client's value on the PUT response and does not contradict
  ADR 0003 D14, which serves *the proxy's own* sealed CRC32C on GET and HEAD — a
  different value on a different leg, owned by [ticket 013](013-storage-format-v2.md).

**Adjacent, same family, worth knowing:** the `ETag` a client receives is the backend
ETag, i.e. the ciphertext ETag
([operations.go:284](../../internal/proxy/handlers/object/operations.go#L284)), so a
client following the single-part convention that an ETag is the MD5 of the content gets a
value that does not match the body it was served. That is self-consistent across PUT,
HEAD and GET and no SDK examined verifies it, so it is left alone.

### P-5: one body reader for every handler

Same defect family as F-1 — a handler that reads `r.Body` directly stores or parses the
aws-chunked framing as if it were content.

- [operations.go:404](../../internal/proxy/handlers/object/operations.go#L404)
  `handleDeleteObjects`: `io.ReadAll(r.Body)` → `h.requestParser.ReadBody(r)`.
- [complete.go:90](../../internal/proxy/handlers/multipart/complete.go#L90)
  `CompleteHandler.Handle`: `io.ReadAll(r.Body)` → `h.requestParser.ReadBody(r)`. The
  handler already holds a `*request.Parser`
  ([complete.go:31](../../internal/proxy/handlers/multipart/complete.go#L31)) and never
  uses it.
- `html.UnescapeString(string(bodyData))` before `xml.Unmarshal` in `complete.go`:
  **done**, the call and the `html` import are gone, and the reason is kept as a comment
  at [complete.go:99](../../internal/proxy/handlers/multipart/complete.go#L99). It turned
  a body containing `&amp;lt;Part&amp;gt;` into real markup, so attacker-escaped text
  became document structure before the XML parser saw it. Keep the integration test for
  it in scope.
- [bucket/operations.go:100](../../internal/proxy/handlers/bucket/operations.go#L100)
  `handleCreateBucket`: `xml.NewDecoder(r.Body).Decode(...)` → `ReadBody` +
  `xml.Unmarshal`. Two fixes in passing: gate on `DecodedContentLength(r) > 0` instead of
  `r.ContentLength > 0`
  ([bucket/operations.go:95](../../internal/proxy/handlers/bucket/operations.go#L95)),
  because for an aws-chunked body `r.ContentLength` counts framing bytes; and stop
  swallowing the decode error (`err == nil` today) — a non-empty body that is not
  well-formed XML answers `MalformedXML`, as S3 does. That is a deliberate behavior
  change, called out here so it is not a surprise.

`handleObjectLegalHold` and `handleObjectRetention` used to read the body with
`io.ReadAll` and discard it; both are one-line refusals now and read nothing, so there is
no third case here.

### D-16: bucket configuration handlers

All eight already read through the parser —
[cors.go:68](../../internal/proxy/handlers/bucket/cors.go#L68),
[policy.go:74](../../internal/proxy/handlers/bucket/policy.go#L74),
[lifecycle.go:66](../../internal/proxy/handlers/bucket/lifecycle.go#L66),
[logging.go:169](../../internal/proxy/handlers/bucket/logging.go#L169),
[notification.go:64](../../internal/proxy/handlers/bucket/notification.go#L64),
[versioning.go:64](../../internal/proxy/handlers/bucket/versioning.go#L64),
[tagging.go:66](../../internal/proxy/handlers/bucket/tagging.go#L66),
[acl.go:75](../../internal/proxy/handlers/bucket/acl.go#L75) — so they inherit both the
aws-chunked decoding and, after this ticket, the verification. **The gap is purely a
test**, which is why D-16 folds in here at near-zero cost.

### Configuration

**No key.** `encryption.verify_upload_digests` was withdrawn on 2026-09-09 before it was
built (ADR 0012 D3 widened, D4 struck) and does not exist anywhere in the tree. The CRC
family never had a knob by design — a control that only exists in configuration is worse
than none, and there is nothing to trade. Adding one now would also have to answer to
[ADR 0013](../adr/0013-a-configuration-key-exists-only-if-code-reads-it.md).

---

## Work breakdown

- [x] **Prerequisite check.** Done: no `ContentMD5` and no `Checksum*` on any backend
      input, and no backend `Checksum*` copied onto a plaintext response. Note for the
      record: those copies never reached the wire — `writeGetObjectResponse` ignored them
      — so nothing in this tree emits an `x-amz-checksum-*` response header today. Do not
      describe the removal as more than that.
- [x] Delete the `Content-MD5` → `ChecksumAlgorithm = SHA256` line on `DeleteObjects` —
      gone; `DeleteObjectsInput` carries `Bucket` and `Delete` only.
- [x] Delete the `html.UnescapeString` call before `xml.Unmarshal` in `complete.go` —
      gone, with the reason kept as a comment.
- [x] ~~Config: `encryption.verify_upload_digests`, default false, plus the
      `config/*-example.yaml` files and `test/e2e/velero/values-proxy.yaml`.~~ **Void
      2026-09-09: no key.**
- [ ] Capture aws-chunked trailers in the decoder instead of draining them
      ([streaming_aws_decoder.go:105](../../internal/proxy/request/streaming_aws_decoder.go#L105)),
      including the `data + io.EOF` partial-line case; expose `Trailers()`; keep ignoring
      `x-amz-trailer-signature`.
- [ ] New `internal/proxy/request/checksum.go`: algorithm registry (header name → hash
      constructor, expected digest length), sentinel errors for mismatch and malformed
      value, and the `verifyingReader` above.
- [ ] CRC64NVME: package-level slicing-by-8 table built once, own update loop, no
      per-`Write` table rebuild.
- [ ] Wire the verifier into both parser entry points
      ([parser.go:43](../../internal/proxy/request/parser.go#L43),
      [:108](../../internal/proxy/request/parser.go#L108)). Return the inner reader
      unwrapped when the request declares nothing.
- [ ] Answer `BadDigest` / `InvalidDigest` on all three PUT routes; `putObjectSegmented`
      asks the verifier before mapping the SDK error; `putObjectAutoMultipart` replaces
      500 `UploadError` at
      [operations.go:841](../../internal/proxy/handlers/object/operations.go#L841) for
      this case only; `UploadPart` answers through `errorWriter` instead of `http.Error`.
- [ ] `DeleteObjects` refuses a request with no body digest and verifies the one it gets
      (ADR 0012 D14). The current no-requirement behaviour is pinned by
      [deleteobjects_coverage_test.go:597](../../internal/proxy/handlers/object/deleteobjects_coverage_test.go#L597),
      which has to change with it.
- [ ] **P-5 (a)**: `handleDeleteObjects` through `ReadBody`.
- [ ] **P-5 (b)**: `CompleteHandler.Handle` through `ReadBody`.
- [ ] **P-5 (c)**: `handleCreateBucket` through `ReadBody`, gated on
      `DecodedContentLength`, `MalformedXML` on a bad non-empty body.
- [ ] Flip `TestObjPutClientChecksumsAreAcceptedAndDropped`
      ([objectput_coverage_test.go:1498](../../internal/proxy/handlers/object/objectput_coverage_test.go#L1498)):
      it asserts the defect and its comment names this work as the fix. It becomes the
      `BadDigest` case; keep its non-forwarding assertions.
- [ ] Unit tests in `internal/proxy/request`: extend
      [framing_test.go](../../internal/proxy/request/framing_test.go) with a
      per-algorithm trailer builder and a `corrupt` variant, then table-test every
      framing × every algorithm × {correct, wrong, malformed base64,
      declared-but-absent} through both `ReadBody` and `StreamingReader`.
- [ ] Unit tests for the eight bucket configuration handlers (**D-16**): an aws-chunked
      body per handler, correct and wrong trailer.
- [ ] Integration tests (below).
- [ ] Measurement (below), recorded in this ticket.
- [ ] Docs: README statement that every declared checksum is verified, with the measured
      cost per algorithm as a table (replacing the § Checksums text that says the
      headers have no effect today); the trailer statement in `SECURITY_ARCHITECTURE.md`
      (what is verified on the client leg, what is not, and why nothing is stored),
      replacing the "Client checksums" residual-risk entry and ticking its hardening
      checkbox.

---

## Success criteria

**Unit** — `make test-unit` green, and specifically:

- For each of the six framings in
  [framing_test.go](../../internal/proxy/request/framing_test.go#L71) and each algorithm:
  a correct trailer passes and returns the payload byte for byte (SHA-256 comparison, per
  the work order — no hex dumps), a deliberately wrong trailer returns the mismatch
  error, a malformed base64 value returns the malformed error, and a trailer named in
  `X-Amz-Trailer` but never sent returns the mismatch error.
- A wrong `Content-MD5`, `-sha1` and `-sha256` each fail with `BadDigest`, **and no
  client digest is ever handed to the backend** — the three existing non-forwarding
  assertions must still hold.
- A body declaring no checksum is returned by the parser **unwrapped** (assert the
  concrete reader type — this is the zero-cost property, and it is easy to lose in a
  later refactor).
- The trailer whose last line has no terminating CRLF is still captured.

**Integration** — `make test-integration` and `make test-integration-tls`, both green, no
test skipped or disabled. New cases, using the raw signer
([s3_signing_helper.go:210](../../test/integration/s3_signing_helper.go#L210)) to
hand-build bodies the SDK will not produce:

- Hand-built aws-chunked PUT with a correct and a deliberately wrong trailer checksum,
  for CRC32, CRC32C and CRC64NVME, at two sizes that select the two PUT routes: below
  `optimizations.streaming_segment_size` (12 MiB by default) for `putObjectSegmented`,
  and above it for `putObjectAutoMultipart`. Add a third shape with no
  `X-Amz-Decoded-Content-Length`, which is the other way into the multipart route
  ([operations.go:228](../../internal/proxy/handlers/object/operations.go#L228)).
  Correct → 200 and the object reads back with a matching SHA-256; wrong → **400
  `BadDigest`** and `HeadObject` on the key answers 404 — nothing was stored and no
  multipart upload was left behind (`ListMultipartUploads` against MinIO directly, not
  through the proxy: P-7).
- The kopia-shaped case: a plain (identity-framed) PUT with a wrong `Content-MD5`,
  answered 400 `BadDigest`, which is what MinIO answers directly.
- Client-driven `UploadPart` with a wrong trailer → 400 on that part, and the upload can
  still be aborted cleanly.
- `DeleteObjects` with no digest → refused; with a wrong digest → 400.
- **D-16**: one bucket configuration PUT (`cors`, `policy`, `lifecycle`, `logging`,
  `notification`, `versioning`, `tagging`, `acl`) with an aws-chunked body — correct
  trailer applies the configuration, wrong trailer answers 400 and leaves the
  configuration unchanged.
- `DeleteObjects` and `CompleteMultipartUpload` with aws-chunked bodies (P-5), and a
  `CompleteMultipartUpload` body containing `&amp;lt;Part&amp;gt;` that must **not**
  parse as markup.

**Performance** — regressions are reported, not absorbed:

- `make test-integration-performance` after `./start-demo.sh`, 1 GB upload and download,
  three runs, compared against the numbers this branch records. The CRC32 path must not
  move the upload figure measurably; anything beyond noise is a finding, not a cost of
  doing business.
- A Go benchmark on the CRC64NVME implementation: package-level table versus the naive
  `crc64.New(crc64.MakeTable(nvme))`, at the decoder's 128 KiB read size, reporting B/op.
  The naive form must not ship.
- The published cost number (ADR 0012 D13): measure a kopia-shaped upload (20 MiB
  objects, the size kopia writes per pack blob) without a digest, with `Content-MD5` and
  with `x-amz-checksum-sha256`, and record the three end-to-end figures next to the
  primitive numbers in the Status block. It goes into the README cost table; it gates
  nothing.

**End to end** — `./test/e2e/velero/e2e-up.sh` then `make test-e2e-velero`, all 13
scenarios green. Velero's own uploader sends CRC32 trailers, so this is the check that
always-on CRC verification does not break a real client.

---

## Risks and open questions

- ~~**The default does not fix the probed defect on the kopia path.**~~ **Closed
  2026-09-09:** there is no default; kopia's `Content-MD5` is verified like everything
  else, at about ten times the encryption pass per byte on its uploads, a number the
  README states.
- **SHA is cheaper than MD5 on current hardware**, measured 2026-09-09: SHA-1 and SHA-256
  run at 3.4 to 3.5 GB/s with the ARMv8 instructions, MD5 at 0.95 GB/s with none. Moot
  for the rule, which no longer distinguishes families; kept because an x86 server
  without SHA-NI puts SHA into MD5's class, which was not measured.
- **CRC32 is a 32-bit check, not an integrity guarantee.** It catches transmission
  corruption, which is what it is for. It does not detect a deliberate modification on
  the client leg, and nothing in this ticket claims it does — the client leg's adversary
  is explicitly out of the threat model (ADR 0014). `SECURITY_ARCHITECTURE.md` must say
  this in the same breath as the new control, or the control gets over-trusted.
- **Unverified: whether any S3 client sends `x-amz-checksum-crc64nvme` on upload.**
  aws-sdk-go-v2 at the pinned version defaults to CRC32
  (`middleware_setup_context.go:59`); AWS S3 *records* CRC64NVME for new objects
  server-side, which is a different thing. The algorithm is implemented because the
  header exists, not because a measured client sends it — so the table trap above is a
  latent cost, not a current one.
- **Unverified: how MinIO behaves on a wrong trailer checksum** for each algorithm, which
  is the comparison baseline the integration tests assert against for `Content-MD5`.
  Check it once when writing them and record what it answers; do not assume the proxy and
  MinIO must agree on the error code for every algorithm.
- **Behavior change on `handleCreateBucket`**: a malformed non-empty body now answers
  `MalformedXML` where it was silently accepted. Correct, and matches S3, but it is a
  visible change for any client that was sending junk and getting away with it.
- ~~**Interaction with the v2 ticket.**~~ **Resolved 2026-09-10: the segment chain
  landed.** The prediction held — the four-route table collapsed to the three routes
  above, `streaming_threshold` and the GCM/CTR split are gone, and the parser choke point
  and the verifier design survived untouched. The reason the tests should assert on
  *client-visible* status codes rather than on which internal route ran survives with it.
