# Ticket 014: Verify client upload checksums

## Status (2026-09-06)

**Open.** Carries **D-9**, **P-5** and **D-16** from the Velero path review
(the [label index](README.md#label-index) defines them), item 3 of its order
of work. It has one hard dependency: the **before-merge N-6 work**
(b, c, d), which stops the proxy from *forwarding* the client's `Content-MD5`
to the backend (b, c) and removes the backend checksum copies on GET and HEAD
(d — latent today, never emitted on the wire; see the prerequisite check).
That work removes the only checksum handling the proxy has; this ticket puts the
verification in its place, so the two belong to one story — merging the removal
without this ticket leaves the client-to-proxy leg with no integrity check at
all. It does **not** depend on the storage-format-v2 ticket (order of work item
2): the choke point here is the request parser, which v2 does not touch. It is
still scheduled after v2, because the PUT-route tests it adds touch handlers v2
rewrites, and writing them twice is waste.

**Decided 2026-09-09 (repository owner, ADR 0012 D3/D4/D14): the switch is gone before
it was built.** Every checksum a client declares is verified, `Content-MD5`, SHA-1 and
SHA-256 included; `encryption.verify_upload_digests` is not added anywhere.
`DeleteObjects` requires a digest and verifies it always (D14). Every line below that
says "with the switch on/off" or "default false" reads as "always"; the config,
example-file and README-key items are void, and the measurement stays as a published
cost table, not as a gate. Measured 2026-09-09, Apple M5 Pro, one core, 64 KiB blocks,
Go 1.27: CRC32 and CRC32C 12 GB/s, AES-GCM seal 9.1 GB/s, SHA-1 3.5 GB/s, SHA-256
3.4 GB/s, MD5 0.95 GB/s. MD5 costs about ten times the encryption pass per byte and
lands on kopia's uploads; that number goes into the README.

---

## Before you start

- The status above names a hard dependency on the before-merge work that stops
  the proxy forwarding the client's `Content-MD5` and drops the backend checksum
  copies on GET/HEAD. It landed and shipped: no `ContentMD5` and no `Checksum*`
  field is set on any backend input any more (comments mark both former forward
  sites), and no backend `Checksum*` value is copied onto a plaintext GET or
  HEAD response. This ticket starts with no dependency.
- The `ChecksumAlgorithm = SHA256` line on `DeleteObjects` and the
  `html.UnescapeString` call before `xml.Unmarshal` in `complete.go` are already
  deleted; both work items are ticked below.
- `SECURITY_ARCHITECTURE.md` exists at the repo root and already states that
  client checksums are dropped and not verified, with a hardening entry pointing
  at [ADR 0012](../adr/0012-client-checksums-are-verified-never-forwarded.md).
  The docs item is an edit of that text, not a new file.
- `handleObjectLegalHold` and `handleObjectRetention` are one-line refusals now
  and read no body at all.
- Go is 1.27.1 (`go.mod`, `Containerfile`), not 1.26. The CRC64 slicing-by-8
  rebuild on every write of 2 KiB or more is still there in that toolchain.
- Line numbers cited below have drifted — re-locate by symbol, not by line.
  Behaviour at each cited spot is unchanged unless a bullet above says
  otherwise. Still live exactly as described: the raw `io.ReadAll` in
  `handleDeleteObjects` and `CompleteHandler.Handle`, `xml.NewDecoder(r.Body)`
  in `handleCreateBucket`, the trailer drain loop, and the absence of
  `verify_upload_digests` anywhere in the tree.

## Settled

- `DeleteObjects` verifies its mandatory body digest **always** and refuses a
  request that carries none, independently of `verify_upload_digests`: that
  key's cost argument is about multi-megabyte uploads, not a delete document of
  a few kilobytes. Confirmed 2026-09-09 as ADR 0012 D14; the key itself no longer
  exists.

---

## Context

Under the threat model recorded on 2026-09-06 the S3 endpoint is **hostile**:
it can read, change, swap, truncate and lie. Everything the proxy stores is
defended by the DEK layer and by the object integrity mechanism. Nothing
defends the **client-to-proxy leg**, and that leg is where the plaintext still
exists. A byte corrupted before the proxy encrypts is encrypted faithfully,
authenticated faithfully, and is from then on indistinguishable from correct
data — for the object HMAC today and for the v2 segment tags tomorrow. The
upload checksum is the only check that can catch it, and per **D-19** it is the
only one the proxy will run on that leg (per-chunk SigV4 signatures stay
unverified, deliberately: the adversary is on the other leg).

What happens today:

- The aws-chunked trailer is read and thrown away. The decoder drains trailer
  lines in a loop and returns nil
  ([streaming_aws_decoder.go:100](../../internal/proxy/request/streaming_aws_decoder.go#L100)),
  which the type comment states outright
  ([streaming_aws_decoder.go:27](../../internal/proxy/request/streaming_aws_decoder.go#L27)).
  Every current aws-sdk-go-v2 client sends one: with
  `RequestChecksumCalculation` at its default `WhenSupported` the SDK picks
  CRC32 when the caller names no algorithm
  (`service/internal/checksum@v1.11.2/middleware_setup_context.go:59`), and
  frames it as a trailer over HTTPS.
- `Content-MD5` is accepted and never checked. It no longer reaches the backend
  on any route — the two forwards are gone, and a comment marks each spot. A
  deliberately wrong
  digest gets **200** from the proxy on both the small-object and the
  auto-multipart path (probed on this tree at 2 MiB and 8 MiB, `strict` mode);
  MinIO answers **400** to the same request. kopia sets `SendContentMd5: true`
  and therefore sends one on **every** blob it writes, so its integrity intent
  is dropped for all Velero volume data.

D-9 settles what to do: verify, on by default, never forward, never store —
with one performance-driven exception, stated plainly rather than hidden. CRC is
free on hardware; a second full MD5 or SHA pass is not, and on a bulk-upload path
(kopia's, for example) it would eat upload throughput to protect the leg whose
adversary is out of the threat model ([ADR 0001](../adr/0001-the-backend-is-hostile.md)).
So the CRC family is always verified and the digest family is opt-in.

---

## Scope

**In scope — this ticket closes D-9, P-13, P-5, D-16 and N-6 (a) (since 2026-09-09
there is no switch: everything declared is verified):**

- Verification of `x-amz-checksum-crc32`, `-crc32c` and `-crc64nvme`, from a
  request header or from the aws-chunked trailer, **always**.
- Verification of `Content-MD5`, `x-amz-checksum-sha1` and `-sha256`, **always**
  (2026-09-09; was: behind `encryption.verify_upload_digests`, default false).
- A mismatch answers `BadDigest`; a malformed digest value answers
  `InvalidDigest`. On every PUT route: small-object direct, streaming
  single-part, auto-multipart, and client-driven `UploadPart`.
- No client checksum value ever reaches the backend, and none is ever written to
  object metadata.
- **P-5**: the three handlers that read the body raw go through
  `Parser.ReadBody`, and the `html.UnescapeString` call before `xml.Unmarshal`
  in `complete.go` is deleted regardless of the rest.
- **D-16**: the eight bucket configuration handlers get an aws-chunked body
  test of the same shape.

**Out of scope:**

- Per-chunk and trailer **signature** verification — D-19, decided: leave, and
  say so in `SECURITY_ARCHITECTURE.md`.
- Response checksums on GET/HEAD. The backend value describes ciphertext and is
  meaningless to a client that receives plaintext; removing it is the
  before-merge N-6 (d) work, and object integrity is the v2 ticket's job.
  Serving a checksum of our own is a separate idea with a real but narrow
  benefit, sketched under [Later: a plaintext response
  checksum](#later-a-plaintext-response-checksum) so it is not confused with
  this one.
- Echoing the verified value back to the client on the PUT response (rationale
  below).
- `s3_security` knobs, `use_tls` refusal, presign lifetime — configuration
  hygiene ticket (D-6, D-7, N-5).

**Explicitly not closed here:** N-6 (b), (c) and (d) are before-merge work on
this branch, listed below only as the dependency they are.

---

## Design

### Where the hash goes: one pass, no extra copy

Every request body in the proxy funnels through exactly two functions — once
P-5 below closes the three handlers that still read `r.Body` raw:

| Entry point | Used by |
|---|---|
| [`Parser.ReadBody`](../../internal/proxy/request/parser.go#L43) | small-object PUT ([operations.go:463](../../internal/proxy/handlers/object/operations.go#L463), [:514](../../internal/proxy/handlers/object/operations.go#L514)), client-driven `UploadPart` ([upload.go:77](../../internal/proxy/handlers/multipart/upload.go#L77)), the eight bucket configuration handlers |
| [`Parser.StreamingReader`](../../internal/proxy/request/parser.go#L117) | streaming single-part PUT ([operations.go:624](../../internal/proxy/handlers/object/operations.go#L624)), auto-multipart ([operations.go:1275](../../internal/proxy/handlers/object/operations.go#L1275)) |

Both already choose between the aws-chunked decoder and the raw body from
headers alone ([parser.go:49](../../internal/proxy/request/parser.go#L49),
[:121](../../internal/proxy/request/parser.go#L121)). The verifier goes **around
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

1. **One pass, no copy.** The hash reads `p[:n]` — the destination buffer the
   caller already owns and is about to consume, still in L1/L2. No staging
   buffer, no second traversal, no allocation per `Read`. On the streaming
   paths that buffer is the 64 KiB `bufio` window
   ([operations.go:625](../../internal/proxy/handlers/object/operations.go#L625),
   [:1276](../../internal/proxy/handlers/object/operations.go#L1276)); on
   `ReadBody` it is the pre-sized buffer `readAllSized` fills
   ([parser.go:73](../../internal/proxy/request/parser.go#L73)).
2. **Zero cost when nothing is declared.** If the request names no algorithm the
   parser returns the inner reader unwrapped — not even a `Read` indirection.
   Only algorithms the request actually declares get a hash, so a
   CRC32-trailered upload costs exactly one CRC32 pass and nothing else.
3. **It sees the plaintext payload, which is what the checksum covers.** The
   aws-chunked framing is stripped by the inner reader before the verifier sees
   a byte; the encryptor sits after it. Neither ciphertext nor framing is ever
   hashed.

Rejected alternatives, so they are not re-proposed: hashing **inside**
`streamingAWSChunkedReader.Read`
([streaming_aws_decoder.go:63](../../internal/proxy/request/streaming_aws_decoder.go#L63))
would miss every identity body — kopia's `Content-MD5` PUT, `DeleteObjects`,
`CompleteMultipartUpload` — and would need a second copy of the same logic.
Hashing inside the encryption manager would miss the `none` provider entirely
and would have to be threaded through three provider layers.

### Trailer capture

Trailer values arrive **after** the last payload byte, which is exactly when the
verifier needs them. The decoder must keep them instead of draining them
([streaming_aws_decoder.go:100](../../internal/proxy/request/streaming_aws_decoder.go#L100)):
parse each `name:value` line into a small map, expose it as `Trailers()`, and
keep ignoring `x-amz-trailer-signature` (D-19). Two details the current drain
loop hides:

- `bufio.ReadString('\n')` returns **data together with `io.EOF`** when the last
  line has no terminator. The current code returns on the error and discards
  that line; the capture must parse the partial line first. The
  `unsigned_trailer_without_final_crlf` framing already in the tests
  ([framing_test.go:119](../../internal/proxy/request/framing_test.go#L119)) is one
  CRLF away from this case.
- A trailer named in `X-Amz-Trailer` that never arrives is a **failed
  verification**, not a missing one. Otherwise omitting the trailer is a free
  opt-out from the check the client asked for.

### Algorithms, packages and hardware

Everything is stdlib. **No new dependency.** Verified against `go.mod`
(aws-sdk-go-v2 v1.46.0, service/s3 v1.111.0) and the Go 1.27 tree.

| Header | Algorithm | Package | Hardware |
|---|---|---|---|
| `x-amz-checksum-crc32` | CRC-32/IEEE | `hash/crc32`, `crc32.MakeTable(crc32.IEEE)` (stdlib caches this table) | amd64 PCLMULQDQ (`ieeeCLMUL`), arm64 ARMv8 CRC32 (`ieeeUpdate`, gated on `cpu.ARM64.HasCRC32`) |
| `x-amz-checksum-crc32c` | CRC-32C/Castagnoli | `hash/crc32`, `crc32.MakeTable(crc32.Castagnoli)` (cached) | amd64 SSE4.2 `castagnoliSSE42`, arm64 `castagnoliUpdate` |
| `x-amz-checksum-crc64nvme` | CRC-64/NVME | `hash/crc64`, reflected polynomial `0x9a6c9329ac4bc9b5` | **none** — software slicing-by-8 only |
| `Content-MD5` | MD5 | `crypto/md5` | no hardware instruction on either arch; hand-written scalar asm only |
| `x-amz-checksum-sha1` | SHA-1 | `crypto/sha1` | ARMv8 SHA1 / x86 SHA-NI when the CPU advertises them |
| `x-amz-checksum-sha256` | SHA-256 | `crypto/sha256` | ARMv8 SHA2 / x86 SHA-NI, otherwise AVX2 |

All values are base64 of the big-endian digest, which is what `hash.Hash.Sum`
already produces for `crc32`, `crc64`, MD5, SHA-1 and SHA-256.

The CRC64NVME polynomial is the same constant aws-sdk-go-v2 uses
(`service/internal/checksum@v1.11.2/algorithms.go:44` and `:106`). That package
sits under `github.com/aws/aws-sdk-go-v2/service/internal/`, so Go's internal
rule makes it unimportable from here; the constant is one line, copy it.

**CRC64NVME is a performance trap and must not be used naively.**
`crc64.MakeTable` caches only ISO and ECMA; for any other polynomial
`crc64.update` rebuilds a 16 KiB slicing-by-8 helper table **on every `Write`
of 2048 bytes or more** (`$GOROOT/src/hash/crc64/crc64.go`, the
`else if len(p) >= 2048` branch). At a 64 KiB read size that is one 16 KiB
allocation and an 8×256 build loop **per 64 KiB of payload** — roughly 256 MiB
of garbage per GiB uploaded. This is the same `makeSlicingBy8Table` cost
[ticket 012](012-performance-audit-round2.md) item 1.1 measured at 1.16 % flat
CPU when the SDK was validating CRC64 responses. Build the slicing-by-8 table
once into a package-level `var` and run the update loop directly (about 25
lines), and benchmark it against the naive form so the number is on record.

### What is verified, and what the client gets back

| Source | Known | Verified |
|---|---|---|
| `x-amz-checksum-*` request header | before the body | always, every algorithm |
| `Content-MD5` request header | before the body | always (2026-09-09; was: only with the switch) |
| aws-chunked trailer named in `X-Amz-Trailer` | after the last byte | same rule per algorithm |
| `x-amz-trailer-signature` | after the last byte | never (D-19) |

- Mismatch → **400 `BadDigest`**
  ([error_mapping.go:34](../../internal/proxy/response/error_mapping.go#L34)).
- Value that is not valid base64, or decodes to the wrong length → **400
  `InvalidDigest`** ([error_mapping.go:40](../../internal/proxy/response/error_mapping.go#L40)).
- A digest header that is present but not verified (MD5 with the switch off) is
  **dropped**, not forwarded. The backend must never be asked to check a digest
  of a plaintext it never receives — that is exactly N-6 (b) and (c).

Comparison is on the decoded bytes with `bytes.Equal`. No secret is involved on
either side (the client knows the plaintext it just sent), so constant time buys
nothing here; note it rather than reaching for `crypto/subtle`.

### Failure behavior, per PUT route

The verdict must land before anything is committed. It does, on all four routes:

| Route | Body read at | Verdict lands | Result |
|---|---|---|---|
| Small object, direct | [operations.go:463](../../internal/proxy/handlers/object/operations.go#L463) / [:514](../../internal/proxy/handlers/object/operations.go#L514) | inside `ReadBody`, **before any backend call** | 400, nothing stored, nothing to clean up |
| Client-driven `UploadPart` | [upload.go:77](../../internal/proxy/handlers/multipart/upload.go#L77) | inside `ReadBody`, before the backend `UploadPart` | 400, that part never reaches the backend |
| Streaming single-part | [operations.go:624](../../internal/proxy/handlers/object/operations.go#L624) | during the SDK's body read, surfacing as the `PutObject` error at [operations.go:711](../../internal/proxy/handlers/object/operations.go#L711) | request aborted mid-body, S3 commits nothing |
| Auto-multipart | [operations.go:1275](../../internal/proxy/handlers/object/operations.go#L1275) | `io.ReadFull` at [operations.go:1375](../../internal/proxy/handlers/object/operations.go#L1375) returns it, `producerErr` set at [:1378](../../internal/proxy/handlers/object/operations.go#L1378) | existing abort path at [:1438](../../internal/proxy/handlers/object/operations.go#L1438) aborts the S3 upload; **before** `CompleteMultipartUpload` |

Two details that decide the implementation:

- **Do not rely on `errors.Is` through the SDK.** On the streaming single-part
  route the reader error travels through `net/http`, `*url.Error` and smithy
  wrapping before the handler sees it. The handler must ask the verifier
  directly (`if verr := v.Err(); verr != nil { → BadDigest }`) *before* mapping
  the SDK error. Deterministic, and one field instead of a wrapping audit.
- **The auto-multipart verdict always precedes Complete**, including when the
  object size is an exact multiple of the part size: there the last full
  `ReadFull` returns with `err == nil` and the EOF (and therefore the verdict)
  arrives on the next iteration, which still runs before `close(jobs)` and
  Complete. The existing `n == 0 && partNumber > 1` break at
  [operations.go:1382](../../internal/proxy/handlers/object/operations.go#L1382)
  is reached only on a *clean* EOF, so a mismatch cannot slip through it.

The error answers must change accordingly: [:466](../../internal/proxy/handlers/object/operations.go#L466)
and [:517](../../internal/proxy/handlers/object/operations.go#L517) currently write
`ReadError` (400 and 500), and [:1440](../../internal/proxy/handlers/object/operations.go#L1440)
writes 500 `UploadError`. A checksum verdict must not be reported as an internal
error; use
[`WriteGenericError`](../../internal/proxy/response/errors.go#L73) with
`BadDigest` / `InvalidDigest`. `UploadPart` needs one more step: it answers a
read failure with `http.Error` — a plain-text body, not an S3 error document
([upload.go:80](../../internal/proxy/handlers/multipart/upload.go#L80)), even
though the same handler answers its other failures through `errorWriter`
([upload.go:169](../../internal/proxy/handlers/multipart/upload.go#L169)).

### Never forwarded, never stored, never echoed

- **Never forwarded.** Already true in the tree: both `Content-MD5` forwards are
  gone, and so is the `ChecksumAlgorithm = SHA256` that `DeleteObjects` set
  merely because the client sent a `Content-MD5` — two unrelated quantities, and
  the client's MD5 was not consulted either way. With
  `RequestChecksumCalculationWhenRequired`
  ([server.go:171](../../internal/proxy/server.go#L171)) the SDK still supplies the
  checksum `DeleteObjects` mandates. Keep it that way.
- **Never stored.** No `s3ep-crc32`, no `s3ep-md5`, nothing. A checksum of the
  **plaintext** written in cleartext metadata next to the ciphertext hands the
  hostile backend a confirmation oracle: for a small or low-entropy object
  (a Velero `velero-backup.json`, a short manifest) it can guess a candidate
  plaintext offline and check it against 4 bytes of CRC. This ticket adds no key
  to the metadata list in [CLAUDE.md](../../CLAUDE.md); v2 rewrites that list on its
  own account.
- **Never echoed.** Real S3 returns the checksum on the PutObject response.
  Neither SDK examined reads it (other clients unchecked): aws-sdk-go-v2 validates response checksums only on
  the GetObject-shaped operations (`middleware_validate_output.go`), minio-go
  does not validate a PutObject response digest, and the value is the client's
  own number anyway. Skipping it is the minimum code that solves the problem; if
  a client turns up that needs it, the value is already computed and the echo is
  three lines.

### Later: a plaintext response checksum

Not this ticket, and not a defect. Recorded because the question comes up every
time someone reads N-6 (d) and sees that the proxy emits no `x-amz-checksum-*`
at all.

**What it would buy.** Not transport integrity: the proxy-to-client leg is TLS,
and the adversary in the threat model sits on the other side. Not object
integrity either: the HMAC today and the per-segment GCM tags in
[013](013-storage-format-v2.md) already prove the decrypted bytes are authentic,
keyed, which a CRC is not. It buys exactly one thing nothing else covers —
**errors in the proxy itself**. A tag proves the plaintext of a segment is
genuine; it does not prove the proxy assembled and served the right bytes. An
off-by-one in range slicing or in v2 segment reassembly survives every check we
have, and a client comparing a checksum it can recompute would catch it.

**Why it is not a small change.** Headers precede the body, so a checksum
computed while streaming is only known once the body is already gone. Serving it
therefore requires the value to be computed at upload and stored — and stored
**encrypted under the DEK**, never in cleartext metadata, for the confirmation
oracle reason in [Never forwarded, never stored, never echoed](#never-forwarded-never-stored-never-echoed) above.

**When.** Bundle it, do not do it alone:

- with this ticket, which already computes the plaintext CRC on the upload path,
  so the value is a by-product rather than a second pass;
- with [013](013-storage-format-v2.md), which rewrites the metadata key list on
  its own account — that is the moment to add a key, not before.

**Scope if it happens.** Whole-object GET and HEAD only. Real S3 returns no
object-level checksum on a ranged GET either, so a range needs no answer. Priority
is low: it is defence in depth against our own bugs, not part of the threat model.

**Adjacent, same family, worth knowing:** the `ETag` a client receives is the
backend ETag, i.e. the ciphertext ETag, so a client following the single-part
convention that an ETag is the MD5 of the content gets a value that does not
match the body it was served. That is self-consistent across PUT, HEAD and GET
and no SDK examined verifies it (other clients unchecked), so it is left alone; it was *not* self-consistent
before the metadata self-copy was fixed to report the copy ETag.

### P-5: one body reader for every handler

Same defect family as F-1 — a handler that reads `r.Body` directly stores or
parses the aws-chunked framing as if it were content.

- [operations.go:834](../../internal/proxy/handlers/object/operations.go#L834)
  `handleDeleteObjects`: `io.ReadAll(r.Body)` → `h.requestParser.ReadBody(r)`.
- [complete.go:89](../../internal/proxy/handlers/multipart/complete.go#L89)
  `CompleteHandler.Handle`: `io.ReadAll(r.Body)` →
  `h.requestParser.ReadBody(r)`. The handler already holds a `*request.Parser`
  ([complete.go:30](../../internal/proxy/handlers/multipart/complete.go#L30)) and
  never uses it.
- `html.UnescapeString(string(bodyData))` before `xml.Unmarshal` in
  `complete.go`: **done**, the call and the `html` import are gone. It turned
  a body containing `&amp;lt;Part&amp;gt;` into real markup, so attacker-escaped
  text became document structure before the XML parser saw it. `encoding/xml`
  resolves entities itself; no client sends HTML-escaped XML. Keep the
  integration test for it in scope.
- [bucket/operations.go:100](../../internal/proxy/handlers/bucket/operations.go#L100)
  `handleCreateBucket`: `xml.NewDecoder(r.Body).Decode(...)` → `ReadBody` +
  `xml.Unmarshal`. Two fixes in passing: gate on
  `DecodedContentLength(r) > 0` instead of `r.ContentLength > 0`
  ([bucket/operations.go:95](../../internal/proxy/handlers/bucket/operations.go#L95)),
  because for an aws-chunked body `r.ContentLength` counts framing bytes; and
  stop swallowing the decode error (`err == nil` today) — a non-empty body that
  is not well-formed XML answers `MalformedXML`, as S3 does. That is a
  deliberate behavior change, called out here so it is not a surprise.

`handleObjectLegalHold` and `handleObjectRetention` used to read the body with
`io.ReadAll` and discard it; both are one-line refusals now and read nothing, so
there is no third case here.

### D-16: bucket configuration handlers

All eight already read through the parser —
[cors.go:68](../../internal/proxy/handlers/bucket/cors.go#L68),
[policy.go:74](../../internal/proxy/handlers/bucket/policy.go#L74),
[lifecycle.go:66](../../internal/proxy/handlers/bucket/lifecycle.go#L66),
[logging.go:169](../../internal/proxy/handlers/bucket/logging.go#L169),
[notification.go:64](../../internal/proxy/handlers/bucket/notification.go#L64),
[versioning.go:64](../../internal/proxy/handlers/bucket/versioning.go#L64),
[tagging.go:66](../../internal/proxy/handlers/bucket/tagging.go#L66),
[acl.go:75](../../internal/proxy/handlers/bucket/acl.go#L75) — so they inherit both
the aws-chunked decoding and, after this ticket, the verification. **The gap is
purely a test**, which is why D-16 folds in here at near-zero cost.

### Configuration

**Void since 2026-09-09 — there is no key; the block below is kept for the record
only.** One new key, in the block D-9 names:

```yaml
encryption:
  verify_upload_digests: false   # default
```

`EncryptionConfig` ([config.go:54](../../internal/config/config.go#L54)) gets a
`VerifyUploadDigests bool` field with the `mapstructure:"verify_upload_digests"`
tag; the default goes next to the other encryption defaults
([config.go:357](../../internal/config/config.go#L357)). No validation entry is
needed for a bool. The CRC family has no knob by design — a control that only
exists in configuration is worse than none, and there is nothing to trade.

---

## Work breakdown

- [x] **Prerequisite check.** Done: no `ContentMD5` and no `Checksum*` on any
      backend input, and no backend `Checksum*` copied onto a plaintext
      response. Note for the record: those copies never reached the wire —
      `writeGetObjectResponse` ignored them — so nothing in this tree emits an
      `x-amz-checksum-*` response header today. Do not describe the removal as
      more than that.
- [ ] Capture aws-chunked trailers in the decoder instead of draining them
      ([streaming_aws_decoder.go:100](../../internal/proxy/request/streaming_aws_decoder.go#L100)),
      including the `data + io.EOF` partial-line case; expose `Trailers()`;
      keep ignoring `x-amz-trailer-signature`.
- [ ] New `internal/proxy/request/checksum.go`: algorithm registry (header name
      → hash constructor, expected digest length), sentinel errors for mismatch
      and malformed value, and the `verifyingReader` above.
- [ ] CRC64NVME: package-level slicing-by-8 table built once, own update loop,
      no per-`Write` table rebuild.
- [ ] Wire the verifier into both parser entry points
      ([parser.go:43](../../internal/proxy/request/parser.go#L43),
      [:117](../../internal/proxy/request/parser.go#L117)). Return the inner reader
      unwrapped when the request declares nothing.
- [x] ~~Config: `encryption.verify_upload_digests`, default false, plus the five
      `config/*-example.yaml` files and `test/e2e/velero/values-proxy.yaml`.~~ **Void
      2026-09-09: no key.**
- [ ] Answer `BadDigest` / `InvalidDigest` on all four PUT routes; the streaming
      route asks the verifier before mapping the SDK error; the auto-multipart
      route replaces 500 `UploadError` at
      [operations.go:1440](../../internal/proxy/handlers/object/operations.go#L1440)
      for this case only.
- [x] Delete the `Content-MD5` → `ChecksumAlgorithm = SHA256` line on
      `DeleteObjects` — already gone; `DeleteObjectsInput` carries `Bucket` and
      `Delete` only.
- [ ] **P-5 (a)**: `handleDeleteObjects` through `ReadBody`.
- [ ] **P-5 (b)**: `CompleteHandler.Handle` through `ReadBody`. The
      `html.UnescapeString` half is already done.
- [ ] **P-5 (c)**: `handleCreateBucket` through `ReadBody`, gated on
      `DecodedContentLength`, `MalformedXML` on a bad non-empty body.
- [ ] Unit tests in `internal/proxy/request`: extend
      [framing_test.go](../../internal/proxy/request/framing_test.go) with a
      per-algorithm trailer builder and a `corrupt` variant, then table-test
      every framing × every algorithm × {correct, wrong, malformed base64,
      declared-but-absent} through both `ReadBody` and `StreamingReader`; every
      algorithm is always verified (2026-09-09).
- [ ] Unit tests for the eight bucket configuration handlers (**D-16**): an
      aws-chunked body per handler, correct and wrong trailer.
- [ ] Integration tests (below).
- [ ] Measurement (below), recorded in this ticket.
- [ ] Docs: README statement that every declared checksum is verified, with the
      measured cost per algorithm as a table; the trailer statement in
      `SECURITY_ARCHITECTURE.md` (what is verified on the client leg, what is
      not, and why nothing is stored). The file exists and already says the
      headers are dropped and unverified — this replaces that text.

---

## Success criteria

**Unit** — `make test-unit` green, and specifically:

- For each of the six framings in
  [framing_test.go](../../internal/proxy/request/framing_test.go#L71) and each
  algorithm: a correct trailer passes and returns the payload byte for byte
  (SHA-256 comparison, per the work order — no hex dumps), a deliberately wrong
  trailer returns the mismatch error, a malformed base64 value returns the
  malformed error, and a trailer named in `X-Amz-Trailer` but never sent returns
  the mismatch error.
- A wrong `Content-MD5`, `-sha1` and `-sha256` each fail with `BadDigest`
  (2026-09-09: always), **and no client digest is ever handed to the backend**.
- A body declaring no checksum is returned by the parser **unwrapped** (assert
  the concrete reader type — this is the zero-cost property, and it is easy to
  lose in a later refactor).
- The trailer whose last line has no terminating CRLF is still captured.

**Integration** — `make test-integration` and `make test-integration-tls`, both
green, no test skipped or disabled. New cases, using the raw signer
([s3_signing_helper.go:210](../../test/integration/s3_signing_helper.go#L210)) to
hand-build bodies the SDK will not produce:

- Hand-built aws-chunked PUT with a correct and a deliberately wrong trailer
  checksum, for CRC32, CRC32C and CRC64NVME, at a size below
  `streaming_threshold` (small-object path) and at a size above it that also
  trips the auto-multipart route (≥ 5 MiB with `strict`). Correct → 200 and the
  object reads back with a matching SHA-256; wrong → **400 `BadDigest`** and
  `HeadObject` on the key answers 404 — nothing was stored and no multipart
  upload was left behind (`ListMultipartUploads` against MinIO directly, not
  through the proxy: P-7).
- The kopia-shaped case: a plain (identity-framed) PUT with a wrong
  `Content-MD5` at 2 MiB and at 8 MiB in `strict`, the two sizes N-6 (a) was
  probed at. Both answer 400 `BadDigest`, which is what MinIO answers directly
  (2026-09-09: always, no switch).
- The N-6 (b)/(c) regression guard needs *different* shapes, because neither
  probe size reaches the forwarding code: in `strict` a 2 MiB PUT takes the
  direct route and an 8 MiB PUT takes auto-multipart
  ([operations.go:485](../../internal/proxy/handlers/object/operations.go#L485)),
  and neither sets `ContentMD5` on the backend input. (b) needs
  `integrity_verification: off` and an object at or above `streaming_threshold`,
  which is the only way into `putObjectStreamingReader`; (c) needs a
  client-driven `UploadPart` carrying a `Content-MD5`. In both, assert the
  stored object carries **no** `Content-MD5`.
- Client-driven `UploadPart` with a wrong trailer → 400 on that part, and the
  upload can still be aborted cleanly.
- **D-16**: one bucket configuration PUT (`cors`, `policy`, `lifecycle`,
  `logging`, `notification`, `versioning`, `tagging`, `acl`) with an
  aws-chunked body — correct trailer applies the configuration, wrong trailer
  answers 400 and leaves the configuration unchanged.
- `DeleteObjects` and `CompleteMultipartUpload` with aws-chunked bodies (P-5),
  and a `CompleteMultipartUpload` body containing `&amp;lt;Part&amp;gt;` that
  must **not** parse as markup.

**Performance** — regressions are reported, not absorbed:

- `make test-integration-performance` after `./start-demo.sh`, 1 GB upload and
  download, three runs, compared against the numbers this branch records. The
  always-on CRC32 path must not move the upload figure measurably; anything
  beyond noise is a finding, not a cost of doing business.
- A Go benchmark on the CRC64NVME implementation: package-level table versus the
  naive `crc64.New(crc64.MakeTable(nvme))`, at a 64 KiB write size, reporting
  B/op. The naive form must not ship.
- The published cost number (ADR 0012 D13): measure a kopia-shaped upload (20 MiB
  objects, the size kopia writes per pack blob) without a digest, with `Content-MD5`
  and with `x-amz-checksum-sha256`, and record the three end-to-end figures next to
  the primitive numbers in the Status block. It goes into the README cost table; it
  gates nothing (2026-09-09).

**End to end** — `./test/e2e/velero/e2e-up.sh` then `make test-e2e-velero`, all
13 scenarios green. Velero's own
uploader sends CRC32 trailers, so this is the check that always-on CRC
verification does not break a real client.

---

## Risks and open questions

- ~~**The default does not fix the probed defect on the kopia path.**~~ **Closed
  2026-09-09:** there is no default; kopia's `Content-MD5` is verified like everything
  else, at about ten times the encryption pass per byte on its uploads, a number the
  README states.
- **SHA is cheaper than MD5 on current hardware**, measured 2026-09-09: SHA-1 and
  SHA-256 run at 3.4 to 3.5 GB/s with the ARMv8 instructions, MD5 at 0.95 GB/s with
  none. Moot for the rule, which no longer distinguishes families; kept because an
  x86 server without SHA-NI puts SHA into MD5's class, which was not measured.
- **CRC32 is a 32-bit check, not an integrity guarantee.** It catches
  transmission corruption, which is what it is for. It does not detect a
  deliberate modification on the client leg, and nothing in this ticket claims
  it does — the client leg's adversary is explicitly out of the threat model
  (D-19). `SECURITY_ARCHITECTURE.md` must say this in the same breath as the
  new control, or the control gets over-trusted.
- **Unverified: whether any S3 client sends `x-amz-checksum-crc64nvme` on
  upload.** aws-sdk-go-v2 at the pinned version defaults to CRC32
  (`middleware_setup_context.go:59`); AWS S3 *records* CRC64NVME for new objects
  server-side, which is a different thing. The algorithm is implemented because
  the header exists, not because a measured client sends it — so the table trap
  above is a latent cost, not a current one.
- **Unverified: how MinIO behaves on a wrong trailer checksum** for each
  algorithm, which is the comparison baseline the integration tests assert
  against for `Content-MD5`. Check it once when writing them and record what it
  answers; do not assume the proxy and MinIO must agree on the error code for
  every algorithm.
- **Behavior change on `handleCreateBucket`**: a malformed non-empty body now
  answers `MalformedXML` where it was silently accepted. Correct, and matches
  S3, but it is a visible change for any client that was sending junk and
  getting away with it.
- **Interaction with the v2 ticket.** v2 rewrites the PUT routing (the
  GCM/CTR split and `streaming_threshold` both go away), so the four-route
  table above collapses. The parser choke point and the verifier survive
  unchanged; the route-specific error plumbing does not. This is the reason for
  scheduling after v2, and the reason the tests should assert on
  *client-visible* status codes rather than on which internal route ran.
