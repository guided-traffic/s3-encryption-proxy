# Request paths

What happens between the listener and the backend, per verb. Handlers live in
`internal/proxy/handlers/`; the crypto they do goes through
`internal/orchestration.Manager`. One handler reaches past it on purpose:
`handlers/object/range.go` plans a stored window straight from the format
constants in `pkg/encryption/dataencryption`, because that plan has to exist
before there is a key to plan with.

## Before the handler

Four middlewares wrap the S3 routes, in this order (`internal/proxy/router.go`):
SigV4 authentication, request tracking, logging, CORS. Authentication is first,
so nothing else runs for a request that will be refused and no handler ever runs
unauthenticated. `/health` and `/version` sit on a subrouter registered ahead of
the chain and are the only paths outside it. What SigV4 does and does not verify
is in [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md).

The tracking counter is what a graceful shutdown waits on
([ADR 0015](../adr/0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md));
`Server.Shutdown` then stops the manager's session sweep.

## PUT

```
PUT /{bucket}/{key}
  ├─ x-amz-copy-source present?  → refused, 422 NotSupportedWithEncryption
  │                                 (the proxy cannot re-encrypt inside the backend)
  ├─ plaintextLen = DecodedContentLength(r)
  │     X-Amz-Decoded-Content-Length when present, else Content-Length, else -1
  │
  ├─ plaintextLen < 0 or > optimizations.streaming_segment_size (12582912 # default)
  │     → the internal multipart producer, see multipart.md
  └─ otherwise
        → one PutObject, sealing as the backend reads
```

**Route on the plaintext length, never on the wire length.** The wire length of
an aws-chunked upload includes the chunk framing and the trailer, so routing on
it would make the decision depend on how the client framed the request rather
than on how big the object is.

There is no threshold to tune and no second cipher to choose. The only thing the
size decides is whether the object fits in one backend request.

**The exit provider passes through on both branches.** `putObjectSegmented` and
`putObjectAutoMultipart` both ask `IsExitProvider`: the first stores the body
exactly as it arrived, the second keeps its free list, its workers and its abort
and completion and only skips the sealing step (`passThrough`). Neither draws a
data key and neither writes proxy metadata. The client-driven multipart path does
the same in `multipart/create.go`, `upload.go` and `complete.go`, where no session
is registered at all and the completed-part list is built from the client's own
list. The routing above is unchanged by the provider — a large or undeclared PUT
still becomes an internal multipart upload — so the only difference is what goes
into the parts.

**A short body cannot become a stored object on either write path**, but not by
the same mechanism, and that is worth knowing before you move either one.

- *One request.* The backend is promised `CiphertextSize(plaintextLen)` before
  the first byte moves. The sealer itself does not help here: it reads a
  truncated source as a clean end of stream and produces a valid, shorter chain.
  What refuses it is `net/http`, which fails a request whose body runs out before
  the declared `Content-Length`. Nothing is stored.
- *The producer.* `io.ReadFull` reads a truncated body as a clean end too, and
  here there is no promised total to violate — every part already sent was well
  formed, so the upload would complete into a short object that verifies against
  its own trailer. The producer therefore compares what it read against
  `Parser.PlaintextContentLength` and aborts the backend upload itself.

That second check needs a declared plaintext length. An aws-chunked upload
without `X-Amz-Decoded-Content-Length` has none — `PlaintextContentLength`
reports it as unknown rather than handing back a wire length that counts framing
— and a truncation of one of those is not caught.

**What a PUT accepts and drops.** What survives the handler is the entity headers
— `Content-Type`, `Content-Encoding` minus the `aws-chunked` token the proxy
already decoded, `Content-Disposition`, `Content-Language`, `Cache-Control` — and
every `x-amz-meta-*` key outside the proxy's own prefix. A key *inside* that
prefix is refused with `400 InvalidArgument` naming it, before any backend
request, rather than dropped
([ADR 0009](../adr/0009-the-metadata-prefix-is-the-proxys-namespace.md) D6); all
three write paths call `object.UserMetadata`, so none of them can apply a
different rule. Both write paths forward the same set. One thing a client asks for still does not
survive and does not fail loudly: **`x-amz-expected-bucket-owner`**.

Three entries left this list. The **conditional headers** are carried now:
`If-Match` and `If-None-Match` reach the backend on `PUT` and on
`CompleteMultipartUpload`, so `If-None-Match: *` fails a write against an existing
key instead of telling both writers of a race that they won. So do the **storage
headers** ([ADR 0007](../adr/0007-forward-it-or-refuse-it.md) D3), with the three
SSE-C headers refused `501` by name. And **the client's integrity claim is
checked** rather than dropped — see below.

**The client's checksum.** `Content-MD5`, `x-amz-checksum-*` and the aws-chunked
checksum trailer are verified against the decoded plaintext payload and then
dropped; the value never reaches the backend, which could not check a digest of a
plaintext it never receives, and is never written to metadata
([ADR 0012](../adr/0012-client-checksums-are-verified-never-forwarded.md)).

The verifier is one reader wrapped around whatever `Parser.ReadBody` or
`Parser.StreamingReader` would otherwise return
([checksum.go](../../internal/proxy/request/checksum.go)), so it always sees the
payload with the framing already stripped, and a request declaring nothing gets
the inner reader back with no `Read` indirection at all. Three things about it
are easy to break and are pinned by tests:

- **A body nothing reads is verified explicitly.** The verification rides on a
  reader, so a payload no consumer pulls is a payload no verdict covers. A
  zero-length `PUT` is the case: the SDK attaches no stream at all when the
  content length is zero, so `putObjectSegmented` takes the verdict itself
  before it builds the request. `handleCreateBucket` reads its body
  unconditionally for the same reason.
- **It holds the last payload byte back.** The verdict for a value that arrives as
  a trailer can only be known at the end of the stream, and by then a consumer
  streaming straight to the backend would already have delivered everything. Not
  releasing the final byte until the verdict is in is what keeps "nothing is
  stored on a failure" true on the pass-through write, where the body goes to the
  backend unchanged. On the encrypting single-request write the property falls out
  of the format anyway: the codec cannot emit the trailer without seeing plaintext
  EOF, so the backend is at least 40 bytes short.
- **The handler asks the reader, not the error.** On the single-request `PUT` the
  read error travels through `net/http`, `*url.Error` and smithy wrapping before
  the handler sees it, so `putObjectSegmented` calls `request.Verdict(body)`
  before it maps the SDK error. `putObjectAutoMultipart` asks the same question
  after the producer loop rather than threading the error out of `io.ReadFull`,
  which swallows it whenever a part buffer happens to fill exactly.
- **The answer is a 400, never a 5xx.** `MapError` recognises the two sentinels
  ahead of everything else, so every existing `WriteS3Error` call site — the eight
  bucket configuration handlers included — answers `BadDigest` or `InvalidDigest`
  rather than reporting a client mistake as a proxy failure an SDK would retry.

**Only a clean end of stream ends an object.** `fillPart` in the producer counts
a literal `io.EOF` as the end and treats everything else as a failure, because
`io.ReadFull` reports the same `io.ErrUnexpectedEOF` for the legitimate short
last read and for a body whose framing stopped early — and the aws-chunked
decoder raises exactly that error for a stream with no terminating chunk. Folding
the two together committed a truncated object sealed with its own trailer, which
then verified on every later read. The declared-length guard after the loop
cannot catch it: this path is the one taken when no length was declared. Do not
put `io.ReadFull` back.

`DeleteObjects` is the one verb that *requires* a digest, as S3 does, and refuses
a request without one; the digest is checked before the document is parsed, so a
refused request deletes nothing.

`CompleteMultipartUpload` is the one verb that must **not** verify its body, and
it reads through `Parser.ReadBodyUnverified` for that reason: there
`x-amz-checksum-*` is the digest of the completed object, which is what
`aws-sdk-go-v2` puts on `CompleteMultipartUploadInput`, so hashing the XML and
comparing would answer `BadDigest` to a correct client. Keep that call as it is.

The `x-amz-checksum-` family is claimed as a whole: a header under it that is not
an implemented algorithm, and is not one of `-algorithm`, `-mode` or `-type`,
answers `501 NotImplemented`. That is what stops the `xxhash` algorithms the
pinned SDK can send — none of which has a standard-library hash — from being
accepted behind a `200` with the check silently dropped. Adding an algorithm is
one row in `checksumAlgorithms`; adding one that needs a dependency is an ADR.

The aws-chunked decoder keeps the trailer block instead of draining it
([streaming_aws_decoder.go](../../internal/proxy/request/streaming_aws_decoder.go),
`readTrailers`). It parses each line before checking the read error, because
`bufio.ReadString` returns the data together with `io.EOF` when the last line
carries no terminator — and some clients end the block without one.
`x-amz-trailer-signature` is skipped: it is not a checksum
([ADR 0014](../adr/0014-authentication-is-sigv4-no-rate-limiting.md)).

CRC-64/NVME gets its own slicing-by-8 table, built once at package load
([crc64nvme.go](../../internal/proxy/request/crc64nvme.go)). `hash/crc64` caches a
helper only for its own ISO and ECMA tables and rebuilds one on every `Write` of
2048 bytes or more for any other polynomial; on Go 1.27.1 escape analysis keeps
that 16 KiB on the stack, so what it costs is the build loop rather than an
allocation. `BenchmarkChkCRC64NVME` measures both forms against each other so the
claim stays a measurement.

## GET

```
GET /{bucket}/{key}
  ├─ Range header?  → the ranged path below
  ├─ GetObject from the backend
  ├─ no proxy metadata, or a foreign format id
  │     ├─ exit provider  → that answer, relayed unopened
  │     └─ otherwise      → 403 InvalidObjectState
  ├─ the wrapped key fails its tag
  │     → 403 InvalidObjectState
  ├─ a stored length that no writer of this format could produce
  │     → 403 InvalidObjectState
  └─ stream: open segment by segment, release each after it verifies
        a fault here aborts the body — see storage-format.md
```

`Content-Length` is `PlaintextSize` of the stored length, so a client is told the
size of what it will receive rather than what the backend holds. A backend that
reports no length produces a response without one; the body is correct either
way.

The response is composed from an allowlist, never proxied. The backend's
`x-amz-checksum-*` describe stored ciphertext, its `Content-Length` describes
stored bytes, and its metadata carries the proxy's own keys — none of that may
reach a client. `Handler.cleanMetadata` drops every key under the configured
prefix, case-insensitively, because `net/http` canonicalises header names on the
way in.

One asymmetry: the pass-through branch returns the backend's metadata map as it
came, uncleaned. It is reached only for an object that carries no proxy metadata
— under `type: exit`, `serveWholeObject` sends a segmented object down the
decrypting branch, which cleans — and the pass-through *write* paths refuse
client-supplied `s3ep-*` headers, so through this proxy such an object cannot be
created. What can still reach it is an object written straight into the backend
with keys in the proxy's namespace: those are handed to the client as they are.
`HEAD` cleans on every branch.

## Ranged GET

The window is planned from the requested plaintext range, then exactly that
ciphertext window is fetched. `Content-Range` describes **plaintext** offsets and
the plaintext total, so a client never has to know the object is stored
encrypted.

**Under the exit provider the path starts with a `HeadObject`** (`objectIsSegmented`).
A range has to name a stored window before it can ask for it, and under that
provider the bucket holds both kinds of object, so the answer decides: a plain
object gets `passThroughRange`, where the client's own header goes to the backend
verbatim and the answer is relayed, and a segmented one goes on into the plan
below. It is the only provider that pays that round trip — under an encrypting
provider every readable object is a segmented one, so the window follows from the
request and a foreign object is refused when its metadata arrives with the
`GET`.

An explicit `bytes=a-b` costs one backend request: the window is planned
optimistically, the backend clamps it, and the object's real length comes back in
the same answer's `Content-Range`. A suffix (`bytes=-500`) or open-ended
(`bytes=100-`) range is relative to the end of the object, so its length is
needed first and it costs a `HEAD` ahead of the `GET`. That `HEAD` deliberately
carries no precondition: it is the proxy's own probe asking how long the object
is, and the client's condition rides on the `GET` that follows, which is the
request the client actually made.

**Which Range headers are acted on is decided twice, and the two answers
differ.** `parseRangeSpec` runs before any backend call and only classifies;
`parseByteRange` runs once a length is known and resolves. A header the first one
will not act on — more than one range, a missing `bytes=` unit, an explicit range
whose bounds are not numbers — is **ignored**, and the whole object is served
with no `Content-Range`, which is what AWS and the backend do. A header only the
second one rejects — `bytes=-abc`, `bytes=abc-`, the forms that pass the first
parser because one bound is empty — is `400 InvalidArgument`. The `501` arm for
multiple ranges in `writeRangeError` is unreachable from here: the first parser
has already turned that header into a whole-object read.

A range the proxy resolves as unsatisfiable — a start at or past the end, an
inverted `bytes=9-0`, a zero-length suffix — is `416 InvalidRange` composed by
the proxy, with `Content-Range: bytes */<plaintext size>`; it costs a `HEAD`
wherever it did not already have the length. One case never gets that far: an
explicit range whose provisional window begins past the stored object is refused
by the backend first, and that `416` is relayed **without** the `Content-Range`
header — pinned as a known defect in
`TestObjGetRangeBackendErrorIsMappedThrough`.

A backend answer the proxy cannot plan against — no `Content-Range` because the
backend served the whole object, or one it cannot parse — is `500 InternalError`,
and no stored byte reaches the client.

## HEAD

Answered from the backend's own `HEAD`. The plaintext size is arithmetic on the
stored size, so no second request is needed
([ADR 0010](../adr/0010-sizes-and-listings-describe-the-plaintext.md)). `HEAD`
has decided per object all along: `segmented` comes from the object's metadata,
and a plain object's stored length *is* its plaintext length and is reported
unchanged.

An object with no proxy metadata, a foreign format id, or a stored length no
writer of this format could have produced is refused before anything is
described — unless the exit provider is active, where such an object is one this
proxy has nothing to do with and is described from the backend's own answer.
That holds when the backend reports no length too — a `HEAD` that confirmed an
object `GET` would refuse was a defect, and it is pinned. There is
no fallback that states the stored length as if it were the plaintext length: a
client sizing a buffer from a `HEAD` would get a number the `GET` never delivers.

It stops one step short of `GET`, and deliberately: `HEAD` never unwraps the data
key, so an object whose wrapped key does not authenticate is described with a
`200` here and refused with `403` on the first read.

**All four conditional headers reach the backend**, the same four a `GET` carries,
so the two verbs give the same answer to the same precondition
([ADR 0007](../adr/0007-forward-it-or-refuse-it.md) D7). Until 5.0.0 `HEAD`
carried none at all — nothing it was asked to check could fail — and `GET`
carried only the two ETag ones. `Range` is still dropped on a `HEAD`, which is
what AWS does.

## DELETE

`DELETE /{bucket}/{key}` forwards, honours `versionId`, and answers `204` with
`x-amz-version-id` and `x-amz-delete-marker` from the backend. Nothing is
decrypted; nothing has to be, because the object is deleted whole.

`POST /{bucket}?delete` is the bulk form. The request document is parsed and a
new one is built from the backend's answer rather than relayed, so the
delete-marker fields a versioned bucket needs survive. No digest is required of
the request document (ADR 0012 D14, not built).

## The multipart verbs

`POST ?uploads`, `PUT ?partNumber&uploadId`, `POST ?uploadId` and
`DELETE ?uploadId` are routed to `handlers/multipart/` ahead of the catch-all
object route, and the part routes require `partNumber` to match `[0-9]+`. What
those handlers do with a part, and why the part table rather than the client's
completion document is the authority, is [multipart.md](multipart.md).

`UploadPartCopy` is refused `422 NotSupportedWithEncryption` for the same reason
`CopyObject` is. `ListMultipartUploads` answers `501`. `ListParts` answers `200`
with a fabricated empty document — the accept-and-report-success shape ADR 0007
exists to forbid, and the last instance of it on this surface.

Every other refusal on these verbs says what it is. A missing `uploadId`, an
unparseable completion body, an empty part list, a part number out of range, a
missing ETag, a duplicate part number and an unreadable part body all answered
`500 InternalError` with the generic message until 5.0.0, so every SDK retried a
request that could never succeed.

## What is refused rather than pretended

Three object sub-resources stopped being refused on 2026-09-11 and are
passthrough now — `?tagging` (`GET`, `PUT`, `DELETE`), `?retention` and
`?legal-hold` (`GET`, `PUT`) — together with `PUT /{bucket}?acl` and `?cors`,
which carry the client's document in full
([ADR 0007](../adr/0007-forward-it-or-refuse-it.md) D4, D5). Each answers a
document of the proxy's own with XML tags: the SDK's types carry none, so
`encoding/xml` bound by Go field name and a `<Tagging>` body yielded an empty tag
set. The same fix went one level out for every bucket sub-resource `GET`.

A verb or sub-resource the proxy does not implement answers `NotImplemented`
rather than being forwarded or silently ignored
([ADR 0007](../adr/0007-forward-it-or-refuse-it.md)). Both the bucket and the
object dispatcher work the same way, and the split between their two answers
matters:

- A sub-resource that **has** a route but did not match it — so the method is
  wrong for it — is `405 MethodNotAllowed`. Running the base operation instead is
  how `DELETE ?legal-hold` deleted the object and `PUT ?restore` overwrote it.
- A query parameter on **no** list is `501 NotImplemented`. Running the base
  operation instead is how `DELETE /bucket?encryption` deleted the bucket.
- A `PUT` still carrying `partNumber` and `uploadId` reached the base object
  operation because its part number is not a number. It is `400 InvalidArgument`,
  which is what AWS answers; running the base `PUT` replaced the whole object
  with the body of one part.

Everything `x-amz-*` is admitted by `request.IsAWSProtocolQueryParam` rather than
listed literally — listing them by hand is what refused every pre-signed download
once aws-sdk-go-v2 started putting `X-Amz-Checksum-Mode` into the URL.

The status codes and their reasoning are [errors.md](errors.md).
