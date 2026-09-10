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
every `x-amz-meta-*` key outside the proxy's own prefix
([ADR 0009](../adr/0009-the-metadata-prefix-is-the-proxys-namespace.md)). Both
write paths forward the same set. Three things a client asked for do not survive,
and none of them fails loudly:

- **The client's integrity claim.** `Content-MD5`, `x-amz-checksum-*` and the
  aws-chunked checksum trailer are read off the wire and discarded — no write
  path parses any of them, and the trailer lines are drained unread. A deliberately
  wrong digest is answered `200`. So the one leg where the plaintext still exists
  unprotected, client to proxy, is not covered
  ([ADR 0012](../adr/0012-client-checksums-are-verified-never-forwarded.md), the
  decision that exists to end this). Forwarding the values is not the fix: they
  describe the plaintext and the body is a sealed chain.
- **The conditional headers.** `If-None-Match: *` is how a client makes a write
  fail when the key already exists; here it reaches neither the backend nor a
  check, so both writers of a race are told they won and one write is lost.
- **The storage headers and `x-amz-expected-bucket-owner`**
  ([ADR 0007](../adr/0007-forward-it-or-refuse-it.md)).

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
decrypting branch, which cleans — and the pass-through *write* paths drop
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
needed first and it costs a `HEAD` ahead of the `GET`. That `HEAD` carries no
conditional headers at all, so the length the window is planned from was read
without the precondition the `GET` then applies.

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

**Every conditional header is dropped on the way to the backend** — `If-Match`,
`If-None-Match`, `If-Modified-Since`, `If-Unmodified-Since` — and so is `Range`,
so nothing a `HEAD` is asked to check can fail. Pinned by
`TestObjGetHeadObjectDropsEveryConditionalHeader`, not fixed. `GET` is better but
not whole: it forwards the two ETag preconditions and drops the date ones.

**Listings do not do the same arithmetic.** Every entry still carries the size the
backend stores, and the response is an XML encoding of the SDK's output structure
rather than an S3 listing document. That is the unbuilt half of ADR 0010, and it
is what makes every synchronising client re-transfer everything on every run.

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
exists to forbid, recorded there and not fixed.

## What is refused rather than pretended

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
