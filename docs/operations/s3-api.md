# S3 API behaviour worth knowing

The proxy is transparent for the operations clients actually use. The
behaviours below differ from a plain S3 endpoint in ways worth stating before
you point a client at it.

What the proxy guarantees about the bytes themselves — the stored format, the
metadata it writes, what happens to an object it did not write, checksums and
entity tags — is [integrity.md](integrity.md).

## Ranged reads (`Range: bytes=...`)

Supported for encrypted objects, which matters for any client that reads
objects in pieces rather than whole (kopia, and therefore Velero volume
backups, do exactly this).

A ranged read fetches only the segments its window covers — at most one segment
of over-read at each end — and opens each of them under its own tag, so a partial
read is authenticated exactly like a whole one. An object this proxy did not
write is refused rather than passed through; see
[Objects this proxy did not write](integrity.md#objects-this-proxy-did-not-write).

The response is a normal `206 Partial Content` whose `Content-Range` describes
**plaintext** offsets and the plaintext total, so a client never has to know the
object is stored encrypted.

An explicit `bytes=a-b` costs one backend request. A suffix range (`bytes=-500`)
and an open-ended one (`bytes=100-`) are relative to the end of the object, so
the proxy needs its length first and they cost one `HEAD` ahead of the `GET`.

**Under the exit provider an explicit range costs one extra `HEAD`**. The stored
window a range translates to depends on whether the object is one this proxy
encrypted, and under that provider a bucket holds both kinds, so the proxy has to
ask before it can request the window. A suffix range and an open-ended one pay
nothing extra: they need the object's length anyway, and it is the same `HEAD`.
Under an encrypting provider an explicit range never asks: every readable object
is a sealed one, the window follows from the request, and an object that turns
out to be foreign is refused when its metadata arrives with the `GET`.

A range carries no `x-amz-checksum-*` header: the object's sealed checksum
describes the whole plaintext, and a checksum over part of it is a different
value the proxy does not compute. A whole-object `GET` and a `HEAD` do carry it —
see [What a read costs](#what-a-read-costs) below.

## What a read costs

A **whole-object `GET`** reads the object's **end first**: one request for the
last 64 KiB and the trailer, then — only if the object is larger than that — a
second for the remainder, carrying `If-Match` on the first answer's `ETag`. Every
stored byte is fetched exactly once, an object of at most 64 KiB costs one backend
request, and anything larger costs two.

What the order buys is what the proxy can say before it answers: the
`Content-Length` of a whole-object `GET` and of a `HEAD` is the plaintext length
**the object's own trailer authenticates**, not a number the backend reported
about itself, and both verbs answer with `x-amz-checksum-crc32c` over the
plaintext. It also moves three failures from the middle of a download to before
it starts — a damaged trailer, a truncated object, and a stored length the trailer
contradicts are `403 InvalidObjectState` with nothing written, where they used to
arrive as a body that stopped early. A fault inside a segment is still found while
the body is flowing, and there the body is cut off: a response that has already
answered `200` cannot un-answer it.

A **`HEAD`** costs one backend request, as it always did — it reads the object's
last 40 bytes rather than asking for its metadata.

**Under the exit provider a whole-object read stays a single forward pass**, and
carries neither the authenticated length nor the checksum header. A bucket on the
way out holds objects this proxy never encrypted, those have no trailer at all,
and telling the two apart would cost a `HEAD` on every read of the provider whose
job is getting the data out
([ADR 0025](../adr/0025-leaving-is-a-supported-mode.md)).

## Write paths

All three write paths produce identical bytes, so nothing about a stored object
says how it was uploaded:

| Upload | Path |
|---|---|
| `PUT` with a declared length at or below `optimizations.multipart_part_size` | One `PutObject`; the body seals as the backend reads it |
| `PUT` with no declared length, or above that size | An internal multipart upload with parts of that size, sent while the body is still arriving |
| A client's own multipart upload | One client part becomes one backend part; the object's closing record is written at `CompleteMultipartUpload` |

**Under the exit provider all three store what the client sent.** The routing is
unchanged — a large or undeclared `PUT` still becomes an internal multipart
upload — but no path seals anything, none draws a data key, and none writes
`s3ep-*` metadata. On a client's own upload the proxy keeps no part table either:
the list the client sends at `CompleteMultipartUpload` is the object, and the
backend is what checks it, so the part-size rule below does not apply and the
backend's own rules are the ones a client meets.

**A client-driven multipart upload sizes its parts, within one rule:** every
part except the last has to cover whole 64 KiB segments and clear S3's own 5 MiB
minimum. The usual part sizes satisfy it — 5 MiB, 8 MiB and 16 MiB are all
multiples of 64 KiB — but a client that picks something like 5,000,000 bytes
gets `400 EntityTooSmall` on its second part. The last part may be any size: it
is held until `CompleteMultipartUpload`, which uploads it with the trailer
behind it, so that one part sits in the proxy's memory until then.
`optimizations.multipart_short_part_buffer_size` bounds what **all** open
uploads hold there together: a last part that does not fit beside them right now
is answered `503 SlowDown` and retries, and one larger than the whole budget is
answered `400 EntityTooLarge`, which no retry can change. A completion list that disagrees with what was uploaded is answered
`400 InvalidPart`, and the upload stays open. **Part numbers run 1 to 9999**, not
to S3's 10000: the object's closing record needs a part number of its own
whenever the client's last part is one the proxy stored where it arrived, and
part 10000 is refused with `400 InvalidArgument` when it is sent rather than at
completion, after every byte has been transferred
([ADR 0011](../adr/0011-the-proxy-owns-the-part-layout.md)).

## Pre-signed URLs

Query-string AWS Signature V4 is validated alongside the `Authorization` header
form, so URLs minted with `PresignGetObject` and friends work through the proxy.
`X-Amz-Expires` is mandatory and is bounded by
`s3_security.max_presign_expiry_seconds`, **one hour by default**. That is a
deliberate deviation from the S3 maximum of seven days, which remains the ceiling
the setting may not exceed: a pre-signed URL is a bearer credential for exactly
as long as it claims, so the shipped default is the shortest window that serves
the clients this proxy is tested against. Raise it if yours mint longer URLs.

The signing time is subject to `s3_security.max_clock_skew_seconds`, so a URL
cannot extend its own lifetime by claiming to have been signed in the future.
That same tolerance is added to the end of the window, so a URL is accepted for
`X-Amz-Expires` plus the skew — and that tolerance now governs the
`Authorization`-header form as well, which used to use a fixed 900 seconds
whatever the configuration said.

## Object size

`HEAD` and `GET` report the **plaintext** size. The stored object is larger by
28 bytes per 64 KiB segment plus the 40-byte trailer, and reading it back
directly from the backend will show that difference.

**Listings report the plaintext size too.** `ListObjectsV2` and `ListObjects`
compute it from the stored size, which is arithmetic the proxy controls: no
metadata is read and no extra request is made, so a listing of a thousand keys
costs a thousand divisions and nothing else
([ADR 0010](../adr/0010-sizes-and-listings-describe-the-plaintext.md)).
`HEAD`, `GET` and a listing therefore agree.

**Under the exit provider a listing reports the stored size verbatim**, for every
entry, and does not invert the arithmetic. Such a bucket holds both kinds of
object and a listing has no metadata to tell them apart; inverting would be exact
for the encrypted ones and would *under*-report every plain object whose stored
size happens to look like one this proxy could have written. Over-reporting a
size costs a re-transfer. Under-reporting one tells a sync client the remote copy
is shorter than its local file, and it uploads over the remote — so the error is
kept deliberately on the harmless side. `HEAD` is exact either way: it reads the
object's metadata and reports the plaintext size for an encrypted object and the
stored size for a plain one.

**One deliberate inexactness.** In a bucket that also holds objects this proxy
did not write — foreign objects, or content uploaded straight to the backend —
a listing entry for such an object is short by the segment overhead whenever its
stored size happens to look like one the proxy could have written: 40 bytes plus
28 per 64 KiB. The listing cannot tell those entries apart without a `HEAD` per
key, and that round trip is the thing this design exists to avoid. It costs
nothing in practice: such an object is refused on read anyway (see
[Objects this proxy did not write](integrity.md#objects-this-proxy-did-not-write)), so a
client cannot act on the size it read.

## Listing parameters

| Parameter | Behaviour |
|---|---|
| `prefix`, `delimiter`, `marker`, `continuation-token` | forwarded |
| `start-after`, `fetch-owner` | forwarded (V2) |
| `encoding-type` | the proxy always requests URL encoding from the backend and decodes it; `encoding-type=url` re-encodes the answer and echoes `<EncodingType>url</EncodingType>` |
| `max-keys` absent | the backend default applies |
| `max-keys` 0 to 1000 | forwarded verbatim, `0` included |
| `max-keys` above 1000 | clamped to 1000 |
| `max-keys` negative or not an integer | `400 InvalidArgument` |

The clamp is the proxy's own: MinIO does not clamp, so the same request answers
at most 1000 keys through the proxy and possibly more straight from the backend.

`<Owner>` names the client that made the request — the access key it
authenticated with — never the account the proxy uses against the backend
([ADR 0008](../adr/0008-every-response-describes-the-proxy.md)). It appears
on a V2 listing only when `fetch-owner=true` is set, and on a V1 listing always.

No `<ChecksumAlgorithm>` or `<ChecksumType>` element is ever emitted: a backend
checksum describes the ciphertext, and the object's own sealed checksum can only
be read by opening its trailer, which a listing will not do per entry. A `GET` or
a `HEAD` of one object does report it, as `x-amz-checksum-crc32c`.

`<ETag>` is the backend's value with the marker described under
[Entity tags](integrity.md#entity-tags), exactly as `GET` and `HEAD` answer it: a listing that
disagreed with a `HEAD` of the same object would be worse than either answer on
its own.

## `HeadBucket`

`HEAD /{bucket}` calls the backend's `HeadBucket`. It answers `x-amz-bucket-region`
from the backend when the backend sends one, and otherwise with the configured
`s3_backends[0].region` — **the region a client reads here is the proxy's
statement, not the backend's**, because MinIO sends no region header at all.

## Storage headers on upload

The proxy's mandate is the confidentiality of object **content**. A header that
does not touch content is the client's business and is carried to the backend
unchanged, on all three upload paths — a single-request `PUT`, the proxy's
internal multipart producer and client-driven `CreateMultipartUpload`
([ADR 0007](../adr/0007-forward-it-or-refuse-it.md) D3). They used to be
accepted, discarded and answered `200 OK`.

| Header | Behaviour | What it means through this proxy |
|---|---|---|
| `x-amz-server-side-encryption`, `...-aws-kms-key-id` | forwarded, and the backend's answer is restated | the **backend** encrypts its own copy of the ciphertext. It is not the proxy's encryption, and the header says nothing about it. The confirmation the backend sends back is restated on a single-request `PUT`, a completed multipart upload, a whole-object `GET` and a `HEAD` ([ADR 0008](../adr/0008-every-response-describes-the-proxy.md) D13) — a ranged read and a part upload deliberately carry none |
| `x-amz-server-side-encryption-customer-*` (SSE-C) | `501 NotImplemented`, naming the header | no read path carries the customer key, so an object written this way could never be read back. Refused on every verb until the key travels on all of them ([ADR 0007](../adr/0007-forward-it-or-refuse-it.md) D6) |
| `x-amz-tagging` | forwarded | tag keys and values are stored **in the clear** on the ciphertext object. For a backup bucket that is a labelled index of what each object is |
| `x-amz-storage-class` | forwarded | a tier the backend applies. An object written into an archive tier still appears in a listing and then fails on `GET` |
| `x-amz-acl`, `x-amz-grant-*` | forwarded | the grant acts on the **ciphertext** object. `public-read` exposes its bytes, its size, its timing and its `s3ep-*` metadata to everyone the grant names |
| `x-amz-object-lock-mode`, `-retain-until-date`, `-legal-hold` | forwarded | WORM on the ciphertext object. It defends against a **compromised credential**, which is the common ransomware path for a backup bucket. It defends against nothing at a compromised backend, which can ignore its own lock |
| `x-amz-website-redirect-location` | forwarded | stored as the backend stores it |
| `Content-Type`, `Cache-Control`, `Content-Disposition`, `Content-Encoding`, `Content-Language`, `Expires` | forwarded | they describe the plaintext, so they survive encryption unchanged and `GET` and `HEAD` return them |
| `x-amz-expected-bucket-owner` | forwarded, **on every verb** | the guard acts where it can be answered: the backend fails the call `403 AccessDenied` when the bucket belongs to another account. Not limited to uploads — every backend call the proxy makes carries it ([ADR 0007](../adr/0007-forward-it-or-refuse-it.md) D14) |
| `x-amz-bypass-governance-retention`, `x-amz-mfa` | **dropped** | still not forwarded on the delete paths. Without them the backend refuses the delete, so a delete that needs one fails rather than succeeding unguarded |

**`x-amz-expected-bucket-owner` before 5.0.0.** Only `DeleteBucket` honoured it.
Every other verb read it, dropped it and answered success — so a client that set
it on `PUT`, `DeleteObject` or `DeleteObjects` believed the bucket ownership had
been checked and it had not. If a deployment relies on that header, the guard now
takes effect: a request against a bucket owned by a different account starts
answering `403 AccessDenied` where it used to succeed. That is the intended
behaviour and the reason the change is in a major.

`x-amz-object-lock-retain-until-date` that is not an RFC 3339 timestamp, and an
`Expires` that is not an HTTP-date, answer `400 InvalidArgument` naming the
header. Storing the object without the header the client asked for is the silent
success the decision exists to forbid.

`Content-Encoding` loses an `aws-chunked` token: that describes the request
framing, which the proxy has already decoded, so storing it would mislabel the
object. A `PUT` with no `Content-Type` leaves the field unset rather than storing
an empty one, so the backend applies its own default.

None of this changes the proxy's own encryption. The object body is an
authenticated segment chain either way.

## `<Location>` in a completed multipart upload

`CompleteMultipartUploadResult` carries a `<Location>` naming **the proxy**, never
the backend: the backend's own value names the internal storage endpoint and is
text that endpoint controls. It is built from `X-Forwarded-Proto` and
`X-Forwarded-Host` when they are present — the first value of each — and
otherwise from the connection the proxy sees and the `Host` header. Behind a
TLS-terminating ingress that is the difference between `https://` and a
`http://` the client never used.

No trusted-proxy list guards those two headers, deliberately: the element is
reflected only to the sender of the request and drives no decision inside the
proxy, so a client that forges them misleads only itself.

## Conditional requests

`If-Match`, `If-None-Match`, `If-Modified-Since` and `If-Unmodified-Since` are
forwarded to the backend on `GET`, ranged `GET` and `HEAD`, and `If-Match` and
`If-None-Match` on a single-request `PUT` and on `CompleteMultipartUpload`
([ADR 0007](../adr/0007-forward-it-or-refuse-it.md) D7). `GET` and `HEAD`
give the same answer to the same precondition, and `If-None-Match: *` against an
existing key answers `412 PreconditionFailed` instead of overwriting the object.

**A `PUT` the proxy turns into its internal multipart upload carries neither** —
one with no declared length, or larger than `optimizations.multipart_part_size`.
The two entity-tag preconditions are dropped there and the write proceeds, so a
create-if-absent `PUT` of a large object still overwrites. Send such a write as a
client-driven multipart upload, where `CompleteMultipartUpload` carries them.

Until 5.0.0 only the two entity-tag headers were carried, and only on a `GET`:
`HEAD` carried none, so it answered `200` where `GET` answered `304`; a
revalidating `GET` with `If-Modified-Since` fetched, decrypted and transferred
the whole object; and a create-if-absent `PUT` overwrote what it was written to
protect.

A date the proxy cannot parse is ignored rather than refused, which is what
RFC 9110 asks of a recipient. **Send back the entity tag the proxy gave you and
revalidation works**: the marker of
[Entity tags](integrity.md#entity-tags) is removed again before the precondition is
evaluated, including from a list of tags and from `*`. Computing an MD5 of your
own file and sending that will not work, and is not what an entity tag is for.

## What an unauthenticated request is told

Every S3 path requires a SigV4 signature; the proxy holds the backend credentials
itself, so there is no anonymous access to pass through. The refusal names what
actually failed
([ADR 0014](../adr/0014-authentication-is-sigv4-no-rate-limiting.md) D13):

| Request | Answer |
|---|---|
| No `Authorization` header at all | `403 AccessDenied` |
| A scheme this proxy does not implement | `400 InvalidRequest` |
| An `Authorization` header that does not parse | `400 AuthorizationHeaderMalformed` |
| An access key id no `s3_clients` entry carries | `403 InvalidAccessKeyId` |
| A signature that does not match | `403 SignatureDoesNotMatch` |
| A timestamp outside `max_clock_skew_seconds`, or a pre-signed URL past its lifetime | `403 RequestTimeTooSkewed` |

400 means the request itself is unusable, 403 that it was understood and refused.
The message is fixed per code: the attempted access key id, the signed header
names and the clock offset are logged and never echoed back.

## Request ids

Every answer carries `x-amz-request-id`, and an S3 `<Error>` document repeats the
same value in `<RequestId>`. It is the proxy's own identifier — sixteen uppercase
hex characters, minted per request, never the backend's — and the proxy's access
log line for that request carries it as `request_id`
([ADR 0008](../adr/0008-every-response-describes-the-proxy.md) D12a). So a
failure a client reports can be found in this proxy's log by that one value. An
`x-amz-request-id` a client sends is replaced: the value names the proxy's
handling of the request, which nothing a client supplies can name. `x-amz-id-2`
is not stated at all — there is no second value the proxy can vouch for.

## Operations the proxy does not implement

A sub-resource the proxy does not implement is answered rather than performed,
in one of two ways: a query parameter the proxy does not recognise at all, and
an object's `?acl` and `?attributes`, which it recognises and does not
implement, answer `501 NotImplemented`; a sub-resource that has a route but not
for the verb used — `DELETE /bucket/key?retention`, say — and `?restore`, which
has no route at all, answer `405 MethodNotAllowed`. It used to fall through to
the base operation for its HTTP method instead, which is how
`DELETE /bucket?encryption` **deleted the bucket**. Only query parameters on an
allowlist now reach the base bucket and object operations; any other parameter
is refused rather than dropped — as
`501 NotImplemented` naming `ObjectSubResource` or `BucketSubResource`, with the
parameter itself in the proxy's log.

What that means for a client today:

- **Object sub-resources: four are passthrough, the rest are refused.**
  `?tagging` (`GET`, `PUT`, `DELETE`), `?retention` (`GET`, `PUT`) and
  `?legal-hold` (`GET`, `PUT`) reach the backend and answer with its document —
  they carry no plaintext of the object and the proxy has nothing to add to them
  ([ADR 0007](../adr/0007-forward-it-or-refuse-it.md) D4). `?torrent` is
  refused with `422 NotSupportedWithEncryption`: the backend would compose that
  document from the ciphertext it holds. `?acl`, `?attributes` and S3 Select
  answer `501`, and so does a verb `?tagging` does not define. A verb
  `?retention` or `?legal-hold` does not define — a `DELETE` on either, say — answers
  `405 MethodNotAllowed`, and so does `?restore`, which has no route at all. A
  request document that does not parse answers `400 MalformedXML`, through the
  proxy's own error document.
- **A request document is bounded.** Every body the proxy parses whole — each
  bucket and object sub-resource document, and the `Delete` document of a batch
  delete — is read under `optimizations.max_request_document_size` (2 MB
  `# default`) and answers `400 EntityTooLarge` above it, before the backend is
  called. The default refuses nothing S3 itself accepts
  ([ADR 0024](../adr/0024-an-upload-forwards-while-it-receives.md) D8). A
  `Delete` naming more than a thousand objects is `400 MalformedXML` whatever its
  size, which is the separate S3 rule.
- **Bucket sub-resources read but mostly do not write.** `GET` is forwarded for
  all of them, and so is `DELETE` for `?cors`, `?policy`, `?tagging`,
  `?lifecycle`, `?replication` and `?website` — each answering `204` with no
  body, as S3 does. Of the `PUT`s only `?acl`, `?cors`, `?policy` and `?logging`
  reach the backend, and they carry the client's document **in full**, grant for
  grant and rule for rule ([ADR 0007](../adr/0007-forward-it-or-refuse-it.md)
  D5); an XML body that does not parse answers `400 MalformedXML` through the
  proxy's own error document, and a `?policy` body that is not JSON — or is
  empty — answers `400 MalformedPolicy`. `?versioning`, `?tagging`,
  `?notification` and `?lifecycle` parse no body and answer `501` whenever one is
  present — which it always is — and `?replication`, `?website`, `?accelerate` and
  `?requestPayment` answer `501` outright. **Enable versioning on the bucket
  directly at the backend**, not through the proxy.
- **Every sub-resource that answers at all answers a real S3 document.** Each
  such `GET` returns the document S3 defines, under the S3 namespace, with the
  XML declaration in front of it — `<CORSConfiguration><CORSRule><AllowedMethod>`,
  not the Go field names of an SDK struct. Until 5.0.0 these responses were the
  `aws-sdk-go-v2` output struct XML-encoded, so the root element was its Go type
  name, the element names were its field names, there was no namespace, and an
  internal `<ResultMetadata>` element was part of every one of them. No S3 client
  could parse any of them.
- **Multipart listing works**: `ListParts` answers from the proxy's own part
  table, with the plaintext size and the `ETag` this proxy answered per part —
  the object's last part included, which the proxy holds until
  `CompleteMultipartUpload` and which the backend therefore does not know about.
  `part-number-marker` and `max-parts` are honoured, and an upload id the proxy
  has no session for is `404 NoSuchUpload`. `ListMultipartUploads` is forwarded to
  the backend.

Five object sub-resources used to answer `200` for work they did wrongly or not
at all. Three of them are now real, and two are refused:

| Request | What it used to do | Today |
|---|---|---|
| `PUT /bucket/key?legal-hold` | Always set the hold **on**, whatever the body asked for, so a request to release one applied one | passthrough: the status in the body is the one that reaches the backend |
| `GET /bucket/key?legal-hold` | Empty `200` with no document | passthrough: a `<LegalHold>` document |
| `PUT`/`GET /bucket/key?retention` | Sent `Mode=Governance` with no retain-until date, or answered an empty `200` | passthrough: the mode and date in the body reach the backend, `x-amz-bypass-governance-retention` with them |
| `POST /bucket/key?select&select-type=2` | Ran a fabricated query, discarded the event stream, answered an empty `200` | `501 NotImplemented` |
| `GET /bucket/key?attributes` | Returned the object **bytes** where `GetObjectAttributes` expects an XML document | `501 NotImplemented` |

**A query string containing a `;` is refused with `400 InvalidArgument`**, after
authentication and before any routing decision
([ADR 0007](../adr/0007-forward-it-or-refuse-it.md) D13). S3 never uses `;`
as a query separator, and Go's query parser silently discards every
`&`-separated segment that contains one while the router splits on both
characters — so such a request would otherwise be routed by one reading of its
query and handled by another. A percent-encoded `%3B` is a value byte and is
unaffected.

`CopyObject` (`PUT` with `x-amz-copy-source`) and `UploadPartCopy` answer
`422 NotSupportedWithEncryption`: a server-side copy runs inside the backend,
where the proxy cannot decrypt and re-encrypt. `UploadPartCopy` used to be
unreachable and its request stored an empty part; it is now routed and refused.

## Versioned buckets

`versionId` is forwarded to the backend on `GET`, ranged `GET`, `HEAD` and
`DELETE`, so a client addressing one specific version gets that version rather
than the current one. `x-amz-version-id` is returned on `GET`, `HEAD`, `PUT`,
`DELETE` and `CompleteMultipartUpload`, and `x-amz-delete-marker` on a `DELETE`
that created one. An encrypted multipart upload writes exactly one
version: every metadata value exists before the first backend byte is sent, so
nothing rewrites the finished object to attach it.

