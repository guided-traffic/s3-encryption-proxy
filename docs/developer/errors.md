# Errors

Every failure a client sees on an S3 path is meant to be an S3 `<Error>` document
with an S3 error code. `http.Error` is a bug on any path a client reaches: the SDK
cannot parse a code out of a text body and synthesises one from the status line,
so the real reason never arrives. Six paths still do it — see
[Where this is still wrong](#where-this-is-still-wrong).

Code: `internal/proxy/response/`. Two functions render the document —
`ErrorWriter.WriteS3Error` (`errors.go`) and `utils.HandleS3Error`
(`internal/proxy/utils/utils.go`) — and both classify through the same
`response.MapError`, so the status a client sees does not depend on which handler
produced the error. Both marshal through `encoding/xml` rather than concatenating
strings: a code, message or resource path holding `&` or `<` cannot break the
document or inject elements into it, and a control character in an object key —
`%0C` over the URL path — cannot produce a body no client can parse.

## Choosing a status class

The rule that matters most is not which code but **which class**, because the
class decides what the client's SDK does next.

**A permanent state of the object is a 4xx.** A 5xx makes an SDK retry a request
that cannot succeed — measured at three backend requests per client read — and
makes a client that treats 5xx as transient file a corruption as a passing
outage. Both are wrong answers to "this object is not readable here".

**A transient failure is a 5xx**, because there a retry is exactly right. A KMS
that cannot be reached, a backend that timed out.

The line runs through the cause, not through the symptom. A wrapped key that
fails its authentication tag is permanent, so it is 403. The same call failing
because the key provider is unreachable would be 5xx.

## How a backend error is classified

`MapError` (`error_mapping.go`) is the only mapper.

aws-sdk-go-v2 never hands back a typed error directly: it wraps it as
`*smithy.OperationError` → `*awshttp.ResponseError` → the typed error. Everything
unwraps with `errors.As` rather than type-switching on the value, which is what
made every backend error surface as 500 `InternalError` before.

The chain is the only source of the code. The code and message come from
`smithy.APIError`, the status from `awshttp.ResponseError`. **An error carrying
neither is internal by definition**: it is answered 500 `InternalError` with a
fixed generic message, and its own text is never mapped and never returned.

Three corrections run over the result:

- A status below 400 — except **304**, which is the answer to a conditional read
  and must reach a revalidating client — or above 599 is forced to 500. S3
  answers some operations with `200` and an `<Error>` body; aws-sdk-go-v2 rewrites
  that to 500 only for the operations that register the customization, and the
  ones it leaves out are this proxy's data plane. A 1xx is the worst of them:
  `net/http` writes it as informational without committing the status, so the body
  write then commits an implicit 200 carrying the error document.
- `NoSuchBucket` whose message says the bucket has no website configuration
  becomes `NoSuchWebsiteConfiguration`, because clients branch on the code.
- What is still missing is filled from tables: the status from `codeStatus`, the
  code from the status via `codeForStatus`, the message from `codeMessage` and
  otherwise from `http.StatusText`.

## The refusals worth knowing

| Situation | Answer |
|---|---|
| Object carries no proxy metadata, or names a foreign format | `403 InvalidObjectState`, *Object is not encrypted by this proxy* — under `type: exit` the object is served verbatim instead, because there it is not this proxy's object |
| The wrapped data key fails its authentication tag | `403 InvalidObjectState`, *Object key material failed authentication* |
| Server-side copy under encryption — `CopyObject`, `UploadPartCopy` | `422 NotSupportedWithEncryption` |
| A verb or sub-resource that is not implemented | `501 NotImplemented` |
| A sub-resource that has a route, but not for this method | `405 MethodNotAllowed` — running the base operation deleted objects |
| A `PUT` still carrying `partNumber` and `uploadId`, so the part routes refused it | `400 InvalidArgument` — running the base `PUT` replaced the object with one part |
| A multipart part layout that cannot be stored as a chain | `400 InvalidPart`, and the upload is aborted |
| A completion list that does not describe the upload | `400 InvalidPart`, and the upload survives |
| A second short part in one session | `400 EntityTooSmall`, at upload time |
| The short-part buffer is full | `503 SlowDown`, and the upload survives |
| An unknown upload id | `404 NoSuchUpload` |
| More than one byte range in one `Range` header | `501 NotImplemented` |
| A range outside the plaintext | `416 InvalidRange`, with `Content-Range: bytes */<plaintext size>` |
| A `Range` header that does not parse | `400 InvalidArgument` |
| Sealing or opening failed for any other reason | `500 EncryptionError` / `500 DecryptionError` |

The bound behind the `SlowDown` row is
`optimizations.multipart_short_part_buffer_size`, `67108864` (64 MiB) `# default`:
the largest short part one upload may hold until Complete. It is back pressure
rather than a refusal — SDKs retry a `SlowDown` with backoff and the upload is
still there when they do
([ADR 0011](../adr/0011-the-proxy-owns-the-part-layout.md)).

Five codes are the proxy's own, not codes AWS defines:
`NotSupportedWithEncryption` (422), `EncryptionError` (500), `DecryptionError`
(500), `UploadError` (500) and `InvalidPartNumber` (400). How clients surface them
is not verified. `InvalidObjectState`, `EntityTooSmall`, `SlowDown`, `InvalidPart`
and the rest of the table are S3's own codes with S3's own statuses.

## Aborting a body

Once a status line is out there is no code left to send. A fault found while
streaming is reported by **aborting the response body**, which reaches the client
as an unexpected EOF against the declared `Content-Length`. Prefer to decide a
refusal before the response begins where the information is available — that is
why the metadata check runs before any plaintext is written.

The decrypting reader is what makes this work: it hands out nothing it has not
authenticated, and it returns an error rather than `io.EOF` when the chain
disagrees with the trailer ([ADR 0003](../adr/0003-objects-are-an-authenticated-segment-chain.md)).
That error arrives at the handler **from `Read`**, inside the copy loop —
`Close` on both the whole-object reader and the range reader returns `nil` and
adds no check of its own.

## What never reaches a client

- **The raw SDK error text.** It carries the backend `RequestID`, `HostID` and the
  operation name. Logged at debug instead.
- **Any internal error's own text**, because it carries key fingerprints, backend
  endpoints and operation context. An error with neither an APIError nor an HTTP
  status gets the fixed generic message.
- **Authentication failure detail**, which carries attacker-controlled text — the
  attempted access key id, signed header names, clock offsets. Reflecting it
  echoed that text into the response body and broke the XML whenever a key
  contained `&` or `<`. `authErrorMessage` in `internal/proxy/middleware_setup.go`
  holds one fixed sentence per code instead.

What **does** reach the client is the backend's own `<Message>`, verbatim, for any
error the SDK parsed a code out of. That is deliberate: it is the storage
endpoint's description of a request the client made, and clients act on it.

## Where this is still wrong

Present tense, all of it verified in this tree.

**Six refusals answer a bare text body with no S3 code**, so an SDK synthesises a
code from the status line: `handlers/bucket/cors.go` (empty body, unparseable
CORS XML), `handlers/bucket/acl.go` (unparseable ACL XML) and
`handlers/multipart/upload.go` (body read failure, missing `uploadId` or
`partNumber`, unparseable `partNumber`). Recorded against D1 and D8 of
[ADR 0007](../adr/0007-forward-it-or-refuse-it.md).

**Eight client mistakes in multipart are answered `500 InternalError`** with the
generic message, and an SDK retries all of them. They are handed to
`WriteS3Error` as a plain `fmt.Errorf`, and an error carrying no APIError and no
HTTP status is internal by definition — the class rule above, inverted: a missing
`uploadId` on Complete, on Abort and on ListParts; an unparseable completion body;
an empty part list; a part number outside 1..10000; a missing ETag; a duplicate
part number. Each has an S3 code that says what happened — `InvalidRequest`,
`MalformedXML`, `InvalidPart`, `InvalidPartNumber` — and none of them is used.

**A read whose fingerprint names a provider that is not loaded answers
`500 DecryptionError`.** Retiring a key from the configuration is a permanent
state of every object it wrote, so this is the 4xx case answered as a 5xx.
`writeDecryptionError` (`handlers/object/operations.go`) gives 403 only to
`ErrForeignObject` and `ErrKeyMaterialUnreadable`; an unresolved fingerprint falls
through to the generic branch. So does the exit provider's own fingerprint: it
holds no key material and answers an unwrap with `ErrExitProviderKeyUse`, which
is not `ErrWrappedDEKAuth`, so an object the backend labelled
`exit-provider-fingerprint` is refused as a `500` as well. The refusal is the
point — no key of the backend's choosing is ever handed back — but it is the same
permanent-state-as-5xx shape.

**`MapError`'s `internalMarkers` table has no producer.** `KEK_MISSING` →
`422 DecryptionError`, `KEY_MISSING` and `UNSUPPORTED_PROVIDER` →
`400 InvalidRequest` are matched on the error text, and nothing in the tree emits
those markers any more; only the unit tests reach the branch. It is the mechanism
that used to answer the unresolved-fingerprint case above.

**`ListParts` answers a fabricated empty document with `200`**
(`handlers/multipart/list.go`), which is the accept-discard-report-success shape
[ADR 0007](../adr/0007-forward-it-or-refuse-it.md) exists to forbid.
