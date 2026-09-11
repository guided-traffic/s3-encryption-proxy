# Errors

Every failure a client sees on an S3 path is an S3 `<Error>` document with an S3
error code. `http.Error` is a bug on any path a client reaches: the SDK cannot
parse a code out of a text body and synthesises one from the status line, so the
real reason never arrives. Six paths still did it until 2026-09-11; none does now.

Code: `internal/proxy/response/`. **One** function renders the document,
`ErrorWriter.WriteS3Error` (`errors.go`), classifying through `response.MapError`,
so the status a client sees does not depend on which handler produced the error.
There used to be a second implementation of the same document in
`internal/proxy/utils`; two implementations of one document is how they diverge,
and it is gone.

It marshals through `encoding/xml` rather than concatenating strings: a code,
message or resource path holding `&` or `<` cannot break the document or inject
elements into it, and a control character in an object key — `%0C` over the URL
path — cannot produce a body no client can parse. It marshals **before** it
commits a status, so a marshalling failure answers `500` instead of leaving a
truncated body behind a `200` the client has already been told to trust.

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
| A client metadata key inside the configured prefix | `400 InvalidArgument` naming the key, on `PUT` and `CreateMultipartUpload`, before any backend request |
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

## What was wrong, and what is still

Present tense, all of it verified in this tree.

**Closed 2026-09-11: the refusals that did not say what they were.** Three groups
went at once, all of them under D1 and D8 of
[ADR 0007](../adr/0007-forward-it-or-refuse-it.md):

- **Six bare text bodies with no S3 code**, which an SDK cannot read a `<Code>`
  out of — it synthesises one from the status line instead. `?cors` (empty body,
  unparseable document), `?acl` (unparseable document) and `UploadPart` (body
  read failure, missing `uploadId` or `partNumber`, unparseable `partNumber`).
  They are `MalformedXML`, `IncompleteBody` and `InvalidArgument` now, each an
  `<Error>` document that names the parameter or element it refuses.
- **Eight client mistakes in multipart answered `500 InternalError`** with the
  generic message, so an SDK retried every one of them to the end of its budget.
  They were handed to `WriteS3Error` as a plain `fmt.Errorf`, and an error
  carrying neither an `APIError` nor an HTTP status is internal by definition —
  the class rule above, inverted. Each has the code that says what happened:
  `InvalidArgument` for a missing `uploadId` on Complete, Abort and ListParts,
  `MalformedXML` for an unparseable completion body, `InvalidRequest` for an
  empty part list, `InvalidPartNumber` for a part number outside 1..10000,
  `InvalidPart` for a missing ETag and `InvalidPartOrder` for a duplicate.
- **A read whose fingerprint names a provider that is not loaded.** It answered
  `500 DecryptionError`, and so did the exit provider's own fingerprint, which
  holds no key material and answers an unwrap with `ErrExitProviderKeyUse`.
  Retiring a key is a permanent state of every object it wrote, not an outage, so
  both are `403 InvalidObjectState` now, beside the wrap that does not
  authenticate. `ErrUnknownFingerprint` is the sentinel that carries it out of
  `ProviderManager.DecryptDEK`. Anything else an unwrap can fail with — a
  provider with a network round trip behind it, when one exists — stays a 5xx,
  because a retry is the right answer to an outage (ADR 0005 D10).

**`MapError`'s `internalMarkers` table has no producer.** `KEK_MISSING` →
`422 DecryptionError`, `KEY_MISSING` and `UNSUPPORTED_PROVIDER` →
`400 InvalidRequest` are matched on the error text, and nothing in the tree emits
those markers any more; only the unit tests reach the branch. It is the mechanism
that used to answer the unresolved-fingerprint case above.

**`ListParts` answers a fabricated empty document with `200`**
(`handlers/multipart/list.go`), which is the accept-discard-report-success shape
[ADR 0007](../adr/0007-forward-it-or-refuse-it.md) exists to forbid.
