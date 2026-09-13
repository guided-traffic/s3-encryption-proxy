# ADR 0008: Every response describes the proxy, never the backend

## Status

**Accepted.** Date: 2026-09-07.

Implemented today: the completed-multipart `<Location>` names the proxy instead of echoing
the backend endpoint; every XML response body is marshalled from a typed structure rather
than concatenated; one error mapper turns a backend failure into an S3 error document, and
its substring fallback — which guessed an S3 code out of arbitrary error text — is deleted;
the bucket-listing error path answers an `<Error>` document instead of a plain-text
`Internal Server Error`; the proxy's own `s3ep-*` metadata is filtered out of decrypted
`GET`, `HEAD` and ranged responses; no backend checksum header is emitted; and a backend
answer that carries an error document behind a non-error status is answered `500` with the
code preserved, with `304 Not Modified` carved out.

**Fully implemented on the 5.0.0 branch.** The three items this block carried are closed:

- ~~The `<Location>` element honouring `X-Forwarded-Proto` and `X-Forwarded-Host`.~~
  **Landed 2026-09-11** in wave 2. Both headers win over the connection the proxy sees, and
  only the first value of a comma-separated list is taken.
- ~~Listing documents composed as real S3 documents.~~ **Landed 2026-09-10** (ADR 0010).
  `ListObjectsV2`, `ListObjects` and `ListBuckets` are composed by the proxy under the S3
  namespace, `<Owner>` names the calling client rather than the backend account, and the
  element order was captured from a running backend rather than read out of the reference.
- ~~Two implementations of the error document side by side.~~ **One left**, wave 2.

~~**Open against D7**: six refusals answer a bare plain-text body.~~ **Closed 2026-09-11** in
wave 2, together with seven other multipart client mistakes: no handler answers a bare status
with a plain-text body any more, so every failure a handler answers is an `<Error>` document.

**D12 implemented 2026-09-11.** Every timestamp a response document carries is rendered in the
format S3 emits, and a timestamp the proxy does not have is omitted rather than rendered as the Go
zero value. Before it, `ListBuckets` answered `0001-01-01T00:00:00Z` for a bucket the backend
reported without a creation date, and spelled a date it did have without the three fractional
digits the object listing was already emitting for the same instant — so two documents of one
product disagreed on how to write a timestamp.

**Narrower than D12 says** (2026-09-12): one shared renderer covers the two object listings and the
bucket listing. The lifecycle document, the object retention document and the part listing spell
the same format themselves, so what holds today is one format in four places, not the single point
of change D12 asks for. None of the four renders year 0001 — an absent value leaves its element
out, or empty where S3 does not make the element optional.

**Closed against D9** (2026-09-12). The exit provider's pass-through read handed the
backend's metadata back uncleaned. The condition was wider than first recorded: not only an
object written under a *different* configured prefix, but any object this proxy did not write
in the current format — an object written by 4.x under the shipped prefix included, which
returned the wrapped data key and the key fingerprint that release stored beside it. The
stripping now happens where the response is written rather than at each caller, so a read
path cannot be added without it. D9 was widened in the same change to say so.

**Open against D3** (2026-09-12): five documents still go out without the S3 namespace —
`InitiateMultipartUploadResult`, `CompleteMultipartUploadResult`, and the object `?tagging`,
`?retention` and `?legal-hold` documents. Every listing, every bucket sub-resource document and
`DeleteResult` carry it, and the bucket and object `?tagging` documents disagree with each other
over the same root element. The rule stands; these five are outstanding.

**Open against D10** (2026-09-12). The access-control documents still carry backend identities:
`GET /{bucket}?acl` answers with the backend account's `<Owner>` and with the grantees the backend
returned, and the `<TargetGrants>` of `GET /{bucket}?logging` carry the same. Both object listings,
the bucket listing and the two multipart listings name the requesting client as D10 requires.
Whether an access-control document can be brought under the rule at all — the proxy has no
truthful substitute for a grantee it did not grant — is undecided.

**Amended 2026-09-13: D13 added, and it landed the same day.** A documentation audit read
D1 as forbidding the restatement of *any* single backend value and filed the server-side-encryption
confirmation on a completed multipart upload as a violation of it. It is not one — D1 forbids
handing the backend's response object through as a whole, not restating one typed value — and the
misreading cost a round of work, which is the evidence that the rule as written did not carry its
own boundary. D13 writes that boundary in. Decided 2026-09-12 with the owner, recorded and built
2026-09-13: the confirmation now reaches the client on all four paths D13 names — a single-request
upload, a completed multipart upload, a whole-object read and a metadata request — from one writer
they all call, so a fifth path cannot be added that quietly drops it. A ranged read and a client
part upload stay silent, deliberately, and stay named under Residual risks.

## Context

The proxy is the S3 endpoint its clients talk to. The backend behind it is treated as
hostile (see ADR 0001), which makes every byte the backend puts into a response
attacker-controlled text until the proxy has examined it. Several defects, all found within
one sweep, turned out to be the same defect:

* The `<Location>` element of a completed multipart upload was the backend's own location
  string, unescaped. Every client that completed an upload learned the internal backend
  endpoint, and learned it from a value the backend chooses.
* Response documents were built by string concatenation in several places, so a key
  containing `&` or `<` produced a body the client could not parse. The client retried, and
  every attempt leaked a real backend upload that could neither be completed nor aborted
  through the proxy. Two of those sites reflected text an attacker supplies directly — an
  attempted access key id and the raw request URL.
* The error mapper carried a substring fallback: if the text of an internal error happened
  to contain the name of an S3 code, the client was answered with that code. A local
  failure was reported as a backend condition.
* One backend failure path answered `text/plain` with a bare `Internal Server Error`, so an
  `AccessDenied` on that path reached the client as a deserialization failure with no code
  at all.
* Listings and bucket sub-resource documents are the backend SDK's response objects run
  through an XML encoder. The root element is named after the operation output rather than
  the wire document, the S3 namespace is missing, and elements the proxy has no business
  restating — backend checksum descriptors, request-charged and result-metadata elements,
  an owner element carrying the backend account — appear or would appear on the wire.
* A backend can answer `200 OK` with an `<Error>` document in the body. Real S3 does exactly
  this for some operations. The proxy forwarded that status, so any client that branches on
  the status code alone read a failed operation as a success.

Then the reverse failure: once `<Location>` was built by the proxy, it was built from the
connection and the `Host` header the client sent, so behind a TLS-terminating ingress it
reports `http://` for a connection the client made over `https://`, with whatever hostname
the client sent.

The common rule behind all of these is that what the proxy returns is the proxy's own
answer. Everything else — leaking the backend endpoint, guessing a code from a string,
passing the backend's document through unread — is the proxy declining to be the endpoint
it claims to be.

## Decision

**D1** (boundary added 2026-09-13, see D13). Every response the proxy sends is composed by the
proxy: the status, the error code, the headers and the body are values the proxy can state
truthfully. A backend response object is never serialised onto the wire as received. This forbids
handing the backend's response object through as a whole; it does not forbid restating a single
typed value the backend returned. D13 decides which values may be restated.

**D2.** Response bodies are marshalled from typed structures with an XML encoder, never
assembled from strings. Escaping is a property of the encoder, not of a call the author
has to remember.

**D3.** Response documents carry the S3 element names, the S3 document root and the S3
namespace, and they carry only elements the proxy can vouch for. Elements that describe
what the backend stored rather than what the client receives are omitted, not forwarded.

**D4.** The `<Location>` of a completed multipart upload names the proxy as the client
addressed it: the first value of `X-Forwarded-Proto` and `X-Forwarded-Host` when present,
otherwise the scheme of the connection and the `Host` header of the request. It never
names the backend endpoint.

**D5.** No trusted-proxy list guards those forwarded headers. The value is reflected only
to the sender of the request and drives no decision inside the proxy, so a client that
forges the headers misleads only itself. The user-facing documentation states that the
element mirrors `X-Forwarded-Proto` and `X-Forwarded-Host` as received.

**D6.** A backend failure is translated into an S3 error the proxy states itself: the code
and status come from the typed error, never from pattern-matching the text of an error
message.

**D7.** Every failure the client sees is an S3 `<Error>` XML document with a code, on every
path. No plain-text body, no bare status, no empty body.

**D8.** An error carried behind a non-error status is a failure: any status below `400`
that carries an error code is answered `500` with the code and message preserved, and the
forced `500` derives its own code and message rather than keeping the backend's `OK`.
`304 Not Modified` is the single carve-out, because the proxy forwards conditional request
headers and a matching precondition legitimately produces it.

**D9.** The proxy's own metadata namespace never appears in a response. Every key carrying
the configured `encryption.metadata_key_prefix` is stripped from `GET`, `HEAD` and ranged
responses (ADR 0009 owns the namespace itself) — including a read the proxy serves without
decrypting, because an object it did not write may still carry what an earlier version of it
stored.

**D10.** The identity of the backend account never appears in a response document. Where an
owner element is emitted at all, it names the requesting client — its own access key id as
both the identifier and the display name.

**D11.** Adding a new pass-through of backend-supplied text or a backend-supplied element is
a decision taken per element, with a stated reason why the proxy can vouch for that value.
The default is not to pass it through.

**D12** (added 2026-09-11). A value the proxy does not have is omitted, never rendered as a
zero value. A missing timestamp leaves its element out of the document rather than claiming
year 0001: an absent element is a gap the client can see and handle, while a date is a value
it acts on. This is D11 read in the other direction — the default is not to invent a value
any more than to pass one through — and it is the same rule that keeps a listing from
reporting a size or a checksum the proxy cannot vouch for. Every timestamp a response document
carries is rendered by one function, in the format S3 emits (RFC 3339 with exactly three
fractional digits), so two documents of the same product cannot spell the same instant
differently.

**D13** (added 2026-09-13). Whether a backend-supplied response header may be restated is decided
by **what the header describes**, not by whether the proxy computes the value itself.

* A header that describes a property of the **backend service** passes through, restated by the
  proxy from a typed value. The server-side-encryption confirmations —
  `x-amz-server-side-encryption` and `x-amz-server-side-encryption-aws-kms-key-id` — are that case.
  On a write the proxy forwards the client's own server-side-encryption request headers to the
  backend, so the answer confirms something the client itself asked for and would have received from
  S3 with no proxy in the path. On a read no such request header exists; the answer then states how
  the backend service holds the object, which is still a property of that service and not a
  statement about the bytes the client receives.
* A header that describes the **stored object** belongs to the proxy and is restated from what the
  client actually receives, never forwarded. The stored object is ciphertext and the client receives
  plaintext, so a forwarded `Content-Length` or a forwarded `x-amz-checksum-*` would make the
  response lie about the bytes being delivered (ADR 0010, ADR 0012).
* The sorting is per header, with a stated reason, exactly as D11 requires of any pass-through.
  No class of header passes through by default.
* A header that passes under this rule is served on **every** object path that has one, not on some.
  The paths this decision settles are a single-request upload, a completed multipart upload, a
  whole-object read and a metadata request; a ranged read and a client part upload also receive the
  header from the backend and are named under Residual risks. An asymmetry between two paths is a
  defect of the response surface, not a
  property of the path.

## Consequences

* The proxy owes its clients a complete error surface of its own. Every backend condition
  has to be mapped, and a condition nobody mapped must still produce a well-formed document
  with a defensible code — which is why the unmapped case is `500 InternalError` rather
  than a passthrough.
* Composing documents costs code that forwarding does not, and it can lag: an element S3
  adds later does not appear until someone adds it here. That is the accepted price of
  never emitting an element the proxy cannot vouch for.
* D8 changes behaviour against real S3, not only against a hostile backend. S3 answers some
  operations `200 OK` with an error document; a client written to that shape now sees `500`
  from this proxy. Accepted: a status-only client must not read a failed operation as
  success.
* The `304` carve-out is load-bearing and easy to lose. Stated without it, D8 turns every
  cache revalidation into a `500`.
* D4 means the proxy reflects two client-settable headers into a response body. That is
  safe only as long as the value stays purely informational: the moment anything — a log
  consumer, an audit trail, a redirect — treats it as trustworthy, D5's reasoning is void
  and the analysis has to be redone.
* D10 costs the truthful answer wherever it reaches. A client that wants to know which
  backend account owns the objects cannot learn it from any listing; it can still learn it
  from `?acl`, which is the open item in the Status section.
* D3 removes information some clients use: no checksum descriptors in listings at all,
  because the backend's checksums describe ciphertext (ADR 0012) and the proxy's own
  plaintext CRC32C is sealed inside the object (ADR 0003 D14), where no listing can read it
  without a round trip per entry — the one ADR 0010 D2 forbids. A whole-object `GET` or a
  `HEAD` under an encrypting provider does report it, as `x-amz-checksum-crc32c`; a ranged
  read and every read under the exit provider do not.
* Two implementations of the error document existed when this was written and rendered identical
  bytes; two implementations of one document is how they diverged the first time, so consolidating
  them was part of this decision. **Done, verified 2026-09-12**: one renderer is left, and every
  failure path goes through it — the authentication middleware, which composes its own message set,
  hands the document to the same writer.
* D13 widens the response surface instead of narrowing it, which is the opposite of what the rest
  of this record does. The confirmation has to be produced on every object path that answers with
  one, and every path added later inherits the obligation; a path that forgets it reproduces the
  defect D13 closes, in a new place.
* The per-header sorting D13 demands has no shortcut. Each backend response header has to be
  classified before it may be emitted, and the classification asks what the header describes, not
  whether the value was convenient to compute. That is deliberate work per header, and it is the
  price of not shipping the deny list rejected below.

## Alternatives Considered

**Faithful proxying: forward whatever the backend answered, status included.** Defensible
for a plain proxy and it is what the code did. It loses under this product's threat model:
the proxy exists to turn the backend's answer into something a client can rely on, and a
`200` carrying an error document is precisely the answer a hostile backend would choose.

**Keep the error-mapper substring fallback.** It produced a plausible-looking code more
often than the alternative. It also answered a purely internal failure as a backend
condition whenever the message text happened to contain an S3 code name, which makes every
mapped code untrustworthy. Deleted.

**Build the `<Location>` from the connection and `Host` alone.** No new inputs, nothing
spoofable that was not already spoofable. Rejected because it is wrong in the deployment
shape the product is built for: behind an ingress it reports the wrong scheme and whatever
host the client sent anyway.

**A configured public URL for the `<Location>`.** Unspoofable and explicit. Rejected: it
costs a configuration key, its validation, its documentation and a defined behaviour when
unset, in a release whose direction is deleting configuration keys that nothing reads
(ADR 0013).

**Drop the `<Location>` element.** The smallest change, and it removes the question instead
of answering it; the bucket, key and ETag elements carry the load. Rejected because the
owner wants deployments behind an ingress to receive a correct value even without a
concrete consumer today.

**A trusted-proxy CIDR list gating the forwarded headers.** The textbook answer for
`X-Forwarded-*`. Rejected here: the configuration has no concept of a trusted proxy, the
one place that had a similar notion is being deleted, and the value gates no decision, so
the list would buy nothing but its own maintenance.

**Marshal the backend response objects and let clients cope.** It is what happens today,
and the two SDKs used in testing tolerate it because they match elements by local name. It
fails a strict client, a schema validator and any implementation that checks the namespace
— and it is the mechanism by which backend-chosen elements reach the wire unread.

**A blanket pass-through of every backend response header the proxy does not compute itself,
with a deny list for the rest.** The fuller expression of D13's first clause, and probably the
right long-run shape: it would end the asymmetry for every header at once instead of one header at
a time. Rejected because the deny list is a design of its own — every header has to be sorted by
whether it describes the plaintext object or the stored one, and one forgotten entry is a false
statement about customer data on a path nobody looked at. The narrow rule above is what was decided
instead; the blanket form remains available as a decision of its own.

## Residual risks

* **Two further paths receive the confirmation and stay silent.** A ranged read and a client
  part upload both get the server-side-encryption headers from the backend and drop them, and
  D13 does not oblige them. A ranged read answers a partial object, where a statement about how
  the whole object is held at rest is at best ambiguous; a part upload is not an object yet.
  Both are deliberate omissions rather than oversights, and both are open to revisit — but
  until then the response surface is not uniform, which is the very thing D13 calls a defect
  elsewhere.
* **Which S3 clients read `<Location>` was never established.** No client source was read;
  what is verified is only that the end-to-end backup scenarios pass with the value the
  proxy produces. The decision to keep and improve the element rather than drop it rests on
  intent, not on a known consumer.
* **A forged `X-Forwarded-Proto` or `X-Forwarded-Host` is accepted as sent.** Accepted, on
  the argument in D5. It is an accepted risk, not an absent one.
* **Informational statuses were never reproduced over the wire.** A backend answering
  `1xx` and then writing an error body makes the HTTP server commit an implicit `200`
  carrying that document — the sharpest instance of exactly the defect D8 closes. It is
  covered by the rule as written but was not tested against a real backend.
* **The set of non-error statuses that can carry an error was determined against the pinned
  backend SDK and against S3 and MinIO only.** Another backend may produce shapes nobody
  walked through.
* **The ETag is still the backend's** wherever an object or a stored part has one. It
  describes the stored ciphertext, not the plaintext the client receives. The single
  exception runs the other way: the short last part a client-driven upload leaves in the
  session is not at the backend yet, so the proxy answers an entity tag it derives from that
  part's own plaintext checksum, and `ListParts` repeats it until the part is stored. The
  backend entity tag is a deliberate, documented exception to D1 — correcting it is a
  storage-format question, not a response question — and it means "every response describes
  the proxy" is not yet literally true.
* ~~**Two backend headers survive on the completion response.**~~ **Reclassified 2026-09-13 by
  D13, and this bullet no longer states the risk.** `CompleteMultipartUpload` restating the
  backend's `x-amz-server-side-encryption` and `x-amz-server-side-encryption-aws-kms-key-id` is an
  application of the rule, not an exception to it: both describe the backend service, the client's
  own server-side-encryption request headers are forwarded to reach it, and the answer confirms
  what the client asked for. Calling it the header form of the `<Location>` leak was wrong — the
  `<Location>` named an endpoint the client never mentioned. The defect runs the other way: the
  same confirmation is absent on every other object path, which is what D13 closes.
* **The key id can name a key the client never named.** A client that asks for `aws:kms` without
  naming a key is answered with the identifier the backend chose, which for a key management
  service is normally an ARN and therefore carries the backend's account and region — the same
  class of fact as the endpoint the `<Location>` element used to leak, and one D10 keeps out of
  every response document. Not tested against a backend configured with a default key management
  key. Accepted as part of the
  confirmation — it is what the client would receive from S3 directly — but it is the one place
  where D13's first clause hands back something the client did not already know, and it was not
  tested against a backend configured with a default key management key.
* **Closed 2026-09-12: no refusal answers a plain-text body.** The request-validation refusals
  answer the same `<Error>` document as the backend ones, so D7 holds on every path a handler
  answers, not only on the backend ones. The surface is still not uniform, and what is left is
  the router's rather than a handler's: a method no route declares is answered by the routing
  default with a bare `405`, no `<Error>` document and no `Allow` header, and a preflight
  `OPTIONS` is answered there too, before the middleware that would answer it. Pinned as current
  behaviour by a test that says it is a defect.
* **The substitute owner identity is a recorded default, not a validated one.** Answering
  with the client's own access key id has not been checked against a strict client or
  against a client that compares the value across requests.
* **Closed 2026-09-12: the listing element order is the order a running backend emits**, captured
  from it rather than read out of the API reference, and pinned by a test that asserts the raw
  response body — the SDK matches by local name and would pass either order. What is settled is
  agreement with that backend, which is MinIO; no order was ever captured from AWS S3 itself, and
  the reference and the backend disagree in three places.
* **The key encoding of the composed listing rests on an implementer default, not an
  owner decision.** The recorded answer is to request `encoding-type=url` from the backend,
  decode what comes back as query-encoded, and echo `<EncodingType>url</EncodingType>` only
  when the client asked for it. Query decoding turns `+` into a space, which is right for a
  backend that encodes a space that way — MinIO is recorded doing so — and silently
  corrupts a key containing a literal `+` unless the backend percent-encoded it. Guarded
  only by a round-trip test over a key set containing `+`, a space, `&`, `<`, `%`, `%2B`
  and a non-ASCII character; unverified against any backend but MinIO, and it is the
  sharpest edge in the listing rewrite.

## References

* ADR 0001 — The S3 backend is hostile, and only the proxy's own verification counts
* ADR 0006 — The proxy serves any S3 client
* ADR 0007 — Forward it or refuse it, never silently drop it
* ADR 0009 — The metadata prefix is the proxy's namespace
* ADR 0010 — Sizes and listings describe the plaintext
* ADR 0011 — The proxy owns the part layout it writes, and refuses copies it cannot re-encrypt
* ADR 0012 — Client-supplied checksums are verified against the plaintext and never forwarded
* ADR 0013 — A configuration key exists only if code reads it, and an unworkable configuration refuses to start
* [README.md](../../README.md) — S3 API behaviour worth knowing: the refusals, checksums, versioned buckets
* [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md) — threat model and trust boundaries
