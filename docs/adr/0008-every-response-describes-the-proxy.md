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
wave 2, together with seven other multipart client mistakes: no handler calls `http.Error`
any more, so every failure is an `<Error>` document.

**Open against D9**, narrowly: the exit provider's pass-through read hands the backend's
metadata back uncleaned, so an object this proxy encrypted under a *different* configured
prefix and then read under the exit provider returns its `s3ep-*` keys to the client. The
provider was named `none` when this was found (ADR 0025 renamed it and changed what it does;
the leak is unchanged).

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

**D1.** Every response the proxy sends is composed by the proxy: the status, the error code,
the headers and the body are values the proxy can state truthfully. A backend response
object is never serialised onto the wire as received.

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
the configured `encryption.metadata_key_prefix` is stripped from decrypted `GET`, `HEAD`
and ranged responses (ADR 0009 owns the namespace itself).

**D10.** The identity of the backend account never appears in a response document. Where an
owner element is emitted at all, it names the requesting client — its own access key id as
both the identifier and the display name.

**D11.** Adding a new pass-through of backend-supplied text or a backend-supplied element is
a decision taken per element, with a stated reason why the proxy can vouch for that value.
The default is not to pass it through.

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
* D10 costs the truthful answer. A client that genuinely wants to know which backend
  account owns the objects cannot learn it through the proxy.
* D3 removes information some clients use: no checksum descriptors in listings at all,
  because the backend's checksums describe ciphertext (ADR 0012) and no plaintext checksum
  is stored.
* Two implementations of the error document exist today and render identical bytes. Two
  implementations of one document is how they diverged the first time; consolidating them
  onto one is part of this decision and is outstanding work, not a completed state.

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

## Residual risks

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
* **The ETag is still the backend's.** It describes the stored ciphertext, not the plaintext
  the client receives, on every path that returns one. This is a deliberate, documented
  exception to D1 — correcting it is a storage-format question, not a response question —
  and it means "every response describes the proxy" is not yet literally true.
* **A few request-validation paths still answer a plain-text body** instead of an S3 error
  document. They are not backend errors, so D7 is not violated by the backend path, but the
  client-visible surface is not yet uniform.
* **The substitute owner identity is a recorded default, not a validated one.** Answering
  with the client's own access key id has not been checked against a strict client or
  against a client that compares the value across requests.
* **S3 element order and namespace details were taken from the API reference**, not
  captured from a real S3 response. Only schema-validating parsers care, and those are
  exactly the clients D3 is for; the ordering must be captured from a live backend before
  assertions are locked.
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
