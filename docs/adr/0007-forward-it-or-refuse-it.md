# ADR 0007: Forward it or refuse it, never silently drop it

## Status

**Accepted.** Date: 2026-09-11.

**Implemented, except where this record says otherwise**: D7 on the proxy's own multipart upload
and D8's answer to `?restore`, both under Residual risks. D6 is built as the refusal; carrying the
customer key on every verb, which is what would lift it, is not built. The refusal half ships since
4.0.0 and the forwarding half since 5.0.0. What is built, per decision:

- **D1.** An unrouted bucket query parameter does not fall through to the base operation for its
  HTTP method, and the object sub-resources that have no implementation refuse rather than answer
  a fabricated `200 OK`. The six response-header overrides — `response-content-type`,
  `response-content-language`, `response-expires`, `response-cache-control`,
  `response-content-disposition` and `response-content-encoding` — are applied to the answer of a
  `GET`, whole-object and ranged alike, and to a `HEAD`: S3 defines them on that verb too, and a
  `HEAD` is documented to answer the headers a `GET` answers. What the request asked for wins over
  what the object carries, on every read verb and under the exit provider as well. They are
  honoured rather than refused because they are legitimate S3. `ListParts` answers from the
  proxy's own part table under an encrypting provider, with `404 NoSuchUpload` for an upload it
  has no session for, and from the backend under the exit provider, where there is no part table
  and the backend's sizes are already the plaintext sizes (ADR 0011, ADR 0025).
- **D2.** `Expires` is forwarded as an entity header describing the plaintext, like
  `Cache-Control`; `GET`, ranged `GET` and `HEAD` return it from the raw header the backend sent.
- **D3 and D6.** All ten storage headers reach the backend, from one reader and two appliers
  shared by every upload path, so a single-request `PUT`, the internal multipart producer and
  client-driven `CreateMultipartUpload` cannot answer the same request differently. The three
  customer-key headers are refused `501 NotImplemented` naming the header, in front of every S3
  route rather than per verb, because D6 lifts only when every verb carries the key. Two headers
  the proxy has to parse — `x-amz-object-lock-retain-until-date` and `Expires` — answer
  `400 InvalidArgument` when they are not a date, rather than being dropped.
- **D4.** `?tagging` (`GET`, `PUT`, `DELETE`), `?retention` and `?legal-hold` (`GET`, `PUT`) reach
  the backend. Each document is one the proxy defines itself, carrying the element names S3
  defines, because the SDK's own request and response shapes carry none and an XML encoder then
  falls back to their internal field names: a `<Tagging>` body read into the SDK shape yields an
  empty tag set, and writing its response shape out produces a root element no client reads. A
  body that does not parse answers `400 MalformedXML`. The integration tests read every result
  straight from the backend, so what is proven is that the request arrived there rather than that
  the proxy echoed what it was handed.
- **D5.** `PUT /{bucket}?acl` and `PUT /{bucket}?cors` parse into documents of this proxy's own
  and carry every grant and every rule to the backend; a body that does not parse, or one whose
  root element is not the document that sub-resource takes, answers `400 MalformedXML` through the
  proxy's own error document. Every bucket sub-resource `GET` answers the document S3 defines, and
  the bucket sub-resource `DELETE` arms answer `204` with no body.
- **D7.** All four preconditions are carried on `GET`, ranged `GET` and `HEAD`, and the two
  entity-tag ones on a single-request `PUT` and on a client-driven `CompleteMultipartUpload`, from
  one reader shared by those paths. A date the proxy cannot parse is ignored rather than refused,
  which is what RFC 9110 asks of a recipient. The internal `HEAD` the ranged path may take — to
  decide per object under the exit provider, or to resolve a suffix or open-ended range —
  deliberately carries no precondition: it asks how long the object is, and the client's condition
  rides on the `GET` that follows, which is the request the client actually made.
- **D8.** Every refusal a handler answers carries the S3 error code that says what happened —
  none answers a bare plain-text body, and a client mistake in multipart is not reported as
  `500 InternalError` for an SDK to retry to the end of its budget. `?restore` is the exception.
- **D9 and D10.** An unrouted query parameter is refused by name; a part upload whose part number
  is not a number answers `400 InvalidArgument` instead of overwriting the object.
- **D11.** A backend error document under a non-error status is turned into a failure.
- **D13.** A raw query carrying a `;` is answered `400 InvalidArgument`, after authentication and
  ahead of the handler, pinned by a test that drives the bypass shape over the wire and asserts the
  object is byte-identical afterwards. A percent-encoded semicolon is a value byte and is not
  affected.
- **D14.** `x-amz-expected-bucket-owner` reaches the backend on every call site the handlers make,
  from one reader, and the two SDK input types that carry no such field are the two S3 defines none
  for. A source-level test reads the proxy's own sources and fails on a backend call that does not
  set the field, because the way this decays is a new backend call that forgets it: that compiles,
  passes its own behaviour tests, and fails open.

## Context

The proxy sits in the request path of any S3 client and rewrites the object body. Every
other part of a request — headers it does not need, sub-resource documents, query
parameters — has exactly three possible fates: forward it, refuse it, or drop it and claim
success. The third is the one this decision exists to forbid.

**The concrete failure.** Probed against a running stack:

```
aws --endpoint-url http://127.0.0.1:8080 s3api put-object --bucket <probe> --key sse.txt \
    --body f --server-side-encryption AES256 --storage-class STANDARD_IA \
    --tagging 'k=v' --acl private
```

answered `200 OK` with an ETag. Read directly from the backend, the stored object had no
server-side-encryption marker, an empty tag set and storage class `STANDARD`. Four things
the client asked for, four silent drops, one success. The same shape appeared one level
out: `PUT /{bucket}?acl` and `PUT /{bucket}?cors` parsed the client's document into a shape
that had nowhere to put a `<Grant>` or a `<CORSRule>`, so both were gone before the backend
was addressed. `?acl` then set the bucket's access control to the owner with no grants behind a
`200 OK` — the silent-success shape. `?cors` called nothing at all, because a `PutBucketCors`
with an empty rule set is not a valid request, and answered a perfectly good CORS document
`500 InternalError` — a hard failure rather than a lie, from the same root. That is why D5 asks
for the document to be carried in full rather than for a wider shape to be parsed into. The
response half had the same defect: every bucket sub-resource `GET` answered the backend SDK's
output structure XML-encoded — root element the type name, element names the field names, no
S3 namespace — which no S3 client could parse (ADR 0008).

The sharpest instance of the class was already closed before this decision: an unrouted
bucket sub-resource used to execute the base operation for its HTTP method, so
`DELETE /{bucket}?encryption` **deleted the bucket**. That is why this is a security rule
and not a compatibility preference. It is the product's second rule applied to the request
surface: a control that exists only in configuration or documentation is worse than no
control, because it gets relied upon. A client that sets a header and gets a success learns
that the proxy honours it, and every later assumption builds on that.

The analysis that preceded this decision proposed refusing most of the dropped headers —
server-side encryption because asking a hostile backend to encrypt buys nothing, tagging
because tags are stored in the clear on a ciphertext object, canned ACLs because they grant
backend access to principals the proxy does not control. The repository owner rejected that
framing. The proxy protects the **confidentiality of object content**. None of those
headers touches content: they select a storage tier, attach labels, set access control and
retention on an object whose bytes are already ciphertext. A client that puts a public ACL
on a ciphertext object gets a public ciphertext object — which is what it ordered. The
defect in the probe was the lie, not the forwarding.

Re-checking for cases where forwarding is itself a trap found exactly one.
Customer-provided-key server-side encryption (SSE-C) requires the key on every request
that touches the object. No read path in the proxy carries it, so accepting it on upload
alone would write objects the proxy could never read back — a silent time bomb rather than
a silent drop. That asymmetry, not policy, is what earns the refusal.

## Decision

- **D1.** A request the proxy accepts is either honoured or refused with a named S3 error
  code and a matching HTTP status. Accepting a request, discarding part of what it asked
  for, and answering success is forbidden. This holds for request headers, request bodies,
  sub-resources and query parameters alike.
- **D2.** A request element the proxy does not itself need is **forwarded to the backend
  unchanged**. The proxy's mandate is the confidentiality of object content; anything that
  does not touch content is the client's business and is passed on, not adjudicated.
- **D3.** Every upload path — single-part `PUT`, the proxy's internal multipart pipeline
  and client-driven `CreateMultipartUpload` — forwards the same set of storage headers,
  through one shared decision, with no path-dependent behaviour:
  `x-amz-server-side-encryption`, `x-amz-server-side-encryption-aws-kms-key-id`,
  `x-amz-tagging`, `x-amz-storage-class`, `x-amz-acl` and the `x-amz-grant-*` headers,
  `x-amz-object-lock-mode`, `x-amz-object-lock-retain-until-date`,
  `x-amz-object-lock-legal-hold`, and `x-amz-website-redirect-location`.
- **D4.** The object sub-resources `?tagging` (GET, PUT, DELETE), `?retention` (GET, PUT)
  and `?legal-hold` (GET, PUT) are passthrough: the request reaches the backend and the
  backend's answer comes back value for value, in the document this proxy composes (ADR 0008).
  They carry no plaintext of the object and the proxy has nothing to add to them.
- **D5.** `PUT /{bucket}?acl` and `PUT /{bucket}?cors` carry their document to the backend
  in full — every grant, every rule. A body that does not parse answers `MalformedXML`
  through the proxy's own error document, not a bare transport error.
- **D6.** The three customer-key headers —
  `x-amz-server-side-encryption-customer-algorithm`,
  `x-amz-server-side-encryption-customer-key` and
  `x-amz-server-side-encryption-customer-key-MD5` — are refused with `501 NotImplemented`,
  naming the header. The refusal is lifted only when **every** verb that touches an object
  carries the key: `PUT`, `GET`, ranged `GET`, `HEAD`, `CreateMultipartUpload` and every
  `UploadPart`. When it is lifted, the key transits the proxy on the backend leg and the
  `-algorithm` and `-key-MD5` response headers are echoed; the key is never logged, never
  stored, never cached and never placed in object metadata. SSE-C through this proxy is
  compatibility with clients and bucket policies that require it, not protection against
  the backend.
- **D7.** Conditional request headers are honoured, not dropped: `If-Match`,
  `If-None-Match`, `If-Modified-Since` and `If-Unmodified-Since` on `GET`, ranged `GET` and
  `HEAD`; `If-Match` and `If-None-Match` on `PUT` and `CompleteMultipartUpload`.
  `If-None-Match: *` against an existing key answers `412 PreconditionFailed` instead of
  silently overwriting the object. `GET` and `HEAD` give the same answer to the same
  precondition.
- **D8.** A refusal says what is true. `501 NotImplemented` means the proxy does not
  implement the operation. `400 InvalidArgument` or `MalformedXML` means the request is
  wrong. `422 NotSupportedWithEncryption` means encryption forecloses the operation
  (ADR 0011). A refusal names the header, parameter or element it refuses, so the client
  learns what to remove.
- **D9.** A query parameter the proxy does not route is refused by name; it never executes
  the base operation for its HTTP method. Parameters in the `x-amz-*` namespace are
  protocol, not sub-resources, and are admitted everywhere — the namespace is the
  allowlist, because a literal list of SDK parameter names goes stale.
- **D10.** A `PUT` carrying both `partNumber` and `uploadId` whose part number is not a
  number answers `400 InvalidArgument`. It must never reach the plain object `PUT` and
  replace the object it was uploading a part into. `GET ?partNumber` keeps
  `501 NotImplemented`, because a read of one part is genuinely not implemented.
- **D11.** A backend answer that carries an error under a non-error status is answered as a
  failure: any status below 400 other than `304 Not Modified`, and any status above 599,
  becomes `500`, keeping the backend's S3 error code. A client that branches on the status
  code alone must never read a failed operation as a success (ADR 0001, ADR 0008).
- **D12.** What is forwarded is documented as forwarded, together with its consequence:
  object tags and `x-amz-meta-*` user metadata reach the backend **in the clear** on a
  ciphertext object; access-control settings act on the ciphertext object; object lock
  defends against a compromised credential, not against a compromised backend; and a
  forwarded `x-amz-server-side-encryption` is the backend encrypting its own copy, not the
  proxy's encryption.
- **D13.** A request whose raw query string contains a `;` is refused with
  `400 InvalidArgument`, after authentication and before any routing decision. S3 never uses
  `;` as a query separator. The standard library's query parser silently drops every
  `&`-separated segment that contains one, while the router splits on both characters, so such
  a request would be routed by one reading of its query and handled by another. Refusing the
  character closes the whole class of parser disagreement, not one instance of it: no handler
  ever sees a query that the parser and the router read differently. The refusal is proven
  over the wire, by a test that first reproduces the bypass against the release before it and
  then asserts the refusal.
- **D14.** `x-amz-expected-bucket-owner` is carried on **every** backend
  call the proxy makes on a client's behalf, on every verb that S3 defines it for. It is the
  one header whose drop fails open: S3 answers `403 AccessDenied` when the bucket belongs to
  another account, which is what defends a client against reading from, writing to or deleting
  a bucket name someone else re-created after the original was removed. A proxy that drops it
  performs the operation and answers success, so the client believes a guard is in place and
  has none — D1's failure shape applied to a security control rather than to a preference.
  The two verbs that do not carry it are the two S3 does not define it for: `CreateBucket`,
  where the bucket has no owner yet, and `ListBuckets`, which is account-scoped.
  **All or nothing, deliberately.** A guard is worth what its weakest verb honours: honouring
  it on some verbs is worse than honouring it on none, because a client tests it on one verb,
  sees it work, and builds every later assumption on that. This is why it is one reader used
  at every call site rather than a header added where someone noticed it missing.
  `x-amz-mfa` and `x-amz-request-payer` stay dropped everywhere, and
  `x-amz-bypass-governance-retention` is carried on `PUT ?retention`, where shortening a
  governance retention is the client's decision to make against the backend, and dropped on the
  delete verbs. None of those drops is the same case as the ownership guard: without them the
  backend refuses the operation, so they fail closed. They are a capability gap, not a false
  assurance.

## Consequences

- **Tags and user metadata are a plaintext index at the backend.** Forwarding
  `x-amz-tagging` means tag keys and values sit in the clear next to ciphertext, exactly
  like the `x-amz-meta-*` user metadata the proxy already forwards. For a backup bucket
  that is a labelled map of what each ciphertext object is. This is a confidentiality
  statement the security architecture has to make explicitly; it is the accepted cost of
  treating storage attributes as the client's business.
- **A public ACL makes a public ciphertext object.** Its bytes, its size, its timing and
  its `s3ep-*` metadata become readable by anyone the grant names. The proxy does not
  second-guess that.
- **Object lock protects against the wrong adversary if read carelessly.** A hostile
  backend can ignore a retention setting; a compromised **credential** cannot, and that is
  the common ransomware path for a backup bucket. Forwarding is worth it for the second
  adversary and worthless against the first, and the documentation must say which.
- **A forwarded `x-amz-server-side-encryption` produces a response header that reads like a
  guarantee the proxy did not make.** The client sees encryption confirmed by the component
  the threat model calls the adversary. Only the proxy's own envelope encryption protects
  the content.
- **The cost of forwarding is asymmetric and sticky.** A refusal fails loudly and is fixed
  in minutes. A forward that succeeds teaches the client that the header is honoured, and
  reversing it later is a breaking change for every client that learned it.
- **SSE-C is a hard failure for anyone who needs it.** A client, or a bucket policy, that
  requires customer-key encryption cannot use this proxy until the key is carried on every
  verb. That is deliberate: the alternative is an object nobody can read.
- **The proxy's S3 surface grows.** Three sub-resource families and two bucket documents
  need real backend calls, real XML, error mapping and tests. Every one of them is surface
  that must stay faithful; refusing was cheaper to maintain.
- **The non-error-status rule needs its carve-out.** `304 Not Modified` reaches the proxy
  as a backend error carrying a sub-400 status, and it is a correct answer to a conditional
  read. Without the exception, every cache revalidation becomes a `500`.
- **The rule does not create features.** What the proxy genuinely does not implement stays
  refused — `PUT /{bucket}?versioning` keeps its `501 NotImplemented`. Honesty is the
  requirement; implementation is a separate decision. What the proxy has something truthful to
  answer from is answered: `ListMultipartUploads` is forwarded, and `ListParts` is answered
  beside it — from the proxy's own part table under an encrypting provider (ADR 0011), from the
  backend under the exit provider (ADR 0025).

## Alternatives Considered

- **Refuse most of the storage headers, per-header.** The original analysis: refuse
  server-side encryption, SSE-C, tagging, canned ACLs and the website redirect; forward
  only storage class and object lock. It lost on scope — it makes the proxy the arbiter of
  storage policy it does not own — and on evidence: the case for refusing was weakest
  exactly where the cost was highest, since no client's mapping from its own configuration
  onto these headers was ever verified, and a refusal turns a legitimate client setting into
  a hard upload failure.
- **Keep accepting and discarding.** The status quo, and the cheapest option. It loses to
  the product's second rule: the client is told the work was done. It is also what made
  `DELETE /{bucket}?encryption` delete a bucket, one level out.
- **Forward the customer-key headers on `PUT` only, and deal with reads later.** Rejected:
  it converts a silent drop into an unreadable object, which is strictly worse. Either every
  verb carries the key or none does.
- **Encrypt object tags so tagging can be forwarded without leaking.** Rejected: encrypted
  tags stop being usable for backend-side filtering, which is most of the point of tags, and no
  client asked for it. Encrypting tags would reverse the plaintext-tag consequence above.
- **Refuse `PUT ?acl` and `PUT ?cors` outright**, on the grounds that no consumer is known.
  Rejected: it is the same silent-`200` class one level out, carrying the document properly
  is not harder than refusing it, and the refusal would be a visible regression for real
  access-control management.
- **Proxy the backend's answer faithfully, including a `2xx` that carries an error
  document.** Defensible as pure proxying, and rejected under the hostile-backend rule: the
  proxy exists to turn the backend's answer into something a client can trust.
- **Keep `501 NotImplemented` for the malformed part upload.** Rejected: the request is
  malformed, not unimplemented, and AWS answers `InvalidArgument`. The refusal must say
  which of the two it is.
- **Allowlist pre-signed protocol query parameters by literal name.** Tried, and it broke:
  the SDK added a checksum-mode parameter to every pre-signed `GetObject` URL, which the
  list did not contain, so every pre-signed download was refused with
  `501 NotImplemented`. Admitting the `x-amz-*` namespace replaced it — no S3 sub-resource
  lives in that namespace, and every query parameter is covered by the request signature,
  so nobody who cannot already sign the request can add one.

## Residual risks

- **D13 closes one parser disagreement, not the class.** The bypass it closes: the standard
  library's query parser discards any `&`-separated segment that contains a `;` and swallows
  the error, while the router splits on both characters, so a `PUT` whose query contains a `;`
  would fall through to the plain object `PUT` with an **empty** parsed query and overwrite the
  object — the part-overwrite data loss through a different door, authenticating cleanly
  because the canonical query string is built from the same parsed query. Found by reading the
  libraries; reproduced over the wire by the test that pins the refusal. What stays open is the
  general form: any further disagreement between the parser and the router about a query string
  is the same class, and nothing but review finds the next one.
- **D14's effect is not proven against any backend this project can reach.** Three were
  probed on 2026-09-11 — MinIO, LocalStack 3.8 and Wasabi — and **none implements
  `x-amz-expected-bucket-owner`**: a `HeadObject` carrying a bucket owner id that owns nothing
  succeeds against all three. The conformance suite of
  [ADR 0027](0027-conformance-is-asserted-against-a-backend-that-is-not-minio.md) was built
  partly to close this and reports it by name as a backend deviation on each of them
  (re-checked 2026-09-12). One cause rather than three coincidences: the header names an **AWS
  account id**, and an implementation with no AWS account model has nothing to check it
  against. LocalStack is the sharpest case, because it does model account ids and still does
  not enforce it.
  So what is proven stops one step earlier than the wire: the unit tests assert the field on
  the SDK input, and a source-level test asserts that every call site sets it. **The guard's
  behaviour is verified against AWS's specification, not against an implementation of it.**
  Only a backend that enforces the header closes this, and none of the three does — which
  also means the header is, against those backends, a guard the *client* believes in and
  nothing downstream honours. That is the backend's gap rather than the proxy's, and forwarding
  remains the only correct thing for the proxy to do: a client pointed at AWS gets a working
  guard, and one pointed at these three is no worse off than talking to them directly.
- **The forwarded storage headers are exercised by one SDK and by no real client.** Eight of
  the ten are sent through the proxy by the integration suite, with every assertion read
  straight from the backend, so the forwarding itself is proven for them; the SSE-KMS key id
  and the `x-amz-grant-*` headers are pinned only by unit tests over the shared reader. What is
  not proven is that any client an operator actually runs sends them: the end-to-end backup
  client sets only a checksum algorithm, and the claim that a backup tool's storage-location
  settings map onto exactly these headers is **from memory and unverified**.
- **Whether SSE-C should be refused outright on a plain-HTTP client listener is open.** The
  customer key travels in a request header; without TLS on the client leg it travels in the
  clear. Refusing would be consistent with the rest of the plain-HTTP stance. To be decided
  when SSE-C is implemented.
- **Forwarding `x-amz-storage-class` lets a client write an object into a tier it cannot
  read back.** An archived object still appears in a listing and then fails on `GET`. This
  is a documented limit and was **not verified** against any backend.
- **The response side has not been swept the way the request side has.** This decision
  covers what the proxy does with what a client sends. Which backend response headers reach
  the client, and which are dropped, is ADR 0008's subject and was not re-audited here. The
  consequence above arrives through that door as well: under ADR 0008 D13 the backend's
  `x-amz-server-side-encryption` and `x-amz-server-side-encryption-aws-kms-key-id` are restated
  on a single-request upload, a completed multipart upload, a whole-object read and a metadata
  request, so a client can be told its object is server-side encrypted by the component the
  threat model calls the adversary — on a read, without having asked for anything.
- **A large `PUT` drops its preconditions.** A body above `optimizations.multipart_part_size`,
  or one of undeclared length, becomes the proxy's own multipart upload, and the completion of that
  upload carries neither `If-Match` nor `If-None-Match`. A create-if-absent upload of a large
  object therefore overwrites what it was written to protect and answers `200` — D7's own
  failure shape, one verb further on, and the write suite does not reach it because it uses
  small bodies. Open.
- **Admitting a query parameter and honouring it are decided in two different places.** The
  six `response-*` header overrides are admitted by the allowlist a base object request is
  checked against, which does not look at the verb, and honoured by each read verb separately.
  A new read verb inherits the admission and not the honouring, so it would answer `200` with
  the stored values to a client that asked for others — D1's failure shape, and the one a `HEAD`
  already had once.
- **One refusal says something untrue.** `?restore` has no route of its own, so every
  verb carrying it is answered `405 MethodNotAllowed` — `POST` included, which is the verb S3
  defines for it. There the method is right and the operation is simply unimplemented, so D8
  asks for `501 NotImplemented`, which is what `?attributes` and S3 Select answer. Open.
- **Not measured:** the cost of forwarding these headers on the upload paths. It is header
  copying next to encryption and expected to be irrelevant, but no benchmark was taken
  (ADR 0020 is the standard any claim to the contrary has to meet).

## References

- ADR 0001 — The S3 backend is hostile, and only the proxy's own verification counts
- ADR 0006 — The proxy serves any S3 client
- ADR 0008 — Every response describes the proxy, never the backend (the response half of
  the same honesty rule; D11 is its status-code consequence)
- ADR 0009 — The metadata prefix is the proxy's namespace (why a client metadata key inside
  the prefix is refused rather than dropped)
- ADR 0010 — Sizes and listings describe the plaintext
- ADR 0011 — The proxy owns the part layout it writes, and refuses copies it cannot
  re-encrypt (the `422 NotSupportedWithEncryption` refusals, and the real part listing)
- ADR 0012 — Client-supplied checksums are verified against the plaintext and never
  forwarded (its exceptions to D2 and to D1: a plaintext digest describes a body the backend
  never sees, and on `CompleteMultipartUpload` alone the declared digest is of the completed
  object, so it is neither verified nor forwarded — that exemption and its reasoning live
  there)
- ADR 0013 — A configuration key exists only if code reads it, and an unworkable
  configuration refuses to start (the same rule, applied to configuration)
- ADR 0020 — Performance is measured before and after, never asserted (the standard the
  unmeasured forwarding cost has to meet)
- ADR 0023 — Filename encryption, if it ships, encrypts directory segments only (what the
  backend learns regardless, which forwarded tags add to)
- [docs/operations/s3-api.md](../operations/s3-api.md) — the operations the proxy refuses, sub-resource by
  sub-resource, and the versioning behaviour a client sees today
- [docs/operations/integrity.md](../operations/integrity.md) — the checksum behaviour
- [docs/security/stored-objects.md](../security/stored-objects.md) — what the backend learns
  anyway; [docs/security/refusals.md](../security/refusals.md) — the handlers that refuse rather
  than pretend; [docs/security/threat-model.md](../security/threat-model.md) — the trust boundary
  the forwarding decision is measured against
