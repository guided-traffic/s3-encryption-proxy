# ADR 0007: Forward it or refuse it, never silently drop it

## Status

**Accepted.** Date: 2026-09-07.

Two halves, at different stages.

The **refusal half is implemented and released, the last of it in 4.0.0**: an unrouted bucket query
parameter no longer falls through to the base operation for its HTTP method, four object
sub-resources that answered a fabricated `200 OK` now refuse, a backend answer carrying an
error document under a non-error status is turned into a failure, and a malformed part
upload answers `400 InvalidArgument` instead of overwriting the object.

The **forwarding half lands in 5.0.0 and is going in piece by piece.**

**D3 and D6 implemented 2026-09-11.** All ten storage headers reach the backend, from one
reader and two appliers shared by every upload path, so a single-request `PUT`, the internal
multipart producer and client-driven `CreateMultipartUpload` cannot answer the same request
differently. The three customer-key headers are refused `501 NotImplemented` naming the
header, in front of every S3 route rather than per verb, because D6 lifts only when every verb
carries the key. Two headers the proxy has to parse — `x-amz-object-lock-retain-until-date`
and `Expires` — answer `400 InvalidArgument` when they are not a date, rather than being
dropped. The unit and integration tests that pinned the silent drop are inverted per header.

**`Expires` is forwarded under D2, not under D3**, which does not name it: it is an entity
header describing the plaintext, like `Cache-Control`, and it was the last one still dropped.
`GET`, ranged `GET` and `HEAD` return it, from the raw header the backend sent.

**D4 implemented 2026-09-11.** `?tagging` (`GET`, `PUT`, `DELETE`), `?retention` and
`?legal-hold` (`GET`, `PUT`) reach the backend, and the seven backend operations the
dead-code round removed came back with the handler arms that call them — the same move the
listing rewrite made for `HeadBucket`, a method arriving with its caller rather than ahead of
it. Each document is a type of this proxy's own with XML tags, because the SDK's input and
output structs carry none and `encoding/xml` then binds by Go field name: a `<Tagging>` body
unmarshalled into the SDK type yields an empty tag set, and marshalling its output type
produces a root element no client reads. A body that does not parse answers `400 MalformedXML`.
The integration tests read every result straight from the backend, so what is proven is that
the request arrived there rather than that the proxy echoed what it was handed.

**D5 implemented 2026-09-11, together with the response half it exposed.** `PUT /{bucket}?acl`
and `PUT /{bucket}?cors` parse into documents of this proxy's own and carry every grant and
every rule to the backend; a body that does not parse, or one whose root element is not the
document that sub-resource takes, answers `400 MalformedXML` through the proxy's own error
document rather than a plain-text body no SDK can read a code out of.

Doing it exposed the same defect on the way out, one the earlier reads of this ADR had not
named: **every bucket sub-resource `GET` answered the aws-sdk-go-v2 output struct XML-encoded**
— root element the Go type name, element names the Go field names, no S3 namespace, and the
SDK's internal `ResultMetadata` element inside every document. Twenty-one responses no S3
client could parse. All of them now answer the document S3 defines, and the `DELETE` arms that
answered `200` with such a struct answer `204` with no body. The two writers that produced
them are deleted: one committed its status before it marshalled, so a marshalling failure left
a truncated body behind a `200`; the other existed only for two fabricated documents a
nil-backend branch produced, which production could never reach.

What is still outstanding: D7
— of which only `If-Match` and `If-None-Match` on a whole and on a ranged `GET` are carried
today, so `HEAD` and `GET` still disagree, no upload path carries one, and `If-Modified-Since`
and `If-Unmodified-Since` are dropped everywhere. The `Decision` section is written in the
present tense throughout.

**Amended 2026-09-09:** D13 adds a refusal for a query string that contains a `;`, closing the
bypass that was recorded under Residual risks. It is a new client-visible refusal, so it lands
with 5.0.0 (ADR 0018). **Implemented 2026-09-11**, after authentication and ahead of the
handler: a raw query carrying a `;` is answered `400 InvalidArgument`, and the refusal is
pinned by a test that drives the bypass shape over the wire and asserts the object is
byte-identical afterwards. A percent-encoded semicolon is a value byte and is not affected.

**Amended 2026-09-10, correcting what this block said about D5.** `PUT /{bucket}?acl` and
`PUT /{bucket}?cors` were recorded here as both forwarding an empty document behind a
`200 OK`. Only half of that is true. Both parse the client's document into a shape that has
nowhere to put a `<Grant>` or a `<CORSRule>`, so both are gone before the backend is
addressed — and there the two part company. `?acl` calls `PutBucketAcl` with the owner and no
grants, which is the silent-success shape D1 forbids; the canned `x-amz-acl` header form is
the one that works. `?cors` calls nothing at all: a `PutBucketCors` with an empty rule set is
not a valid request, so a perfectly good CORS document is answered `500 InternalError`. That
is a hard failure rather than a lie — D5 unbuilt, not D1 violated — and it is the reason D5
asks for the document to be carried in full rather than for a wider shape to be parsed into.

**Amended 2026-09-10:** the 5.0.0 dead-code removal dropped every backend operation no request
ever reached, seventeen of them, and eight are precisely the ones the forwarding half re-adds:
object tagging (`GET`, `PUT`, `DELETE`), object retention (`GET`, `PUT`), object legal hold
(`GET`, `PUT`) and `ListMultipartUploads`. The decision does not change — an operation the
proxy declares but never calls is a capability on paper, which is what ADR 0013 removes
elsewhere — but the cost of D4 rises: the proxy no longer speaks those operations to the
backend at all, so building it starts from nothing rather than from a call already in place.

**Also open against D1 and D8**, and not previously recorded: six refusals still answer a
bare plain-text body with no S3 error code — one under `PUT /{bucket}?acl`, two under
`PUT /{bucket}?cors` and three in `UploadPart`. A client SDK cannot parse a code out of a text
body; it synthesises one from the status line, so the reason never reaches the client. And
`ListParts` answers a fabricated empty document with `200`, which is the
accept-discard-report-success shape this decision exists to forbid.

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
out: `PUT /{bucket}?acl` discarded every `<Grant>` and `PUT /{bucket}?cors` every rule,
both behind a `200 OK`, because the request body was parsed into a structure that could not
hold them.

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
  backend's document is echoed as returned. They carry no plaintext of the object and the
  proxy has nothing to add to them.
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
- **D13** (added 2026-09-09). A request whose raw query string contains a `;` is refused with
  `400 InvalidArgument`, after authentication and before any routing decision. S3 never uses
  `;` as a query separator. The standard library's query parser silently drops every
  `&`-separated segment that contains one, while the router splits on both characters, so such
  a request would be routed by one reading of its query and handled by another. Refusing the
  character closes the whole class of parser disagreement, not one instance of it: no handler
  ever sees a query that the parser and the router read differently. The refusal is proven
  over the wire, by a test that first reproduces the bypass against the release before it and
  then asserts the refusal.

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
  now need real backend calls, real XML, error mapping and tests. Eight of those calls the
  proxy no longer makes at all, since 5.0.0 removed every backend operation nothing reached,
  so the work starts one step further back than when this was decided. Every one of them is
  surface that must stay faithful; refusing was cheaper to maintain.
- **The non-error-status rule needs its carve-out.** `304 Not Modified` reaches the proxy
  as a backend error carrying a sub-400 status, and it is a correct answer to a conditional
  read. Without the exception, every cache revalidation becomes a `500`.
- **The rule does not create features.** What the proxy genuinely does not implement stays
  refused — `PUT /{bucket}?versioning` keeps its `501 NotImplemented`. Honesty is the
  requirement; implementation is a separate decision. `ListMultipartUploads` is the
  counter-example: it was refused because the proxy had nothing to answer from, and since
  5.0.0 it does — every open client-driven upload, with its bucket, its key, when it started
  and its parts (ADR 0011). The refusal is now a statement about work not done, which is a
  weaker reason than the one it was written for.

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
- **Encrypt object tags so tagging can be forwarded without leaking.** Rejected for now:
  encrypted tags stop being usable for backend-side filtering, which is most of the point of
  tags, and no client asked for it. If tags are ever encrypted, the plaintext-tag consequence
  above reverses and this ADR is amended.
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

- **Settled 2026-09-09: a `;` in the query string is refused (D13).** The bypass it closes:
  the standard library's query parser discards any `&`-separated segment that contains a `;`
  and swallows the error, while the router splits on both characters, so a `PUT` whose query
  contained a `;` fell through to the plain object `PUT` with an **empty** parsed query and
  overwrote the object — the part-overwrite data loss through a different door, authenticating
  cleanly because the canonical query string was built from the same parsed query. Found by
  reading the libraries; reproduced over the wire by the test that pins the refusal. What
  stays open is the general form: any further disagreement between the parser and the router
  about a query string is the same class, and nothing but review finds the next one.
- **No client exercised in this repository sends any of the forwarded storage headers.** The
  end-to-end backup client sets only a checksum algorithm. So nothing proves the forwarding
  works against a real client until the tests for it exist, and the claim that a backup
  tool's storage-location settings map onto exactly these headers is **from memory and
  unverified**.
- **Whether SSE-C should be refused outright on a plain-HTTP client listener is open.** The
  customer key travels in a request header; without TLS on the client leg it travels in the
  clear. Refusing would be consistent with the rest of the plain-HTTP stance. To be decided
  when SSE-C is implemented.
- **One fabricated success survives the rule.** `ListParts` answers an empty
  `<ListPartsResult>` at `200 OK` without asking anything, so a client verifying an upload is
  told it has zero parts. It is decided that it answers from the real part table (ADR 0011),
  and since 5.0.0 the proxy does hold that table — the part numbers and stored ETags of a
  client-driven upload, for as long as the upload is open. The material for a true answer
  exists and the answer is still not built from it, so this stays a live instance of exactly
  what D1 forbids.
- **Forwarding `x-amz-storage-class` lets a client write an object into a tier it cannot
  read back.** An archived object still appears in a listing and then fails on `GET`. This
  is a documented limit and was **not verified** against any backend.
- **The response side has not been swept the way the request side has.** This decision
  covers what the proxy does with what a client sends. Which backend response headers reach
  the client, and which are dropped, is ADR 0008's subject and was not re-audited here. One
  instance is known and is the consequence above arriving through the other door:
  `CompleteMultipartUpload` echoes the backend's `x-amz-server-side-encryption` and
  `x-amz-server-side-encryption-aws-kms-key-id` response headers, so a client can be told
  its object is server-side encrypted on a verb where the proxy never asked for it.
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
  forwarded (the one deliberate exception to D2: a plaintext digest describes a body the
  backend never sees)
- ADR 0013 — A configuration key exists only if code reads it, and an unworkable
  configuration refuses to start (the same rule, applied to configuration)
- ADR 0020 — Performance is measured before and after, never asserted (the standard the
  unmeasured forwarding cost has to meet)
- ADR 0023 — Filename encryption, if it ships, encrypts directory segments only (what the
  backend learns regardless, which forwarded tags add to)
- [README.md](../../README.md) — the operations the proxy refuses, sub-resource by
  sub-resource, and the checksum and versioning behaviour a client sees today
- [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md) — what the backend learns
  anyway, the handlers that refuse rather than pretend, and the trust boundary the
  forwarding decision is measured against
