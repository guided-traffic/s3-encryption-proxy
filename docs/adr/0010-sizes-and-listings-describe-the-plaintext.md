# ADR 0010: Sizes and listings describe the plaintext

## Status

**Accepted.** Date: 2026-09-07.

**Implemented on the 5.0.0 branch, 2026-09-10.** `GET`, `HEAD` and both object listings answer
with the plaintext length of the object the client will receive, and they agree with each
other. A listing entry is corrected by arithmetic on the stored size, so no listing costs an
extra backend request and none reads per-object metadata.

The listing document is an S3 document: `ListBucketResult` under the S3 namespace, preceded by
an XML declaration, with the elements in the order a schema-validating parser expects and
without the elements an SDK output structure carries for its own bookkeeping. `start-after`,
`fetch-owner` and `encoding-type` are forwarded instead of dropped; `max-keys` is honoured
inside its range, clamped above it, and refused with `InvalidArgument` when it is negative or
not an integer. `HEAD /{bucket}` calls the backend's bucket-existence operation instead of an
object listing with a page size of zero, so a bucket that does not exist answers `404` rather
than `200`. No checksum element is emitted, because a backend checksum describes ciphertext.
`ListBuckets` gained the namespace, forwards its parameters, and names the caller in `<Owner>`
as D6 requires.

**Two things this decision did not anticipate**, both measured against a real backend before
the code was written rather than taken from the API reference. The element order differs from
the documented one in three places. And the backend does not clamp an oversized page request —
it echoes the number it was given and returns what it has — so the clamp is the proxy's own
behaviour and a deliberate deviation from the backend it runs against; the user-facing
reference says so.

**Two defects found in the shipped documents and not yet fixed.** `KeyCount` is forwarded from
the backend instead of counted from the entries the proxy actually emitted, so a backend that
miscounts is repeated verbatim into a document the proxy composes. And a bucket the backend
returns without a creation date is serialised as the Go zero time, which states a fact the
proxy does not have — the element has to disappear instead, and a unit test currently asserts
the defect.

## Context

A client that asks how big an object is must be told the size of the object it will receive.
Encryption adds framing to the stored bytes, so the stored size is always larger than the
plaintext size, and a proxy that forwards the stored size is answering a question the client
did not ask.

The concrete failure is bandwidth, not correctness. `aws s3 sync`, `rclone` and every other
synchronising client compare the size in a listing against the size on the other side and
re-transfer whatever does not match. Against this proxy nothing ever matches, so every object
is re-uploaded or re-downloaded on every run, forever, silently. The same defect existed on
`HEAD` and was fixed there; the listing is what is left, and the listing is the path such
clients hit constantly.

Fixing it naively is worse than the disease. The correction depends on how the object was
encrypted, which is per-object metadata, and a listing does not return metadata. Deriving it
would cost one metadata round trip per key — a thousand extra backend requests for a
thousand-key page, on the hottest read path in the product. Under the segment chain of ADR 0003
the correction is instead pure integer arithmetic on a number the listing already carries: the
framing is a constant per object plus a constant per segment, and the mapping from stored size
to plaintext size inverts exactly, including for the empty object and for a plaintext that is
an exact multiple of the segment size. That is why the size decision waits for the format and
why it then costs one division per entry.

The same responses carry a second, older problem. The listing is the last S3 response in the
proxy that is not an S3 response: the wrong root element, no XML namespace, elements S3 never
emits, elements S3 always emits missing, and an element order that is an accident of struct
layout. The SDKs in use tolerate it because they match elements by local name and ignore the
root. A strict client, a schema validator, or any implementation that checks the namespace does
not — and ADR 0006 says the product serves any S3 client, not the two that happen to be
forgiving.

Third, the listing is a place where the proxy speaks on behalf of a hostile backend (ADR 0001).
Whatever the backend puts into a listing entry describes ciphertext: its checksums describe
bytes the client will never see, and its owner element identifies the account the proxy holds
credentials for, not the caller. Passing either through unread is the listing form of the defect
ADR 0008 rules out everywhere else.

## Decision

**D1.** Every size the proxy reports describes the plaintext the client would receive — in
`GET`, in `HEAD`, and in every listing entry. There is no response in which the proxy reports
the size of the stored bytes as the size of the object.

**D2.** A listing size is computed by the proxy from the stored size alone, by arithmetic over
the storage format the proxy controls. It is never read from a field the backend chose and never
obtained by a per-key round trip. **A listing issues no per-object request, under any
circumstances**, whatever it would buy.

**D3.** When the active provider does not encrypt (`type: none`), a listing reports the stored
size verbatim. When a stored size cannot be one this proxy wrote — it is smaller than the
proxy's own framing, so no plaintext maps to it — the listing reports that stored size verbatim
rather than inventing a corrected number.

**D4.** A listing response is a real S3 document, built explicitly by the proxy: root element
`ListBucketResult` for the object listings and `ListAllMyBucketsResult` for the bucket listing,
carrying `xmlns="http://s3.amazonaws.com/doc/2006-03-01/"`, preceded by an XML declaration, with
S3's element names, S3's element order, `LastModified` at millisecond precision, and an absent
value rendered as an absent element rather than an empty one. No element appears that S3 does not
emit. Keys are XML-escaped by the encoder, never by string concatenation.

**D5.** No listing entry carries a checksum element. `ChecksumAlgorithm` and `ChecksumType` from
the backend describe ciphertext, and the proxy's own plaintext checksum is sealed inside the
object (ADR 0003) where no listing can read it, so the honest answer is no checksum element at
all. This is a confidentiality and truthfulness rule, not a formatting one.

**D6.** `<Owner>` never reflects the backend account. When owner information is requested, the
proxy answers with the requesting client's access key id as both `ID` and `DisplayName`, on the
object listings and on the bucket listing alike.

**D7.** Every listing parameter is honoured or refused, never silently dropped: `prefix`,
`delimiter`, `max-keys`, `continuation-token`, `start-after`, `fetch-owner` and `encoding-type`
on `ListObjectsV2`; `prefix`, `delimiter`, `marker`, `max-keys` and `encoding-type` on the original
`ListObjects`; `prefix`, `max-buckets`, `continuation-token` and `bucket-region` on `ListBuckets`. The
parameters S3 echoes are echoed, and the pagination fields — the continuation token or marker,
the key count, the truncation flag — are emitted, so a client can page to exhaustion.

**D8.** `max-keys` is validated: absent leaves the backend default in force; a value from `0`
through `1000` is forwarded verbatim, `0` included; a value above `1000` is clamped to `1000`; a
negative value or a non-integer answers `400 InvalidArgument`.

**D9.** The proxy owns the on-the-wire encoding of keys. It always requests URL encoding from the
backend so that the backend's document parses whatever bytes a key contains, decodes the values it
receives before using them, re-encodes on output only when the client asked, and echoes
`EncodingType` in that case.

**D10.** `HEAD /{bucket}` is a bucket existence check, not a listing with a page size of zero. It
answers with `x-amz-bucket-region`, falling back to the configured `s3_backend.region` when the
backend states no region.

**D11.** Every error on a listing path is an S3 XML error document, like every other error the
proxy returns.

**D12.** `<ETag>` stays the entity tag of the stored bytes on listings and on `HEAD`, and is
documented as a known deviation from S3, where it is an MD5 of the object content. Making it
describe the plaintext is a storage-format question, not a listing question, and is not decided
here.

## Consequences

- Every synchronising client re-transfers its entire dataset **once**, on the upgrade that
  changes the reported size, and then stops re-transferring on every run. That is the point of
  the change, and it is a visible cost on the day of the upgrade.
- In a bucket that also holds objects written outside the proxy, or written under the
  non-encrypting provider while an encrypting provider is now active, the computed sizes
  under-report those foreign entries by the framing overhead of the segment chain. The listing
  cannot tell such an entry apart without the per-key round trip D2 forbids. This is accepted:
  under ADR 0001 an object without the proxy's own metadata is refused on read
  (`InvalidObjectState`) when the active provider encrypts, so a client cannot act on such a size
  anyway, and a bucket of pre-existing plaintext is migrated through the proxy once rather than
  read in place. It is pinned by a test so that nobody later "fixes" it by adding a round trip.
- The `ETag` deviation of D12 survives. A client that compares entity tags rather than sizes
  still sees a mismatch on every object, so this change does not fix every synchronising client —
  only the ones that compare sizes, which is most of them.
- Making the bucket existence check a real existence check changes which backend permission it
  needs. A backend policy that grants only the listing permission and not the bucket-head one
  starts failing a check that used to succeed. That is the correct error surface, and it is a
  breaking change for such a deployment.
- The proxy answers `x-amz-bucket-region` from its own configuration when the backend states no
  region. If the two disagree, the proxy states its own. Acceptable, because the proxy is the
  endpoint the client is talking to, but it is a statement about the proxy rather than a fact from
  the backend and is documented as such.
- Building the document explicitly costs a small constant per listing and means new S3 listing
  fields must be added deliberately rather than appearing for free. That is the trade being made:
  nothing the backend adds reaches a client without someone deciding it should.
- The size rule must be stated in the user-facing reference, including the mixed-bucket
  under-report. A size correction that is not documented is indistinguishable from a bug report.

## Alternatives Considered

- **Keep forwarding the stored size and document it.** Zero work, and the documentation would be
  read by nobody whose client is silently re-uploading a terabyte a night. Rejected: the cost lands
  on the operator as bandwidth and on the backend as request charges, invisibly.
- **Fetch the per-object metadata for each key in a listing.** Correct sizes today, without waiting
  for the format change. Rejected outright, and named in D2 so it is not proposed again: it turns
  one backend request into one per key on the most frequently used path in the product, an
  order-of-magnitude regression to fix a byte count.
- **Store the plaintext size in object metadata and read it back in the listing.** A listing does
  not return user metadata, so this does not even work without the round trip above; and a size the
  backend can edit is a number the proxy would be trusting, against ADR 0001. The arithmetic is
  proxy-controlled and cannot be tampered with.
- **Correct sizes before the format change, using the per-object algorithm marker.** The marker is
  metadata, so this is the round trip again in a different costume.
- **Patch the existing document instead of rebuilding it** — rename the root element and move on.
  Rejected: it leaves the missing namespace, the elements S3 never emits, the empty elements that
  come from marshalling an SDK structure, and an element order no schema validator accepts. The
  defects are one defect.
- **Build the document by string concatenation** for full control of order and formatting.
  Rejected: it re-introduces the escaping bug the current encoder does not have. Keys containing
  `&`, `<` or `"` must keep working, so the document stays encoder-generated with explicit types.
- **Reject `max-keys` above 1000** rather than clamping. Rejected because S3 clamps; a client that
  asks for more should get a full page, not an error.
- **Stop forwarding the encoding request to the backend** and keep the current behaviour. Rejected
  as the primary design, because it leaves keys containing XML-hostile bytes breaking the
  backend-to-proxy parse. It is retained as the fallback if the decoding proves fragile — see below.
- **Split the work: document rewrite now, sizes after the format change.** Rejected: two reviews of
  the same rewritten responses, and the second one invalidates the first one's tests.

## Residual risks

- **Element order is not settled.** The order to emit was taken from the S3 API reference and has
  not been captured from a real backend response. Order matters only to schema-validating parsers —
  which are exactly the clients this change exists for. **Open:** capture a real response and pin
  the order against it before the assertions are locked; prefer the order of the backend the test
  suite runs against if the two differ, and record the deviation.
- **The decoding shape for URL-encoded keys is not settled.** Query-style decoding turns `+` into a
  space; path-style decoding does not. The backend the suite runs against encodes a space as `+`,
  which argues for query-style, but a key containing a literal `+` is then only safe if the backend
  percent-encodes it. **Unverified against anything but that one backend, and open.** It is guarded
  by a round-trip test over a hostile key set — literal `+`, space, `&`, `<`, `%`, a
  percent-encoded `+`, and a non-ASCII character, written then listed then read back. A failure of
  that test is a reason to fall back to not requesting an encoding from the backend at all, not a
  reason to weaken the test.
- The `max-keys` clamp-above / refuse-below rule is a reading of S3's documented behaviour and has
  not been verified against AWS S3. If the backend under test disagrees, S3 wins and the deviation
  is recorded.
- The bucket-listing pagination cannot fail in the test environment: the backend the suite runs
  against returns every bucket in a single response, so continuation-token forwarding there is
  covered only by unit tests against a mocked backend. Stated rather than implied to be
  end-to-end coverage.
- Storage class and restore semantics are out of scope and unverified. An archived object lists as
  readable and then fails on read; that is a known limit, not something this decision addresses.
- The size arithmetic assumes the storage format ships as designed in ADR 0003. A different
  segment size, a different trailer or a per-object header changes the function — and only the
  function; the document, the parameters and the bucket existence check are independent of the
  format.
- The behaviour described here as current was verified in the tree when the decision was taken and
  has not been re-verified since. What is decided does not depend on that; what is claimed about
  today's responses does.

## References

- ADR 0001 — The S3 backend is hostile, and only the proxy's own verification counts
- ADR 0003 — Objects are stored as an authenticated segment chain (the size function follows from it)
- ADR 0006 — The proxy serves any S3 client
- ADR 0007 — Forward it or refuse it, never silently drop it
- ADR 0008 — Every response describes the proxy, never the backend
- ADR 0012 — Client-supplied checksums are verified against the plaintext and never forwarded
- ADR 0017 — Stored data compatibility is not owed; a major release may break the format
- ADR 0019 — Integration and end-to-end tests are the product; they are never skipped
- ADR 0020 — Performance is measured before and after, never asserted
- [README.md](../../README.md) — the listing reference: reported sizes, forwarded parameters, the
  `max-keys` rule, the mixed-bucket under-report, the entity-tag deviation
- [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md) — the hostile-backend model and why no
  checksum element is emitted
