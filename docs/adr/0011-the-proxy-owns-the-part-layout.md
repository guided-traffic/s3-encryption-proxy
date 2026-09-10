# ADR 0011: The proxy owns the part layout it writes, and refuses copies it cannot re-encrypt

## Status

**Accepted.** Date: 2026-09-07.

**Implemented on the 5.0.0 branch, 2026-09-10, except D6's `ListParts` and D7's startup check.**
In the tree: both server-side copy verbs are refused (D9); one client part becomes exactly one
backend part and none waits for another (D1); the part-table rules are enforced at Complete and a
layout that cannot be stored as a chain answers `InvalidPart` and aborts the upload (D2, D3); the
trailer rides the short last part or goes as an extra part of its own (D4, D5); a second short
part answers `EntityTooSmall` at upload time and a full short-part buffer answers `SlowDown`
(D5); the client's part set is checked against the proxy's table and a mismatch is `InvalidPart`
(D6); and the self-copy that used to run after every multipart completion is gone, with its
5 GiB ceiling (D8). All of it is now covered over the wire against a real backend, not by unit
tests alone.

**Amended 2026-09-10, from what the wire coverage found.** D3 says the part size is inferred from
the largest part seen. It has to be the largest part that could be a *middle* part: a short last
part is by definition not the part size, and a client that puts all its parts in flight at once —
which every uploader does — regularly delivers it first. For the same reason the held part takes
its offset at Complete rather than on arrival. The residual risk below assumed part 1 is
dispatched before the last part, which is true; dispatch is not arrival, and that is what the
inference has to survive.

**Not implemented:** `ListParts` answered from the part table (D6) — it is still the stub that
answers an empty document for any upload id — and the reserved part number for the trailer (D4),
so an upload that uses all 10000 parts is refused by the backend at completion rather than by the
proxy when the part is sent.

**Implemented 2026-09-10:** the startup check that `optimizations.streaming_segment_size` is a
multiple of the segment size (D7). A configured value that is not one is refused by name at
startup instead of producing parts the read path cannot verify.

**Narrower than D5 says:** `optimizations.multipart_short_part_buffer_size` bounds **one part in
one session**, not the total held across sessions. A single upload cannot park more than the
configured bytes, so no one client can exhaust memory through one session; concurrent sessions
each get their own allowance, so the real ceiling is the cap times the number of open uploads.
The key is still the operator's sizing lever, but it is not the global bound D5 describes.

**Amended 2026-09-09:** the global short-part buffer of D5 is a configuration key with a low
default, not a constant, because it is memory an operator budgets against the container limit;
and the copy refusal of D9 stays unconditional under the pass-through provider too.

## Context

The proxy encrypts each part as it arrives, so what the backend stores is never the client's bytes.
The part layout at rest is the proxy's, and the read path has to find a given plaintext offset in it.

Under the segment chain the read path computes that position arithmetically from the stored size —
no per-object layout is consulted. Storing a layout instead would mean storing state that describes
the object, and under a hostile backend (ADR 0001) any such state is state the adversary can change
or drop. So the layout has to be constrained at write time instead of recorded.

The concrete failures that forced the rule:

* A part boundary that falls inside a segment cannot be sealed independently — the segment spans two
  backend parts, and no part can be encrypted without the other. Arbitrary client part sizes
  therefore either forbid the format or force a stored layout map.
* Parts were processed in one ordered pipeline: a retried part number, or part 3 arriving before
  part 2, blocked the request until the session aged out. Every AWS SDK retry reuses the part
  number, so this is ordinary client behaviour, not an edge case.
* Re-encrypting a part at the same offset under the old stream cipher would have reused the
  keystream — two plaintexts under one keystream. The hang was the only thing hiding it.
* Because the integrity value was only known after the last part, the proxy attached the encryption
  metadata by copying the finished object onto itself. That is a full server-side rewrite of every
  multipart object, it doubles versions on a versioned bucket, and server-side copy is hard-capped
  at 5 GiB: every multipart upload above that size failed **after** all bytes were transferred and
  the upload was committed, leaving an object the proxy cannot read back.
* S3 refuses a non-final part below 5 MiB with `EntityTooSmall`. Verified by direct calls against
  the MinIO release the demo stack runs (`RELEASE.2025-09-07T16-13-09Z`), which refuted an earlier
  claim that MinIO does not enforce the minimum: parts of 1 MiB + 36 B fail Complete, parts of
  5 MiB + 36 B succeed. Appending the authenticated trailer as an extra part turns the client's last
  part into a middle part, and most SDK uploaders produce a short last part.
* `ListParts` answered a fabricated empty document with `200`, so a client verifying its own upload
  was told it had no parts.
* Server-side copy runs inside the backend, where the proxy has no access to the plaintext. Under
  the segment chain every segment is bound to the object key the client used, so a backend copy to a
  different key produces an object that is undecryptable under its new name — a corruption the
  client discovers at read time, not at copy time.

## Decision

**D1.** Every client part is encrypted by the proxy and becomes exactly one backend part. A retried
or re-uploaded part replaces its own backend part and nothing else; re-encryption draws fresh
segment nonces, so repeating a part is safe. There is no ordered pipeline and no waiting for a
predecessor.

**D2.** A client-driven multipart upload must use uniform, segment-aligned parts. At Complete the
proxy checks, against its own part table, that every part except the highest-numbered one has the
same plaintext size, that this size is a multiple of the segment size, that each part was encrypted
at the offset its number implies, and that part numbers are contiguous from 1. A violation answers
`InvalidPart` and aborts the upload, so no object is ever created with a layout the read path cannot
verify.

**D3.** The part size is inferred from the largest part seen in the session; the check in D2 is what
makes the inference safe, because a wrong inference produces a refusal, never a stored object.

**D4.** The authenticated trailer is uploaded as one extra part when the client's last part is 5 MiB
or larger. A client-driven upload therefore has 9999 usable part numbers, not 10000.

**D5.** A client part below 5 MiB is held as ciphertext in the session and re-uploaded at Complete
under its own part number with the trailer appended. Two bounds make that buffer finite:

* At most one short part per session. A second part below 5 MiB can never complete, so it is
  refused with `EntityTooSmall` at upload time — not at Complete — and the upload is aborted.
* Across all sessions, buffered short-part bytes are capped by
  `optimizations.multipart_short_part_buffer_size` — bytes, default 64 MiB, at least 5 MiB so
  that one session can always complete, checked at startup (amended 2026-09-09). A short part
  that would exceed the cap answers `SlowDown` (503), which SDKs retry with backoff; the session
  stays open. The cap is a configuration key because it is memory the operator sizes against
  the container limit: a proxy that serves one application with a known number of concurrent
  uploads is sized for that number, and a cap the operator cannot lower reaches the
  out-of-memory kill before it reaches `SlowDown`. The buffer is short-lived — it exists from
  the arrival of a short last part until the client completes or aborts the upload — so the
  default covers a dozen sessions parking a maximal short part at once, and more with typical
  ones.

**D6.** Complete is built from the proxy's own part table, never from the ETags in the client's XML —
those ETags describe ciphertext the proxy produced, and a trailer re-upload makes one of them stale.
The client's document is still parsed and its part set is checked against the table; a mismatch is
`InvalidPart`. `ListParts` is answered from the same table.

**D7.** When the proxy drives the upload it picks its own parts: an upload whose plaintext length the
client does not declare, or whose plaintext exceeds `optimizations.streaming_segment_size`, is sent
to the backend as a multipart upload with parts of that size. `optimizations.streaming_segment_size`
must be a multiple of the segment size or the proxy refuses to start. The trailer rides the last
part the proxy builds, so this path spends no extra part number.

**D8.** A multipart completion is final. Every metadata value is known before the first backend byte
is sent and is set at `CreateMultipartUpload`, so the proxy never rewrites the finished object to
attach metadata.

**D9.** Server-side copy is refused under encryption: a `PUT` carrying `x-amz-copy-source` and
`UploadPartCopy` answer `422 NotSupportedWithEncryption`. The proxy does not forward such a request,
and does not silently produce an object it cannot read back.

**D10.** A client that needs an object under a second name re-uploads it through the proxy. Producing
a correct copy would mean fetching, decrypting and re-encrypting the source; that is not implemented
and is not owed by this decision.

## Consequences

* A client that copies inside a bucket — `aws s3 mv`, a sync that prefers copy over re-upload, a
  backup tool that promotes an object by copying it — fails with a refusal instead of degrading.
  Re-uploading through the proxy costs a full round trip of the object in both directions.
* The refusal is a hard stop at a point where S3 offers a cheap operation. This is the part of the
  decision nobody likes, and it is deliberate: a copy that produced an unreadable object is worse.
* The part rule holds for every uploader checked with its default settings, so ordinary clients are
  unaffected. A client that sizes parts unusually fails at Complete — after all bytes have been
  transferred. The failure is late and expensive, and it is never a silent corruption.
* One part number is spent on the trailer, and a client-driven upload costs one extra backend
  request. An upload whose last part is short pays a re-upload of at most 5 MiB instead.
* The proxy holds up to 5 MiB per session, and the configured cap in total, of buffered
  ciphertext — 64 MiB by default. Under that pressure clients see `SlowDown` and retry rather
  than fail, and a client that keeps sessions open without completing them is throttled, not
  fed. The cap is one term of the memory budget an operator sizes a pod with (ADR 0020).
* Session state — the part table — must live for the whole upload and is client-controlled in
  number; only an idle expiry and the global cap bound it.
* An existing deployment whose `optimizations.streaming_segment_size` is not a multiple of the
  segment size stops starting after the upgrade. That is deliberate — a silent fixup would produce
  parts the read path cannot verify — and it is an upgrade step the release notes have to name.
* Removing the post-completion rewrite removes the 5 GiB ceiling, halves write amplification, leaves
  one object version per upload, and stops the entity headers and the ETag from being rewritten
  behind the client's back.
* Complete becomes a check that can refuse, and aborting the upload on refusal means the transferred
  bytes are discarded rather than left as an orphan.
* `ListParts` stops lying, and `ListMultipartUploads` is forwarded to the backend instead of being
  refused.

## Alternatives Considered

**Store a per-object part layout instead of constraining part sizes.** Three places were costed.
Writing it after Complete keeps exactly the server-side rewrite this decision removes, with its
5 GiB ceiling. Object tags need new machinery on both the write and the read side and consume a
proxy-owned tag slot; the recorded objection that several S3-compatible targets lack object tagging
was never verified against a named target. Reading the layout from the object before every ranged
read costs a second backend request per range, or a per-object cache whose invalidation must hold
against a backend that changes the object underneath it. All three add state that describes the
object, and that is state the backend can lie about. The arithmetic rule needs none.

**Drop the trailer and flag the last segment instead.** It does not dissolve the problem for
client-driven multipart: the proxy learns which part is last only at Complete, and a last part of
exactly the part size is indistinguishable from a middle part when it arrives. Flagging it
afterwards means re-encrypting it, which means buffering a full-size part per session instead of at
most 5 MiB, plus more session state.

**Buffer every short part and let Complete sort it out.** A client sending 1 MiB parts would have
the proxy hold all of them until Complete failed. Refusing the second short part at upload time
bounds the buffer at one part per session and reports the problem where the client can still act
on it.

**Fetch an uploaded part back from the backend rather than buffering it.** No S3 verb reads an
uploaded, uncommitted part, and part copy reads committed objects only.

**Attach the late-bound value after Complete by object tagging.** Considered as the cheaper
replacement for the self-copy: metadata-only, no size cap. It still needs a proxy-owned tag
namespace, an extra read-side request, and it leaves a crash window between the completion and the
tagging in which the stored object carries no encryption metadata. It is moot under the new format,
where nothing is late-bound.

**Forward server-side copy to the backend unchanged.** Cheap, and it writes ciphertext bound to the
source object key under a different name. The client is told the copy succeeded and finds out at the
next read that the object cannot be decrypted.

**Implement copy inside the proxy as fetch, decrypt, re-encrypt.** Correct, and it turns an
operation the client asked to happen inside the backend into a full transfer through the proxy in
both directions. It is a separate piece of work; nothing in the product needs it today, and the
refusal says so honestly.

## Residual risks

* The part-size inference assumes part 1 is dispatched before the last part. True for every uploader
  checked; unverified for uploaders outside that list. A violation is a clean `InvalidPart`, not a
  corrupt object.
* One SDK computes its part size as *object size / 10000 + 1* above roughly 48.8 GiB with its default
  settings, which is not segment-aligned. Such an upload fails at Complete, and the operator
  documentation must tell clients to configure an aligned part size for objects that large.
* **Settled 2026-09-09: the cap is a configuration key (D5)**, because it is memory the operator
  budgets against the container limit. It is a resource bound, not a security control. The
  default of 64 MiB is a sizing judgement — a dozen sessions parking a maximal short part,
  more with typical ones, and comfortably above what the end-to-end backup client opens — and
  it is checked by that suite, not derived from a measurement of real client concurrency.
* **Settled 2026-09-09: the copy refusal stays unconditional, under `none` as well.** `none` is
  not a production mode, and one behaviour on the API surface beats a provider-dependent
  branch. A backend-side copy without re-encryption is impossible by construction under the
  name binding of ADR 0003 D4 — any binding a copy could keep is one a swap could keep too —
  so the only future route is the proxy-side copy named under Alternatives: fetch, decrypt,
  re-encrypt under the new name, streaming, for both copy verbs. An additive feature for a
  later release, when a client needs it.
* `NotSupportedWithEncryption` and the 422 status are the proxy's own, not codes AWS defines. How
  clients surface them was not verified.
* Neither copy refusal is exercised over the wire: no test asserts that a refused part copy leaves no
  part behind on the backend upload, or that a refused object copy leaves no destination object
  (see ADR 0019).
* The memory bounds in D5 are asserted by an automated test, not by a one-off measurement; the
  throughput effect of one client part becoming one independent backend part is an argument until the
  before/after numbers exist (see ADR 0020).
* The rules in D2 are enforced at Complete against the proxy's own table. If a future change lets a
  part be written without a table entry, the check silently narrows — the table is the only record
  that the layout is the one the read path assumes.

## References

* ADR 0001 — The S3 backend is hostile, and only the proxy's own verification counts
* ADR 0003 — Objects are stored as an authenticated segment chain
* ADR 0006 — The proxy serves any S3 client
* ADR 0007 — Forward it or refuse it, never silently drop it
* ADR 0010 — Sizes and listings describe the plaintext
* ADR 0017 — Stored data compatibility is not owed; a major release may break the format
* ADR 0019 — Integration and end-to-end tests are the product; they are never skipped
* ADR 0020 — Performance is measured before and after, never asserted
* [README.md](../../README.md) — S3 API behaviour worth knowing: the copy refusals, multipart part
  sizes, and the migration note for the major release
* [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md) — why an operation refuses instead of
  pretending, and what the backend is trusted with
