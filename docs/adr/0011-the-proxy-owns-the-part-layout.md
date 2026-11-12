# ADR 0011: The proxy owns the part layout it writes, and refuses copies it cannot re-encrypt

## Status

**Accepted.** Date: 2026-09-14.

**Implemented.** Both server-side copy verbs are refused, under every provider (D9). One client
part becomes exactly one backend part and none waits for another (D1). The part-table rules are
enforced at Complete, and a layout that cannot be stored as a chain answers `InvalidPart` and
aborts the upload (D2, D3). The trailer rides a held last part or goes as an extra part of its
own, and part number 10000 of a client-driven upload is answered `400 InvalidArgument` naming the
reason when the part is sent, instead of the backend refusing the closing part at completion after
every byte has been transferred (D4). A second part that cannot be a middle part answers
`EntityTooSmall` at upload time; a part that does not fit beside what other uploads hold answers
`SlowDown`, and one larger than the whole budget answers `400 EntityTooLarge` before it is read
(D5). The client's part set is checked against the proxy's table and a mismatch is `InvalidPart`,
and `ListParts` is answered from that table (D6). A value of `optimizations.multipart_part_size`
that is not a multiple of the segment size is refused by name at startup, and a configuration
that still carries the key's earlier name, `optimizations.streaming_segment_size`, is refused by
a message that names the replacement (D7). No multipart completion is followed by a rewrite of
the finished object, so the 5 GiB ceiling that rewrite imposed is gone (D8).

**`ListParts`** answers each `<Part>` with the plaintext length the client sent (ADR 0010) and the
entity tag `UploadPart` answered with, the held last part included — the client uploaded it and
was given a tag for it, and the backend does not have it. `part-number-marker` and `max-parts` are
honoured, and an upload id the proxy has no session for is `404 NoSuchUpload`. Under the exit
provider the proxy keeps no table, so there the verb is forwarded. `ListMultipartUploads` is
forwarded as *Consequences* says.

**The short-part budget is the process's**, claimed when a part is held and given back on every
ending — completion, abort, idle sweep, shutdown sweep. The `EntityTooLarge` refusal happens
**before the part is read**: the read stops at the budget, so a body the proxy may not keep is
never buffered in full first — which is what makes the key a memory bound rather than a bound on
what is retained.

**A re-sent part number drops the held copy it replaces.** A client may send any part number
again, and a held short part that comes back large enough to be stored where it lies would
otherwise stay in the session: Complete would store the held bytes under that number while the
part table described the new ones — an object that stores cleanly and fails authentication on
every read, behind a `CompleteMultipartUpload` that answered `200 OK`. The superseded copy is
dropped where the replacement is buffered, and on the streamed path — the path a client takes
when it declares a length that could be a middle part's, which is what an SDK retry with
different chunking produces. The streamed drop happens once the backend has acknowledged the part
and its sealed length has been checked, not when the part is prepared: every failure before that
point leaves the part table as it found it, and a held part is one the client uploaded
successfully, so it may only disappear once its replacement stands. Dropping it gives the
short-part budget back with it.

**Test coverage.** All of it but the short-part budget is covered over the wire against a real
backend; the `EntityTooLarge` answer is asserted by unit tests alone, and the `SlowDown` answer
only as the error behind it, never as the response a client sees.

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
* A client part under the pass-through provider, read whole with no bound, lets one authenticated
  client end the process with one large part. The cost is not one part in memory but three and a
  half times the part, because a buffer that collects a body of unknown length doubles and copies
  as it fills.

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

**D3.** The part size is inferred from the largest part seen in the session that could be a
*middle* part — whole segments, and at least the backend's minimum part size. A short last part is
by definition not the part size, and a client that puts all its parts in flight at once — which
every uploader does — regularly delivers it first. For the same reason a held part takes its offset
at Complete rather than on arrival. The check in D2 is what makes the inference safe, because a
wrong inference produces a refusal, never a stored object.

**D4.** The authenticated trailer is uploaded as one extra part when the client's last part could be
a middle part — whole segments and at least 5 MiB. Otherwise that part is held and the trailer rides
on it. A client-driven upload has 9999 usable part numbers either way, not 10000. Under the
pass-through provider all 10000 remain, because there the backend owns the part layout and nothing
of the proxy's is written behind the client's last part.

**D5.** A client part that cannot be a middle part — one that does not cover whole segments, or that
is below the backend's 5 MiB minimum — is held as plaintext in the session and sealed at Complete
under its own part number with the trailer appended. Two bounds make that buffer finite:

* At most one held part per session. A second part that cannot be a middle part can never complete,
  so it is refused with `EntityTooSmall` at upload time — not at Complete. The upload itself
  survives the refusal: the client can still send a part that fits, or abort.
* Across all sessions, buffered short-part bytes are capped by
  `optimizations.multipart_short_part_buffer_size` — bytes, default 64 MiB, at least 5 MiB, the
  backend's minimum part size, checked at startup. A part that does not fit beside what other
  uploads hold right now answers `SlowDown` (503), which SDKs retry with backoff; the session stays
  open. A part larger than the whole cap answers `400 EntityTooLarge` and is refused before its
  body is read, because no other upload finishing can make room for it and a 503 would have the SDK
  retry it to its own attempt limit. The cap is a configuration key because it is memory the
  operator sizes against the container limit: a proxy that serves one application with a known
  number of concurrent uploads is sized for that number, and a cap the operator cannot lower
  reaches the out-of-memory kill before it reaches `SlowDown`. The buffer is short-lived — it
  exists from the arrival of a held last part until the client completes or aborts the upload — so
  the default covers a dozen sessions parking a typical unaligned tail of a few MiB at once, while
  one session parking a maximal one exhausts it.
* The cap bounds every part this process holds, not only the ones a session holds. A
  pass-through part whose plaintext length the request declares is forwarded to the backend while
  it arrives and is never held. One whose length the request does not declare has to be buffered
  to be sized, and it is buffered against this same budget although no session owns it: claimed
  before the body is read, refused above the whole cap with `400 EntityTooLarge`, answered
  `SlowDown` while other holders have it, and given back when the bytes are gone. A bound per
  request instead would let N concurrent requests hold N times the number the operator sized
  against the container limit, which is the failure this bound exists to prevent.

**D6.** Complete is built from the proxy's own part table, never from the ETags in the client's XML —
those ETags describe ciphertext the proxy produced, and a trailer re-upload makes one of them stale.
The client's document is still parsed and its part set is checked against the table; a mismatch is
`InvalidPart`. `ListParts` is answered from the same table.

**D7.** When the proxy drives the upload it picks its own parts: an upload whose plaintext length the
client does not declare, or whose plaintext exceeds `optimizations.multipart_part_size`, is sent
to the backend as a multipart upload with parts of that size. `optimizations.multipart_part_size`
must be a multiple of the segment size or the proxy refuses to start. The trailer rides the last
part the proxy builds, so this path spends no extra part number. The key's name says what one of
its two jobs is — the size of one backend part — and not the format's own 64 KiB segment, which it
is a multiple of and never equal to; its second job, the plaintext size above which a single PUT
stops being one request and becomes a multipart upload, is documented rather than named.

**D8.** A multipart completion is final. Every metadata value is known before the first backend byte
is sent and is set at `CreateMultipartUpload`, so the proxy never rewrites the finished object to
attach metadata.

**D9.** Server-side copy is refused: a `PUT` carrying `x-amz-copy-source` and `UploadPartCopy`
answer `422 NotSupportedWithEncryption`, under every provider, the pass-through provider included —
one behaviour on the API surface beats a provider-dependent branch. The proxy does not forward such
a request, and does not silently produce an object it cannot read back.

**D10.** A client that needs an object under a second name re-uploads it through the proxy. Producing
a correct copy would mean fetching, decrypting and re-encrypting the source; that is not implemented
and is not owed by this decision.

## Consequences

* A client that copies inside a bucket — `aws s3 mv`, a sync that prefers copy over re-upload, a
  backup tool that promotes an object by copying it — fails with a refusal instead of degrading.
  Re-uploading through the proxy costs a full round trip of the object in both directions.
* The refusal is a hard stop at a point where S3 offers a cheap operation. This is the part of the
  decision nobody likes, and it is deliberate: a copy that produced an unreadable object is worse.
* A backend-side copy without re-encryption is impossible by construction under the name binding
  of ADR 0003 D4 — any binding a copy could keep is one a swap could keep too — so the only route
  to a copy is the proxy-side one named under Alternatives: fetch, decrypt, re-encrypt under the
  new name, streaming, for both copy verbs. It is an additive feature, built when a client needs it.
* The part rule holds for every uploader checked with its default settings, so ordinary clients are
  unaffected. A client whose parts could each be a middle part — whole segments, at least 5 MiB —
  but are not uniform fails at Complete, after all bytes have been transferred, which is late and
  expensive; a client whose parts cannot be middle parts is refused at the second of them, or at the
  first when that part alone exceeds the budget. Neither is ever a silent corruption.
* One part number is spent on the trailer, and a client-driven upload costs one extra backend
  request. An upload whose last part has to be held pays a re-upload of that part instead —
  up to one part size for an ordinary uploader, up to the whole budget for one whose parts are far
  from segment-aligned.
* The proxy holds one such part per session and the configured cap across all of them — 64 MiB
  by default — as buffered plaintext, sealed only at Complete. Under that pressure clients see
  `SlowDown` and retry rather than fail, and a client that keeps sessions open without completing
  them is throttled, not fed. The cap is one term of the memory budget an operator sizes a pod
  with (ADR 0020). It is a resource bound, not a security control.
* A pass-through part whose length is declared costs the proxy almost no memory: a 256 MiB part
  grows the heap by about half a megabyte, measured.
* Session state — the part table — must live for the whole upload and is client-controlled in
  number; only an idle expiry and the global cap bound it.
* A deployment whose `optimizations.multipart_part_size` is not a multiple of the segment size, or
  whose configuration still names `optimizations.streaming_segment_size`, does not start. That is
  deliberate — a silent fixup would produce parts the read path cannot verify — and it is an
  upgrade step the release notes name.
* Without the post-completion rewrite there is no 5 GiB ceiling, write amplification is halved,
  an upload leaves one object version, and the entity headers and the ETag are not rewritten
  behind the client's back.
* Complete is a check that can refuse, and aborting the upload on refusal means the transferred
  bytes are discarded rather than left as an orphan.
* `ListParts` describes the upload truthfully, and `ListMultipartUploads` is forwarded to the
  backend: it names uploads rather than bytes, so nothing in it has to be converted, and the
  document is the proxy's own.

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
afterwards means re-encrypting it, which means buffering a full-size part per session
unconditionally, where only a part that cannot be a middle part is held now, plus more session
state.

**Buffer every short part and let Complete sort it out.** A client sending 1 MiB parts would have
the proxy hold all of them until Complete failed. Refusing the second short part at upload time
bounds the buffer at one part per session and reports the problem where the client can still act
on it.

**Fetch an uploaded part back from the backend rather than buffering it.** No S3 verb reads an
uploaded, uncommitted part, and part copy reads committed objects only.

**Attach the late-bound value after Complete by object tagging.** Considered as the cheaper
replacement for the self-copy: metadata-only, no size cap. It still needs a proxy-owned tag
namespace, an extra read-side request, and it leaves a crash window between the completion and the
tagging in which the stored object carries no encryption metadata. It is moot under the segment
chain, where nothing is late-bound.

**Forward server-side copy to the backend unchanged.** Cheap, and it writes ciphertext bound to the
source object key under a different name. The client is told the copy succeeded and finds out at the
next read that the object cannot be decrypted.

**Implement copy inside the proxy as fetch, decrypt, re-encrypt.** Correct, and it turns an
operation the client asked to happen inside the backend into a full transfer through the proxy in
both directions. It is a separate piece of work; nothing in the product needs it today, and the
refusal says so honestly.

**Forward server-side copy under the pass-through provider.** Rejected: one behaviour on the API
surface beats a provider-dependent branch (D9).

## Residual risks

* **The inference depends on sizes, not on arrival order.** It takes the largest part seen that
  could be a middle part, so a last part that is short or unaligned does not move it whenever it
  arrives. What is left is a last part that clears both bars and is still smaller than the part
  size, arriving before any full-size one: the offsets taken until a larger part arrives are then
  wrong. Complete catches it, because it checks every part against the offset its number implies.
  A violation is a clean `InvalidPart`, not a corrupt object.
* One SDK computes its part size as *object size / 10000 + 1* above roughly 48.8 GiB with its default
  settings, which is not segment-aligned. An unaligned part can only ever be an object's last one,
  so such an upload is refused before Complete — at its second part with `EntityTooSmall`, or at its
  first with `EntityTooLarge` once the computed part size passes
  `optimizations.multipart_short_part_buffer_size`. The failure comes early rather than after all
  bytes have been transferred, and the operator documentation must still tell clients to configure
  an aligned part size for objects that large.
* The default of 64 MiB for the short-part cap is a sizing judgement — a dozen sessions parking a
  typical unaligned tail of a few MiB, one session parking a maximal one exhausting it, and
  comfortably above what the end-to-end backup client opens — and it is checked by that suite, not
  derived from a measurement of real client concurrency.
* **The copy refusal also binds an operator migrating out.** Under the exit provider (ADR 0025),
  a supported way out, both verbs are still refused before any provider is consulted, so an
  operator migrating out cannot copy inside the backend either — not even the plain objects written
  since the switch, for which a copy would be safe.
* `NotSupportedWithEncryption` and the 422 status are the proxy's own, not codes AWS defines. How
  clients surface them was not verified.
* **Both copy refusals are exercised over the wire**, each against a real backend and each
  asserting the `422` and the code. The object copy also asserts that no object exists at the
  destination key afterwards. What is unasserted is the part copy's residue: no test asks the
  backend directly whether the refused `UploadPartCopy` left a part on the open upload (see
  ADR 0019).
* The memory bounds in D5 are asserted by an automated test, not by a one-off measurement. The
  client-driven part path has before/after throughput numbers, recorded against ADR 0024, which
  owns that measurement. They measure the change that made a part forward while it is received,
  not D1's own change — no run isolates the effect of one client part becoming one independent
  backend part, and it landed together with the format change (see ADR 0020).
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
* ADR 0025 — Leaving is a supported mode
* [docs/operations/s3-api.md](../operations/s3-api.md) — the copy refusals and the multipart part sizes
* [docs/operations/upgrading.md](../operations/upgrading.md) — the migration note for the major release
* [docs/security/refusals.md](../security/refusals.md) — why an operation refuses instead of
  pretending; [docs/security/threat-model.md](../security/threat-model.md) — what the backend is
  trusted with
