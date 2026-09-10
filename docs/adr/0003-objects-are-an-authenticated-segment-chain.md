# ADR 0003: Objects are stored as an authenticated segment chain

## Status

**Accepted.** Date: 2026-09-07.

**Decided and specified; not implemented.** It lands with the next major release, **5.0.0**.
What ships today is the format this decision replaces: a whole-object `aes-gcm` form for small
objects and an `aes-ctr` form plus a whole-object HMAC for everything else, with integrity
selected by `encryption.integrity_verification` (`off`, `lax`, `strict`, `hybrid`). In that
format no mode refuses a tampered `aes-ctr` download, a ranged read is not authenticated by the
proxy at all, and an object carrying no proxy metadata is served to the client as plaintext even
under an encrypting provider. Those are the defects this ADR closes by construction. Until 5.0.0
is out, the shipped proxy must not be described as fit for an untrusted backend, whatever the
integrity setting says.

**Amended 2026-09-07**, before implementation: D13 adds a sealed plaintext checksum to the
format. It was weighed as part of the same release rather than left for later, because
adding it afterwards would be a second format break.

**Amended 2026-09-09**, before implementation: the checksum moves from the metadata set into the
trailer, because a value that exists only at the end of the stream cannot sit in metadata that
every write path sends before the first body byte. D2, D6, D9, D12a and D13 change accordingly,
D13a is withdrawn, and D14 adds how the value is served: on a whole-object `GET` and on `HEAD`,
without a configuration key, and not on a ranged read.

## Context

The backend is hostile: it can read, alter, reorder, truncate, substitute and roll back anything
it stores, and it can lie in metadata and in listings (ADR 0001). Two consequences drive this
decision. Integrity means *the proxy* verifies — "authenticated by TLS and by the backend" is not
integrity when the backend is the adversary. And a control that exists only in configuration or
in documentation is worse than no control, because it gets relied upon.

The shipped format fails both, and it fails them for ordinary clients rather than in a corner:

- **A ranged read cannot be verified.** The whole-object HMAC covers the whole object, so a
  partial read is checked against nothing. Clients that read their data with small ranged GETs —
  kopia, which is what Velero uses for volume data, is the concrete case — perform entire restores
  out of reads the proxy does not authenticate.
- **Integrity is separable from decryption.** It lives in its own metadata key, so a backend that
  removes that one key switches verification off. That downgrade works in every mode, `strict`
  included; `lax` additionally delivers data whose verification failed.
- **No mode refuses tampered data on the `aes-ctr` path.** The verifying reader releases the
  plaintext before it verifies, and it is not constructed at all when the backend answers without
  a `Content-Length`. The mismatch exists only as a log line.
- **A missing metadata set is read as "not encrypted".** The proxy hands the body through as
  plaintext under an encrypting provider, so stripping the metadata and substituting the body is
  an unsignalled content injection.
- **Two ciphers, two guarantees, one product.** `aes-gcm` objects are bound to their object key
  and authenticated by their tag; `aes-ctr` objects are bound to nothing and authenticated by a
  metadata key. Which one an object got depended on its size and on configuration, so the
  guarantee an operator had was not one they could state.

Only a format in which every stored byte is authenticated at a granularity a ranged read can use
keeps both properties: partial reads for any S3 client, and integrity that does not depend on a
setting.

## Decision

**D1.** An object is stored as a chain of plaintext segments, each sealed with **AES-256-GCM**
under one per-object data key (ADR 0002), followed by an authenticated trailer. The format is
identified by the fixed string **`s3ep-gcm-seg-v2`**, written to the `s3ep-dek-algorithm`
metadata key.

**D2.** The segment size is **65536 bytes of plaintext** and is a **constant of the format, not a
configuration value**. Each segment costs 28 bytes on the wire (a 12-byte nonce and a 16-byte
tag), 0.043 %, plus a 40-byte trailer per object: a nonce, the sealed length and checksum, and a
tag.

**D3.** Each segment carries its **own random 96-bit nonce, inline**. Nonces are never derived
from a segment counter or an object prefix.

**D4.** Every seal in the object binds the same associated data: the format id, the
**client-visible object key** (no bucket), and an 8-byte big-endian index — the plaintext offset
divided by the segment size for a segment, an all-ones value for the trailer. The fixed-length
prefix and suffix around the one variable field make the encoding unambiguous.

**D5.** **The bucket is not in the associated data.** The bucket name plays no part in encryption
or decryption, so a ciphertext bucket can be replicated, copied or renamed without re-encryption.

**D6** (amended 2026-09-09). The trailer authenticates the **total plaintext length** and the
**CRC32C of the whole plaintext** (D13), sealed together. A whole-object read verifies every
segment *and* the trailer, and checks the trailer's length and checksum against the bytes it
produced before it releases the last segment, so truncation or extension at any segment boundary
is detected, and so is a fault in the proxy's own assembly of verified plaintext.

**D7.** **Integrity is not configurable.** There is no integrity mode, no separate integrity
metadata key, and no opt-out: a byte that is not authenticated is not served.
`encryption.integrity_verification` and `optimizations.streaming_threshold` do not exist (ADR
0013). `s3ep-aes-iv` and `s3ep-hmac` leave the metadata set (ADR 0009).

**D8.** A segment is verified against its own index before its plaintext is released. A segment
that fails its tag, or whose index does not match the position it was fetched from, is an error;
if the response is already in flight, the body is aborted mid-stream.

**D9** (amended 2026-09-09). A ranged read fetches **only the segments the range covers** — one
contiguous backend request, at most one segment of over-read at each end, plus the trailer when
the range reaches the end of the object, so backend traffic is bounded at twice the segment size
plus their framing and the trailer above the bytes returned: 2·65536 + 2·28 + 40 bytes. No range
costs a second backend request, and no range is served unverified.

**D10.** Under an encrypting provider, an object that carries no proxy metadata, or whose
`s3ep-dek-algorithm` is not `s3ep-gcm-seg-v2`, is **refused** on GET, HEAD and ranged GET with
`InvalidObjectState`, **HTTP 403**, message *Object is not encrypted by this proxy*. Only the
`none` provider passes objects through, and it passes everything through. A bucket holding
pre-existing plaintext is never read in place and is not migrated (ADR 0001 D5, amended
2026-09-09): its content is uploaded through the proxy from the source.

**D10a** (amended 2026-09-10). An object whose **wrapped data key does not authenticate** gets
the same answer: `InvalidObjectState`, **HTTP 403**, message *Object key material failed
authentication*. The object names this format and carries a full metadata set, so it is not the
foreign object of D10 — but the state is equally permanent, and reporting it as a server fault
had two costs. A client SDK retries a 5xx to the end of its retry budget on a read that cannot
succeed, which turns one request into several against the backend that caused it; and a client
that treats 5xx as transient files a corrupted object as a passing outage and never reports the
corruption. Under ADR 0001 the party that can produce this state is the backend, so neither cost
may be left to it to decide. The distinction is drawn only for a wrap that fails its
authentication tag — a genuinely transient failure, such as a KMS that cannot be reached, stays a
5xx, because there a retry is the right thing to do.

**D11.** All three write paths — a single PUT, a proxy-driven multipart upload for a large or
unbounded body, and a client-driven multipart upload — produce the **identical byte layout**. The
data key, the wrapped key and the complete metadata set exist before the first backend byte is
sent, so no object is rewritten after completion to attach late metadata.

**D12.** The plaintext length is a **pure function of the stored length**, so it is reported
without a per-object round trip (ADR 0010). That function converts what the backend reports; the
trailer is the authenticated copy and is what integrity rests on.

**D12a** (amended 2026-09-08). The two formulas of D12 answer for **any** stored length,
including lengths no writer can produce. The backend is the adversary and reports the stored
length freely: with the 40-byte trailer of D2, `C = 68` yields `n = 1, P = 0` and `C = 65605`
yields `n = 2, P = 65509` — both plausible, both unreachable. The size function therefore carries a well-formedness guard that
rejects a length no chain can have: `P >= 0` and, with `n` segments, `n == 0 && P == 0` or
`(n-1)·S < P <= n·S`. Verified exhaustively over `P = 0 .. 5·S+5` plus 12 MiB and 1 GiB, on
2026-09-08 for the 36-byte trailer and again on 2026-09-09 for the 40-byte one: the guard agrees
with reachability at every length, and the round trip is exact. This is not a
security control — the trailer is what authenticates the length — but a rejected length is a
`500`, not a fabricated size served in a `HEAD`.

**D13** (amended 2026-09-09). The trailer carries a **CRC32C over the whole plaintext, sealed
with the length under the object's data key** — never in the clear, because a cleartext checksum
of a small object is a guessing oracle for the backend. It is written on every write path; on a
client-driven multipart upload it is folded from per-part values at completion, a re-uploaded part
replacing its own term. It protects nothing the segment seals already protect; it exists so that a
fault in **the proxy's own** assembly of verified plaintext — a dropped byte at a segment
boundary, a reused buffer, an off-by-one — is caught, which no seal in this format can do, because
such a fault happens after verification. The proxy checks it itself on every whole-object read
(D6), and it serves the value to the client (D14, ADR 0012). The value is a detector for
accidental faults, not a cryptographic integrity value, and it does not have to be one: the seal
around it is. It lives in the trailer and not in the metadata because metadata is sent before the
first body byte on every write path, and the checksum exists only after the last.

**D13a** (amended 2026-09-08, **withdrawn 2026-09-09**). Superseded: with the checksum inside
the trailer there is no second seal to separate, and the trailer's all-ones index of D4 covers
both values. The rule is kept in place so that the reserved index is not reintroduced from an
older copy. As it stood: the checksum seal binds its own reserved AAD index,
**`0xFFFFFFFFFFFFFFFE`** — the trailer's all-ones index minus one, one more unreachable value at
the top of the range (a 5 TiB object reaches segment index 2^26.3). Without a distinct index the
checksum seal and the trailer seal share the same AAD under the same key, and only their differing
lengths (a 4-byte CRC32C against an 8-byte length) keep a backend from swapping the two sealed
blobs. That length difference is a real barrier today but an accidental one: a later checksum of 8
bytes would make the two blobs interchangeable, and the separation would vanish in a change that
looks unrelated to it. The reserved index puts the separation in the AAD, where D4 already keeps
the separation of every other seal in the object. There is no live attack this closes in the
absence of it; the index is domain separation stated where the rest of the domain separation
lives, at the cost of one named constant.

**D14** (added 2026-09-09). The checksum is served as `x-amz-checksum-crc32c` on a whole-object
`GET` and on `HEAD`, and there is no configuration key for it: the proxy's own check is not
optional (D7), and the echo to the client is measured before it is ever made optional (ADR 0012,
ADR 0020). It is served without a per-object round trip wherever the object allows it. `HEAD` is
answered from one ranged backend read of the object's last 40 bytes, which carries the metadata,
the stored length and the trailer, so `HEAD` reports the authenticated plaintext length and the
checksum from a single request. A whole-object `GET` reads the last 65604 bytes first — one
segment with its framing plus the trailer; when that covers the whole object, which is every
object of at most one segment, it is the only backend request. Otherwise the remainder is fetched
with a second request carrying `If-Match` on the entity tag of the first, so an object replaced
between the two answers `412` before any body byte, and the held tail is appended to the stream.
Every stored byte is fetched exactly once. A ranged read carries no checksum (ADR 0012); the read
path is built so that a checksum over a bounded range can be added later without a format change,
and it is not built now.

## Consequences

- **Every object written by an earlier release becomes unreadable.** There is no read-only path
  for the old format and no in-place migration: data is re-uploaded through the new proxy. This
  is the cost the major release exists to pay (ADR 0017).
- **Tiny ranged reads amplify.** A 512-byte read costs a 64 KiB segment fetch — 128×. Clients
  that read in kilobyte-sized ranges pay it, and no segment cache is added to soften it.
- **A whole-object read above one segment costs two backend requests**, one after the other: the
  tail first, then the remainder under `If-Match`. Each byte is fetched once. Objects of one
  segment or less, every `HEAD` and every ranged read stay at one request. The price is one
  backend round trip per large whole-object read, which the transfer of at least 64 KiB dwarfs;
  it is measured, not assumed (ADR 0020).
- **The checksum pass is not free, and its price is now measured rather than estimated.** CRC32C
  costs about 0.73 of the AES-GCM pass per byte. In the implemented codec that is the difference
  between **4452 MiB/s with the checksum and 8706 MiB/s without it**, both measured in the same
  run: the segment chain is 1.74× the path it replaces as implemented, where the cipher alone
  would be 3.40×. Confirmed by the owner
  on 2026-09-10 with those numbers in hand: **the checksum stays.** Integrity is the reason this
  format exists, the change is still a speed-up rather than a cost, and a checksum added after
  the format ships would be a second format break. What it does *not* buy is end-to-end
  throughput: the crypto is a few percent of the proxy's per-byte upload time either way.
- **The segment size cannot be tuned.** An operator with an unusual read pattern has no knob, by
  design: making it configurable would make the nonce bound and the stored layout depend on
  configuration.
- **Operators lose the ability to turn integrity off.** Every read pays authentication. That is
  the point, but it removes a lever some deployment will eventually want.
- **`optimizations.streaming_segment_size` must be a multiple of 64 KiB.** A deployment whose
  value is not aligned fails to start rather than being silently rounded.
- **The trailer collides with S3's 5 MiB part minimum in client-driven multipart.** Appending it
  as an extra part turns the client's last part into a middle part, and a short middle part is
  refused with `EntityTooSmall`. The proxy therefore keeps a last part below 5 MiB in memory and
  re-uploads it with the trailer attached. The bounds on that buffer, and the refusals that
  enforce them, are ADR 0011.
- **Clients get 9999 usable parts, not 10000** — one is reserved for the trailer. A visible
  deviation from S3, documented as such.
- **A failure after the first byte is a truncated body, not an error document.** A proxy that has
  already answered 200 cannot un-answer it.
- **Buckets that mix proxy objects with foreign objects stop working for readers**, loudly and
  intentionally.
- **What it buys.** One cipher and one code path instead of two of each; the post-completion
  object rewrite disappears, and with it the hard failure it caused above 5 GiB; segments are
  independent, so upload parts no longer have to be encrypted in sequence; and a re-uploaded part
  is safe, because fresh random nonces at the same plaintext offsets are not key-stream reuse.
- **Other format-visible changes ride the same release** — the key-encryption-key identifier and
  the wrapped-key layout (ADR 0004) — because a second change after 5.0.0 would be a second
  migration.

## Alternatives Considered

- **Keep the current format and document its limits.** Rejected: it makes the guarantee a
  property of a configuration value the backend can strip, which is the failure this decision
  exists to remove.
- **Keep AES-CTR and add per-segment HMAC tags.** Reaches the same property and costs more: two
  primitives instead of one, and the slower one does the integrity work — CTR followed by
  HMAC-SHA256 is two passes where AES-GCM on AES-NI or PMULL is one. The layout work is identical
  and nothing simplifies.
- **Refuse ranged reads of integrity-protected objects.** Correct on paper, and it breaks every
  client that reads ranges — volume restores through kopia become impossible. It would also make
  the guarantee hold only in a configuration that differed from the examples the project ships.
- **Serve a range by decrypting the whole object.** Correct and pathological: a 32-byte read of a
  20 MiB blob costs 20 MiB of backend traffic and a full decrypt, on every read.
- **Derived per-segment nonces (the Tink AES-GCM-HKDF streaming construction).** It assumes a
  single sequential writer. S3 multipart is not that: a part can be uploaded again with different
  content, and an SDK retry after a half-received request is normal. A derived nonce is then
  reused with a different plaintext, which costs the confidentiality of both plaintexts and the
  authentication key for that object.
- **XChaCha20-Poly1305**, which is random-nonce-safe by design. Roughly two to four times slower
  than hardware AES-GCM at this segment size, for a margin the random 96-bit nonce already gives.
- **Store a per-object part layout instead of fixing the geometry.** Three homes were weighed —
  attaching it after completion by a server-side self-copy, storing it in object tags, or reading
  it from the trailer before every ranged read. The first is the full-object rewrite this decision
  deletes; the second is new machinery on both sides; the third is either an extra round trip per
  range or a cache that must hold against a backend that changes the object underneath it. State
  that exists only to describe the object is state the backend can lie about.
- **Drop the trailer and flag the last segment in its associated data.** Does not dissolve the
  short-part problem: in a client-driven upload the proxy learns which part is last only at
  completion, so flagging it means re-encrypting it, which means buffering a full-size part per
  session instead of a short one.
- **Put the bucket, or a configured per-deployment label, into the associated data.** The bucket
  closes the cross-bucket swap but makes every bucket copy, rename or disaster-recovery
  replication a re-encryption. A configured label is one more value the stored format depends on,
  where a mislabel makes a whole bucket unreadable.
- **The checksum in the metadata set**, as D13 first said. Not implementable: metadata is sent
  before the first body byte on every write path, `CompleteMultipartUpload` accepts none, and the
  only late-metadata mechanism is the self-copy this decision deletes.
- **Keep the self-copy only to attach the checksum.** Resurrects the rewrite of every multipart
  object and its 5 GiB failure (ADR 0011).
- **No checksum at all.** Zero cost, and the earlier recommendation of this document. Rejected
  because the format is written once and a checksum added later is a second format break, while
  the difference to carrying one is four bytes in the trailer and one CRC pass.
- **A cryptographic hash instead of CRC32C.** SHA-256 costs about 2.5 times the AES-GCM pass per
  byte and cannot be combined across parts that arrive out of order or are uploaded again, so a
  client-driven upload would need per-segment state until completion — gigabytes for the largest
  objects — or a tree construction of its own. CRC-64 in the standard library is software only,
  slower than SHA-256, and as linear as CRC32C. The seal supplies the cryptographic protection;
  the value inside it only has to detect accidental faults, which is what a CRC is for.
- **Two parallel backend requests on every whole-object read**, trailer and body at once. No
  added latency, but every read of a small object costs two requests, which is where request
  count hurts most. The tail-first read keeps small objects at one request.
- **A configuration key for the client-facing checksum.** Rejected for now: a key exists only
  when a measured cost needs it (ADR 0013, ADR 0020), and adding one later with the shipped
  behaviour as its default breaks nothing.

## Residual risks

- **Rollback and same-key cross-bucket substitution stay undefended.** No AEAD prevents a backend
  from serving an older version of the same key, and with the bucket out of the associated data it
  can also serve one bucket's object under the same key in another bucket wrapped by the same key
  encryption key. Accepted. The mitigations are one key encryption key per deployment, backend
  versioning and object lock where available, and the client's own consistency checks.
- **Partly measured 2026-09-10, and the expectation was too optimistic in one direction and
  irrelevant in another.** The cipher does beat AES-CTR plus SHA-256: the shipped codec runs at
  1.74× the path it replaces, where the primitive alone would be 3.4× — the checksum takes the
  difference. What the expectation missed is that **the cipher is not what the upload ratio pays
  for.** Measured against a direct backend, a proxy on the streaming write path is at or above
  the backend, while the proxy-driven multipart producer is at 57–70 %. At the smallest measured size the gap is
  about 34 milliseconds, of which the integrity pass is under 8 % and the post-completion rewrite
  about 5 %; removing both is worth roughly an eighth of the deficit. What carries the rest has
  not been attributed — it is a property of the write path rather than of the format, and this
  decision does not govern it. Whether the format change improves upload throughput at the edge
  therefore depends on choices in the handlers it rewrites, not on the cipher. Whole-object throughput, small-object throughput, ranged-read throughput with its
  backend byte amplification, and a hard resident-memory bound are the gate before this ships
  (ADR 0020); a regression stops the change rather than being explained afterwards.
- **Read amplification is not yet quantified** against a real read mix; the benchmark that would
  do it does not exist yet.
- **Settled 2026-09-09: the format carries the sealed plaintext checksum**, in the trailer (D13).
  What remains is what it does not cover, below.
- **Splicing two sealed versions of a re-uploaded part is a 32-bit hurdle, not a proof.** A part
  uploaded again with different content before completion leaves two validly sealed versions of
  the same segments with a hostile backend, which can serve any mix of them on a whole-object
  read: the segment-granular form of the rollback accepted above. The sealed checksum turns the
  mix into a guess with one chance in 2^32 per attempt, each failure an aborted body. An adversary
  who knows both plaintext versions can solve the linear CRC given more than 32 exchangeable
  segments. Accepted: it needs a hostile backend, both plaintexts and a client that re-sends a
  part with other bytes, which SDK retries do not do.
- **Ranged reads carry no client-verifiable checksum.** Every byte of a ranged read is verified
  against the backend by the proxy; a fault in the proxy's own slicing is pinned by boundary tests
  and by the client's own layer where it has one. A checksum over a bounded range would need no
  format change — its plaintext assembled from verified segments before the headers are written —
  and the read path must not preclude it. Deferred, because the examined SDK validates a response
  checksum only on a `200`, never on a `206`, so nothing in scope would check it.
- **Two requests can see two versions.** The tail and the remainder of a whole-object read are
  separate backend requests. `If-Match` on the second turns a change in between into a `412`, and
  the trailer's length and checksum catch whatever a lying backend serves regardless. Not a new
  exposure; stated so the two-request read is not mistaken for one.
- **Verified 2026-09-10:** the backend the suite runs against answers a suffix range larger than
  the object with `206` and the whole object, carrying a content range that states the real
  length. A range whose end lies past the object is clamped the same way, and a range starting at
  or past the end is `416`. The read path still handles `200` as well, because that is the
  backend's behaviour and not the format's.
- **The primitive cost of the checksum pass is measured; its end-to-end cost is not.** ADR 0020
  governs; a regression stops the change.
- **The buffer the trailer forces is bounded by a guess, not by a measurement.** It is a resource
  limit rather than a security control, and the bound and its open questions are ADR 0011.
- **The random-nonce bound holds only while the segment size is a constant.** 2^32 segments per
  data key at 64 KiB is 256 TiB in one object, far past S3's 5 TiB object limit — safe by
  construction, and it would have to be rechecked if the segment size ever became configurable.
- **A client-driven upload whose parts are not aligned to the format is refused at completion**
  rather than corrupted; the rule and the uploaders it was checked against are ADR 0011.
- **Not verified:** the claim that object tagging is unsupported by several S3-compatible targets,
  which was one argument against storing a part layout in tags. The alternative loses on the other
  arguments regardless.
- **Unit-level coverage of the request handlers that carry this format is thin**, so the change is
  carried almost entirely by the integration and end-to-end suites (ADR 0019).

## References

- ADR 0001 — The S3 backend is hostile, and only the proxy's own verification counts
- ADR 0002 — One data key per object, wrapped by a configured key encryption key
- ADR 0004 — One local key provider: 256 random bits, an authenticated wrap, no passphrases
- ADR 0009 — The metadata prefix is the proxy's namespace
- ADR 0010 — Sizes and listings describe the plaintext
- ADR 0011 — The proxy owns the part layout it writes, and refuses copies it cannot re-encrypt
- ADR 0012 — Client-supplied checksums are verified against the plaintext and never forwarded
- ADR 0013 — A configuration key exists only if code reads it, and an unworkable configuration
  refuses to start
- ADR 0017 — Stored data compatibility is not owed; a major release may break the format
- ADR 0019 — Integration and end-to-end tests are the product; they are never skipped
- ADR 0020 — Performance is measured before and after, never asserted
- [README.md](../../README.md) — user-facing reference: ranged reads, the error the proxy answers
  for a foreign object, the storage overhead, and the migration procedure
- [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md) — threat model, what the stored
  format guarantees, and the residual risks above from the operator's side
