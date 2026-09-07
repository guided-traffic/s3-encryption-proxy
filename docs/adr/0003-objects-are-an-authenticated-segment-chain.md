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
metadata set. It was weighed as part of the same release rather than left for later, because
adding it afterwards would be a second format break.

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
tag), 0.043 %, plus a 36-byte trailer per object.

**D3.** Each segment carries its **own random 96-bit nonce, inline**. Nonces are never derived
from a segment counter or an object prefix.

**D4.** Every seal in the object binds the same associated data: the format id, the
**client-visible object key** (no bucket), and an 8-byte big-endian index — the plaintext offset
divided by the segment size for a segment, an all-ones value for the trailer. The fixed-length
prefix and suffix around the one variable field make the encoding unambiguous.

**D5.** **The bucket is not in the associated data.** The bucket name plays no part in encryption
or decryption, so a ciphertext bucket can be replicated, copied or renamed without re-encryption.

**D6.** The trailer authenticates the **total plaintext length**. A whole-object read verifies
every segment *and* the trailer and checks the trailer's length against the bytes it produced,
so truncation or extension at any segment boundary is detected.

**D7.** **Integrity is not configurable.** There is no integrity mode, no separate integrity
metadata key, and no opt-out: a byte that is not authenticated is not served.
`encryption.integrity_verification` and `optimizations.streaming_threshold` do not exist (ADR
0013). `s3ep-aes-iv` and `s3ep-hmac` leave the metadata set (ADR 0009).

**D8.** A segment is verified against its own index before its plaintext is released. A segment
that fails its tag, or whose index does not match the position it was fetched from, is an error;
if the response is already in flight, the body is aborted mid-stream.

**D9.** A ranged read fetches **only the segments the range covers** — one contiguous backend
request, at most one segment of over-read at each end, so backend traffic is bounded at twice the
segment size above the bytes returned. No range costs a second backend request, and no range is
served unverified.

**D10.** Under an encrypting provider, an object that carries no proxy metadata, or whose
`s3ep-dek-algorithm` is not `s3ep-gcm-seg-v2`, is **refused** on GET, HEAD and ranged GET with
`InvalidObjectState`, **HTTP 403**, message *Object is not encrypted by this proxy*. Only the
`none` provider passes objects through, and it passes everything through. A bucket holding
pre-existing plaintext is migrated **through** the proxy by a documented procedure, never read in
place.

**D11.** All three write paths — a single PUT, a proxy-driven multipart upload for a large or
unbounded body, and a client-driven multipart upload — produce the **identical byte layout**. The
data key, the wrapped key and the complete metadata set exist before the first backend byte is
sent, so no object is rewritten after completion to attach late metadata.

**D12.** The plaintext length is a **pure function of the stored length**, so it is reported
without a per-object round trip (ADR 0010). That function converts what the backend reports; the
trailer is the authenticated copy and is what integrity rests on.

**D13.** The metadata set carries a **CRC32C over the whole plaintext, sealed under the object's
data key** — never in the clear, because a cleartext checksum of a small object is a guessing
oracle for the backend. It is written on every write path and served back to the client on a
whole-object read (ADR 0012). It is not part of the segment chain and protects nothing the
segment seals already protect; it exists so that a client can detect a fault in **the proxy's
own** assembly of verified plaintext — a dropped byte at a segment boundary, a reused buffer, an
off-by-one — which no seal in this format can catch, because such a fault happens after
verification. It lives in the metadata rather than in the trailer because a response header has
to be written before the body, and the trailer is only read at the end of the object.

## Consequences

- **Every object written by an earlier release becomes unreadable.** There is no read-only path
  for the old format and no in-place migration: data is re-uploaded through the new proxy. This
  is the cost the major release exists to pay (ADR 0017).
- **Tiny ranged reads amplify.** A 512-byte read costs a 64 KiB segment fetch — 128×. Clients
  that read in kilobyte-sized ranges pay it, and no segment cache is added to soften it.
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

## Residual risks

- **Rollback and same-key cross-bucket substitution stay undefended.** No AEAD prevents a backend
  from serving an older version of the same key, and with the bucket out of the associated data it
  can also serve one bucket's object under the same key in another bucket wrapped by the same key
  encryption key. Accepted. The mitigations are one key encryption key per deployment, backend
  versioning and object lock where available, and the client's own consistency checks.
- **Performance is a well-argued expectation, not a measurement.** One GHASH-accelerated pass
  should beat AES-CTR plus a SHA-256 pass, and removing the post-completion rewrite and the
  sequential encryption is a pure gain — but per-segment setup at 64 KiB, 28 extra bytes per
  segment on the wire, and the loss of the in-place stream-cipher XOR all cut the other way.
  Unverified. Whole-object throughput, small-object throughput, ranged-read throughput with its
  backend byte amplification, and a hard resident-memory bound are the gate before this ships
  (ADR 0020); a regression stops the change rather than being explained afterwards.
- **Read amplification is not yet quantified** against a real read mix; the benchmark that would
  do it does not exist yet.
- **Open, not decided: whether the format carries an encrypted plaintext checksum** to catch the
  proxy's own reassembly bugs, which no segment tag can. The recommendation on the table is not to
  carry one, since it can be added later as an additional metadata key — additive for the proxy's
  own reader rather than a second format break — but no decision has been taken. See ADR 0012 for
  what happens to client-supplied checksums.
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
