# ADR 0032: The entity tag is a change token, never a content digest, and its shape says so

## Status

**Accepted.** Date: 2026-09-13.

**Implemented 2026-09-13, the same day it was decided.** Every answer and every inverse
below is in the tree, and both client suites now meet every target they state — rclone 28
of 28, s3cmd 19 of 19, from fifteen and nine before the marker. The unit, integration and
conformance suites are green, the last of them driving the inverse end to end: a client
sends back the tag a metadata request gave it and receives `304`.

The workaround the read cases carried for the single-request upload is gone with the
defect, which is the other half of that number: those cases now place their object with
the client's defaults, so a regression on the write side breaks them too.

Two questions this decision creates are open and named under *Residual risks*: what
replaces the end-to-end digest s3cmd loses, and what the marker costs in per-object
requests.

This closes the question ADR 0010 D12 left open — *"making it describe the plaintext is a
storage-format question, not a listing question, and is not decided here"* — by answering it
in the negative. D12's deviation does not survive; it is replaced by the rule here.

## Context

An HTTP entity tag is an opaque change token. It has one defined job, `If-Match` and
`If-None-Match`: equal bytes carry equal tags, different bytes carry different ones. What the
string contains is nobody's business.

S3 made it more than that by convention. A single-request upload answers the MD5 of the object
content — thirty-two lower-case hex digits in quotes — and a completed multipart upload answers
`md5(md5(part₁) ‖ … ‖ part_N) -N`, a different value in a different shape whose trailing `-N`
is the signal *this is not a content digest*. The convention is written in no specification, and
every S3 client relies on it anyway.

This proxy stores a segment chain under a random per-object data key. The backend's entity tag
is therefore the MD5 of nonces, ciphertext, authentication tags and a sealed trailer, and the
same plaintext uploaded twice produces two different tags. That much is unavoidable and would be
harmless.

**What is not harmless is the shape.** Thirty-two hex digits in quotes states *I am the MD5 of
this object's content*, and a client that does not know it is talking to an encrypting proxy has
no way to learn otherwise. Two named clients act on that statement and lose data or refuse work
because of it:

- rclone verifies a single-request upload by comparing its own file MD5 with the entity tag,
  reports `corrupted on transfer`, and **deletes the object it just uploaded**. Its own test for
  an MD5-shaped tag is a thirty-two-hex-digit match; its escape hatches are set from its own
  encryption configuration or a compiled-in per-provider quirk table, neither of which this
  proxy can reach.
- s3cmd compares the tag against a local digest at six sites, with no length test and no hex
  test. Its only escape is a hyphen anywhere in the string. Without one it can upload nothing
  below `optimizations.streaming_segment_size` and no explicit multipart upload at all.

Both are the same defect seen twice: the proxy makes a claim it cannot keep. Eight candidate
answers were costed against two end-to-end suites; the analysis is summarised under
*Alternatives Considered*.

The question underneath them is not which string to answer. It is whether this product owes a
client a content digest in the entity tag at all — and it does not. It seals a CRC32C of the
whole plaintext into every object and answers it as `x-amz-checksum-crc32c` on a whole-object
`GET` and on `HEAD` (ADR 0003 D13, D14). That is a digest the proxy computes itself, over the
bytes the client actually receives, and it is stronger evidence than an entity tag can be. The
entity tag goes back to being what HTTP says it is.

## Decision

**D1** The entity tag this proxy answers is a change token. It is never a digest of the object's
content, and no client may treat it as one. Content verification is `x-amz-checksum-crc32c`, the
proxy's own sealed CRC32C over the whole plaintext, and the per-request checksums of ADR 0012 —
never the entity tag.

**D2** Under an encrypting provider, an entity tag whose value is exactly thirty-two hexadecimal
digits is answered with the suffix `-0` inside the quotes. Any other shape passes unchanged,
`<hex>-N` from a multipart completion included. This is the whole of the change: the value is not
replaced, the shape is corrected so it stops making a claim the proxy cannot keep.

**D3** The marker is answered at **object level and at part level**. Object level is every verb
that states an object's entity tag: a single-request upload, a completed multipart upload, a
whole-object read, a ranged read, a metadata request, and both object listings. Part level is
every verb that states a part's entity tag. Object level alone is not a decision that can be
taken: a client that drives its own multipart upload judges the answer part by part and never
sees an object-level tag, so half the marker leaves such a client unable to upload at all.

**D4** The marker is invertible, and the proxy inverts it. Every entity tag a client sends back
is unmarked before it is used or forwarded: the `If-Match` and `If-None-Match` headers, which may
carry a list of tags and may carry `*`, and the part list of a multipart completion. A client
that returns exactly what it was given revalidates and completes exactly as it would without the
marker.

**D5** The inverse rule is driven by shape, never by trimming a trailing `-0`. A tag is unmarked
only when removing `-0` leaves exactly thirty-two hexadecimal digits. This proxy already answers
entity tags of its own that end in `-0` legitimately — a held zero-length part is one — and a
trim rule would corrupt them.

**D6** `-0` is the marker because it stays inside the grammar every S3 client already parses,
`<hex>-<number>`, and because S3 cannot produce it: a completed multipart upload has at least one
part. A marker a real object could wear would not be invertible, which rules out `-1`. A suffix
outside the grammar was measured and rejected: the clients that matter have no path for it.

**D7** Under the exit provider nothing is marked, on any verb. There the stored bytes are the
plaintext and the backend's entity tag is the truth about them, which is the same reason its
sizes pass through unmarked (ADR 0025).

**D8** This is a compatibility correction, not an honesty correction, and it is documented as
one. The proxy stops making a false claim; it does not yet describe itself. The marked value is
still a decorated backend value rather than something the proxy computed, which is what ADR 0008
D13 asks of a header describing the stored object. It does not conflict with ADR 0008 D12
either: `-0` is not a zero value standing in for a value the proxy does not have, it is a shape
that removes a false promise while staying invertible.

**D9** The multipart formula is not honoured and is documented as a limit under ADR 0006 D2. A
multipart object answers the backend's `<hex>-N` over the stored parts, so a client that
recomputes the formula over its own plaintext parts sees a mismatch. Closing that would require
storing a plaintext composite, which is D10.

The limit is stated where a user meets it — the client's own configuration section in
`README.md` carries the one setting it asks for and the reason — and the suite states it as a
target rather than carrying it as a failure: the case that drives a client's defaults asserts the
refusal, and the cases that drive the documented setting assert the upload. That case turns red
the day an upstream client ships a provider entry for this endpoint, which is the day the limit
can be lifted rather than a regression.

**D10** A plaintext digest sealed in the object is refused for this release and is the only route
by which the entity tag could ever become a content digest again. It would cost a six-fold
slower seal — MD5 has no hardware instruction where CRC32C and SHA-2 do — it is structurally
impossible over the whole plaintext on the client-driven multipart path, where parts arrive in
any order and may be re-uploaded, and it would make the entity tag a value the client chooses in
full and the proxy then evaluates preconditions against. Today's tag cannot be predicted, chosen
or collided by a client, and D1 is what makes keeping that property free.

## Consequences

- **A client that verifies uploads by entity tag stops verifying them.** That is the mechanism by
  which this fixes anything, and for one of the two named clients it is a real loss: s3cmd sends
  no `Content-MD5` on an object body, so after the marker its uploads succeed with no end-to-end
  digest anywhere rather than being refused because the only digest disagreed. Over TLS the
  record MAC covers the wire; over the plain listener nothing does. See *Residual risks*.
- **Two clients fall back to per-object requests.** A listing no longer looks like a digest
  source, so a sweep asks per object instead of trusting the listing. On this proxy each such ask
  is an authenticated object read, and the data-key cache is finite, so a sweep over a large
  bucket can turn one listing into a full miss stream that also evicts entries serving real
  reads. Unmeasured, and named under *Residual risks*.
- **Some clients now rely on a client-written plaintext digest in object metadata.** Both named
  clients store one — under their own metadata keys, in the clear, beside the ciphertext — and
  fall back to it once the entity tag is not a digest. Under ADR 0001 that value is written by
  the client and readable and writable by the adversary, so a comparison against it proves
  nothing about the stored object. This reliance predates the marker; the marker widens it.
- Clients that treat the entity tag opaquely — the AWS SDKs and CLI, Velero, kopia, Barman — see
  a different string and nothing else.
- The cost on the wire is one shape test per answered tag and one per precondition header. There
  is no per-byte cost, which is the whole reason this answer beats every alternative that
  computes something.
- An object this proxy did not write is marked too when it appears in a listing under an
  encrypting provider. It is refused on every read anyway (ADR 0003), so the marker describes a
  tag no client can act on.

## Alternatives Considered

- **Leave it and document the client flags.** Turns nothing green. Its only lever is upstream: a
  per-provider quirk entry in rclone, which one provider already carries for exactly this reason.
  That would close every rclone case at no cost to this product and closes none of s3cmd's, and
  it is an upstream release cycle rather than a decision this project can take.
- **Object-level marker only.** Half the answer: a client that drives its own multipart upload
  never sees an object-level tag, so it can upload nothing below the streaming ceiling. This is
  why D3 covers part level.
- **Omit the entity tag under an encrypting provider.** Measured dead. One client substitutes an
  empty string and fails the same comparison, with a source comment reading *force re-upload*; in
  a listing the absent element crashes it outright.
- **A tag outside the `<hex>-<number>` grammar** — a prefix, base64, a longer hex string.
  Measured dead for the same client: it has exactly one escape, a hyphen, with no length or hex
  test anywhere. Such a tag fixes none of its cases and breaks three that pass today.
- **Write every object as a backend multipart upload**, so every tag is natively `<hex>-N`.
  Measured: 3.2× on a one-kilobyte write, to change the shape of a string. Its one genuine
  advantage is that the value stays a real backend entity tag, invented nowhere.
- **Answer the plaintext MD5 and a plaintext multipart composite, sealed in the object.** The
  only candidate that closes the last open client case, and it is D10's refusal: it buys two
  end-to-end cases over the marker, for a storage format change, a new precondition evaluator, a
  six-fold slower seal and a security regression the marker does not have. If it is ever wanted
  it is a major release with a format break, which ADR 0017 already permits and prescribes a
  procedure for.

## Residual risks

- **s3cmd loses its only end-to-end digest, and what replaces it is not decided.** Two
  complements were proposed and neither is chosen: verifying `x-amz-content-sha256` against the
  decoded body where a client declares a real payload hash, which would give that client a
  stronger check than it had before the marker; and serving `x-amz-checksum-crc32c` on the verbs
  that lack it — an upload, a part upload, a completion, a ranged read — where the value is
  already computed. The second moves no client case and is worth doing anyway, because it is the
  only integrity channel this proxy can vouch for itself.
- **The per-object request cost of the marker is unmeasured.** It is the one axis on which this
  decision can lose, and it was asserted in both directions during the analysis. What settles it
  is a request count, not a wall clock: a bucket of a thousand small objects, a sweep with each
  named client, backend requests counted before and after. It decides whether the marker needs a
  mitigation, such as a larger data-key cache — not whether the marker ships.
- **The last open client case is closed by no proxy-side value of any shape.** One client builds
  its expected tag from the MD5s of its own plaintext parts and compares the whole string against
  the tag of a post-upload metadata request; the parts this proxy stores are ciphertext. It is a
  reporting gap and not an integrity gap: every part that client sends carries a `Content-MD5`
  that this proxy verifies against the decoded plaintext before a byte reaches the backend
  (ADR 0012), and the ordering and completeness the composite would prove are what the segment
  associated data and the sealed trailer already enforce.
- **No backend in the conformance set has been asserted never to answer `-0`.** D5's shape rule
  makes the inverse safe regardless, but the premise that `-0` cannot arrive from outside is
  worth pinning where backends are compared (ADR 0027).
- **The unit test layer would pass a broken implementation.** The entity-tag fixtures in the unit
  tests are names rather than digests, so a forward map keyed on the thirty-two-hex shape never
  fires against them. Real fixtures are needed per emission site and per internal pin, or a
  marker wrongly applied to an internal precondition would not be caught.

## References

- ADR 0003 — Objects are an authenticated segment chain, and the trailer seals the plaintext CRC32C
- ADR 0006 — The proxy serves any S3 client; an undocumented deviation is a defect
- ADR 0008 — Every response describes the proxy, never the backend
- ADR 0010 — Sizes and listings describe the plaintext; D12 is closed by this ADR
- ADR 0012 — Client-supplied checksums are verified against the plaintext and never forwarded
- ADR 0017 — Stored data compatibility is not owed, and how a format break is run
- ADR 0025 — Leaving is a supported mode: the exit provider changes no value it did not write
- [README.md](../../README.md) — S3 API behaviour worth knowing
