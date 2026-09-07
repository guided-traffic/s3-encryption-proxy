# ADR 0012: Client-supplied checksums are verified against the plaintext and never forwarded

## Status

**Accepted.** Date: 2026-09-07.

Implemented today: the proxy accepts `Content-MD5`, `x-amz-checksum-*` and the aws-chunked
checksum trailer, and discards all of them. The forwarding defect is fixed — no client checksum
value reaches the backend on any write path any more. No backend checksum reaches a client on any
read path either; that half was never a live defect, only dead value copying no response path ever
emitted, and it is removed.

Decided and specified, **not implemented**: the verification itself, the trailer capture, the
`BadDigest` / `InvalidDigest` answers and the `encryption.verify_upload_digests` key. It is
scheduled for the next major release (5.0.0), after the storage-format change, because the new
error answers are client-visible and belong in one set of release notes; that placement was
settled on 2026-09-07, together with the decision that the proxy serves its own plaintext
checksum back on a whole-object read (D10). Until then a client's integrity intent on the
upload leg is silently dropped, which is the state this ADR exists to end. One question in this
family is still open and is listed under [Residual risks](#residual-risks).

## Context

The backend is hostile (ADR 0001) and everything the proxy stores is defended by its own key layer
and object integrity (ADR 0003). Nothing defends the **client-to-proxy leg**, and that is the last
place where the plaintext exists. A byte corrupted before the proxy encrypts is encrypted
faithfully, authenticated faithfully, and from then on indistinguishable from correct data: every
integrity mechanism the product has confirms the corruption. The upload checksum the client already
computed is the only check that can catch this, and it is the only one the proxy runs on that leg —
the per-chunk signatures of an aws-chunked upload stay unverified for the reasons recorded in
ADR 0014.

Three concrete failures made the decision necessary:

1. **The trailer is read and thrown away.** Current AWS SDK clients frame a CRC-32 checksum as an
   aws-chunked trailer by default. The proxy parses the trailer block and drops it.
2. **A wrong digest was answered `200`.** A deliberately wrong `Content-MD5` was accepted on the
   small-object and the internally split multipart paths, probed at 2 MiB and 8 MiB. The backend
   answers `400` to the same request when addressed directly. One widely used backup uploader sets
   a `Content-MD5` on every blob it writes, so its integrity intent was dropped for all of its data.
3. **The client digest was forwarded with the ciphertext.** Two write paths passed the client's
   `Content-MD5` to the backend together with the encrypted body it does not describe, and a third
   asked the backend for a SHA-256 over a document the proxy re-serialises merely because the client
   had sent a digest. Asking the backend to check a digest of a plaintext it never receives is
   incoherent at best. This half is fixed.

The cost picture is asymmetric and drives the one compromise. A cyclic redundancy check runs on
dedicated instructions on both supported architectures and rides along in the buffer the reader
already holds. A second full MD5 or SHA pass does not, and on a bulk-upload client it is paid on
every byte to protect a leg whose adversary is deliberately outside this threat model.

## Decision

**D1** The proxy verifies a client-supplied upload checksum against the **plaintext payload it
received** — aws-chunked framing stripped, before encryption. Ciphertext is never hashed for a
client checksum, and framing bytes are never part of the hashed payload.

**D2** Verification applies to every request that carries a body, on every write path: the direct
single-object write, the streaming write, the multipart upload the proxy splits internally, the
client-driven part upload, the bucket configuration writes, and the multi-object delete.

**D3** The cyclic-redundancy families — `x-amz-checksum-crc32` (CRC-32/IEEE),
`x-amz-checksum-crc32c` (CRC-32C) and `x-amz-checksum-crc64nvme` (CRC-64/NVME) — are verified
**unconditionally**, whether the value arrives as a request header or as an aws-chunked trailer.
They get no configuration key: a control that exists only in configuration is worse than none, and
here there is nothing to trade.

**D4** The cryptographic digests — `Content-MD5`, `x-amz-checksum-sha1` and
`x-amz-checksum-sha256` — are verified only when `encryption.verify_upload_digests` is true.
Its default is **false**, because verifying them costs a second full pass over every upload.

**D5** A checksum named in `X-Amz-Trailer` that never arrives is a **failed** verification, not an
absent one. Otherwise omitting the trailer is a free opt-out from the check the client asked for.
`x-amz-trailer-signature` is not a checksum and is not verified.

**D6** A mismatch answers `400 BadDigest`. A value that is not valid base64, or that decodes to the
wrong length for its algorithm, answers `400 InvalidDigest`. Both are proper S3 error documents; a
checksum verdict is never reported as an internal error.

**D7** The verdict lands **before anything is committed**: on a failure nothing is stored, no part
reaches the backend, and no multipart upload is left behind for a client to discover and clean up.

**D8** No client checksum value is ever sent to the backend — not the value the proxy verified, not
one it declined to verify, and not an algorithm choice derived from the client having sent a digest
at all. A digest that is present but not verified is dropped.

**D9** No checksum of the plaintext is ever written to object metadata. A plaintext checksum sitting
in cleartext next to the ciphertext hands the backend a confirmation oracle: for a small or
low-entropy object it can guess a candidate plaintext offline and confirm it against a few bytes of
checksum.

**D10** The proxy never relays the backend's checksum: that value describes ciphertext and is
meaningless to a client that receives plaintext (ADR 0008). It does serve **its own** checksum over
the plaintext on a whole-object read — a CRC32C computed at upload and stored sealed under the
object's data key (ADR 0003) — as `x-amz-checksum-crc32c` on `GET` and `HEAD`. A ranged read
carries none: the value covers the whole object and there is nothing honest to say about a slice.
On a write response the proxy returns no checksum of its own.

**D10a** That returned value is the client's end-to-end check on the read leg, and it is the only
control that can catch a fault in the proxy's own assembly of already-verified plaintext. It is
never computed from what the proxy is about to send — it is the value recorded at upload — because
a checksum computed over the same buffer that may be corrupt proves nothing.

**D11** The comparison is a plain byte comparison. No secret is involved on either side — the client
knows the plaintext it just sent — so constant-time comparison buys nothing and is not used.

**D12** An upload is checked against the length the client declared. A body that ends early is a
failed request, never a committed short object: a client that hangs up mid-upload must not leave a
truncated object behind that then verifies as intact. This is independent of any checksum the
client may or may not have sent, and it is the reason the stored format carries an authenticated
length of its own (ADR 0003).

**D13** A verified cyclic redundancy check is documented as a **transmission-corruption check, not
an integrity guarantee**, in the same breath as the control itself, in the security architecture and
in the user-facing reference. Both documents also state plainly that the default configuration does
**not** verify a client that sends only `Content-MD5`.

## Consequences

- **The default does not close the defect that was probed.** The failure was found with
  `Content-MD5`, which is what the affected uploader sends and the one family behind the switch. At
  the default that client's leg is unverified: the digest is no longer forwarded to a backend that
  cannot check it, but it is not checked here either. This is a conscious trade, and it has to be
  written out rather than left for an operator to infer from "verification is on by default".
- **A second configuration key exists where the direction of travel is fewer of them** (ADR 0013).
  It earns its place only because the cost it gates is measured, not assumed.
- **Cost when nothing is declared is zero**, and a request that declares one algorithm pays exactly
  one pass over the payload. The always-on family must not move the upload throughput figure
  measurably; anything beyond noise is a finding, not a cost of doing business (ADR 0020).
- **The switch is conservative in one direction.** MD5 has no hardware instruction on either
  supported architecture, while SHA-1 and SHA-256 do. If measurement shows the SHA family costing
  materially less than MD5, the honest follow-up is splitting the families, not flipping the
  default.
- **Clients lose values real S3 returns**: no checksum echo on the write response, no object
  checksum on read. Neither examined SDK reads either; other clients are unverified.
- **More requests fail than before**, by design. A client that was sending a wrong or malformed
  checksum and getting `200` now gets `400`, on paths where the same request already failed against
  the backend directly.
- **New behaviour needs new tests, on both transports.** The trailer framing that carries a checksum
  only appears over TLS, so the plain-HTTP suite alone cannot cover this (ADR 0019).

## Alternatives Considered

**Verify every algorithm unconditionally.** The clean rule, and the one an operator would expect.
Lost on throughput: a second full cryptographic pass on every uploaded byte, paid permanently, to
protect a leg whose adversary is explicitly outside the threat model. Rejected in favour of the
split with the cost stated out loud.

**Verify nothing and keep forwarding the client checksum to the backend.** The status quo before
the fix. The backend is asked to validate a digest of a plaintext it never receives, so the check is
either a guaranteed failure or — as observed — quietly ineffective while the proxy answers `200`.
It also spends the client's integrity intent on the wrong leg.

**Store the plaintext checksum in object metadata so any later read can verify it.** Attractive
because it makes the check permanent rather than transient. Rejected: it is a confirmation oracle
for a hostile backend against small or low-entropy objects, which is precisely the adversary this
product is built for.

**Compute the hash inside the chunked-body decoder.** Cheapest to write, and wrong: it sees only
aws-chunked bodies and would miss every identity-framed request — the plain write carrying a
`Content-MD5`, the multi-object delete, the multipart completion — and would need a second copy of
the same logic for those.

**Compute the hash inside the encryption layer.** Rejected: it never runs under the pass-through
provider, so uploads through it would go unchecked, and the expected value would have to be threaded
through several provider layers that have no business knowing about HTTP headers.

**Echo the verified checksum on the write response, as real S3 does.** The value is already
computed, so this is small. It lost on evidence: neither examined SDK reads a write-response
checksum, and the value is the client's own number handed back. It stays available if a client that
needs it turns up.

**Verify the per-chunk signatures of an aws-chunked upload instead.** Real implementation cost for a
protection on the client leg, whose adversary is out of scope; the decision to leave them unverified
belongs to ADR 0014. Checksum verification buys most of the same practical benefit for far less.

## Residual risks

- **Open: whether the multi-object delete body digest is covered by the switch or always verified.**
  That operation mandates a body digest, so its presence is free and the throughput argument behind
  the default — which is about multi-MiB uploads — does not apply. The working answer is to verify it
  always and refuse a request that omits it, but this has not been settled and must not be
  implemented as though it had.
- **Settled 2026-09-07: the proxy does serve a checksum of its own over the plaintext** on a
  whole-object read (D10). The residual is what it does not cover: a ranged read gets no checksum,
  the value proves nothing about a client that does not check it, and most clients with their own
  integrity layer will ignore it. It was taken now rather than later because the storage format is
  written exactly once and a field added afterwards is a second format break.
- **Accepted: a cyclic redundancy check catches transmission corruption, not deliberate
  modification.** Nothing in this decision claims otherwise, and the security architecture must say
  so next to the control or the control gets over-trusted.
- **Accepted: at the default, a client that sends only `Content-MD5` is unverified.** Stated in the
  user-facing reference rather than left implicit.
- **Not verified: whether any S3 client sends `x-amz-checksum-crc64nvme` on upload.** The current AWS
  SDK default is CRC-32; the algorithm is implemented because the header exists, not because a
  measured client sends it.
- **Not verified: how a given backend answers a wrong trailer checksum, per algorithm.** The proxy
  promises `BadDigest` and `InvalidDigest` for its own verdicts; it does not promise to match a
  backend's error code for every algorithm, and no such agreement should be assumed when writing the
  tests.
- **Not verified: clients beyond the two SDKs examined**, for both the response-echo and the
  response-checksum questions.
- **Not covered by this decision:** the `ETag` a client receives is the backend's, computed over
  ciphertext, so a client following the convention that a single-part `ETag` is a digest of the
  content gets a value that does not match the body it was served. It is self-consistent across
  write, read and head, and no examined client verifies it, so it is left as is.

## References

- ADR 0001 — The S3 backend is hostile, and only the proxy's own verification counts
- ADR 0003 — Objects are stored as an authenticated segment chain
- ADR 0007 — Forward it or refuse it, never silently drop it
- ADR 0008 — Every response describes the proxy, never the backend
- ADR 0009 — The metadata prefix is the proxy's namespace
- ADR 0013 — A configuration key exists only if code reads it, and an unworkable configuration
  refuses to start
- ADR 0014 — Authentication is SigV4 on both forms; there is no rate limiting and no IP blocking
- ADR 0018 — A major release is declared by a label, never discovered at merge
- ADR 0019 — Integration and end-to-end tests are the product; they are never skipped
- ADR 0020 — Performance is measured before and after, never asserted
- [README.md](../../README.md) — user-facing reference; it gains the
  `encryption.verify_upload_digests` entry and the throughput trade it carries when the
  verification ships
- [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md) — the client leg, what is verified on
  it and what is not
