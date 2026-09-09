# ADR 0012: Client-supplied checksums are verified against the plaintext and never forwarded

## Status

**Accepted.** Date: 2026-09-07.

Implemented today: the proxy accepts `Content-MD5`, `x-amz-checksum-*` and the aws-chunked
checksum trailer, and discards all of them. The forwarding defect is fixed — no client checksum
value reaches the backend on any write path any more. No backend checksum reaches a client on any
read path either; that half was never a live defect, only dead value copying no response path ever
emitted, and it is removed.

Decided and specified, **not implemented**: the verification itself, the trailer capture and the
`BadDigest` / `InvalidDigest` answers. It is scheduled for the next major release (5.0.0), after
the storage-format change, because the new error answers are client-visible and belong in one set
of release notes; that placement was settled on 2026-09-07, together with the decision that the
proxy serves its own plaintext checksum back on a whole-object read (D10).

**Amended 2026-09-09**, twice. The served value is the checksum sealed in the object's trailer
(ADR 0003 D13, D14), the header has no configuration key, and a ranged read carries none, for the
reason under Residual risks. And the split between an always-verified and an opt-in family is
withdrawn before it was built: **every checksum a client declares is verified**, whatever its
algorithm, and the `encryption.verify_upload_digests` key of the first version of this record does
not exist (D3 widened, D4 struck, D14 added for the multi-object delete). Until 5.0.0 a client's
integrity intent on the upload leg is silently dropped, which is the state this ADR exists to end.

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

The cost picture is asymmetric and drove the one compromise, withdrawn on 2026-09-09 (D3, D4). A cyclic redundancy check runs on
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

**D3** (amended 2026-09-09). **Every checksum the client declares is verified, unconditionally**:
`x-amz-checksum-crc32` (CRC-32/IEEE), `x-amz-checksum-crc32c` (CRC-32C), `x-amz-checksum-crc64nvme`
(CRC-64/NVME), `x-amz-checksum-sha1`, `x-amz-checksum-sha256` and `Content-MD5`, whether the value
arrives as a request header or as an aws-chunked trailer. There is no configuration key: the
client chooses the algorithm and with it the cost; the proxy either honours the declaration or
drops it, and dropping it behind a success answer is the pattern ADR 0007 forbids everywhere
else. A control that exists only in configuration is worse than none, and here there is nothing
to trade.

**D4** (struck 2026-09-09). ~~The cryptographic digests — `Content-MD5`, `x-amz-checksum-sha1`
and `x-amz-checksum-sha256` — are verified only when `encryption.verify_upload_digests` is true.
Its default is **false**, because verifying them costs a second full pass over every upload.~~
Withdrawn before it was built; D3 covers these algorithms. The cost that motivated the key is
real and was measured on 2026-09-09: MD5 has no hardware instruction on either supported
architecture and costs about ten times the AES-GCM pass per byte; SHA-1 and SHA-256 cost about
two and a half times where the hardware accelerates them, and fall into MD5's class where it does
not. That cost is the client's choice, and it is stated as a table in the user-facing reference
instead of being gated.

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
the plaintext on a whole-object read — a CRC32C computed at upload and stored sealed in the
object's trailer under its data key (ADR 0003 D13) — as `x-amz-checksum-crc32c` on a whole-object
`GET` and on `HEAD`, served as ADR 0003 D14 describes and with no configuration key. A ranged read
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

**D13** (amended 2026-09-09). A verified cyclic redundancy check is documented as a
**transmission-corruption check, not an integrity guarantee**, in the same breath as the control
itself, in the security architecture and in the user-facing reference. The user-facing reference
also carries the measured cost per algorithm, so that an operator whose client sends `Content-MD5`
knows what that choice costs on the proxy.

**D14** (added 2026-09-09). The multi-object delete must carry a body digest, as it must on S3: a
request without any verifiable digest — no `Content-MD5` and no `x-amz-checksum-*` — is refused
with `400 InvalidRequest`, and the digest it carries is verified against the raw body before the
document is parsed, with D6's answers on failure. The body is a few kilobytes and the operation is
destructive, so there is no cost argument and every reason for the check.

## Consequences

- **The defect that was probed is closed, because there is no default to hide behind.** The
  failure was found with `Content-MD5`, which is what the affected uploader sends; that client's
  leg is verified like every other, and what it costs is that client's choice, stated in the cost
  table.
- **No configuration key**, in the direction ADR 0013 points. The one this record first proposed
  was withdrawn on 2026-09-09 before it was built, once the primitive costs were measured and
  "verify what the client declares" turned out to be what ADR 0007 already requires.
- **Cost when nothing is declared is zero**, and a request that declares one algorithm pays exactly
  one pass over the payload. A request that declares a CRC must not move the upload throughput
  figure measurably; anything beyond noise is a finding. A request that declares MD5 pays about
  ten times the encryption pass per byte, on that request alone, and the figure is published
  rather than gated (ADR 0020).
- **The cost lands on the operator's processor for a choice the client made.** That is true of
  everything the proxy does per byte. The lever is the client's configuration: the AWS SDK sends
  CRC32 by default, and other clients can be told to send a CRC or nothing. Which clients offer
  that lever was not surveyed.
- **Clients lose values real S3 returns**: no checksum echo on the write response, no object
  checksum on read. Neither examined SDK reads either; other clients are unverified.
- **More requests fail than before**, by design. A client that was sending a wrong or malformed
  checksum and getting `200` now gets `400`, on paths where the same request already failed against
  the backend directly.
- **New behaviour needs new tests, on both transports.** The trailer framing that carries a checksum
  only appears over TLS, so the plain-HTTP suite alone cannot cover this (ADR 0019).

## Alternatives Considered

**Verify every algorithm unconditionally.** The clean rule, and the one an operator would expect.
First rejected on throughput — a second full cryptographic pass on every uploaded byte, to protect
a leg whose adversary is outside the threat model — in favour of a split with an opt-in key.
**Adopted on 2026-09-09**, before the key was built: the pass is paid only by a client that
declares such a digest, which is that client's choice; the primitive costs were measured rather
than assumed; and the split contradicted ADR 0007, since a digest accepted and not checked behind
a `200` is accept-and-discard. The rejected alternative is now the split itself.

**Keep the key with a default of on.** The same verification by default, plus an operator escape
hatch for a processor-bound deployment. Rejected in favour of no key: the escape hatch would turn
a client's declared check into accept-and-discard, and the lever that costs nothing is on the
client side.

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

- **Settled 2026-09-09: the multi-object delete digest is always required and always verified
  (D14).** What the backend answers to a request that omits it was not verified against AWS or
  the backend the suite runs against; the proxy's own `InvalidRequest` is what is promised.
- **Settled 2026-09-07: the proxy does serve a checksum of its own over the plaintext** on a
  whole-object read (D10). The residual is what it does not cover: a ranged read gets no checksum,
  the value proves nothing about a client that does not check it, and most clients with their own
  integrity layer will ignore it. It was taken now rather than later because the storage format is
  written exactly once and a field added afterwards is a second format break.
- **Deferred: a checksum over a ranged response.** Possible without a format change for a bounded
  range, whose plaintext would be assembled from verified segments before the headers are written.
  Not built, because the examined SDK validates a response checksum only on a `200` and never on a
  `206`, so a value on a ranged response would be checked by no client in scope; the read path is
  kept open for it.
- **Accepted: a cyclic redundancy check catches transmission corruption, not deliberate
  modification.** Nothing in this decision claims otherwise, and the security architecture must say
  so next to the control or the control gets over-trusted.
- **Accepted: a client that sends `Content-MD5` pays about ten times the encryption pass per byte
  on the proxy, for that request.** Measured on one machine on 2026-09-09; the end-to-end figure on
  the backup-client path is recorded when the verification ships, as a published number, not as a
  gate.
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
- [README.md](../../README.md) — user-facing reference; it gains the statement that every
  declared checksum is verified, and the measured cost per algorithm, when the verification ships
- [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md) — the client leg, what is verified on
  it and what is not
