# ADR 0012: Client-supplied checksums are verified against the plaintext and never forwarded

## Status

**Accepted.** Date: 2026-09-13. **Implemented in full.**

Every checksum a client declares is verified against the plaintext payload — `Content-MD5`,
`x-amz-checksum-crc32`, `-crc32c`, `-crc64nvme`, `-sha1`, `-sha256`, `-sha512` and `-md5`;
each of those `x-amz-checksum-*` values whether it arrives as a request header or as an
aws-chunked trailer, `Content-MD5` as a header only — on every write path: the single-request
`PUT`, the multipart upload the proxy splits internally, the client-driven part upload, bucket
creation, every bucket and object sub-resource write that carries a body — the bucket
configuration, object tagging, retention and legal hold — and the multi-object delete. A
mismatch answers `400 BadDigest`, a value that is not a digest of its algorithm's length answers
`400 InvalidDigest`, and the multi-object delete refuses a request carrying no digest at all with
`400 InvalidRequest`. Any other header under `x-amz-checksum-` that carries a digest answers
`501 NotImplemented`. No client checksum value reaches the backend and none is written to object
metadata. The SigV4 payload hash is verified when `s3_security.verify_payload_hash` is on (D15).

A whole-object `GET` and a `HEAD` answer with `x-amz-checksum-crc32c` (D10), served by the
tail-first read (ADR 0003 D14): the value recorded at upload and sealed in the object's trailer,
never one computed from the bytes about to be sent. A ranged read carries none. There is no
configuration key. Under the `exit` provider neither verb carries the header, on any object.
That provider decides per object, and neither verb has opened a trailer when the headers are
written: the `GET` stays one forward pass, the `HEAD` reads metadata alone (ADR 0025).

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

1. **The trailer was read and thrown away.** Current AWS SDK clients frame a CRC-32 checksum as
   an aws-chunked trailer by default. The proxy parsed the trailer block and dropped it.
2. **A wrong digest was answered `200`.** A deliberately wrong `Content-MD5` was accepted on the
   small-object and the internally split multipart paths, probed at 2 MiB and 8 MiB. The backend
   answers `400` to the same request when addressed directly. One widely used backup uploader sets
   a `Content-MD5` on every blob it writes, so its integrity intent was dropped for all of its data.
3. **The client digest was forwarded with the ciphertext.** Two write paths passed the client's
   `Content-MD5` to the backend together with the encrypted body it does not describe, and a third
   asked the backend for a SHA-256 over a document the proxy re-serialises merely because the client
   had sent a digest. Asking the backend to check a digest of a plaintext it never receives is
   incoherent at best.

The cost picture is asymmetric. A cyclic redundancy check runs on dedicated instructions on both
supported architectures and rides along in the buffer the reader already holds. A second full MD5
or SHA pass does not, and on a bulk-upload client it is paid on every byte to protect a leg whose
adversary is deliberately outside this threat model. Who pays it is decided in D3: the client
that declares such a digest, and nobody else.

## Decision

**D1** The proxy verifies a client-supplied upload checksum against the **plaintext payload it
received** — aws-chunked framing stripped, before encryption. Ciphertext is never hashed for a
client checksum, and framing bytes are never part of the hashed payload. The framing is always
stripped, and no configuration changes that: verification covers only what the proxy actually
sees, so a setting that let it see chunk framing instead of the payload would leave a declared
checksum covering the wrong bytes and store framing as object content. A key whose one setting
corrupts data is worse than no key (ADR 0013).

**D2** Verification applies to every request that carries a body, on every write path: the
single-request `PUT`, the multipart upload the proxy splits internally, the client-driven part
upload, bucket creation, every bucket and object sub-resource write that carries a body — the
bucket configuration, object tagging, retention and legal hold — and the multi-object delete.

A body nothing reads is verified all the same. Verification rides on a reader, so a payload no
consumer pulls would be a payload no verdict covers; a zero-length `PUT`, to which the SDK attaches
no stream at all, and a bucket creation that declares no body length take the verdict directly. A
client that declared a digest and then sent nothing is precisely the fault the checksum exists to
catch.

**The completion document is exempt, and it is the only exemption.** On
`CompleteMultipartUpload` alone, `x-amz-checksum-*` is the digest of the **completed object**, not
of the request body, which is why the completion is not among the bodies listed above. Checking it
against the XML would answer `BadDigest` to a correct client. The proxy can neither verify that
value (the plaintext object it would have to hash is gone) nor forward it (the backend holds
ciphertext), so it is dropped; serving the proxy's own is D10.

**D3** **Every checksum the client declares is verified, unconditionally**:
`x-amz-checksum-crc32` (CRC-32/IEEE), `x-amz-checksum-crc32c` (CRC-32C),
`x-amz-checksum-crc64nvme` (CRC-64/NVME), `x-amz-checksum-sha1`, `x-amz-checksum-sha256`,
`x-amz-checksum-sha512`, `x-amz-checksum-md5` and `Content-MD5`. Each of those `x-amz-checksum-*`
values is verified whether it arrives as a request header or as an aws-chunked trailer;
`Content-MD5` is a header only, as the wire format defines it. There is no configuration key: the
client chooses the algorithm and with it the cost; the proxy either honours the declaration or
drops it, and dropping it behind a success answer is the pattern ADR 0007 forbids everywhere
else. A control that exists only in configuration is worse than none, and here there is nothing
to trade.

The cost is real and measured: MD5 has no hardware instruction on either supported architecture
and costs about ten times the AES-GCM pass per byte; SHA-1 and SHA-256 cost about two and a half
times where the hardware accelerates them, and fall into MD5's class where it does not. That cost
is the client's choice, and it is stated as a table in the user-facing reference instead of being
gated.

**An algorithm S3 defines and this proxy does not compute is refused, not dropped.** The pinned
SDK serializes `x-amz-checksum-xxhash3`, `-xxhash64` and `-xxhash128`, and none of them has a
standard-library hash, so without a new dependency they cannot be verified. Any header under
`x-amz-checksum-` that is not an implemented algorithm — and is not one of the three that carry no
digest, `-algorithm`, `-mode` and `-type` — answers `501 NotImplemented`. Accepting it behind a
`200` is the accept-and-discard ADR 0007 forbids, and the family is claimed as a whole so a future
algorithm cannot slip through as one. `x-amz-checksum-sha512` and `x-amz-checksum-md5` are
implemented, both from the standard library.

**D5** A checksum named in `X-Amz-Trailer` that never arrives is a **failed** verification, not an
absent one. Otherwise omitting the trailer is a free opt-out from the check the client asked for.
`x-amz-trailer-signature` is not a checksum and is not verified.

**The declaration drives the verification.** An aws-chunked trailer that arrives without being
named in `X-Amz-Trailer` is not verified: the declaration is how a client asks for the check, and
hashing every algorithm speculatively to catch an undeclared one would cost every upload.

**D6** A mismatch answers `400 BadDigest`. A value that is not valid base64, or that decodes to the
wrong length for its algorithm, answers `400 InvalidDigest`. Both are proper S3 error documents; a
checksum verdict is never reported as an internal error.

**D7** The verdict lands **before anything is committed**: on a failure **nothing is stored** —
no object, no part — and no multipart upload is left behind for a client to discover and clean up.
That last clause binds the whole multipart path, not only a checksum failure: a client-driven
completion whose backend call fails aborts the upload, because the proxy's part table is gone by
then and a retry could not rebuild it — leaving the upload would strand every part with nothing
able to finish or find it.

**The verdict is guaranteed by holding a byte back.** The verifying reader never releases the
final payload byte until it has a verdict, so a consumer streaming the body straight to the
backend cannot have delivered the complete payload while verification is still open. Without it
a pass-through write could have its body accepted by the backend before the mismatch is known.

What makes "nothing is stored" true depends on how far the payload got. Where a write forwards
while it receives — the single-request `PUT`, and a client part whose declared length covers whole
segments and clears the backend's minimum part size — the backend request is open long before the
payload ends; the held byte means that request can never deliver the Content-Length it promised, so
the backend refuses it and the object or the part does not come into existence. Where the proxy
holds the payload instead — every other part, among them a short last part, one whose length the
request does not really declare, and every part under the `exit` provider — the verdict lands
before any backend request for that part exists. And where an upload the proxy split internally
has already sent earlier parts, the abort removes them. Forwarding while receiving is what
ADR 0024 D1 requires, which is why the first case is the one that needs the held byte.

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

**Where no length was declared the check must come from the stream itself.** Only a clean end of
stream ends an object; a source that stopped early is a failed request. The two are not the same
error and must not be treated alike — a read that only reports "fewer bytes than were asked for"
gives the identical answer for the legitimate short last read and for a body whose framing ended
without its terminating chunk, and a proxy that trusts that answer commits the second as if it
were the first. The path with no declared length is exactly the one where nothing else can catch
it, and a truncated object sealed that way verifies against its own trailer on every later read.

**D13** A verified cyclic redundancy check is documented as a **transmission-corruption check, not
an integrity guarantee**, in the same breath as the control itself, in the security architecture
and in the user-facing reference. The user-facing reference also carries the measured cost per
algorithm, so that an operator whose client sends `Content-MD5` knows what that choice costs on the
proxy.

**D14** The multi-object delete must carry a body digest, as it must on S3: a request without any
verifiable digest — no `Content-MD5` and no `x-amz-checksum-*` — is refused with
`400 InvalidRequest`, and the digest it carries is verified against the raw body before the
document is parsed, with D6's answers on failure. The body is a few kilobytes and the operation is
destructive, so there is no cost argument and every reason for the check.

**D15** The SigV4 payload hash is a digest the proxy can verify, and whether it does is the
operator's to decide: `s3_security.verify_payload_hash`, **default `false`**. With it on, an
`x-amz-content-sha256` carrying a real hex digest is checked against the decoded body exactly like
a declared checksum, with D6's answers on failure.

It is a key and not a rule because of what makes it different from every other declaration this
ADR covers: **every signed client sends it.** A `Content-MD5` is a client choosing to be checked
and the cost lands on that client's uploads; the payload hash is present on essentially every
signed request, so verifying it is a SHA-256 pass over every upload the proxy accepts. That is a
per-byte cost on the most used verb the product has, against a threat model where the operator
may already have TLS on the client leg. Neither answer is right for every deployment, which is
what a configuration key is for.

What it buys is the client that declares nothing else. At least one supported client sends no
`Content-MD5` for an object body at all, so without this its uploads reach the backend with no
end-to-end digest anywhere — the entity tag is not one (ADR 0032), and the proxy takes the
payload hash as a signed claim in the canonical request without ever re-deriving it from the body.

Three things the key deliberately does not change:

* **It is skipped for an aws-chunked body**, where the header carries a `STREAMING-*` sentinel and
  the trailers are the declaration. A client cannot be refused for a hash it never claimed
  described the decoded payload.
* **A value that is not a digest is not a declaration.** `UNSIGNED-PAYLOAD` and anything that is
  not 64 hex characters is ignored rather than refused: what that header means to the signature is
  ADR 0014's subject, and this rule only looks at values that are digests.
* **It never satisfies D14.** A batch delete without a deliberate digest stays refused whatever
  this key says, or a refusal S3 defines would appear and disappear with a configuration value —
  and since every signed client sends a payload hash, counting it would retire that rule
  altogether.

With the key on and a client that declares a checksum of its own, both are verified. Skipping the
payload hash whenever something else already covers the body would save a pass, and it is
deliberately not done: the operator asked for the payload hash to be verified, and a rule that
silently decides it is redundant is one nobody can see in the answer.

## Consequences

- **There is no default to hide behind.** A client that sends `Content-MD5`, as the widely used
  backup uploader does on every blob, is verified like every other, and what it costs is that
  client's choice, stated in the cost table.
- **No configuration key for a declared checksum**, in the direction ADR 0013 points: with the
  primitive costs measured, "verify what the client declares" is what ADR 0007 already requires.
  The one key in this area, `s3_security.verify_payload_hash`, governs a digest every signed
  client sends whether or not it asked for a check (D15).
- **Cost when nothing is declared is zero**, and a request that declares one algorithm pays exactly
  one pass over the payload. A request that declares a CRC must not move the upload throughput
  figure measurably; anything beyond noise is a finding. A request that declares MD5 pays about
  ten times the encryption pass per byte, on that request alone, and the figure is published
  rather than gated (ADR 0020).
- **The cost lands on the operator's processor for a choice the client made.** That is true of
  everything the proxy does per byte. The lever is the client's configuration: the AWS SDK sends
  CRC32 by default, and other clients can be told to send a CRC or nothing. Which clients offer
  that lever was not surveyed.
- **Clients lose values real S3 returns**: no checksum echo on the write response, no checksum
  on a ranged read, and none on any read under the `exit` provider. A whole-object `GET` and a
  `HEAD` carry one otherwise (D10). Neither examined SDK reads a write-response checksum; other
  clients are unverified.
- **More requests fail**, by design. A client that sends a wrong or malformed checksum gets
  `400`, on paths where the same request fails against the backend directly.
- **New behaviour needs new tests, on both transports.** The trailer framing that carries a checksum
  only appears over TLS, so the plain-HTTP suite alone cannot cover this (ADR 0019).

## Alternatives Considered

**Verify the cyclic redundancy checks always and the cryptographic digests only behind an opt-in
key.** `Content-MD5`, `x-amz-checksum-sha1` and `x-amz-checksum-sha256` would be checked only when
an operator switches them on, with a default of off, because verifying them costs a second full
cryptographic pass on every uploaded byte to protect a leg whose adversary is outside the threat
model. Rejected: the pass is paid only by a client that declares such a digest, which is that
client's choice; the primitive costs are measured rather than assumed (D3); and a digest accepted
and not checked behind a `200` is the accept-and-discard ADR 0007 forbids.

**The same key with a default of on.** The same verification by default, plus an operator escape
hatch for a processor-bound deployment. Rejected in favour of no key: the escape hatch would turn
a client's declared check into accept-and-discard, and the lever that costs nothing is on the
client side.

**Verify nothing and forward the client checksum to the backend.** The backend is asked to validate
a digest of a plaintext it never receives, so the check is either a guaranteed failure or — as
observed — quietly ineffective while the proxy answers `200`. It also spends the client's integrity
intent on the wrong leg.

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

- **The multi-object delete is stricter than the backend (D14).** Measured against the backend:
  it answers `MissingContentMD5` to a request that omits the header, and `200` to one whose digest
  does not match the body — it checks only that the header is present. The proxy's own
  `InvalidRequest` and `BadDigest` are what is promised. Not verified against AWS itself.
- **What the proxy's own checksum over the plaintext does not cover** (D10): a ranged read gets no
  checksum, the value proves nothing about a client that does not check it, and most clients with
  their own integrity layer will ignore it. It is part of the stored format from the start because
  the format is written exactly once and a field added afterwards is a second format break.
- **Deferred: a checksum over a ranged response.** Possible without a format change for a bounded
  range, whose plaintext would be assembled from verified segments before the headers are written.
  Not built, because the examined SDK validates a response checksum only on a `200` and never on a
  `206`, so a value on a ranged response would be checked by no client in scope; the read path is
  kept open for it.
- **Accepted: "nothing is stored" rests on the backend refusing a short body.** Where a write
  forwards while it receives — the single-request `PUT`, and a client part the proxy forwards as it
  arrives — the proxy has already opened the backend request when the verdict arrives, and what
  keeps the payload from being stored is that the request cannot satisfy its own Content-Length. A
  backend that accepted a body shorter than the Content-Length it was given would store a part the
  digest refused. Measured against MinIO, which does not: a part of 8 MiB whose declared
  `Content-MD5` does not match is answered `400 BadDigest`, and a `ListParts` asked of the backend
  directly, not through the proxy, reports zero parts for that upload; the buffered path answers
  identically. For a part there is a second, proxy-side line: a streamed part is by
  construction a middle part, and `CompleteMultipartUpload` refuses a middle part whose length is
  not the part size the session inferred, so such an upload cannot become an object. Against a backend that both
  ignores Content-Length and is asked to complete anyway, the object's trailer would not
  authenticate what was stored and every read of it answers `403 InvalidObjectState` — wrong, but
  never silently wrong.
- **Accepted: a cyclic redundancy check catches transmission corruption, not deliberate
  modification.** Nothing in this decision claims otherwise, and the security architecture must say
  so next to the control or the control gets over-trusted.
- **Accepted: a client that sends `Content-MD5` pays about ten times the encryption pass per byte
  on the proxy, for that request.** Measured on one machine, 128 KiB blocks, one core: CRC32 12.1
  GB/s, CRC32C 12.1 GB/s, SHA-1 3.5 GB/s, SHA-256 3.4 GB/s, CRC64NVME 2.4 GB/s, MD5 0.94 GB/s.
  **End to end that is far smaller than the per-byte figure suggests**: over the development stack,
  15 repetitions at 8 MiB and at 20 MiB, every algorithm but MD5 was inseparable from an upload
  declaring nothing, and MD5 cost about three percent. The hash runs while the request is bound by
  the backend write, so most of its cost overlaps rather than adds. The per-byte table is what a
  processor-bound deployment should size against; the end-to-end figure is what a client sees.
- **Not verified: whether any S3 client sends `x-amz-checksum-crc64nvme` on upload.** The current AWS
  SDK default is CRC-32; the algorithm is implemented because the header exists, not because a
  measured client sends it.
- **Accepted: an aws-chunked trailer that arrives undeclared is not verified.** A client asks for
  the check by naming the trailer in `X-Amz-Trailer`, as the wire format requires. Catching an
  undeclared one would mean hashing every algorithm on every upload against the chance that one
  turns up.
- **Not verified: how a given backend answers a wrong client checksum, per algorithm.** Measured
  for one case: the backend answers a wrong `Content-MD5`, sent as a request header on
  a plain `PUT`, with `400 BadDigest`, the same as the proxy. The other seven algorithms were not
  compared. The proxy promises `BadDigest` and `InvalidDigest` for its own verdicts; it does not
  promise to match a backend's error code for every algorithm.
- **Not verified: clients beyond the two SDKs examined**, for both the response-echo and the
  response-checksum questions.
- **Not covered by this decision: the entity tag.** The backend's `ETag` is computed over
  ciphertext, so it is no digest of the content a client is served, and two clients with
  end-to-end suites, rclone and s3cmd, check it as one. What the proxy answers is decided by
  ADR 0032: a change token, never a content digest, shaped so that a client does not take it for
  one; content verification on the read leg is D10's checksum.

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
- [docs/operations/integrity.md](../operations/integrity.md) — every declared checksum is verified, and
  the measured cost per algorithm
- [docs/security/upload-integrity.md](../security/upload-integrity.md) — the client leg, what is
  verified on it and what is not
