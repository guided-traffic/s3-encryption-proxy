# Upload integrity: the client leg

What the proxy checks about the *payload* of a write, as opposed to
[the request that carries it](request-authentication.md).

Everything the proxy stores is defended by its own key layer and by the segment
chain's own tags. Nothing defends the **client-to-proxy leg**, and that leg is
the last place where the plaintext exists. A byte corrupted before the proxy
encrypts it is encrypted faithfully, authenticated faithfully, and from then on
indistinguishable from correct data: every integrity mechanism this product has
confirms the corruption. The checksum the client already computed is the only
check that can catch that, and it is the only one the proxy runs on that leg.

**What is checked.** Every checksum a client declares, against the decoded
plaintext payload, on every write path — `Content-MD5`, `x-amz-checksum-crc32`,
`-crc32c`, `-crc64nvme`, `-sha1`, `-sha256`, `-sha512` and `-md5`, as a request
header or as an aws-chunked trailer ([checksum.go](../../internal/proxy/request/checksum.go), wired
into both body readers at [parser.go](../../internal/proxy/request/parser.go)). A
mismatch is `400 BadDigest`, a value that is not a digest of its algorithm's
length is `400 InvalidDigest`, and a trailer named in `X-Amz-Trailer` that never
arrives is a failed verification rather than an absent one. `DeleteObjects`
requires a digest and verifies it before the document is parsed.

**The verdict precedes the commit.** The verifying reader holds the final payload
byte back until it has a verdict, so a consumer streaming the body straight to
the backend can never have delivered the complete payload while verification is
still open. On the internal multipart path the verdict is taken before
`CompleteMultipartUpload` and the upload is aborted on failure. A refused upload
leaves no object and no dangling multipart upload.

That held byte is what "nothing is stored" rests on wherever a write forwards
while it receives — the single-request `PUT`, and since 2026-09-12 a client-driven
`UploadPart` large enough to be a middle part. Such a write has opened its backend
request before the payload ends, so the part is kept from existing by the request
being unable to deliver the Content-Length it promised, not by the backend being
left uncontacted. A backend that stored a body shorter than the length it was
given would keep a part the digest refused; for a part there is a second,
proxy-side line, because `Complete` refuses a middle part whose length is not the
part size the session inferred. Recorded as an accepted residual risk in
[ADR 0012](../adr/0012-client-checksums-are-verified-never-forwarded.md).

**A cyclic redundancy check is a transmission-corruption check, not an integrity
guarantee.** CRC-32 is 32 bits and trivially forgeable. It catches a byte damaged
in transit, which is what it is for; it does not detect a deliberate modification
by anyone positioned on the client leg, and nothing here claims it does. The
adversary on that leg is outside this threat model
([ADR 0014](../adr/0014-authentication-is-sigv4-no-rate-limiting.md)); the
mitigation for it is TLS on the client leg (`tls.enabled`), not the checksum.

**The header family is claimed as a whole.** Anything under `x-amz-checksum-`
that is not an implemented algorithm, and is not one of the three that carry no
digest (`-algorithm`, `-mode`, `-type`), answers `501 NotImplemented`. That
covers the `xxhash` family the pinned SDK can send and no standard-library hash
can compute. The point is that a checksum can never be accepted behind a `200`
without being checked, including one S3 adds later.

**One exception, and it is not a gap in the check.** On
`CompleteMultipartUpload` the header is the digest of the *completed object*,
not of the completion document, so it is not compared against that document. The
proxy can neither verify it — the plaintext object it would have to hash is gone
by then — nor forward it, because the backend holds ciphertext. It is dropped,
and the proxy's own value — the CRC32C sealed in the object's trailer — is
served instead on a whole-object `GET` and on `HEAD` (ADR 0012 D10, landed
2026-09-11 with ADR 0003 D14;
[what the storage format guarantees](stored-objects.md#what-the-storage-format-guarantees)).

**Nothing is forwarded and nothing is stored.** The value describes the plaintext
while the body the proxy uploads is ciphertext, so it is meaningless to the
backend; and a plaintext checksum in cleartext beside the ciphertext would hand a
hostile backend a confirmation oracle — for a small or low-entropy object it
could guess a candidate plaintext offline and confirm it against a few bytes of
checksum. This is the same reason the format's own CRC32C lives sealed inside the
trailer rather than in metadata.

**No configuration can switch the check off.** aws-chunked decoding used to be a
configuration key, and setting it to false made the proxy store chunk framing as
object content and left a declared checksum unverifiable, because what it saw was
the framing rather than the payload. The key is gone: the framing is always
stripped, so a checksum always covers the payload, and there is no value an
operator can set that turns the check into accept-and-discard.

## What this does not cover

- **The per-chunk signatures of an aws-chunked upload.** See
  [H-2](request-authentication.md#h-2-per-chunk-signatures-are-never-verified).
- **A client that declares no checksum at all.** The proxy cannot invent one,
  and the lever is the client's configuration. The AWS SDKs send CRC-32 by
  default.
- **An active attacker on the client leg.** A cyclic redundancy check is
  forgeable; the mitigation is TLS (`tls.enabled`), and that adversary is
  outside [the threat model](threat-model.md#what-is-out-of-scope) in the first
  place.
