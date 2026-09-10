# ADR 0001: The S3 backend is hostile, and only the proxy's own verification counts

## Status

**Accepted.** Date: 2026-09-07.

The threat model is in force and every other ADR rests on it. **The three rules the
stored format used to fail are met on the 5.0.0 branch** (ADR 0003): a ranged read is
verified by the proxy, an object carrying no proxy metadata is refused rather than served,
and a modified object is never delivered whole — whatever any configuration says, because
there is no longer a setting involved. The user-facing documentation no longer tells
operators to treat the backend as trusted infrastructure, which was the honest wording
while the gaps were open and is the wrong wording now.

**Open against D6** ("a control that exists only in configuration is worse than no
control"): `encryption.integrity_verification` and `optimizations.streaming_threshold` are
still parsed, defaulted and validated while no code path reads them. They must go before
the release is cut (ADR 0013).

**Open against D5**, and narrower than it looks: the read path still accepts the
*unprefixed* keys `encrypted-dek`, `dek-algorithm` and `kek-fingerprint` as a fallback
behind the prefixed ones. The prefixed keys win where both exist, so an object this proxy
wrote cannot be hijacked — but the fallback lies outside the proxy's namespace, so a client
can set those keys through `x-amz-meta-*` and turn a clean "this object is not encrypted by
this proxy" refusal into an attempt to unwrap bytes it chose. The wrap is authenticated, so
it fails closed; the exclusivity D5 and ADR 0009 claim is nevertheless not true today.

## Context

The objects this proxy stores belong to whatever S3 client writes through it — cluster
backups, database backups, an `aws` CLI, rclone, any SDK — and the endpoint they land on is
somebody else's storage. The premise of the product is that the operator does not have to
trust that endpoint.

So the backend is treated as **hostile**, not merely untrusted. Assume it can read every
byte it stores, change any byte, swap one object for another, serve a stale version of a
key it once held, truncate a response, and lie in a listing, in object metadata, in an ETag
and in an error.

The model was not adopted in the abstract. Four concrete failures in the shipped product
forced it, and each one is a case where "the backend returned 200 over TLS" was quietly
doing the work of an integrity check:

- **A ranged read could not be verified at all.** The integrity value in `s3ep-hmac`
  covers the whole object, so a partial read is checked against nothing and the bytes are
  served on the backend's word. This is not a corner case: clients that read their data in
  small ranges are ordinary, and a backup restore that reads pack blobs with small ranged
  GETs consists almost entirely of unauthenticated reads.
- **An object with no proxy metadata was served as plaintext.** Under an encrypting
  provider, a body without the expected metadata was assumed to be a pass-through write. A
  backend that strips the metadata and substitutes the body has its substitute delivered,
  behind 200, as if the proxy had written it.
- **Integrity was separable from decryption, and configurable.** `lax` delivered data whose
  verification had failed; `hybrid` accepted an object whose integrity value the backend had
  simply removed; and on the `aes-ctr` path even `strict` released the plaintext before it
  verified, so the mismatch existed only as a log line. Every shipped example configuration
  with an encrypting provider set `strict`, while the code default was `off`. A guarantee
  that holds only in one setting — and only where that setting diverges from the examples
  the project ships — is not a guarantee.
- **Configuration named protection that did not exist.** Rate limiting, failed-attempt
  thresholds and IP unblocking were parsed, validated, defaulted and documented, and read by
  nothing. An operator reading the configuration would have concluded the proxy defends
  something it never touched.

The common shape is the same in all four: a control that is announced but not performed. On
a hostile backend that is worse than an absent control, because it is relied upon.

## Decision

**D1.** The S3 backend is an adversary. It may read, alter, swap, reorder, truncate,
delete, roll back, and lie in listings, metadata, ETags and errors. Every design question is
answered against that capability set, not against an honest-but-curious one.

**D2.** Nothing the backend says or does counts as authentication. A 200 response, a
matching ETag, a plausible `Content-Length`, backend-side object locking, and TLS on the
backend leg are statements about availability and about the network. They are never
statements about the integrity of a stored object.

**D3.** Every plaintext byte the proxy hands to a client is verified by the proxy, at the
granularity of the read that asked for it. A ranged read is verified against the units it
actually overlaps; a whole-object read is verified over the whole object, its length
included. Verification happens before the byte leaves the proxy wherever the response has
not yet begun; where it has, the response body is aborted mid-stream, because a proxy that
has already sent 200 cannot un-send it. The format that makes this possible is ADR 0003.

**D4.** Integrity is not separable from decryption. There is no configuration key that
selects, downgrades or disables verification, and no mode in which a failed or missing
check produces data plus a log line. An object whose integrity the proxy cannot establish is
refused.

**D5.** Fail closed on foreign objects. Under an encrypting provider, an object that carries
no proxy metadata, or whose stored format is not the one this proxy writes, is refused on
GET, HEAD and ranged GET with `InvalidObjectState` and HTTP 403 — the status AWS documents
for that code. There is no opt-out knob. Only the `none` provider passes bytes through, and
it passes through everything; it stays a testing and end-of-life aid, not a production mode.
A bucket that already holds objects the proxy did not write is never read in place, and it
is not migrated (amended 2026-09-09): its content is uploaded through the proxy from the
source, and the foreign objects stay refused until they are removed.

**D6.** A control that exists only in configuration or in documentation is worse than no
control. A configuration key exists only if code reads it (ADR 0013); a handler either does
the thing or refuses (ADR 0007).

**D7.** The stored-object format may change without a migration path. Integrity beats
readability of old objects; the release notes carry the break (ADR 0017).

**D8.** What the backend learns anyway is written down rather than implied away: object key
names, ciphertext sizes, timestamps, the request pattern, and any user metadata the client
sets, all in the clear. The proxy encrypts object bodies and the data keys that protect
them. It does not claim to hide the shape of a bucket.

**D9.** Out of scope, stated as such rather than silently assumed: denial of service and
deletion by the backend (a proxy cannot make an endpoint serve); the client leg, which is
operator-controlled and defended by SigV4 and optional proxy-side TLS (ADR 0014); and side
channels against the host the proxy runs on, whose compromise yields the key encryption key,
the cached data keys, the backend credential and every plaintext in flight.

**D10.** Claims about backend trust in user-facing documents describe what the running code
verifies, not what the design intends. While a rule above is decided but not built, the
README and the security architecture say plainly that the backend must be treated as trusted
infrastructure, and they say which reads are unverified. The claim is upgraded in the same
release that earns it, not before.

## Consequences

- **The stored format has to carry its own authentication at read granularity.** That is a
  full rewrite of the read and write paths and a hard break for stored data. It is the
  single largest piece of work the model imposes (ADR 0003, ADR 0017).
- **Verification costs read amplification.** A tiny ranged read pays for a whole
  authenticated unit. The bound is small and fixed, but a client that ranges in 512-byte
  steps pays it on every read, and the cheap "just forward the range" path is gone for good.
- **Refusing beats pretending, and operators feel it.** An operator who points an encrypting
  provider at a bucket that also holds foreign objects gets 403s instead of bytes, with no
  setting to soften it. Mixed buckets stop being a supported shape.
- **Tolerant modes disappear.** Deployments that ran `lax` or `hybrid` to keep a noisy
  backend quiet lose that option. There is no escape hatch short of the `none` provider,
  which is not an integrity mode but the absence of one.
- **Nothing the backend reports can be believed, so the proxy computes instead.** Sizes and
  listings are derived rather than forwarded (ADR 0010), which costs arithmetic and, in
  places, fidelity to what the backend actually said.
- **The proxy becomes the single point of compromise.** Concentrating all trust above the
  boundary is what makes the model coherent; it also means whoever takes the proxy process
  takes everything. The model does not defend that case, it only states it.
- **Honesty has a marketing cost.** Under D10 the product documentation currently publishes,
  in its own README, that its integrity modes do not refuse a tampered object on one path.
  That is the correct thing to publish and it is not a comfortable sentence.

## Alternatives Considered

**Treat the backend as untrusted-but-not-adversarial, and let TLS plus backend
authentication carry integrity.** The stance the shipped code implicitly took. It makes an
unverified ranged read look acceptable, and it fails precisely in the case the product is
bought for: an endpoint that is not under the operator's control. Rejected — under this
option the proxy protects confidentiality only, and should say so instead of shipping
integrity features.

**Keep integrity configurable, with a recommended strict mode.** Cheaper, and it preserves
compatibility with deployments that tolerate noise. Rejected under D6: the running product
is the proof. Three tolerant modes existed, the strict one did not refuse anything on the
main path, and every shipped example recommended a mode the code default did not use.

**Detect and log a mismatch, leaving the response intact.** Rejected for the same reason.
An integrity signal nobody acts on is an operational cost with no security value, and it
teaches operators that the check exists.

**Warn on missing encryption metadata and pass the object through for compatibility.**
Rejected: that is the substitution attack, with a warning attached. Compatibility with
buckets holding foreign objects is bought instead by a documented one-time migration
through the proxy.

**Refuse ranged reads of protected objects.** Correct on paper and the cheapest way to keep
a whole-object integrity value honest. Rejected: it breaks every client that reads ranges,
including backup restores that read their pack blobs in small ranges, and ADR 0006 does not
allow narrowing the supported client set for a proxy-internal reason.

**Serve every range by reading and verifying the whole object.** Also correct, and
pathological: a 32-byte read of a 20 MiB blob costs 20 MiB of backend traffic and a full
decryption on every read. Rejected as a general rule. It survives only as the fallback that
would have applied if the no-migration precondition had failed — and that precondition
holds, so the fallback is not built.

**Keep a whole-object MAC and add per-unit MACs beside the cipher.** Reaches the same
property as an authenticated segment chain and pays more for it: two primitives instead of
one, the slower of the two doing the integrity work, two passes over the data, and none of
the code the chain lets us delete. Rejected in ADR 0003.

## Residual risks

- **Rollback and deletion are not defended, by construction.** No authenticated format
  prevents a backend from serving an older version of a key: the old bytes, the old metadata
  and the old integrity value are internally consistent, because the proxy wrote them. The
  same holds for serving nothing and for a listing that omits an object. The only defence is
  the client's own consistency checking, where it has any. Operator mitigation: object
  versioning and, where available, object lock on the backend bucket, under a privilege the
  proxy's own backend credential does not hold.
- **A same-key swap across buckets is accepted.** The bucket name is deliberately not bound
  into the encryption, so ciphertext buckets stay copyable, replicable and renamable
  (ADR 0003). Two buckets served by the same key encryption key can therefore be swapped
  key-for-key by the backend. The answer is one key encryption key per deployment, not a
  format binding.
- **Metadata leakage is permanent within this model.** Key names, ciphertext sizes,
  timestamps, request patterns and user metadata stay visible. Directory-segment filename
  encryption would narrow only the first of those, and only if it ships (ADR 0023). Sizes and
  timing are not addressed by anything decided.
- **Per-chunk signatures on the client leg are not verified.** Accepted: the adversary is on
  the other leg, the client leg is operator-controlled and normally TLS, and unsigned payload
  framing is accepted anyway. The residual is a client that signs chunks over plain HTTP and
  expects the proxy to catch a man in the middle (ADR 0014).
- **Everything in D3 to D5 is a rule the current release does not keep.** A deployment on
  3.x or 4.0.x has unverified ranged reads, a pass-through on missing metadata, and no mode
  that refuses a tampered object on the streaming path. That is a limitation, not a
  mitigation, and the interim advice is exactly D10's: treat the backend as trusted
  infrastructure until the segment chain ships.
- **Settled 2026-09-09: there is no migration procedure.** A bucket with objects the proxy
  did not write is not migrated; the data is uploaded through the proxy from its source, and
  the release notes say so (ADR 0017).
- **Open: whether segment-granular verification needs a read cache.** Deliberately not
  decided. The read amplification is bounded and known; whether it hurts a real client is a
  measurement, and it is taken before anything is added (ADR 0020).
- **Not verified in this repository:** the read pattern attributed to range-reading backup
  clients comes from the design round and from end-to-end restores passing, not from
  instrumenting a client; and the proxy has only ever been exercised against the demo MinIO
  backend, so its behaviour against AWS S3 or any other S3-compatible target is unverified.
- **Not verified:** no third party has reviewed this threat model, and the private
  vulnerability-reporting route described in the security architecture has never been used.

## References

- ADR 0002 — One data key per object, wrapped by a configured key encryption key
- ADR 0003 — Objects are stored as an authenticated segment chain
- ADR 0006 — The proxy serves any S3 client
- ADR 0007 — Forward it or refuse it, never silently drop it
- ADR 0010 — Sizes and listings describe the plaintext
- ADR 0013 — A configuration key exists only if code reads it, and an unworkable configuration refuses to start
- ADR 0014 — Authentication is SigV4 on both forms; there is no rate limiting and no IP blocking
- ADR 0017 — Stored data compatibility is not owed; a major release may break the format
- ADR 0020 — Performance is measured before and after, never asserted
- ADR 0023 — Filename encryption, if it ships, encrypts directory segments only
- [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md) — the threat model in operator form, the trust boundaries, and the hardening checklist
- [README.md](../../README.md) — what the product currently claims about backend trust and about integrity verification
