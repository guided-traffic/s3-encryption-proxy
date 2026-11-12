# ADR 0001: The S3 backend is hostile, and only the proxy's own verification counts

## Status

**Accepted.** Date: 2026-09-12.

The threat model is in force and every other ADR rests on it. **D3 to D5 hold of the stored
format** (ADR 0003), and they are met against a running stack rather than argued: a ranged read
is verified against the segments it overlaps, an object carrying no proxy metadata is refused
under an encrypting provider instead of being served, and a tampered object is never delivered
whole — whatever any configuration says, because no setting is involved. Under D10 no
user-facing document tells operators to treat the backend as trusted infrastructure.

**D6 holds of the configuration.** `encryption.integrity_verification`,
`optimizations.streaming_threshold` and the modes `off`, `lax`, `strict` and `hybrid` do not
exist — not in the proxy, not in a shipped example configuration, not in the production deployment
values: integrity is not a setting, it is a property of the stored format (ADR 0003, ADR 0013).
There is no `s3_security` key for a rate limiter, a failed-attempt threshold or an IP block, and
no per-address accounting (ADR 0014). The sessions a client-driven multipart upload creates are
swept: `optimizations.multipart_session_cleanup_interval` sets how often, and
`optimizations.multipart_session_idle_timeout` how long an upload may go without receiving a part
(ADR 0028); the sweep stops when the proxy shuts down. `optimizations.multipart_session_max_age`
does not exist, and a configuration that carries it is refused at startup by name.

**D5 holds of the read path.** The proxy's metadata is consulted only under the configured prefix.
The unprefixed spellings, which a client can set through `x-amz-meta-*`, are read on no path, so
the exclusivity D5 and ADR 0009 claim is true of the product and not only of the design.

**D3, as far as it reaches.** Every segment is authenticated before its plaintext is released, so
the bytes a client receives are always the object's own. What the object *is* — its length and
its checksum — is authenticated where the stream ends, and the tail-first read of ADR 0003 D14
reads that end **before** the response begins: a damaged trailer, a truncation, an extension and
a stored length the trailer contradicts are refused with `InvalidObjectState` and 403, and
`x-amz-checksum-crc32c` is served on a whole-object `GET` and on `HEAD`. What reaches the client as
a body that stops early under an already-sent 200 is a fault inside a segment, which is only
reached once the body is flowing, and every whole-object read under the `exit` provider, which
stays one forward pass and carries neither the authenticated length nor the checksum (ADR 0025).

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
  covered the whole object, so a partial read was checked against nothing and the bytes were
  served on the backend's word. This is not a corner case: clients that read their data in
  small ranges are ordinary, and a backup restore that reads pack blobs with small ranged
  GETs consists almost entirely of reads that were unauthenticated.
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
for that code. There is no opt-out knob. Serving such an object under the `exit` provider, the
way out of the product, is ADR 0025's subject. A bucket that already holds objects the proxy did
not write is never read in place, and it is not migrated: its content is uploaded through the
proxy from the source, and the foreign objects stay refused until they are removed.

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

- **The stored format carries its own authentication at read granularity.** That is a full
  rewrite of the read and write paths and a hard break for stored data, the single largest piece
  of work the model imposes, made in 5.0.0 (ADR 0003, ADR 0017).
- **Verification costs read amplification.** A tiny ranged read pays for a whole 64 KiB segment.
  The bound is small and fixed, but a client that ranges in 512-byte steps pays it on every read,
  and there is no cheap "just forward the range" path — it exists only under the `exit` provider,
  and there only for an object this proxy never encrypted, which costs that provider a `HEAD` on
  every ranged read to tell the two apart, because it decides per object (ADR 0025).
- **Refusing beats pretending, and operators feel it.** An operator who points an encrypting
  provider at a bucket that also holds foreign objects gets `InvalidObjectState` and 403 instead
  of bytes, with no setting to soften it. Mixed buckets are not a supported shape.
- **Tolerant modes are gone.** Deployments that ran `lax` or `hybrid` to keep a noisy backend
  quiet have no equivalent. There is no escape hatch short of the `exit` provider, which is not
  an integrity mode but the way out of the product (ADR 0025).
- **The model deletes far more than it adds.** One cipher, one stored layout, one read path: the
  second cipher, the four integrity modes, the readers that implemented them and the metadata
  keys that carried them are deleted rather than bypassed, and the proxy's production Go went
  from 17,715 lines to 12,357 in the same wave (measured 2026-09-10, on the tree the deletion
  left; what has been built since is not in that column). A guarantee that has no alternative
  branch needs no code to select between branches.
- **Nothing the backend reports can be believed, so the proxy computes instead.** A `GET` and a
  `HEAD` state the plaintext length the object's own **trailer** authenticates (ADR 0003 D14); a
  ranged read and a listing state one derived from the stored length rather than forwarded
  (ADR 0010), so a listing under an encrypting provider does not carry the backend's stored sizes.
  A stored size no chain of this format could have produced is passed through unconverted: that
  entry is not one this proxy wrote, and there is no plaintext length to compute for it.
- **The proxy becomes the single point of compromise.** Concentrating all trust above the
  boundary is what makes the model coherent; it also means whoever takes the proxy process takes
  everything. The model does not defend that case, it only states it.
- **Honesty has a marketing cost.** Under D10 the claim is made in the release that earns it, and
  5.0.0 earns it. What has to be published beside it is the price: a bucket holding objects this proxy did not write is refused with no way to
  soften it, there is no migration for data written by an earlier release, and a read that fails
  verification once the body is already flowing reaches the client as a short body rather than as
  an error.

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
- **A read that fails after the first byte reaches the client as a short body, not as an error.**
  On a whole-object read under an encrypting provider the object's end is read first
  (ADR 0003 D14), so a damaged trailer, a truncation, an extension and a stored length
  the trailer contradicts are refused before the response begins. What is left in this shape is a
  fault inside a segment, a ranged read of any kind, and every whole-object read under the `exit`
  provider: the proxy authenticates every segment before releasing it and stops the moment one does
  not open, so no unauthenticated byte is ever served — but by then the response has begun, and the
  client sees 200, an announced `Content-Length` and fewer bytes than that. A client that checks
  neither the length it was promised nor its own content hash reads a truncated object as a
  complete one.
- **Metadata leakage is permanent within this model.** Key names, ciphertext sizes,
  timestamps, request patterns and user metadata stay visible. Directory-segment filename
  encryption would narrow only the first of those, and only if it ships (ADR 0023). Sizes and
  timing are not addressed by anything decided.
- **Per-chunk signatures on the client leg are not verified.** Accepted: the adversary is on
  the other leg, the client leg is operator-controlled and normally TLS, and unsigned payload
  framing is accepted anyway. The residual is a client that signs chunks over plain HTTP and
  expects the proxy to catch a man in the middle (ADR 0014).
- **Releases before 5.0.0 do not keep D3 to D5.** A deployment on 3.x or 4.0.x has unverified
  ranged reads, a pass-through on missing metadata, and no mode that refuses a tampered object on
  the streaming path. That is a limitation of those releases, not a mitigation, and 5.0.0 does
  not read what they wrote (ADR 0017): the answer is an upgrade with a re-upload, not a setting.
- **There is no migration procedure.** A bucket with objects the proxy did not write is not
  migrated; the data is uploaded through the proxy from its source, and the release notes say so
  (ADR 0017).
- **Open: whether segment-granular verification needs a read cache.** Deliberately not
  decided, and nothing is cached today beyond the unwrapped data keys. The read amplification is
  bounded and known; whether it hurts a real client is a measurement, and it is taken before
  anything is added (ADR 0020).
- **Not verified in this repository:** the read pattern attributed to range-reading backup
  clients comes from the design round and from end-to-end restores passing, not from
  instrumenting a client; and the proxy has never been exercised against AWS S3 itself. The
  conformance suite runs it against backends that are not the demo MinIO — LocalStack on every
  change, Wasabi on a schedule (ADR 0027) — but AWS is untested.
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
- [docs/security/threat-model.md](../security/threat-model.md) — the threat model in operator form, the trust boundaries and the transport legs
- [docs/operations/integrity.md](../operations/integrity.md) — what the product claims about backend trust and about what it verifies before it serves a byte
