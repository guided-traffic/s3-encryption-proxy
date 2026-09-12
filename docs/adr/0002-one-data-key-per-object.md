# ADR 0002: One data key per object, wrapped by a configured key encryption key

## Status

**Accepted.** Date: 2026-09-07.

Implemented today: a fresh data key per object, wrapped by the configured key encryption key,
the wrapped key and the key's fingerprint stored in the object's own metadata, provider
selection on read by that fingerprint, rotation by adding a provider and switching the active
alias, and a bounded in-memory cache of unwrapped data keys whose cache key includes a digest
of the wrapped key.

**Both open items are closed in the tree, 2026-09-10.** Every read unwraps the data key exactly
once: the whole-object read and the ranged read each build one codec from one unwrap, and the
second unwrap below the cache went with the code it lived in. A `HEAD` unwraps nothing at all —
the plaintext size it reports is a function of the stored size (ADR 0010). An object that carries
no wrapped data key is refused under an encrypting provider on every read verb rather than passed
through. The wrap algorithm and the fingerprint derivation changed with ADR 0004, and the
metadata set with ADR 0003; neither changed the rules below.

**Amended 2026-09-10:** a wrapped key that fails its authentication tag is its own answer —
`InvalidObjectState`, HTTP 403 — and deliberately not a 5xx, so a client SDK does not retry
a read that cannot succeed (ADR 0003 D10a).

**Amended 2026-09-10:** the trial-decryption alternative below was rejected in part because the
wrap of the day could not tell a successful unwrap from a failed one. Since ADR 0004 it can — the
wrap authenticates — so that half of the argument has expired. The rejection stands on the other
half: one unwrap attempt per configured provider on every cold read.

**The cache kept its rule and lost its manual controls, 2026-09-10.** The two entry points that
emptied it had no caller and went with the rest of the dead code, which leaves D9's construction
as the only thing standing between a re-upload and a stale key — which is what D9 asks for.
Three properties of that cache the decision does not state and code depends on: it hands back its
own backing array, so a caller must treat an unwrapped data key as read-only; it has a size bound
— a fixed 1024 entries, not an operator setting — but **no expiry**, which ADR 0005 D10 assumes
it has; and the digest of the wrapped key in the cache key is truncated to 64 bits, which makes an
entry unique, not authentic. What decides whether a wrapped key is genuine is its own
authentication tag, and that is checked on a miss, never on a hit.

## Context

The proxy encrypts objects for a backend it does not trust (ADR 0001). Two forces shape the
key layer.

**An object must be readable from itself.** Whoever holds the configured key encryption key
and the stored object must be able to decrypt it — no key database, no sidecar index, no
lookup service. A bucket that is copied, replicated, restored under another name or read by a
second proxy instance stays readable, and no additional component can fail and take the data
with it. That rules out any scheme where the per-object key lives anywhere but on the object.

**Keys must be replaceable without re-encrypting the bucket.** A single key used directly on
object bodies makes rotation equivalent to rewriting every byte ever stored, and puts the
whole data volume under one key. Envelope encryption is the standard answer: a long-lived key
that only ever wraps short-lived keys, and one short-lived key per object.

Two concrete failures fixed the details.

*A cache keyed by identity, not by content, served a stale key.* Unwrapped data keys were
cached under the pair (key fingerprint, object key). Re-uploading the same object key produces
a new data key, but the cache still held the old one, so the next read decrypted new
ciphertext with the previous key. The result was garbage plaintext, an integrity check that
then failed, and an aborted download. It reproduced whenever an object key was read, rewritten
and read again within one proxy lifetime; the full test suite missed it only because each fixed object key
was written once per proxy start. Removing the cache was not acceptable — repeat reads of the
same object are common and the unwrap is the expensive part of a cold read.

*The unwrap cost is not always negligible.* One read path unwraps the wrapped data key twice,
once through the cache and once again below it. With a local symmetric key that is a few
hundred nanoseconds; with an asymmetric key it was measured at roughly 0.94 ms per read, which
halved the throughput ceiling of that path, and with a remote key service every unwrap is a
network round trip (ADR 0005).

## Decision

**D1** Every object is encrypted under its own 256-bit data key, drawn from the system
cryptographic random source at write time. A data key is never reused across objects and is
never derived from the object key, the bucket name or any client input.

**D2** The data key encrypts object bytes; the key encryption key encrypts data keys and
nothing else. The key encryption key never leaves the proxy process: it is never sent to the
backend, never written into object metadata, and never logged.

**D3** The wrapped data key travels with the object, in the object's metadata as
`s3ep-encrypted-dek` (with the configured metadata prefix, ADR 0009). Reading an object
requires the object, its metadata and the configured key encryption key — nothing else. The
proxy keeps no key store whose loss would make a stored object unreadable.

**D4** The object records which key wrapped it: `s3ep-kek-fingerprint` identifies the key,
`s3ep-kek-algorithm` the wrap. On read the proxy selects the configured provider whose
fingerprint matches. There is no default provider and no trial decryption across providers; a
fingerprint that matches nothing configured is an error.

**D5** A fingerprint is derived by the provider from its own key material and is never
configured, so it cannot drift from the key it names. It is stored in the clear on every
object and is therefore treated as public. How the local provider derives it is ADR 0004; a
provider whose key never reaches the proxy is the exception and is ADR 0005.

**D6** Several providers may be configured at once. `encryption.encryption_method_alias` names
the single provider used for writes; every configured provider is available for reads.

**D7** Key rotation is a configuration procedure, not an operation: add the new provider, point
`encryption.encryption_method_alias` at it, restart. Objects written under the old key stay
readable for exactly as long as that provider stays configured. There is no re-encryption job
and no rotation call; re-writing objects through the proxy is the migration. Removing a
provider makes every object wrapped by it permanently unreadable.

**D8** The provider alias is a local configuration label. It is never stored on an object, so
renaming an alias never affects readability.

**D9** Unwrapped data keys may be held in a bounded in-memory cache with eviction. The cache
key includes a digest of the wrapped data key, so a re-upload of the same object key cannot
return the previous data key. Correctness here is by construction, not by invalidating cache
entries from the write paths.

**D10** A read performs at most one unwrap of the data key.

**D11** The key layer fails closed. A wrapped data key that does not unwrap, a fingerprint that
names no configured provider, and an object that carries no wrapped data key under an
encrypting provider are all errors. The proxy never serves stored bytes because a key step did
not work out.

**D12** A successful unwrap authenticates nothing about the object body. Whether the stored
bytes are the bytes the proxy wrote is decided by the object format (ADR 0003).

## Consequences

- **The key encryption key is the single point of total loss.** Lose it and the bucket is
  unreadable, with no escrow and no recovery path. Backing up that configuration is an
  operator obligation the product does not perform.
- **Removing a provider destroys data.** The bucket is not consulted at startup and cannot be:
  the proxy has no way to know which fingerprints are still referenced by stored objects.
  Startup checks provider aliases and the admission rules for key material and nothing else, so
  an operator tidying up an old provider is not warned and not stopped; the loss surfaces on the
  next read of an object that key wrapped.
- **Rotation leaves the old key live.** After a rotation, every object written before it is
  still protected by the previous key, and the previous key must stay configured. A key
  believed compromised stays a real risk until every object it wrapped has been re-written
  through the proxy and the provider removed.
- **The fingerprint is published on every object.** Two buckets carrying the same fingerprint
  prove they share a key, and for a low-entropy or published key the fingerprint is an offline
  oracle that confirms a guess from a single readable object. That is why key admission is
  strict (ADR 0004). It is published towards the backend, not towards clients — the proxy strips
  its own metadata namespace from every response (ADR 0009) — and the backend is exactly where
  the threat model puts the adversary (ADR 0001).
- **Unwrapped data keys sit in process memory,** and the cache widens that window from one
  request to the cache bound. Nothing overwrites a data key: a cache entry's only exit is
  eviction, and after that it is the garbage collector's business. Anyone who can read the
  proxy's memory — including through a profiling endpoint — gets the data keys of recently read
  objects, though not the key encryption key's ability to unwrap anything else.
- **An upload in flight holds its data key for as long as it stays open.** A client-driven
  multipart upload keeps its key from the moment the upload is created until it completes or is
  aborted. One that is neither is ended by the background sweeper once it has gone
  `optimizations.multipart_session_idle_timeout` (default 3600 seconds) without receiving a part,
  which is checked every `optimizations.multipart_session_cleanup_interval` (default 300 seconds).
  An interval of 0 turns the sweeper off, and an abandoned upload then holds its key until the
  process ends. Amended 2026-09-12: the clock used to run from the upload's creation and the key
  used to be called `optimizations.multipart_session_max_age`
  ([ADR 0028](0028-an-abandoned-upload-is-ended-not-forgotten.md)).
- **Superseded cache entries survive until eviction.** The content-derived cache key trades a
  little memory for the guarantee that a stale key is never served; the bound and its eviction
  are what keep that from growing.
- **Every object pays fixed metadata overhead** for its wrapped key and key identity. Every write
  path now produces that metadata before the first backend byte, multipart included, so there is
  no internal copy step left that could drop it and leave an object nobody can read.

## Alternatives Considered

- **Encrypt object bodies directly with the configured key, no envelope.** Simplest, and one
  key covers the entire stored data volume. Rotation would mean rewriting every object, so in
  practice keys would never be rotated. Rejected.
- **Derive the per-object key from the master key and the object key, storing no wrapped key.**
  Saves the metadata and the unwrap. It records no key identity, so several keys cannot coexist
  and rotation is again all-or-nothing — the property the envelope exists for. It also makes the
  per-object key a permanent function of the name, so re-uploading under the same name reuses
  the same key, which is the reuse a nonce-based format must avoid (ADR 0003). Rejected.
- **A key database or sidecar index mapping objects to wrapped keys.** Gives central revocation
  and cheap key inventory. It also adds a component whose loss or inconsistency makes readable
  ciphertext undecryptable, and a bucket restored elsewhere would arrive without it. Rejected;
  the object carries its own wrapped key.
- **Trial decryption over all configured providers instead of a recorded fingerprint.** Would
  keep the key identity off the object and out of the backend's view. It costs an attempt per
  configured provider on every cold read, and against the unauthenticated wrap the product ships
  today it cannot even distinguish success from failure, so the attempt order would decide the
  result. Rejected; the linkage the
  fingerprint leaks is accepted instead.
- **Invalidate the cache from the write paths** instead of keying it by content. Keeps the
  cache lean, but must be wired into every path that writes an object, and a path missed today
  or added tomorrow reintroduces the stale-key defect silently. Rejected.
- **Key the cache by the wrapped data key alone,** dropping the object key. Equivalent in
  practice, since data keys are unique per object. Rejected as offering nothing over including
  both.
- **Disable the cache.** Correct and simple, and it gives up the repeat-read win exactly where
  the unwrap is expensive. Rejected.
- **Patch the double unwrap now.** The code that would be patched is deleted by the format
  change, so the patch would be written twice and measured never. Rejected in favour of
  measuring the single-unwrap path once it exists.

## Residual risks

- **Compromise of the key encryption key compromises everything ever written under it**,
  retroactively, because the backend is assumed to hold the ciphertext forever. Nothing in this
  ADR mitigates that; custody is ADR 0004 and ADR 0005.
- **Key identity for a provider whose key never reaches the proxy is unsettled.** Such a
  fingerprint cannot be a function of key material, and what it should do across a key rotation
  performed inside the key service is an open question, not a decision (ADR 0005).
- **The cache bound is a fixed value, with no expiry.** Whether it should become an operator
  setting, and whether entries need to age out, is open. It matters only once an unwrap is a
  network round trip.
- **D10 holds, and what is measured is the unwrap, not the read.** The rule is true of every read
  path in the tree. What the recorded performance baselines measure is the local wrap and unwrap
  in isolation, with the cache out of the way: roughly 120 to 150 nanoseconds per unwrap on the
  reference machine, against roughly 0.6 milliseconds for a 2048-bit asymmetric unwrap, which the
  harness keeps as a reference point although no such provider exists any more. At that size the
  per-read share disappears under a backend round trip, and one unwrap per read only becomes a
  number worth watching for a provider with a network behind it (ADR 0005, ADR 0020).
- **Not quantified:** what a memory capture of the proxy actually yields. How long a data key
  stays resident is bounded on both sides now — a cached key until it is evicted, an upload's key
  until the upload ends or the sweeper drops it — but nothing overwrites either, so residency in
  practice outlasts residency by design.
- **Rotation depends on the deployment tooling restarting the proxy.** The proxy reads its
  configuration once, at startup, and has no reload path. Tooling that updates the
  configuration without replacing the running process leaves the old key encrypting new objects
  while reporting that the rotation succeeded — a false statement about the data, and the
  reason a restart is part of D7 rather than an implementation detail.

## References

- ADR 0001 — The S3 backend is hostile, and only the proxy's own verification counts
- ADR 0003 — Objects are stored as an authenticated segment chain
- ADR 0004 — One local key provider: 256 random bits, an authenticated wrap, no passphrases
- ADR 0005 — A KMS-backed key encryption key is a provider, not a mode
- ADR 0009 — The metadata prefix is the proxy's namespace
- ADR 0010 — Sizes and listings describe the plaintext
- ADR 0017 — Stored data compatibility is not owed; a major release may break the format
- ADR 0020 — Performance is measured before and after, never asserted
- [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md) — key hierarchy, where each secret
  lives, and rotation by fingerprint
- [README.md](../../README.md) — provider configuration and the rotation procedure
