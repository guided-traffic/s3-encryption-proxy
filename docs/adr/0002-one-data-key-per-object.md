# ADR 0002: One data key per object, wrapped by a configured key encryption key

## Status

**Accepted.** Date: 2026-09-07.

Implemented today: a fresh data key per object, wrapped by the configured key encryption key,
the wrapped key and the key's fingerprint stored in the object's own metadata, provider
selection on read by that fingerprint, rotation by adding a provider and switching the active
alias, and a bounded in-memory cache of unwrapped data keys whose cache key includes a digest
of the wrapped key.

Decided and not built: **one unwrap per read**. One read path unwraps the data key a second
time below the cache; that path is rewritten by the stored-object format change and the cost
is measured afterwards, not patched before (ADR 0003).

Also decided and not built: **failing closed on an object that carries no wrapped data key**.
Today such an object is passed through to the client unchanged, even under an encrypting
provider; refusing it lands with the format change (ADR 0003). The wrap algorithm and the fingerprint
derivation of the local provider also change with that release (ADR 0004), and the exact set
of metadata keys an object carries changes with the format (ADR 0003). Neither changes the
rules below.

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
  the proxy has no way to know which fingerprints are still referenced by stored objects. An
  operator tidying up an old provider will not be stopped.
- **Rotation leaves the old key live.** After a rotation, every object written before it is
  still protected by the previous key, and the previous key must stay configured. A key
  believed compromised stays a real risk until every object it wrapped has been re-written
  through the proxy and the provider removed.
- **The fingerprint is published on every object.** Two buckets carrying the same fingerprint
  prove they share a key, and for a low-entropy or published key the fingerprint is an offline
  oracle that confirms a guess from a single readable object. That is why key admission is
  strict (ADR 0004).
- **Unwrapped data keys sit in process memory,** and the cache widens that window from one
  request to the cache bound. Anyone who can read the proxy's memory — including through a
  profiling endpoint — gets the data keys of recently read objects, though not the key
  encryption key's ability to unwrap anything else.
- **Superseded cache entries survive until eviction.** The content-derived cache key trades a
  little memory for the guarantee that a stale key is never served; the bound and its eviction
  are what keep that from growing.
- **Every object pays fixed metadata overhead** for its wrapped key and key identity, and every
  internal copy path must carry that metadata forward or produce an object nobody can read.

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
- **D10 is a rule, not a measurement.** Today one read path violates it; after the format change
  the single-unwrap cost is to be measured and recorded rather than assumed.
- **Not verified:** that removing a still-referenced provider produces any warning at all.
  Assume it does not, and treat provider removal as destructive.
- **Not quantified:** how long unwrapped data keys remain resident in process memory, and what
  a memory capture actually yields.
- **Rotation depends on the deployment tooling restarting the proxy.** Tooling that updates the
  configuration without replacing the running process leaves the old key encrypting new objects
  while reporting that the rotation succeeded — a false statement about the data, and the
  reason a restart is part of D7 rather than an implementation detail.

## References

- ADR 0001 — The S3 backend is hostile, and only the proxy's own verification counts
- ADR 0003 — Objects are stored as an authenticated segment chain
- ADR 0004 — One local key provider: 256 random bits, an authenticated wrap, no passphrases
- ADR 0005 — A KMS-backed key encryption key is a provider, not a mode
- ADR 0009 — The metadata prefix is the proxy's namespace
- ADR 0017 — Stored data compatibility is not owed; a major release may break the format
- [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md) — key hierarchy, where each secret
  lives, and rotation by fingerprint
- [README.md](../../README.md) — provider configuration and the rotation procedure
