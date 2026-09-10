# ADR 0004: One local key provider — 256 random bits, an authenticated wrap, no passphrases

## Status

**Accepted.** Date: 2026-09-07.

**Implemented on the 5.0.0 branch, 2026-09-10.** `aes` is the one local provider: `rsa` is
deleted from the tree, and the only other type an active provider may have is `none`. The
data key is wrapped with AES-256-GCM under a key derived per wrap with HKDF-SHA256, so a
flipped bit anywhere in the 76-byte wrap fails closed with its own error instead of yielding
a different data key in silence; `s3ep-kek-fingerprint` is an HKDF expansion under a
labelled context rather than a plain hash of the master key; and `aes_key` is base64 of
exactly 32 bytes, with the raw-string fallback gone and the admission rules checked at
startup. The change breaks the stored format (`s3ep-encrypted-dek` and
`s3ep-kek-fingerprint` both changed), which is why it shipped in the release that already
forces a re-upload — see ADR 0003 and ADR 0017.

## Context

The key-encryption layer wraps the per-object data key of ADR 0002 under a configured
master key. Three defects in it were weighed together on 2026-09-07, because each of them
can only be repaired in a release that breaks the stored format, and there is exactly one
such release planned.

**The wrap is unauthenticated.** AES-CTR with no tag is malleable: an adversary who can
write object metadata — which is the whole premise of ADR 0001 — flips bits of the stored
wrapped key and gets a *chosen* modification of the data key back, with no error. Today
that is bounded rather than exploitable, because an AES-256-GCM object fails its own tag
and an AES-CTR object fails its HMAC. The bound does not hold in the configurations where
no integrity check runs, and it is the wrong kind of defence: the key layer must not depend
on the data layer noticing.

**The published fingerprint is a plain hash of the key.** Every object carries
`s3ep-kek-fingerprint` in the clear so that a read can select the provider that wrote it.
Against 256 random bits, publishing a hash of the key leaks nothing. Against a
human-chosen key it is a free offline verification oracle for a dictionary attack, and
recovering the master key unwraps every data key and therefore every object.

**A passphrase is accepted as the master key.** `aes_key: "correct-horse-battery-staple-123"`
starts the proxy today. That is what turns the previous point from theoretical into
practical: the two defects are each defensible alone and dangerous together.

The obvious framing — "hashing a symmetric key is unsafe, so prefer the asymmetric
provider" — is wrong about the primitive and right about the hash. No fingerprint
derivation protects a weak key: the adversary holds the wrapped data key and one
authentication tag forever, so an offline oracle exists whatever the published identifier
looks like. Entropy at the source is the only lever on a guessable key; an authenticated
wrap is the only lever on malleability. The asymmetric provider answers neither.

That provider was examined on its own merits at the same time. It requires both halves of
the key pair in the same configuration, so the one property asymmetry could add here — a
write-only proxy that cannot decrypt what it stored — does not exist and would not serve
any client that reads back what it writes. It unwraps roughly 2,400 times slower than the
symmetric provider (sub-microsecond against just under a millisecond per cold unwrap),
which is the floor for every cache miss on the read path. RSA-2048 sits at a 112-bit
security level under a 256-bit data key and is the one primitive in this design that a
backend archiving ciphertext forever can plausibly break later. It also carries its own
fingerprint defect. No shipped chart, compose file or end-to-end configuration uses it;
every default in the product is already the symmetric provider with a generator-shaped key.

## Decision

**D1.** There is exactly one local key-encryption provider. Its type is `aes` and its key
material is `encryption.providers[].config.aes_key`. Both names stay as they are.

**D2.** The `rsa` provider type is removed. A configuration naming it does not load. There
is no migration path other than the re-upload the major release forces anyway.

**D3.** `aes_key` is standard base64 of exactly **32 bytes**. There is no fallback that
treats the configured string as key material.

**D4.** Key admission is checked at startup, not at the first upload, and refuses a key
whose 32 decoded bytes are all printable ASCII (0x20–0x7E), or that contain **fewer than
16 distinct byte values**. A key from the generator fails the printable-ASCII rule with
probability about 2^-46; the distinct-values rule catches all-zero and repeated patterns.

**D5.** The refusal names `encryption.providers[].config.aes_key`, names the generator
(`make build-keygen`, then `s3ep-keygen`) and `openssl rand -base64 32` as the two
supported ways to produce a key, and states that base64 of a hex string is refused too.

**D6.** The fingerprint and the wrapping key are both **derived** from the master key with
HKDF-SHA256 under distinct labels, never used as the key itself and never published in
raw form. The extraction step takes an empty salt; the fingerprint is a 32-byte expansion
under the label `s3ep-kek-fingerprint`, hex-encoded into the metadata key of the same
name.

**D7.** The wrap is **AES-256-GCM** with a fresh 16-byte random salt per wrap. The
wrapping key is a 32-byte expansion under the label `s3ep-kek-wrap-v1` concatenated with
that salt; the associated data is `s3ep-dek-wrap-v1`; the nonce is random. The stored
`s3ep-encrypted-dek` is salt ‖ nonce ‖ ciphertext ‖ tag, 76 bytes. Two wraps of the same
data key differ.

**D8.** The per-wrap salt is the reason there is no wrap counter: a single wrapping key
with random nonces would carry a message bound of 2^32 wraps, and a rotation trigger that
nothing in the product counts is a control that exists only in documentation. See ADR
0013.

**D9.** A tampered wrapped key fails with its own distinct error — "wrapped data key
authentication failed" — attributed to the object's metadata, **before any object byte is
read or decrypted**. It is never reported as a decryption failure of the body.

**D10.** The pass-through provider `none` stays, for testing and end-of-life only. It is
not a production mode: objects written under it are plaintext at rest and carry no proxy
metadata at all.

**D11.** Custody of the master key is a separate axis from this decision. A key held in a
key management service is its own provider type (ADR 0005). Delivering the local key from
a secret store through `aes_key: "${S3EP_AES_KEY}"` works with no code and is custody by
injection, not a KMS: the key is in process memory for the process lifetime either way.

**D12.** The product exposes no key-rotation operation. Rotation is the configuration
procedure of ADR 0002 — add the new provider, repoint
`encryption.encryption_method_alias`, restart, keep the old provider configured for as
long as objects written under it must stay readable.

## Consequences

- Every stored `s3ep-encrypted-dek` and `s3ep-kek-fingerprint` changes. Objects written by
  earlier versions are unreadable, which is acceptable only because the same release
  already forces a full re-upload (ADR 0003, ADR 0017).
- A local encrypt-only deployment is off the table for good. It was already refused by
  configuration validation, so nothing loses a capability it had — but the door is closed
  deliberately, not by accident.
- The user-facing documentation flips: "RSA recommended for production" and "AES is lower
  security than RSA" are both wrong under this decision and go. The product now offers one
  local choice, which is simpler to document and gives an operator one fewer way to be
  wrong.
- An operator who typed a passphrase into a configuration that starts today gets a startup
  failure after upgrading. That is the intended outcome and it is a hard stop, not a
  warning. Because the value can arrive through an environment reference, no inspection of
  the repository or of a chart can predict which deployments are affected.
- Configurations, charts and examples that name the asymmetric provider stop loading. No
  shipped artefact does, so the cost falls on unknown external users only.
- One key shape, one generator, one rotation procedure, one fingerprint algorithm, one
  wrap. Roughly 1,800 lines of provider, tests, integration suite and example go with the
  asymmetric provider, and PEM handling leaves the product entirely.
- Sub-microsecond unwrap stays the reference point for the read path, which keeps the
  latency budget of a future KMS-backed provider meaningful: the difference between local
  and remote custody is then a clean measurement rather than a comparison of two unrelated
  primitives (ADR 0020).
- The wrap grows from a raw counter-mode blob to 76 bytes of metadata per object. Nobody
  will notice; it is stated so nobody has to rediscover the layout.
- Two HKDF expansions per wrap and one per unwrap are added to a path that had none. Both
  are cheap next to the data layer, and neither has been measured yet.

## Alternatives Considered

**Keep both providers and change only the fingerprint.** The smallest change, and the one
already planned before this round. It leaves the malleable wrap in the one release allowed
to change the wrapped-key layout, so a later fix would be a *second* format break and a
second forced re-upload. It also leaves base64-of-a-passphrase passing the new key rule.
Rejected: the whole point of a format-breaking release is to spend it once.

**Keep both providers, harden the symmetric one.** Closes both key-layer defects in
standard-library code and changes no deployment file. Rejected because it keeps
everything that is wrong with the asymmetric provider — the millisecond unwrap on every
cache miss, the absent encrypt-only mode, its own fingerprint defect, PEM parsing and a
second integration suite — in exchange for a property nobody uses.

**Remove the symmetric provider and keep the asymmetric one, plus a future KMS.** The
owner's first instinct, and the option that makes the weak-key class structurally
impossible: a key pair cannot be typed or pasted. Rejected on what it buys: both halves of
the pair sit in the same secret, so a compromised process or configuration yields
everything either way; the millisecond unwrap becomes the floor for every cold read; the
harvest-now-decrypt-later exposure of RSA-2048 is real for a backend that keeps ciphertext
forever; and every shipped default would have to move off the fast path, for the largest
blast radius of any option on the table, with no KMS available at the time of the release.

**Remove the asymmetric provider *and* rename the surviving one** (a `local` type with a
versioned key string). Cryptographically identical to what was decided; the rename is the
entire cost, paid across charts, examples, end-to-end configuration and a few dozen tests,
on top of a forced re-upload. Rejected: the version belongs in the stored format, which
already carries one.

**KMS only.** The only option that changes what a compromised pod yields. Rejected on
sequencing — no KMS-backed provider exists yet, it is scheduled after the format change,
and making the key service a hard dependency turns its availability into read
availability. It remains the direction of travel (ADR 0005), not a replacement for this
decision.

**Sanction passphrases and price them with Argon2id.** Raises the cost per guess. Rejected
because the adversary works offline and forever against a wrapped key plus a tag: a
32-character passphrase is 40 to 60 bits of entropy, and no work factor survives that
asymmetry. The product refuses passphrases instead of pricing them.

**A deterministic key wrap (AES-KWP, RFC 5649) instead of GCM with a per-wrap salt.**
Genuinely attractive: 40 stored bytes instead of 76, no nonce and no message bound at all.
It lost on dependencies — it is not in the standard library, and the only third-party
library in the product that provides it is itself a candidate for removal for unrelated
reasons, a decision that is still open. If it goes, the wrap would be about eighty
self-written lines of a key-wrap primitive plus test vectors to maintain, and a wrap format
must not depend on a library decision taken after it. The
salted GCM construction uses the standard library only, and it is the same primitive
family as the data layer and as what key management services use internally.

## Residual risks

- **The key admission rules are a heuristic, not an entropy proof.** A passphrase
  containing non-ASCII bytes passes the printable-ASCII rule, and a deliberately weak
  binary key with enough distinct bytes passes everything. The rules catch the accidental
  passphrase; the user-facing documentation must say exactly that and must not claim more.
- **A derived fingerprint does not protect a weak key.** The derivation is deterministic
  and public, so anyone guessing the key can compute the published value and confirm the
  guess. The oracle exists regardless — the wrapped data key and one authentication tag
  are enough. Deriving the fingerprint removes the *raw hash* of the key from the
  metadata; it does not remove the offline attack, which is why the entropy rules are the
  substantive part of this decision.
- **The fingerprint still links deployments.** Two buckets, or two installations, carrying
  the same value provably share a master key. Accepted: selecting the right provider on
  read requires a stable public identifier.
- **The master key remains in process memory and in the configuration or secret for the
  process lifetime.** Nothing in this decision changes that; only a KMS-backed provider
  does (ADR 0005).
- **Metadata corruption remains a denial of service.** An authenticated wrap improves the
  *attribution* of a tampered wrapped key — it is now a named metadata error before any
  body byte is read — not the availability of the object.
- **Same-key object substitution across buckets or deployments is out of scope here.** It
  is a property of what the data layer binds into its associated data, not of the key
  layer, and the answer to it is one master key per deployment.
- **Not verified:** that no external deployment uses the asymmetric provider. The claim is
  that no shipped chart, compose file, example or end-to-end configuration does, which was
  checked; external installations cannot be enumerated. The removal is therefore a
  breaking change for an unknown, believed-empty set of users.
- **Not verified:** the roughly 2,400× unwrap ratio between the two providers comes from a
  benchmark that was run and never committed. The order of magnitude decided nothing on
  its own, but the number should not be quoted as a measured product figure.
- **Not measured:** the cost of the two added HKDF expansions per wrap and the one per
  unwrap. It is expected to be lost in the noise of the data layer; ADR 0020 governs, and
  the read path is being measured after the format change for other reasons anyway.
- **Left unspecified:** whether the HKDF labels and the wrap associated data follow a
  configured metadata prefix. They are written here as fixed constants — they are part of
  the stored format, not of the metadata namespace of ADR 0009 — and nothing in the
  sources says otherwise; an implementer who reads them as configurable would produce a
  format that changes with a configuration key, which is not intended.

## References

- ADR 0001 — The S3 backend is hostile, and only the proxy's own verification counts
- ADR 0002 — One data key per object, wrapped by a configured key encryption key
- ADR 0003 — Objects are stored as an authenticated segment chain
- ADR 0005 — A KMS-backed key encryption key is a provider, not a mode
- ADR 0009 — The metadata prefix is the proxy's namespace
- ADR 0013 — A configuration key exists only if code reads it, and an unworkable configuration refuses to start
- ADR 0017 — Stored data compatibility is not owed; a major release may break the format
- ADR 0020 — Performance is measured before and after, never asserted
- ADR 0021 — Key material and licenses are generated, never committed
- [README.md](../../README.md) — provider reference and key generation
- [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md) — key providers, where each secret lives, rotation, and the hardening checklist
