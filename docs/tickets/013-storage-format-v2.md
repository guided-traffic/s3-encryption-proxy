# Ticket 013: Storage format v2 — segmented AES-GCM

## Status (2026-09-06)

**Open.** This is the central ticket that follows the Velero e2e work, which is
on `main`. It replaces the stored-object format: one
AES-256-GCM segment chain per object instead of the current AES-GCM-whole /
AES-CTR + whole-object-HMAC split. It depends on nothing else in the repository,
but three other tickets are explicitly scheduled **after** it because they would
otherwise be written against code this ticket deletes: the `ListObjectsV2`
rewrite (D-11/P-4), handler-level unit coverage (D-17), and filename encryption.
That work and the pre-merge fixes this ticket depends on are on `main` at HEAD;
PR #330 squashed `feat/velero-support-and-tests`, which is no longer an ancestor
of `main`.

**Decided 2026-09-06 (repository owner):**

- The [precondition](#precondition-rule-3) holds: no production users are
  known. v2 ships as a **major release** whose release notes state that objects
  written by earlier versions are not readable. No read-only v1 path is built.
  The release is **5.0.0**, collected on `feat/major-v5` together with the other
  migration-forcing tickets — [ticket 023](023-major-v5.md) is the bundle.
  (It was going to be 4.0.0; `v4.0.0` was cut on 2026-09-07 from the coverage
  round, PR #331, and carries none of this ticket — D-30 and D-22 were its only
  breaking changes. Objects written by 3.x and by 4.0.x are equally unreadable
  under v2. The branch forks from `main`, not from the Velero branch, which PR
  #330 squashed.)
- `InvalidObjectState` is answered with HTTP **403**, as AWS documents the
  code, not 409.
- The `aes` KEK fingerprint becomes `HMAC-SHA256(KEK, "s3ep-kek-fingerprint")`
  (H-8, [open question 11](#risks-and-open-questions)).
- The `rsa` fingerprint fix from [ticket 022](022-s3-surface-fidelity.md)
  item 8 (one byte of the exponent) ships here too, as `SHA-256` over the DER
  `SubjectPublicKeyInfo`: a second fingerprint change after the major release
  would be a second format break.
- Risk 1 (trailer vs. the 5 MiB part minimum): the claim that MinIO does not
  enforce the minimum was **refuted by test** the same day, so the integration
  suite proves the short-part re-upload. **The re-upload is approved**, on
  the condition that the proxy's memory footprint is held by an automated
  test, not by a manual measurement — see the memory test under
  [Success criteria](#success-criteria) and the two buffer bounds in
  [write path 3](#3-client-driven-multipart).

**Decided 2026-09-07 (repository owner, D-32, [023](023-major-v5.md) decision 2):**

- **The `rsa` provider type is removed in 5.0.0.** It requires both PEMs, so the
  one property asymmetry could add (an encrypt-only writer) does not exist; it
  unwraps ~2,400× slower, sits at a 112-bit floor under a 256-bit DEK, is the
  one primitive a forever-archiving backend can plausibly break later, and no
  shipped Helm, compose or e2e file uses it. `rsa.go`, its tests, the `rsa` arms
  in factory, providers and config, `config/rsa-example.yaml`, the `rsa` half of
  `multi-example.yaml` and `test/integration/encryption-modes/rsa_provider_test.go`
  go. The RSA fingerprint fix from 022 item 8 (bullet above) is void.
- **`aes` is the only local provider and is hardened — work item 2c.** The
  fingerprint decided under open question 11 changes its byte layout (it is
  implemented nowhere): `prk = HKDF-Extract(salt = "", ikm = KEK)`,
  `fingerprint = hex(HKDF-Expand(prk, "s3ep-kek-fingerprint", 32))`. The DEK
  wrap becomes authenticated (024 S-2, which this ticket had left "exactly as
  today"): a fresh 16-byte salt per wrap, `wrapKey = HKDF-Expand(prk,
  "s3ep-kek-wrap-v1" ‖ salt, 32)`, `wrapped = salt ‖ AES-256-GCM(dek)` through
  `cipher.NewGCMWithRandomNonce` with AAD `"s3ep-dek-wrap-v1"`, 76 bytes in
  `encrypted-dek`. The per-wrap salt removes the SP 800-38D bound of 2^32 wraps
  per key, which nothing in the tree could count. Key admission adds two
  checks to D-21: the 32 decoded bytes must not all be printable ASCII (a
  keygen key hits this with probability (95/256)^32 ≈ 2^-46) and must contain at
  least 16 distinct byte values; the error names `s3ep-keygen` and says that
  base64 of a hex string is refused too. Names `aes` and `aes_key` stay.
- Vault is unaffected: a KMS-backed KEK stays a separate provider type
  ([025](025-tink-kms-hcvault.md), after v5), and the local key can be injected
  from Vault through `${S3EP_AES_KEY}` today.
- **The bucket stays out of the AAD (D-33).** The owner's rule: the bucket name
  plays no role in encryption or decryption. Risk 8 below is the accepted
  residual and is written into `SECURITY_ARCHITECTURE.md` H-3 by work item 12.
- **A client key inside the metadata prefix is refused (D-34, 024 H-5).** Work
  item 4a: `400 InvalidArgument` on PUT and CreateMultipartUpload. The
  case-sensitive compare on the single-part paths is fixed on `main` before this
  ticket starts, not here.

---

## Before you start

Checked against the tree on 2026-09-07. Where the fix was unambiguous the text
above and below is already corrected; these are the claims that were wrong.

- "Follows the Velero e2e work on `feat/velero-support-and-tests`, the
  pre-merge fixes landed on the branch": everything this ticket waits for is on
  `main` at HEAD (`test/e2e/velero/`, the handler fixes). PR #330 squashed that
  branch and it is no longer an ancestor of `main`. Corrected in Status.
- Risk 10 said handler coverage is 9.2 %. `go test -short -cover
  ./internal/proxy/handlers/object/` reports **98.0 %** over 13 test files, so
  items 3–9 rewrite a unit suite too, not only integration and e2e. Corrected.
- "The response body is aborted mid-stream — exactly what the HMAC path does
  today" (read path, risk 2): not the same thing. Today's validating reader
  withholds only the final chunk and can fail there in `strict`; every earlier
  byte is already delivered unverified, `lax` hands the tail over and only logs,
  and ranged reads are not verified at all. Aborting at an arbitrary point in
  the body is new. Corrected in both places.
- "With integrity verification on the CTR boundary is 5 MiB whatever
  `streaming_threshold` says" (open question 12): anything from
  `streaming_threshold` up to 5 MiB still takes CTR through
  `putObjectStreamingReader`; only 5 MiB and above goes to auto-multipart.
  Corrected.
- "Decrypt-time provider selection needs `GetProviderByFingerprint`" (open
  question 11): that function has one caller and it is on the encrypt side.
  Decrypt-time selection is `DecryptDEK` → `factory.GetKeyEncryptor`. The
  conclusion — each provider computes its own value — is unchanged. Corrected.
- pprof no longer sits on the monitoring port: it has its own listener, bound to
  a loopback address inside the container (`127.0.0.1:6060`, non-loopback is a
  startup error). The before/after profiles need a port-forward or an exec.
  `/metrics` on `:9090` is unchanged, so the memory test's endpoint stands.

---

## Context

The proxy is deployed against an S3 endpoint that is treated as **hostile**, not
merely untrusted: the backend can read every byte, change any byte, swap
objects, serve stale versions, truncate, and lie in listings and in metadata.
Nothing the backend says counts as authentication. Three rules follow, and they
are the ones this ticket is measured against:

1. Integrity means *the proxy* verifies. "Authenticated by the backend and by
   TLS" is not integrity under this model, because the backend is the adversary.
2. A control that exists only in configuration or documentation is worse than no
   control, because it gets relied upon.
3. The stored-object format may change without a migration path. See
   [Precondition](#precondition-rule-3) below — this one is an assumption, and
   it has a stated fallback.

Under those rules the format shipped today fails for any S3 client that reads
ranges:

- A ranged read of an `aes-ctr` object returns bytes the proxy cannot
  authenticate. The whole-object HMAC in `s3ep-hmac` covers the whole object, so
  a partial read is checked against nothing
  ([rangeread.go:39](../../internal/orchestration/rangeread.go#L39) documents this
  as a deliberate tradeoff). kopia — the uploader Velero uses for volume data —
  reads its pack blobs with small ranged GETs, so **every Velero volume restore
  consists of unauthenticated reads** (D-1, P-1).
- Integrity is separable from decryption, so the backend can strip one metadata
  key to switch it off. `integrity_verification: hybrid` accepts an object
  without `s3ep-hmac` as legacy
  ([hmac_manager.go:116](../../internal/validation/hmac_manager.go#L116) — the
  branch is unreachable, see [open question 12](#risks-and-open-questions)); `lax`
  delivers data whose verification failed
  ([hmac_manager.go:142](../../internal/validation/hmac_manager.go#L142)) (N-2).
- Worse: an object with **no** proxy metadata at all is handed to the client as
  plaintext, under an encrypting provider
  ([manager.go:186](../../internal/orchestration/manager.go#L186),
  `isNoneProviderData` at
  [singlepart.go:327](../../internal/orchestration/singlepart.go#L327), and the
  range path at [range.go:141](../../internal/proxy/handlers/object/range.go#L141)).
  A hostile backend strips the metadata and substitutes the body (N-1).
- Re-uploading a multipart part would reuse the AES-CTR keystream. The CTR
  counter is derived from the sequential byte offset
  ([multipart.go:300](../../internal/orchestration/multipart.go#L300)), so a second
  encryption of part *n* is a two-time pad. Today the retry hangs instead
  ([multipart.go:290](../../internal/orchestration/multipart.go#L290), a `select`
  with no context case), so the reuse is latent, not absent (N-3, P-2).

Documentation does not close any of this. The only construction that keeps both
ranged reads for any S3 client and integrity is a format in which every byte at rest is
authenticated at a granularity ranged reads can use. That is what this ticket
builds.

---

## Scope

**In scope — this ticket closes:**

| Item | What it is |
|---|---|
| D-1 / P-1 | Ranged reads cannot verify the object HMAC |
| P-2 | UploadPart retry or part-number gap hangs the request |
| P-7 | `ListParts` fabricates an empty result, `ListMultipartUploads` is 501 |
| D-10 | Ranged GET of an AES-GCM object costs two backend requests |
| N-1 | GET falls back to pass-through when the encryption metadata is missing |
| N-2 | `integrity_verification: hybrid` / `lax` are downgrade paths |
| N-3 | Re-uploaded multipart part would reuse the CTR keystream |

**In scope — deletions** (no backward compatibility is wanted; dead code goes):

- the post-Complete self-`CopyObject` in both completion paths
  ([complete.go:223](../../internal/proxy/handlers/multipart/complete.go#L223),
  [operations.go:1505](../../internal/proxy/handlers/object/operations.go#L1505));
- the GCM/CTR split in
  [internal/orchestration/singlepart.go](../../internal/orchestration/singlepart.go)
  (`EncryptGCM`, `EncryptCTR`, `DecryptGCMStream`, `DecryptCTRStream`,
  `isNoneProviderData`, `createStreamingEncryptor`, `createStreamingDecryptor`);
- the CTR range reader:
  [internal/orchestration/rangeread.go](../../internal/orchestration/rangeread.go)
  in full, plus `NewCTRStreamAt` / `NewCTRRangeReader` / `addCounter`
  ([aes_ctr.go:262-315](../../pkg/encryption/dataencryption/aes_ctr.go#L262));
- `internal/validation/hmac_calculator.go`, `internal/validation/hmac_manager.go`
  and `internal/validation/hkdf.go` with their tests — `hkdf.go` has no caller
  outside its own package today, and the package-level `DeriveIntegrityKey`
  ([hkdf.go:187](../../internal/validation/hkdf.go#L187)) has none at all; only the
  `HKDFConfig` methods are exercised, by `hkdf_test.go`. `HMACManager` derives
  its key with its own inline HKDF
  ([hmac_manager.go:55](../../internal/validation/hmac_manager.go#L55));
- `hmacValidatingReader` and `hmacGatedDecryptionReader`
  ([streaming_io.go:63](../../internal/orchestration/streaming_io.go#L63),
  [streaming_io.go:254](../../internal/orchestration/streaming_io.go#L254)), plus
  the already-dead `DecryptMultipartWithHMACVerification`
  ([multipart.go:755](../../internal/orchestration/multipart.go#L755)),
  `createStreamingDecryptionReader`
  ([multipart.go:831](../../internal/orchestration/multipart.go#L831)),
  `shouldValidateHMACEarly` / `validateHMACEarly`
  ([operations.go:207](../../internal/proxy/handlers/object/operations.go#L207));
- the config keys `encryption.integrity_verification`
  ([config.go:70](../../internal/config/config.go#L70), default at
  [config.go:357](../../internal/config/config.go#L357), validation at
  [config.go:541](../../internal/config/config.go#L541)) and
  `optimizations.streaming_threshold`
  ([config.go:122](../../internal/config/config.go#L122), default at
  [config.go:344](../../internal/config/config.go#L344), accessor
  `GetStreamingThreshold` at [config.go:874](../../internal/config/config.go#L874)).
  `optimizations.streaming_segment_size`
  ([config.go:119](../../internal/config/config.go#L119)) **stays** as the
  auto-multipart backend part size, with its validation
  ([config.go:644](../../internal/config/config.go#L644)) extended to require a
  multiple of 64 KiB.

**Out of scope** (each has its own ticket, all scheduled after this one):

- D-11 / P-4 — `ListObjectsV2` document rewrite and plaintext sizes. This ticket
  supplies the pure size function it needs, and nothing more.
- D-9 / P-5 / D-16 — upload checksum verification.
- D-6 / D-7 / N-5 — configuration hygiene.
- P-10 — the Helm chart.
- Filename encryption (directory-only form). This format is designed so that
  ticket costs nothing later: the AAD binds the *client's* key, so encrypting
  names never touches a stored object.
- D-19 — per-chunk signatures in aws-chunked uploads stay unverified; v2 does
  not change that leg.
- N-8 — the 30 s `ReadTimeout` / `WriteTimeout`
  ([server.go:138-139](../../internal/proxy/server.go#L138)). Not touched here.

---

## Precondition (rule 3)

**Confirmed by the repository owner on 2026-09-06:** no production users are
known, so no deployment holds data at rest that must stay readable across the
format change. v2 ships as **5.0.0**; the release notes state that objects
written by 3.x and 4.0.x are not readable under v2 and must be uploaded again
through the new proxy. "No backward compatibility" (CLAUDE.md)
covers stored objects, not only APIs.

Kept for the record — the fallback that would have applied had the assumption
failed, and which is **not** built: a **read-only v1 decrypt path** until every
object has been re-encrypted:

- `DecryptData` keeps the `aes-gcm` and `aes-ctr` branches and the whole-object
  HMAC verification for objects that carry `s3ep-dek-algorithm: aes-gcm` or
  `aes-ctr`, in `strict` semantics only (no `lax`, no `hybrid`, no
  pass-through — N-1 and N-2 still apply);
- ranged reads of v1 objects are served by full decryption
  ([range.go:200](../../internal/proxy/handlers/object/range.go#L200)), i.e. the
  D-1 gap is closed by making v1 ranged reads slow rather than unverified;
- writes are v2 only, from day one;
- the v1 path is deleted in a follow-up ticket once a documented re-encryption
  pass has run.

Nothing else in this ticket changes. The rest of the document is written for the
confirmed case.

---

## The format

One object = a chain of segments followed by a trailer, all under one random
per-object DEK, envelope-wrapped by the KEK exactly as today
([providers.go:160](../../internal/orchestration/providers.go#L160)).

| Element | Layout | Size |
|---|---|---|
| Segment *i* | `nonce(12, random)` ‖ `AES-256-GCM(plaintext, ≤ S)` ‖ `tag(16)` | 28 + plaintext bytes |
| Trailer | `nonce(12)` ‖ `AES-256-GCM(uint64 BE total plaintext length)` ‖ `tag(16)` | 36 |

`S = 65536` bytes (64 KiB) of plaintext per segment. **S is a constant of the
format, not a configuration value.** Overhead is 28 B per 64 KiB = 0.043 %, plus
36 B per object. rclone crypt uses the same segment size for the same reason:
it is the knee where per-segment overhead is already negligible and the working
set still fits comfortably in cache ([rclone crypt](https://rclone.org/crypt/)).

### Associated data

Every AEAD invocation in the object binds the same three things:

```
AAD = formatID ‖ clientObjectKey ‖ index
```

- `formatID` — the fixed ASCII string `s3ep-gcm-seg-v2`, 15 bytes, also the
  value written to `dek-algorithm` (below). Fixed length, so the concatenation
  needs no length prefix.
- `clientObjectKey` — the object key **as the client named it**, UTF-8, no
  bucket. Variable length.
- `index` — 8 bytes big-endian. For segment *i* it is `plaintextOffset / S`. For
  the trailer it is `0xFFFFFFFFFFFFFFFF`, a value no segment index can reach (a
  5 TiB object has 2^26.3 segments), which gives the trailer its own domain
  without changing the AAD shape.

Fixed-length prefix and fixed-length suffix around one variable field make the
encoding unambiguous.

**Why the key is in the AAD.** It stops a hostile backend from serving object
A's ciphertext under B's name — it can copy A's metadata too, so the metadata
alone binds nothing. It is the *client's* key, not a backend key, so a later
filename-encryption layer changes nothing for stored objects.

**Why the bucket is not.** A ciphertext bucket can then be replicated or copied
wholesale to another bucket or another provider for disaster recovery without
re-encryption.

**Residual, to be written into `SECURITY_ARCHITECTURE.md`:** the backend can
still swap two objects that have the same key across two buckets served by the
same KEK, and it can serve an older version of the same key (rollback). No AEAD
prevents rollback. The client's own consistency checks — kopia's on a Velero
restore, for example — are the only defence there.

### Why random inline nonces, not Tink's derived nonces

Tink's AES-GCM-HKDF streaming construction
([spec](https://developers.google.com/tink/streaming-aead/aes_gcm_hkdf_streaming))
derives each nonce from a per-object prefix and the segment counter. That
assumes a single sequential writer. S3 multipart is not that: a part can be
uploaded again with different content, and a retry after a half-received request
is normal SDK behaviour. A derived nonce would then be reused with a different
plaintext, which for GCM costs the confidentiality of **both** plaintexts and
the authentication key for that object. This is N-3 in a new costume, and it is
the reason the construction is not copied verbatim.

A random 96-bit nonce per segment removes the case entirely and costs 12 bytes
per 64 KiB. The NIST SP 800-38D random-nonce bound of 2^32 invocations per key
is far away: a 5 TiB object has about 2^26.3 segments, and the DEK is per
object.

XChaCha20-Poly1305 (random-nonce-safe by design) was considered and rejected:
roughly 2 to 4 times slower than hardware AES-GCM at this segment size, for a
margin that is already sufficient.

### Alternatives rejected

The two crypto-level rejections are above (Tink's derived nonces,
XChaCha20-Poly1305). Three design-level alternatives were considered and are not
coming back; they are recorded because each one is a first objection a reader
raises against v2.

**Keep AES-CTR + HMAC and add per-segment HMAC tags.** This is option 2 of D-1:
one tag per block, so a range can be checked against the segments it overlaps.
It reaches the same property as v2 and pays more for it. Two primitives instead
of one, and the slower of the two does the integrity work — CTR then
HMAC-SHA256 is two passes over the data where AES-GCM on AES-NI or PMULL is one.
The layout work is identical: a segment grid, a new stored format, a rewritten
read path, part-boundary rules for multipart. And nothing in the deletion list
above becomes possible — `internal/validation/`, `rangeread.go` and the GCM/CTR
split in `singlepart.go` all survive. Same cost, no simplification.

**Store a per-object part layout instead of constraining part sizes.** The read
path has to know where segment *i* lives. If client parts may have any size,
that mapping must be stored somewhere. Three places were considered, each worse
than the arithmetic:

- *After Complete, by self-copy* — the mechanism the proxy uses today to attach
  the late-bound HMAC
  ([operations.go:1326](../../internal/proxy/handlers/object/operations.go#L1326)
  on the auto-multipart path,
  [complete.go:234](../../internal/proxy/handlers/multipart/complete.go#L234) on
  the client-driven one). It is a full server-side rewrite of every multipart
  object and it carries the >5 GiB hard failure ([ticket
  012](012-performance-audit-round2.md) Tier 3.1). This ticket deletes it;
  storing a layout that way would keep it.
- *In object tags* — new machinery on both sides: the proxy answers all three
  object-tagging verbs with 501 today
  ([tagging.go:64](../../internal/proxy/handlers/object/tagging.go#L64)). The
  recorded reason against it is that object tagging is not supported by several
  S3-compatible targets; that claim is not verified against a named target in
  this repository.
- *In the trailer, read before every ranged GET* — one extra backend round trip
  per range, which is D-10 reintroduced under another name, or a per-object
  layout cache whose invalidation would have to hold against a backend that may
  change the object underneath it.

All three add state to answer a question that the part-size rule in
[write path 3](#3-client-driven-multipart) answers arithmetically and checks
once, at Complete. State that exists only to describe the object is also state
the backend can lie about.

**D-1 option 3 — refuse ranged reads of HMAC-protected objects in `strict`.**
Correct on paper, and it re-breaks ranged reads for every S3 client that issues
them: kopia reads its pack blobs with small ranged GETs, so every Velero volume
restore fails — the code says so at the point where the tradeoff was made
([rangeread.go:42](../../internal/orchestration/rangeread.go#L42)). It would also
require `strict` to stop being what the shipped configuration recommends: every
encrypting example sets `integrity_verification: "strict"`
([README.md:416](../../README.md#L416),
[config/aes-example.yaml:100](../../config/aes-example.yaml#L100)) while the code
default is `off` ([config.go:357](../../internal/config/config.go#L357)). An
integrity guarantee that holds only in one configuration, and only if that
configuration diverges from the examples the project ships, is rule 2 of the
Context above.

**D-1 option 4 — serve a range by reading and verifying the whole object.**
Correct, and pathological for any client that reads small ranges: a 32-byte read of a 20 MiB kopia
pack blob costs 20 MiB of backend traffic and a full decrypt on every read. v2
bounds that same read at 2·S = 128 KiB. Option 4 survives in exactly one place —
as the v1 fallback if the [precondition](#precondition-rule-3) does not hold,
where slow-but-verified beats fast-but-unverified on a path that is being
retired anyway.

### Metadata

| Key (with the configured prefix, default `s3ep-`) | Value |
|---|---|
| `encrypted-dek` | base64 of the KEK-wrapped DEK |
| `dek-algorithm` | `s3ep-gcm-seg-v2` — the format id |
| `kek-algorithm` | as today |
| `kek-fingerprint` | **changed for `aes`** (open question 11, decided): `hex(HMAC-SHA256(KEK, "s3ep-kek-fingerprint"))` replaces `hex(SHA-256(KEK))`. **Changed for `rsa`** (ticket 022 item 8, moved here 2026-09-06): `hex(SHA-256(DER SubjectPublicKeyInfo))` replaces the hand-built `N ‖ byte(E)` hash — the public key is public, so no HMAC is needed, and the DER form is what `openssl` and `ssh-keygen` fingerprint, so an operator can recompute it from the PEM. `tink` (hash of the KEK URI, [tink.go:134](../../pkg/encryption/keyencryption/tink.go#L134)) stays |

All four are known at `PutObject` and at `CreateMultipartUpload` time, because
the DEK is generated before the backend call and `EncryptDEK`
([providers.go:160](../../internal/orchestration/providers.go#L160)) takes only the
DEK and the object key, never the ciphertext. **That is what removes the
self-`CopyObject`.**

Gone: `aes-iv` (there is no per-object IV any more; each segment carries its own
nonce) and `hmac` (integrity is not separable from decryption). Both must be
removed from `BuildMetadataForEncryption`
([metadata.go:41](../../internal/orchestration/metadata.go#L41), the `aes-iv` write
at [metadata.go:57](../../internal/orchestration/metadata.go#L57)), from `GetIV`
([metadata.go:177](../../internal/orchestration/metadata.go#L177)), from
`GetHMAC`/`SetHMAC`/`HasHMAC`
([metadata.go:220](../../internal/orchestration/metadata.go#L220)), and from the
`IsEncryptionMetadata` filter list
([metadata.go:305](../../internal/orchestration/metadata.go#L305)) — the filter is
what keeps proxy metadata out of client responses, so the two keys have to
leave it together with everything else. `CLAUDE.md`'s metadata list is updated
in the same change.

### Size is a pure function of the stored size

```
n = ceil((C - 36) / (S + 28))          number of segments
P = C - 36 - 28 * n                    plaintext length
```

with `C` the stored object length. Derivation: `C = 36 + 28n + P` and
`(n-1)·S < P ≤ n·S`. An empty object stores `C = 36`, `n = 0`, `P = 0`.

This replaces `ComputePlaintextSize` / `ComputeCiphertextSize`
([ciphertext_size.go:13](../../pkg/encryption/ciphertext_size.go#L13)) and is what
lets HEAD ([operations.go:754](../../internal/proxy/handlers/object/operations.go#L754)),
GET and — with D-11 later — LIST report the plaintext length **without a
per-object round trip**.

The trailer is not redundant with this function: the function converts a length
the backend reports, and the backend is the adversary. The trailer is the
authenticated copy, checked on every whole-object read, so truncation or
extension at any segment boundary is detected.

---

## The read path

A range `[a, b]` over the plaintext maps to segments `a/S .. b/S`, which occupy
one contiguous ciphertext window:

```
segFirst = a / S
segLast  = b / S
byteFrom = segFirst * (S + 28)
byteTo   = min(segLast + 1, n) * (S + 28) - 1
```

One `GetObject` with `Range: bytes=byteFrom-byteTo`, then for each segment:
verify the GCM tag with the AAD built from its own index, and slice
`[a - segFirst*S : ...]` out of the concatenated plaintext.

- **Read amplification is at most 2·S = 128 KiB**, against up to 12 MiB if the
  unit of authentication were the backend part.
- Every returned byte is authenticated by the proxy. D-1 has no residue left to
  document.
- **A segment that fails its tag, or whose index does not match the position it
  was fetched from, is an error.** Bytes already written to the client are not
  retractable, so the response body is aborted mid-stream. That is new for
  everything but the tail: today's HMAC path withholds only the final chunk and
  fails there in `strict`, and verifies no ranged read at all.
- Whole-object reads verify every segment **and** the trailer, and check the
  trailer's length against the bytes produced.
- D-10 disappears: there is no algorithm for which a ranged read costs a second
  backend request. `handleGetObjectRange`
  ([range.go:115](../../internal/proxy/handlers/object/range.go#L115)) loses its
  `algorithm != "aes-ctr"` branch
  ([range.go:150](../../internal/proxy/handlers/object/range.go#L150)) and
  `serveRangeByFullDecryption` ([range.go:200](../../internal/proxy/handlers/object/range.go#L200))
  is deleted.
- The GET handler loses its algorithm fork
  ([operations.go:93](../../internal/proxy/handlers/object/operations.go#L93)):
  `handleGetObjectStreamingDecryption`
  ([operations.go:108](../../internal/proxy/handlers/object/operations.go#L108))
  and `handleGetObjectMemoryDecryption`
  ([operations.go:269](../../internal/proxy/handlers/object/operations.go#L269))
  collapse into one path.

### N-1: fail closed

Under an **encrypting** provider, an object that does not carry the proxy's
metadata is an **error** on GET, on HEAD and on ranged GET. Not a warning, not a
pass-through, and **no opt-out knob** — a knob here is rule 2 exactly.

- Error code: `InvalidObjectState`, HTTP **403**, message
  `Object is not encrypted by this proxy`. It is a real S3 code (aws-sdk-go-v2
  models it as `types.InvalidObjectState`), so SDKs map it rather than choking;
  it is documented in the README as the proxy's meaning for it, and it is
  distinct from `NoSuchKey` (the object exists) and from `AccessDenied` (the
  client is allowed, and that code is the one the auth layer uses). The status
  follows AWS, which documents this code with 403 (it is the archived-object
  error on GET) — decided 2026-09-06, so the README documents the proxy's
  meaning of the code, not a status deviation.
- Applies wherever `extractEncryptionMetadata`
  ([helpers.go:35](../../internal/proxy/handlers/object/helpers.go#L35)) returns
  `false` today, and replaces the pass-through at
  [operations.go:63](../../internal/proxy/handlers/object/operations.go#L63),
  [range.go:141](../../internal/proxy/handlers/object/range.go#L141) and
  [manager.go:186](../../internal/orchestration/manager.go#L186).
- An object whose `dek-algorithm` is not `s3ep-gcm-seg-v2` gets the same
  treatment.
- Only the `none` provider passes an object through, and it passes through
  everything, as it does today. `none` remains a testing and end-of-life aid
  (CLAUDE.md), not a production mode (D-13).
- A bucket holding pre-existing plaintext objects is migrated once **through**
  the proxy, by a documented procedure — never read in place.

---

## The write paths

All three produce the identical byte layout. The DEK, the wrapped DEK and the
full metadata set exist before the first backend byte is sent, in all three.

### 1. Single `PutObject`

Read plaintext, emit segments as they fill, append the trailer, one pass, no
buffering beyond one segment. Replaces both `putObjectDirect`
([operations.go:537](../../internal/proxy/handlers/object/operations.go#L537)) and
`putObjectStreamingReader`
([operations.go:609](../../internal/proxy/handlers/object/operations.go#L609)),
and with them the whole size-based routing block at
[operations.go:446-524](../../internal/proxy/handlers/object/operations.go#L446)
including the `streaming_threshold` comparisons and the forced-CTR content-type
special cases. The stored length is known in advance from the plaintext length,
so `Content-Length` on the backend PUT stays exact.

Routing after the change: today auto-multipart is entered on an unknown
`Content-Length` **or** on "HMAC enabled and plaintext >= 5 MiB under an
encrypting provider"
([operations.go:482-489](../../internal/proxy/handlers/object/operations.go#L482)).
The HMAC half of that condition goes with the HMAC, so what is left is: unknown
`Content-Length`, or a plaintext above `streaming_segment_size`, goes to
auto-multipart — a single PutObject needs a known length and a >5 GiB object
needs multipart regardless.

### 2. Auto-multipart (large single PutObject from any client — kopia's path, for example)

`putObjectAutoMultipart`
([operations.go:1212](../../internal/proxy/handlers/object/operations.go#L1212))
keeps its shape — the proxy picks the backend part size from
`streaming_segment_size` (12 MiB default, validated to be a multiple of S) — and
loses:

- the `CreateMultipartUpload` without metadata: the four metadata keys now go
  into `CreateMultipartUploadInput.Metadata`
  ([create.go:61](../../internal/proxy/handlers/multipart/create.go#L61) for the
  client-driven twin);
- the self-`CopyObject` at
  [operations.go:1505](../../internal/proxy/handlers/object/operations.go#L1505),
  and with it the full-object server-side rewrite on every multipart upload and
  the **>5 GiB hard failure** ([ticket 012](012-performance-audit-round2.md)
  Tier 3.1, "item 5" in the findings doc);
- the sequential-encryption constraint. Segments are independent, so parts can
  be encrypted in parallel and the pipeline no longer needs encryption to be
  serialized ahead of the upload workers.

The trailer is appended to the last part the proxy builds. Because the proxy
chooses the parts here, that part is always the last one and no extra part is
needed.

### 3. Client-driven multipart

**Every client part becomes exactly one backend part.** A retried or re-uploaded
part replaces its own backend part and nothing else, which is what dissolves
both P-2 and N-3: there is no ordered pipeline, no `PendingParts`, no blocking
`select`, and re-encrypting part *k* produces fresh random nonces at the same
plaintext offsets, which is safe.

The encryptor of part *k* needs the plaintext offset `(k - 1) * partSize`. It
takes `partSize` from the largest part size seen in the session so far — every
known uploader dispatches part 1 before the last part, so the size is known
before a short last part arrives — and **records the offset it used** in the
session part table.

At `CompleteMultipartUpload` the proxy checks, against the final part table,
that:

1. every part except the highest-numbered one has the same plaintext size;
2. that size is a multiple of S;
3. every recorded offset agrees with `(k - 1) * partSize`;
4. part numbers are contiguous from 1.

A violation fails Complete with `InvalidPart` and aborts the upload, so **no
object is ever created with a layout the read path cannot verify**. Clients get
at most 9999 parts (one is reserved for the trailer; see below).

The rule holds for every uploader checked: aws-sdk-go-v2 `manager.Uploader`
(Velero, 5 MiB), minio-go (rounds part sizes up to 16 MiB multiples,
[minio-go](https://pkg.go.dev/github.com/minio/minio-go/v7)), aws-cli (8 MiB),
rclone (5 MiB), restic (via minio-go). Known exception: aws-sdk-go-v2 switches
to `size/10000 + 1` bytes per part above 48.8 GiB with its default part size
([manager/upload.go](https://github.com/aws/aws-sdk-go-v2/blob/main/feature/s3/manager/upload.go));
such an upload fails at Complete with a clear message, and the README says to
set an aligned `PartSize` for objects that large. Any client that drives
multipart with the SDK's default part size can hit it; within Velero it is only
Velero's own uploader (kopia sets `DisableMultipart: true`, N-7, and never uses
this path).

**Attaching the trailer.** The trailer is 36 bytes and must be the last bytes of
the object. Two cases, and the second is the one the findings doc's one-line
"upload the trailer as one extra part" does not cover:

- the client's last part is **≥ 5 MiB**: upload the trailer as part
  `lastPartNumber + 1`. The client's last part becomes a middle part and still
  satisfies S3's 5 MiB minimum.
- the client's last part is **< 5 MiB**: a separate trailer part would make that
  part a non-final part below the minimum, and S3 — MinIO included, see risk 1 —
  answers `EntityTooSmall` at Complete. So the proxy keeps the ciphertext of a
  part smaller than 5 MiB in the session and at Complete re-uploads it as
  `UploadPart(sameNumber, ciphertext ‖ trailer)`, using the new ETag. Approved
  by the owner on 2026-09-06, with two bounds that make the buffer finite:
  - **Per session, at most one short part.** A second part below 5 MiB in the
    same session can never complete — either it is a non-last part and fails
    rule 1, or `partSize` itself is below the backend's minimum — so the proxy
    answers it with `EntityTooSmall` at `UploadPart` time and aborts the
    upload. Bound: 5 MiB per session.
  - **Across sessions, a global cap on buffered short-part bytes.** Sessions
    are client-controlled and the proxy caps neither their number nor their
    memory today — there is only an idle TTL
    ([manager.go:578](../../internal/orchestration/manager.go#L578)) — so "5 MiB
    per session" alone means "5 MiB times whatever the client opens". The
    proxy keeps one counter of buffered short-part bytes; a short part that
    would push it past the cap is answered with `SlowDown` (503), which every
    SDK retries with backoff, and the session stays open. The cap is a
    constant of 256 MiB, released when a session completes, aborts or
    expires. It is a resource bound, not a security control, so it may become
    a configuration key later if a deployment needs it; it starts as a
    constant because nothing in the repository needs it to vary.

Either way the proxy builds `CompletedMultipartUpload` **from its own part
table**, not from the ETags in the client's XML
([complete.go:149-168](../../internal/proxy/handlers/multipart/complete.go#L149)) —
the client's ETags are over ciphertext the proxy produced, and after a trailer
re-upload one of them is stale. The client XML is still parsed and validated;
it is the part *set* that is checked against the table, and a mismatch is
`InvalidPart`.

With a real part table in the session, P-7 falls out: `ListParts`
([list.go:66](../../internal/proxy/handlers/multipart/list.go#L66)) is served from
it instead of returning a fabricated empty result at HTTP 200, and
`ListMultipartUploads` ([list.go:97](../../internal/proxy/handlers/multipart/list.go#L97))
is forwarded to the backend instead of answering 501.

---

## What changes in the crypto layer

The `ContentType` split in the factory
([factory.go:67](../../pkg/encryption/factory/factory.go#L67), the switch at
[factory.go:76](../../pkg/encryption/factory/factory.go#L76)) has one branch left,
so `ContentTypeWhole` / `ContentTypeMultipart` and `ForceAESGCMContentType` /
`ForceAESCTRContentType` go with it. The `DataEncryptor` /
`EnvelopeEncryptor` stream interfaces
([interfaces.go:33](../../pkg/encryption/interfaces.go#L33),
[interfaces.go:61](../../pkg/encryption/interfaces.go#L61)) do not express a
segment chain — they hand back a `*bufio.Reader` and hide the DEK — so the new
segment codec is a small explicit type in `pkg/encryption/dataencryption`
(`SegmentedGCMWriter` / `SegmentedGCMReader` / `SegmentRangeReader`) that the
orchestration layer drives directly with a DEK it already holds.

That also kills, for free, the double DEK unwrap on the GCM GET path
(item 5.1 of [ticket 012](012-performance-audit-round2.md)): today
`DecryptGCMStream` unwraps through the cache
([singlepart.go:192](../../internal/orchestration/singlepart.go#L192)) and then
`envelope.DecryptDataStream` unwraps again, uncached, through the raw
`KeyEncryptor` ([envelope.go:82](../../pkg/encryption/envelope/envelope.go#L82)).
With the codec driven directly from the cached DEK, there is one unwrap and it
is cached ([providers.go:209](../../internal/orchestration/providers.go#L209)).
The cached DEK is cache-owned and read-only
([providers.go:412](../../internal/orchestration/providers.go#L412) built the key
that makes it safe across re-uploads, ticket 011) — the codec must not zero it.

`AESGCMDataEncryptor` ([aes_gcm.go:20](../../pkg/encryption/dataencryption/aes_gcm.go#L20))
and `AESCTRDataEncryptor` ([aes_ctr.go:19](../../pkg/encryption/dataencryption/aes_ctr.go#L19))
/ `AESCTRStatefulEncryptor` ([aes_ctr.go:142](../../pkg/encryption/dataencryption/aes_ctr.go#L142)) and
`pkg/encryption/envelope/` lose all production callers and are deleted with
their tests.

---

## Relation to tickets 011 and 012

**[Ticket 011](011-dek-cache-stale-on-reupload.md) — dissolved as a bug, its fix
survives as a property.** Option A shipped: the DEK cache key includes a digest
of the wrapped DEK ([providers.go:412](../../internal/orchestration/providers.go#L412)),
so a re-upload cannot return a stale DEK. v2 does not reintroduce the problem
and does not remove the guard — the cache is still keyed the same way, and the
regression test
(`test/integration/360-degree-variants/dek_cache_reupload_test.go`) still has
to pass. What *does* disappear is the symptom the ticket described: with v2 a
stale DEK fails the first segment tag instead of failing a whole-object HMAC at
the end of the stream.

**[Ticket 012](012-performance-audit-round2.md) — item by item:**

| 012 item | Fate under v2 |
|---|---|
| 1.1 SDK flexible checksums | Already done (F-4): `WhenRequired` at [server.go:171-172](../../internal/proxy/server.go#L171). Untouched. |
| 1.2 / N-8 30 s Read/WriteTimeout | **Survives.** Still 30 s at [server.go:138-139](../../internal/proxy/server.go#L138). v2 does not touch the listener. Own work. |
| 1.3 dead code + per-GET Info logs | **Mostly dissolved** — every dead symbol it names is in this ticket's deletion list, and the five Info logs sit in code that goes. Not covered by the deletions: the constant-false `%T` sniff in `writeGetObjectResponse` ([operations.go:359](../../internal/proxy/handlers/object/operations.go#L359)), which item 3 below deletes with the GET fork. |
| 2.1 stream the UploadPart handler | **Survives as work, its blockers dissolve.** [upload.go:77](../../internal/proxy/handlers/multipart/upload.go#L77) still `ReadBody`s the whole part and [upload.go:203](../../internal/proxy/handlers/multipart/upload.go#L203) still `io.ReadAll`s the ciphertext. v2 rewrites this handler anyway, so the streaming version is written here, not later. |
| 2.2 destructive body-sniff | Already done (F-1): header-based detection, `readAllSized`, `aws_chunked_decoder.go` deleted. |
| 2.3 exact-size part buffers | **Dissolved on the client-driven route** (`processPartOrdered`'s 12 MiB pre-size at [multipart.go:245](../../internal/orchestration/multipart.go#L245) goes with the function). The auto-multipart buffer pool is still worth doing and is folded into this ticket's write path. |
| 3.1 metadata at initiate, self-copy removal, >5 GiB failure | **Dissolved.** Done here, and without the `PutObjectTagging` scheme 012 proposed — v2 has no late-bound HMAC, so all metadata fits at initiate. |
| 3.2 Range GET | Already shipped (F-6); v2 replaces the implementation and closes the integrity gap it shipped with. |
| 3.3 HEAD/List size | HEAD already fixed (F-7); v2 changes the size function it calls. List is D-11, after v2. |
| 4.1 transport tuning, 4.2 fill-before-write, 4.3 GOMEMLIMIT/GOMAXPROCS | **Survive.** Independent of the format. 4.2's note about `hmacValidatingReader`'s shrinking tail slices becomes moot. |
| 5.1 double DEK unwrap on GCM GET | **Dissolved** (see above). |
| 5.2 GCM `[]byte` fast path | **Dissolved** — superseded by the segment codec, which is a single buffer per segment by construction. |
| 6.1–6.5 benchmarks | **Survive.** This ticket adds one more (ranged reads) and must not regress the others. |
| "Explicitly not doing" #1: segmented AEAD | **Reversed, deliberately.** 012 rejected it on performance grounds ("the win today is ~0.05 cores"). It is adopted here on *integrity* grounds — D-1 — with performance as a constraint to hold, not a benefit to claim. |

---

## Work breakdown

- [x] **0. Confirm the precondition** (rule 3) with the repository owner.
      Confirmed 2026-09-06: no production users known; v2 is the 5.0.0 major
      release (4.0.0 went out on 2026-09-07 without it) and the release notes
      state the incompatibility. No v1 decrypt path.
      Everything below assumes it holds.
- [ ] **1. Segment codec, standalone and tested.** `pkg/encryption/dataencryption/segmented_gcm.go`:
      writer, sequential reader, ranged reader, the AAD builder, the trailer,
      and `PlaintextSize(C) / CiphertextSize(P)`. Unit tests: empty object,
      1 byte, S-1, S, S+1, exactly n·S, the size function round-trips over a
      table of sizes, a flipped ciphertext bit fails, a swapped pair of
      segments fails, a segment moved to another object key fails, a truncated
      object fails on the trailer, an extended object fails.
- [ ] **2d. Sealed plaintext checksum (ADR 0003 D13, ADR 0012 D10).** Compute a CRC32C over
      the plaintext on every write path, seal it under the object's data key and store it in the
      metadata set; serve it as `x-amz-checksum-crc32c` on whole-object `GET` and `HEAD`, and on
      no ranged read. Never store or serve it in the clear. Tests: the value survives a round trip
      on all three write paths; a `HEAD` and a `GET` of the same object report the same value; a
      ranged read carries no checksum header; the stored metadata value is not the bare checksum
      (read the object directly from the backend and assert it does not match).
- [ ] **2. Metadata set.** Write `dek-algorithm: s3ep-gcm-seg-v2`; delete
      `aes-iv` and `hmac` from `BuildMetadataForEncryption`, `GetIV`,
      `GetHMAC`/`SetHMAC`/`HasHMAC` and the `IsEncryptionMetadata` filter list.
      Update the metadata list in `CLAUDE.md`. Change `AESProvider.Fingerprint()`
      ([aes.go:164](../../pkg/encryption/keyencryption/aes.go#L164)) to
      `hex(HMAC-SHA256(KEK, "s3ep-kek-fingerprint"))` (H-8, open question 11,
      decided 2026-09-06). Change `RSAProvider.Fingerprint()`
      ([rsa.go:124](../../pkg/encryption/keyencryption/rsa.go#L124)) to
      `hex(SHA-256(x509.MarshalPKIXPublicKey(pub)))` and drop the defect
      comment (ticket 022 item 8, moved here 2026-09-06). `tink` stays. Unit
      tests: a known key yields a fixed vector for each provider, two
      providers with different keys differ, the AES value is not
      `hex(SHA-256(KEK))`, and the RSA vector matches
      `openssl pkey -pubin -pubout -outform DER | sha256sum` for the same key.
- [ ] **2b. Remove the raw-string KEK fallback (D-21, open question 13).**
      `NewAESProvider` ([aes.go:43](../../pkg/encryption/keyencryption/aes.go#L43))
      base64-decodes `aes_key` and, when the result is not 32 bytes, falls back to
      `kek = []byte(keyStr)`
      ([aes.go:60-66](../../pkg/encryption/keyencryption/aes.go#L60)), so any
      32-character string is accepted as the AES-256 master key. Delete the fallback:
      `aes_key` is `base64.StdEncoding` of exactly 32 bytes and nothing else, and
      anything else is an error naming the field —
      `encryption.providers[%d].config.aes_key: must be base64 of exactly 32 bytes`.
      Fold `NewAESProviderFromBase64`
      ([aes.go:85](../../pkg/encryption/keyencryption/aes.go#L85)) into it: it already
      implements the wanted behaviour and has no production caller, only
      [aes_coverage_test.go:148](../../pkg/encryption/keyencryption/aes_coverage_test.go#L148).
      Add the same check to `validateProvider`
      ([config.go:609-612](../../internal/config/config.go#L609)), which today only
      requires a non-empty string, so a bad key stops the proxy at startup instead of
      at the first PUT; `${VAR}` expansion already runs before validation
      ([config.go:233](../../internal/config/config.go#L233) before
      [config.go:238](../../internal/config/config.go#L238)), so `${S3EP_AES_KEY}` is
      unaffected. This is the half of H-8 that makes the fingerprint change in item 2
      worth doing: a 32-byte random key makes the published fingerprint harmless, a
      32-character passphrase makes it an offline oracle. Tests: in
      `TestKekAESNewProviderFromConfigMap` the case `raw 32 byte ascii key is used
      verbatim`
      ([aes_coverage_test.go:85-89](../../pkg/encryption/keyencryption/aes_coverage_test.go#L85))
      inverts to expect the new error; `base64 of wrong length falls back to raw bytes
      and is rejected`
      ([:106-110](../../pkg/encryption/keyencryption/aes_coverage_test.go#L106)) loses
      its "falls back" wording and asserts the new message; add a `validateProvider`
      case in `internal/config/validation_coverage_test.go` for a 32-character
      non-base64 key.
- [ ] **2c. Harden the `aes` KEK provider and delete `rsa` (D-32).** In
      [aes.go](../../pkg/encryption/keyencryption/aes.go): derive `prk` once in
      the constructor with stdlib `crypto/hkdf`; `Fingerprint()` returns
      `hex(HKDF-Expand(prk, "s3ep-kek-fingerprint", 32))` (supersedes the
      HMAC form in item 2); `EncryptDEK` draws a 16-byte salt, derives
      `HKDF-Expand(prk, "s3ep-kek-wrap-v1" ‖ salt, 32)`, seals the DEK with
      `cipher.NewGCMWithRandomNonce` and AAD `"s3ep-dek-wrap-v1"`, returns
      `salt ‖ nonce ‖ ct ‖ tag` (76 bytes); `DecryptDEK` reverses it and returns
      a distinct `wrapped DEK authentication failed` error on tag failure, before
      any body byte is read (the `GetObject` is already issued at
      [singlepart.go:463](../../internal/orchestration/singlepart.go#L463)).
      Drop the `keyID` return of `EncryptDEK` and the self-fingerprint check in
      `DecryptDEK` from the `KeyEncryptor` interface (every production caller
      discards the value and the check cannot fail, 024), and drop `RotateKEK`
      from the interface (every implementation is a stub, `Manager.RotateKEK`
      has no caller). Key admission in `validateProvider`
      ([config.go:697](../../internal/config/config.go#L697)): base64 of exactly
      32 bytes (item 2b), not all printable ASCII (0x20–0x7E), at least 16
      distinct byte values; the error names `s3ep-keygen` and
      `openssl rand -base64 32` and says that base64 of a hex string is refused.
      Delete `rsa.go`, `rsa_test.go`, `rsa_coverage_test.go`, the `rsa` arms in
      [factory.go](../../pkg/encryption/factory/factory.go),
      [providers.go](../../internal/orchestration/providers.go) and
      [config.go:701-707](../../internal/config/config.go#L701),
      `config/rsa-example.yaml`, the `rsa` provider in `config/multi-example.yaml`,
      `test/integration/encryption-modes/rsa_provider_test.go`, and every test
      that carries a PEM (eight files). Unit tests: a known key yields a fixed
      fingerprint vector; wrap round-trips; a flipped bit anywhere in the 76
      bytes fails with the new error; two wraps of the same DEK differ; each
      admission rule has one rejected and one accepted shape; the V9 e2e key
      (bytes 0..31) and a keygen key pass. Docs: `SECURITY_ARCHITECTURE.md` 3.2,
      7.1 and H-8 (closes), README provider sections ("RSA recommended for
      production" goes), CLAUDE.md provider list.
- [ ] **3. Read path, whole object.** One `DecryptData` path; verify every
      segment and the trailer; abort the response body on a failure mid-stream.
      Delete `DecryptGCMStream`, `DecryptCTRStream`, `isNoneProviderData`,
      `hmacValidatingReader`, `hmacGatedDecryptionReader`,
      `DecryptMultipartWithHMACVerification`, `createStreamingDecryptionReader`,
      `shouldValidateHMACEarly`, `validateHMACEarly`, the algorithm fork in
      `handleGetObject`, and the constant-false `%T` sniff in
      `writeGetObjectResponse` (operations.go:359, 012 item 1.3).
- [ ] **4. N-1 fail-closed.** `InvalidObjectState` / 403 on GET, HEAD and ranged
      GET under an encrypting provider when the metadata is absent or names
      another format. `none` still passes through. Unit tests per verb; an
      integration test that writes an object **behind** the proxy (directly to
      MinIO) and asserts 403 through the proxy on all three verbs.
- [ ] **4a. Refuse a client key inside the prefix (D-34).** On every PUT and
      CreateMultipartUpload path, a user-metadata key that, lowercased, starts
      with the configured `metadata_key_prefix` answers `400 InvalidArgument`
      naming the key; the three drop-or-keep branches
      ([helpers.go:142-162](../../internal/proxy/handlers/object/helpers.go#L142),
      [operations.go:1048-1058](../../internal/proxy/handlers/object/operations.go#L1048),
      [create.go:155-172](../../internal/proxy/handlers/multipart/create.go#L155))
      collapse onto one helper. Unit test per path; the integration suite's
      injection test asserts 400 and that the object's own metadata is intact.
      Precondition on `main`: the lowercase fix at
      [helpers.go:148](../../internal/proxy/handlers/object/helpers.go#L148) with
      `TestObjPutClientCanInjectEncryptionMetadataOnSinglePartPaths` inverted.
- [ ] **5. Read path, ranged.** Segment-covering window, one backend request,
      index check, slice. Delete `rangeread.go`, `serveRangeByFullDecryption`,
      `NewCTRStreamAt`, `NewCTRRangeReader`, `addCounter` and their tests.
      Boundary tests: offset 0, S-1, S, S+1, a range inside one segment, a range
      spanning exactly two, a suffix range, the last byte.
- [ ] **6. Write path 1 — single PutObject.** Replace `putObjectDirect` and
      `putObjectStreamingReader` with one segmented writer. Remove the
      size-based routing and the forced-content-type special cases.
- [ ] **7. Write path 2 — auto-multipart.** Metadata at
      `CreateMultipartUpload`; trailer on the last proxy-built part; delete the
      self-`CopyObject`; parts encrypted in parallel; keep the bounded part
      buffer pool.
- [ ] **8. Write path 3 — client-driven multipart.** One client part → one
      backend part; per-part offset from the largest observed part size,
      recorded in the session; stream the part instead of `ReadBody` +
      `io.ReadAll` (012 item 2.1); delete `processPartOrdered`,
      `processPartDataInOrder`, `processBufferedPartsData`, `PendingParts`,
      `ExpectedPartNumber`, `OrderingMutex`, `PartBuffer`.
- [ ] **9. Complete.** Enforce the four part-table rules, `InvalidPart` +
      abort on violation; attach the trailer (extra part, or re-upload of a
      short last part); build `CompletedMultipartUpload` from the session table;
      delete the self-`CopyObject`. The two buffer bounds from write path 3:
      `EntityTooSmall` + abort on a second short part in a session, `SlowDown`
      at the global 256 MiB cap. Integration tests: a 5 MiB + 1 MiB upload
      completes and reads back by SHA-256 (the case that fails without the
      re-upload — MinIO enforces the minimum, risk 1); a 5 MiB + 5 MiB upload
      completes with the trailer as an extra part; two 1 MiB parts in one
      session get `EntityTooSmall` on the second and the upload is gone
      afterwards.
- [ ] **10. P-7.** `ListParts` from the session part table;
      `ListMultipartUploads` forwarded to the backend.
- [ ] **11. Size function everywhere.** Replace `ComputePlaintextSize` /
      `ComputeCiphertextSize`; wire HEAD and GET to it. (LIST stays out — D-11.)
- [ ] **12. Config deletions.** Remove `integrity_verification` and
      `streaming_threshold` from the struct, defaults, validation, accessors,
      every `config/*.yaml`, `deploy/helm/.../values-production.yaml`,
      `test/e2e/velero/values-proxy.yaml`,
      `internal/orchestration/README.md` (both still document
      `streaming_threshold` and the GCM/CTR split) and the docs. Extend
      `streaming_segment_size` validation to require a multiple of 65536.
      Delete `internal/config/integrity_verification_test.go`.
- [ ] **13. Delete `internal/validation/`** (`hmac_manager.go`,
      `hmac_calculator.go`, `hkdf.go` and their tests). Confirm with
      `go build ./... && go vet ./...` that nothing references it.
- [ ] **14. Delete the now-unreferenced crypto.** `AESGCMDataEncryptor`,
      `AESCTRDataEncryptor`, `AESCTRStatefulEncryptor`, `ctrStreamReader`,
      `pkg/encryption/envelope/`, the `ContentType` split and the force-content
      types in the factory, with their tests.
- [ ] **15. Benchmarks.** Add the kopia-shaped ranged-read benchmark (below) to
      `test/integration/performance-test/`. Re-run the 1 GB benchmark and the
      small-object numbers; record before/after in this ticket.
      Add the DEK-unwrap microbenchmark D-28 needs — it is **not** in the tree, so
      the obligation has no instrument today: no benchmark in the tree touches the
      KEK unwrap. `grep -rn "func Benchmark" --include='*_test.go'` returns
      `BenchmarkStreamingUpload`, `BenchmarkStreamingDownload`,
      `BenchmarkHKDFDerivation` and, since D-29, `BenchmarkGetResponseCopy` — a GET
      response-copy benchmark, not a crypto one. 024's "measured in this tree"
      numbers for P-1 were taken with a benchmark that was never committed.
      `BenchmarkDEKUnwrap` in `internal/orchestration/`, one sub-benchmark per KEK
      provider (`aes`, `rsa`-2048), run on the pre-v2 commit and again after, both
      numbers recorded here next to 024 P-1's baseline (392 ns / 0.94 ms, Apple M1
      Ultra).
- [ ] **16. Docs.** Rewrite the README "Ranged reads" section
      ([README.md:599](../../README.md#L599)) — the caveat is gone, replaced by the
      guarantee; document `InvalidObjectState`, the part-size rule for
      client-driven multipart, the 0.043 % + 36 B overhead, and the migration
      procedure for a bucket with pre-existing plaintext. **Revise**
      [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md), which was
      already carries the threat model, D-19 and the
      N-4 repository-password recommendation: v2 closes H-1, H-5 and H-6, so
      those three sections are rewritten rather than extended, and the format
      itself belongs in section 3. Update `CLAUDE.md`'s metadata key list —
      `aes-iv` and `hmac` leave it, the format id enters. **Release notes for
      5.0.0:** objects written by 3.x and 4.0.x are not readable under v2 and
      must be uploaded again (item 0); `kek-fingerprint`
      values change for `aes` and `rsa` providers; `integrity_verification` and
      `streaming_threshold` are removed from the configuration;
      `streaming_segment_size` must be a multiple of 64 KiB (risk 4);
      `InvalidObjectState` 403 is the proxy's answer to foreign objects.

---

## Success criteria

**Correctness**

- [ ] `make test-unit` green, including the new codec tests from item 1.
- [ ] `make test-integration` green (plain-HTTP proxy endpoint).
- [ ] `make test-integration-tls` green (TLS endpoint — the only transport on
      which aws-sdk-go-v2 emits `STREAMING-UNSIGNED-PAYLOAD-TRAILER` framing).
- [ ] The existing suites are rewritten, not skipped or disabled. Specifically:
      `test/integration/360-degree-variants/hmac_validation_test.go` becomes a
      segment-tamper suite; `range_read_test.go` gains the boundary table from
      item 5; `comprehensive_multipart_test.go`,
      `comprehensive_singlepart_test.go` and
      `comprehensive_singlepart_ctr_test.go` collapse onto the single data path;
      `dek_cache_reupload_test.go` stays as-is and must still pass;
      `test/integration/encryption-modes/none_provider_test.go` must still show
      pure pass-through.
- [ ] New integration tests: an object written directly to MinIO (behind the
      proxy) is answered with 403 `InvalidObjectState` on GET, HEAD and ranged
      GET under `aes`, and passes through under `none` (`rsa` is gone, D-32); a part
      re-uploaded with different content produces a correct object; a
      client-driven upload with unequal middle parts fails Complete with
      `InvalidPart` and leaves no object; `ListParts` returns the real parts.
- [ ] `./start-demo.sh` comes up and a manual round trip of a 1 byte, a 64 KiB,
      a 12 MiB and a 1 GB object matches by SHA-256 (per WORK ORDER 1: compare
      hashes, never hex dumps).
- [ ] Velero e2e green: `make e2e-up && make test-e2e-velero`, all 13 scenarios,
      including the volume scenarios that exercise kopia's ranged reads and V9
      (provider rotation).
- [ ] `docker logs proxy | tail -50` shows no `InvalidObjectState` and no
      segment-verification error during a clean e2e run.

**Performance** — the criterion from the findings doc, all three parts:

- [ ] The existing 1 GB benchmark (`TestStreamingPerformance` in
      `test/integration/performance-test/performance_test.go`, via
      `make test-integration-performance`) **does not regress on upload or on
      download** against the numbers recorded before the change. Protocol as in
      [ticket 012](012-performance-audit-round2.md): fresh proxy from
      `./start-demo.sh`, 3 runs, report the median, compare against a baseline
      measured on the same machine on the pre-v2 commit (v4.0.0 or the `main`
      commit `feat/major-v5` forks from) — not against the figures written in
      ticket 010.
- [ ] **Small-object throughput does not regress**: `TestPerformanceComparison`
      plus the small-object/high-QPS benchmark (012 item 6.3) if it exists by
      then; otherwise 4 KiB and 256 KiB objects at concurrency 16, QPS and
      p50/p99, before and after.
- [ ] **New benchmark, kopia-shaped ranged reads**, added to
      `test/integration/performance-test/` and reported in this ticket: 4 KiB,
      64 KiB and 4 MiB ranged reads at random offsets from a 20 MiB object
      (kopia's pack blob size), reporting reads/s, MB/s and p50/p99, plus the
      backend byte amplification (bytes fetched / bytes returned — expected
      ≤ 2·64 KiB per read). This is the number that has to be good, because it
      is the ranged-read path every S3 client that reads ranges pays for, the
      Velero restore path among them.
- [ ] **The double DEK unwrap is gone, and measured (D-28, open question 14).**
      `BenchmarkDEKUnwrap` (item 15) reports **one** unwrap per GCM GET, not two, for
      `aes` (the `rsa-2048` sub-benchmark is void since D-32; 024 P-1's 392 ns is the
      baseline, and the hardened wrap of item 2c adds one HKDF expansion and one
      GCM open, so the after number is expected in the low microseconds and is
      written into this ticket). The `rsa` half of this criterion — the GET half
      of `TestPerformanceComparison` against an `rsa` provider, the ~1067 to ~533
      GETs/s ceiling — is dropped with the provider. This
      criterion is the obligation D-28 attached to deferring the interim fix, and
      [025](025-tink-kms-hcvault.md) success criterion 5 — "one Vault round-trip or
      zero, never two" — cannot be checked until it is met.
- [ ] **Memory footprint is held by a test, not by a measurement** (owner
      requirement, 2026-09-06). A new test in
      `test/integration/performance-test/` scrapes
      `process_resident_memory_bytes` from the proxy's monitoring endpoint —
      available today: [server.go:34](../../internal/monitoring/server.go#L34)
      serves the default Prometheus registry, which carries the process
      collector, and the demo maps `9090:9090` (verified live 2026-09-06). Add
      `S3EP_TEST_METRICS_ENDPOINT`, default `http://127.0.0.1:9090/metrics`,
      next to `S3EP_TEST_PROXY_ENDPOINT`
      ([minio_test_helper.go:40](../../test/integration/minio_test_helper.go#L40)).
      The test samples idle RSS first, polls every 100 ms during each
      scenario, and **fails** on a hard bound — no logging-only:
      1. 1 GB PutObject (auto-multipart), then 1 GB GET:
         `peak − idle ≤ 2 × streaming_segment_size × (1 + multipart_upload_concurrency)`,
         120 MiB with the defaults; the factor 2 is GOGC's headroom over live
         data. Ticket 010 measured a 109.2 MiB peak on the pre-v2 code, so the
         assertion has to pass on the pre-v2 commit as well — run it there
         first and record both numbers here. A bound the old code fails is a
         bound that measures GC noise, not the format.
      2. 8 concurrent client-driven multipart uploads of 21 MiB at a 5 MiB
         part size (4 full parts + one 1 MiB short last part each, the Velero
         shape): `peak − idle ≤ 8 × 5 MiB + the bound from 1`. All eight read
         back by SHA-256.
      3. The global cap: sessions that each park one 4 MiB short part and
         never complete, opened until a part is answered with `SlowDown`;
         assert that this happens before 80 sessions (the cap is 256 MiB) and
         that `peak − idle ≤ 256 MiB + the bound from 1`. Abort them all at
         the end. No return-to-idle assertion — Go hands memory back to the
         OS lazily, so that would measure the runtime, not the proxy.
- [ ] pprof before/after archived under `docs/tickets/013-v2/`. Expectation to
      confirm or refute: HMAC-SHA256 disappears from the profile and GHASH does
      not replace all of it, because AES-GCM on AES-NI/PMULL is one pass where
      CTR-then-HMAC was two, and SHA-256 is the slower primitive. **If the
      benchmark regresses, stop and report it** rather than shipping and
      explaining it afterwards.

**Cleanliness**

- [ ] `grep -rn "integrity_verification\|streaming_threshold\|aes-iv\|s3ep-hmac"` over
      the tree returns only `CHANGELOG.md` and `docs/tickets/`, which are history
      and keep the old names on purpose; every other hit today — `config/*.yaml`,
      the two Helm/e2e values files, `README.md`,
      `internal/orchestration/README.md` and
      the code — must be gone.
- [ ] `internal/validation/` is gone; `go build ./... && go vet ./... && make lint`
      clean.
- [ ] Coverage does not drop below the pre-change figure.

---

## Risks and open questions

1. **The trailer part vs. S3's 5 MiB minimum — a real hole in the one-line
   design, resolved above, the resolution provable in the integration suite,
   and approved by the owner on 2026-09-06 with the memory test as the
   condition.** Appending the trailer as an extra part turns the client's last part
   into a middle part, and S3 rejects a middle part below 5 MiB with
   `EntityTooSmall`. aws-sdk-go-v2 `manager.Uploader` with 5 MiB parts produces
   a short last part for most object sizes, so this is the common case for any
   aws-sdk-go-v2 uploader (Velero among them),
   not a corner. The short-part re-upload described in write path 3 solves it.

   An earlier draft of this ticket claimed that MinIO does not enforce the
   minimum, so that the suite could prove neither the problem nor the fix.
   **Refuted 2026-09-06** against the demo MinIO
   (`RELEASE.2025-09-07T16-13-09Z`, direct `s3api` calls, no proxy in the
   path): parts of 1 MiB + 36 B fail Complete with `EntityTooSmall`, parts of
   5 MiB + 36 B complete to a 5 242 916-byte object. The integration suite
   therefore proves both the problem and the fix; no test against AWS is
   needed for this rule. Both cases become an integration test in item 9.

   Two things the resolution above leaves implicit, both to be built:

   - **The 5 MiB session bound needs an early reject.** "At most one part
     below 5 MiB can pass rule 1" is a statement about Complete; a client
     sending 1 MiB parts would have the proxy buffer every one of them until
     Complete fails. Two parts below 5 MiB in one session can never complete —
     one of them is a non-last part and fails rule 1, or `partSize` itself is
     below the minimum and the backend rejects it — so the proxy rejects the
     second one at `UploadPart` time with `EntityTooSmall` and aborts the
     upload. With that, the buffer is at most one part below 5 MiB per
     session, as stated — and the session count is bounded in turn by the
     global cap in write path 3, because the client decides how many sessions
     exist.
   - **A part cannot be fetched back from the backend.** No S3 verb reads an
     uploaded, uncommitted part, and `UploadPartCopy` copies from committed
     objects only. That is why the short part is kept in memory, and why a
     last part of 5 MiB or more gets the extra-part treatment instead:
     buffering it would cost `partSize` per session, not 5 MiB.

   The alternative that was floated — drop the trailer and flag the final
   segment in its AAD (Tink's last-segment flag), size function
   `n = ceil(C / (S + 28))`, `P = C - 28n` — does **not** dissolve the problem
   for client-driven multipart and is not taken. The proxy learns which part is
   last only at Complete, and a last part of exactly `partSize` is
   indistinguishable from a middle part when it arrives. Flagging it later
   means re-encrypting it, which means buffering the highest-numbered
   full-size part until a higher-numbered one arrives: a bound of one
   `partSize` per session instead of 5 MiB, and more session state. The
   trailer keeps the bound small and the rule simple.
2. **Aborting a response body mid-stream is the only honest failure mode for a
   whole-object read**, and clients see it as a truncated body, not as an error
   document. It is **new** everywhere but at the tail: today's HMAC path
   verifies only once the body minus its last chunk is on the wire, and in `lax`
   it hands that chunk over and logs. So it has to be stated in
   `SECURITY_ARCHITECTURE.md`: a proxy that has already sent 200 cannot un-send it.
3. **Read amplification on tiny reads is real.** A 32-byte read costs at least
   one 64 KiB segment fetch. kopia's reads are larger than that, but a client
   that ranges in 512-byte steps pays 128× amplification. Measure it in the new
   benchmark; do not add a segment cache in this ticket.
4. **`streaming_segment_size` must be a multiple of 64 KiB** for the auto-
   multipart path to produce whole segments per part. The validator enforces it,
   but an existing deployment with a non-conforming value now fails to start.
   That is intended (rule 2 beats a silent fixup), and it must be in the
   release notes.
5. **The part-size inference relies on "part 1 is dispatched before the last
   part".** True for every uploader listed above, and checked at Complete
   anyway, so a violation is a clean `InvalidPart` rather than a corrupt object.
   Unverified for uploaders outside that list.
6. **9999 usable parts, not 10000.** One is reserved for the trailer. With a
   5 MiB part size that caps a client-driven upload at ~48.8 GiB rather than
   ~48.8 GiB + 5 MiB — irrelevant in practice, but it is a visible deviation
   from S3 and belongs in the README.
7. **The random-nonce bound.** 2^32 segments per DEK is the SP 800-38D limit; at
   64 KiB that is 256 TiB per object, well past S3's 5 TiB object limit. Safe by
   construction, but if S ever became configurable the bound would have to be
   rechecked — another reason it is a constant.
8. **Rollback and cross-bucket key swap remain undefended**, by design (the
   bucket is deliberately out of the AAD so ciphertext buckets stay copyable).
   Must be written down, not left implicit. **Decided 2026-09-07 (owner, D-33):
   the bucket stays out**; the same-key swap across buckets or deployments under
   one KEK is the accepted residual, answered by one KEK per deployment, and
   `SECURITY_ARCHITECTURE.md` H-3 says so.
9. **Performance is a hope with a good argument, not a measurement.** One
   GHASH-accelerated pass should beat CTR plus a SHA-256 pass, and removing the
   self-copy and the serialization is a pure gain — but per-segment setup at
   64 KiB, the extra 28 bytes per segment on the wire, and the loss of the
   in-place CTR XOR from ticket 010 Tier 1.1 all cut the other way. The
   benchmarks in the success criteria are the gate.
10. **Coverage of `internal/proxy/handlers/object` is 98.0 %** (`go test -short
    -cover`, 2026-09-07 — it was 9.2 % when this ticket was written). The handler
    rewrites in items 3–9 therefore rewrite a large unit suite (13 test files)
    as well as the code, and that suite, not only the integration and e2e runs,
    has to come back green. The new integration tests above stay non-optional.
11. **The KEK fingerprint stays a plain hash of the key unless this ticket
    changes it — H-8, and this is the only ticket that can.**
    `AESProvider.Fingerprint()` returns `hex(SHA-256(KEK))`
    ([aes.go:162-166](../../pkg/encryption/keyencryption/aes.go#L162)) and the
    metadata table above writes it to every object in the clear
    ([metadata.go:52](../../internal/orchestration/metadata.go#L52)). For a key
    from `s3ep-keygen` that leaks nothing; for a low-entropy or published key it
    is an offline verification oracle, and two buckets carrying the same value
    prove they share a KEK.
    [SECURITY_ARCHITECTURE.md H-8](../../SECURITY_ARCHITECTURE.md#h-8-the-aes-kek-fingerprint-is-a-plain-hash-of-the-key)
    carries the finding and names this ticket as the cheap place to fix it,
    because the metadata block is rewritten here anyway; nothing else owns it.
    **Decided 2026-09-06 (owner): derive the identifier as
    `HMAC-SHA256(KEK, "s3ep-kek-fingerprint")`** for the `aes` provider; H-8
    closes with this ticket. The alternative — keeping the plain hash and
    leaving H-8 an operational checklist item — was rejected. The chosen option is compatible
    with how the identifier is used — each configured provider still computes
    its own value from its own key, which is what decrypt-time provider
    selection needs
    (`DecryptDEK`,
    [providers.go:209](../../internal/orchestration/providers.go#L209) →
    `factory.GetKeyEncryptor`; `GetProviderByFingerprint` is the encrypt side
    only, plus the self-check at
    [aes.go:134](../../pkg/encryption/keyencryption/aes.go#L134))
    — and it touches no other part of the format, so it is work item 2 and
    nothing more. It is free because the [precondition](#precondition-rule-3)
    holds: a changed identifier makes every stored object unselectable, which
    the major release accepts. The RSA fingerprint truncation is a different
    defect; it was ticket 022 item 8 and moved here on 2026-09-06 for the same
    reason — after the major release a fingerprint change is a format break of
    its own.

12. **Until this ticket ships, no mode refuses a tampered AES-CTR download (D-20,
    2026-09-07).** [024](024-coverage-round-findings.md) H-1 and H-2, both reproduced by
    tests in the tree: the HMAC reader releases every byte before it verifies, and the
    verifying reader is not even constructed when the backend omits `Content-Length`. The
    owner decided **documentation only** — the format change fixes it by construction and
    an interim patch on the hot path would be deleted by this ticket. What that decision
    obliges *now*: the README must stop presenting `strict` as protection on the CTR path,
    and `SECURITY_ARCHITECTURE.md` H-5 ("only `strict` is safe") must be rewritten to say
    that `strict` is safe for AES-GCM objects and for nothing above
    `streaming_threshold`. That doc change is part of this ticket's prerequisites, not of
    its delivery.

    **The doc obligation is discharged.** `SECURITY_ARCHITECTURE.md` H-5 is rewritten
    (heading and anchor changed to *"`integrity_verification` does not refuse a tampered
    `aes-ctr` object"*), the two statements in §3.4 and §3.5 that contradicted it are
    corrected, `README.md` gains an *Integrity verification* section plus a Security
    bullet, and the mode block in `CLAUDE.md` and the
    three example configs no longer says `strict` aborts. Three things the round found
    while writing it, all verified in the tree and none of them in 024:

    - The scope line is drawn by the **stored `dek-algorithm`**, not by size
      ([operations.go:95](../../internal/proxy/handlers/object/operations.go#L95)). With
      integrity verification on, a plaintext of 5 MiB or more (`multipartMinSize`) goes
      to auto-multipart, but anything from `streaming_threshold` up to that still takes
      CTR through `putObjectStreamingReader`, so the CTR boundary is
      `streaming_threshold`. An upload of unknown `Content-Length` takes CTR at any
      size, and the `application/x-s3ep-force-aes-ctr` content type puts sub-1 KiB
      bodies on CTR.
    - **A missing `s3ep-hmac` is skipped silently in every mode, `strict` included**
      ([singlepart.go:510](../../internal/orchestration/singlepart.go#L510) for CTR,
      [:237](../../internal/orchestration/singlepart.go#L237) for GCM). The old H-5 said
      that downgrade was specific to `hybrid`. It is not, and the
      `"expected HMAC is empty"` branch of `VerifyIntegrity` is unreachable because both
      call sites require `len(expectedHMAC) > 0`. This is a fourth route to the same
      outcome and v2 must close it with the other three.
    - **A correct reader already exists and has no production caller.**
      `hmacGatedDecryptionReader` verifies before emitting its last chunk
      ([streaming_io.go:317-378](../../internal/orchestration/streaming_io.go#L317)), but
      its only entry point `DecryptMultipartWithHMACVerification`
      ([multipart.go:762](../../internal/orchestration/multipart.go#L762)) is called from
      tests only. `shouldValidateHMACEarly` is inert as well — it returns `false`
      unconditionally. v2 deletes all three rather than wiring them up, but whoever does
      the work should know the tree contains a working reader that nothing reaches.

13. **The raw-string KEK fallback goes with the fingerprint change (D-21).** `NewAESProvider`
    accepts any 32-character string as the master key, and H-8 publishes its unsalted
    SHA-256 in every object. The fingerprint half is already decided here; the owner decided
    the fallback is removed in the same release: `aes_key` is base64 of exactly 32 bytes,
    and anything else is a startup error naming the field. `keygen` already emits base64
    and all three example configs use it. A second format break later would be a second
    migration, which is why it rides on [023](023-major-v5.md) with this ticket.

14. **The double DEK unwrap on GCM GET is not patched before v2 (D-28).** [024](024-coverage-round-findings.md)
    P-1: `DecryptDataStream` unwraps the wrapped DEK a second time inside the envelope layer,
    past the ProviderManager cache — 392 ns under `aes`, 936 µs under `rsa`-2048, which
    halves the GET ceiling for the RSA provider. This ticket rewrites that path; the
    obligation it inherits is to **measure single-unwrap cost after**, with the
    performance suite, and to record the number. It is also the reason
    [025](025-tink-kms-hcvault.md) is sequenced after this ticket: with a KMS-backed KEK
    every unwrap is a network round-trip.
