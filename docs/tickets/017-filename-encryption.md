# Ticket 017: Filename encryption, directory segments only

## Status (2026-09-06)

**Open, blocked.** This ticket carries the "Filename encryption" decision of the
Velero path review (item 6 in its order of work; see the
[label index](README.md#label-index)). It **must not start before storage format v2**
([ticket 013](013-storage-format-v2.md)) has landed, and it should follow the
`ListObjectsV2` rewrite that D-11 schedules after v2
([ticket 018](018-listobjectsv2-document.md)), because that ticket is
what makes `start-after`, `encoding-type` and a real `ListBucketResult`
document exist at all — today
[bucket/operations.go:28-43](../../internal/proxy/handlers/bucket/operations.go#L28-L43)
forwards only `prefix`, `delimiter`, `max-keys` and `continuation-token`, and
[:52](../../internal/proxy/handlers/bucket/operations.go#L52) XML-encodes the raw
SDK struct. Four pre-work verifications (Stage 0 below) can change the design
and must be done first; two of them are the open questions the findings doc
left explicitly unanswered.

---

## Before you start

Checked against the tree on 2026-09-07; the ticket's reasoning stands, these
facts under it do not.

- **`SECURITY_ARCHITECTURE.md` is not waiting on anything.** The ticket has it
  created by the storage-format work; it exists at HEAD and already names this
  feature as decided and unimplemented (§3.6 and the out-of-scope list, both
  citing ADR 0023). Write into it. *Fixed in place.*
- **The boundary table lists sites that are dead.** `Get/PutObjectLegalHold`,
  `Get/PutObjectRetention`, `SelectObjectContent`, object ACL and object tagging
  no longer reach the backend at all — they answer `NotImplemented`
  ([operations.go:950-998](../../internal/proxy/handlers/object/operations.go#L950-L998),
  [acl.go:63](../../internal/proxy/handlers/object/acl.go#L63),
  [tagging.go:65](../../internal/proxy/handlers/object/tagging.go#L65)). Of the
  object sub-resources only `?torrent` is still a live passthrough. Re-derive
  the list before Stage 3 rather than transforming dead arms.
- **Every line anchor in that table drifted.**
  `internal/proxy/handlers/object/operations.go` is 1426 lines now: GetObject
  :55, PutObject :549 and :676, DeleteObject :711, HeadObject :734,
  DeleteObjects :858, Torrent :975, auto-multipart :1060/:1081/:1144/:1315,
  post-Complete self-copy :1362. The five passthrough entry points sit at
  [handler.go:229-271](../../internal/proxy/handlers/object/handler.go#L229-L271)
  (:132-171 is now the sub-resource guard), the clear-key debug log at
  [handler.go:191-196](../../internal/proxy/handlers/object/handler.go#L191-L196),
  and the handlers are constructed at
  [router.go:61-64](../../internal/proxy/router.go#L61-L64), not :39-42 — the
  one-wrap argument holds, at those lines.
- **The `UploadPartCopy` shadowing precondition is done.** The copy route is
  registered before the plain part route and the handler answers 422. Nothing
  for this ticket to wait on. *Fixed in place.*
- **`<Location>` no longer needs mapping.** It is built from the proxy's own
  scheme, host and request path, not echoed from the backend. Stage 4 item
  ticked; whether to keep, configure or drop it is the S3 surface-fidelity
  ticket's question, not this one.
- **"No new dependency" for AES-SIV is true only today.**
  `github.com/google/tink/go v1.7.0` is in `go.mod`, but its only production
  import is the unreachable Tink KEK stub
  ([keyencryption/tink.go](../../pkg/encryption/keyencryption/tink.go)), which the
  Vault key-provider work replaces. If that lands first, this feature is the sole
  consumer of a deprecated module path and Stage 1 has to pick one: the
  `tink-crypto/tink-go/v2` import, or another AES-SIV implementation.
- **The findings doc is gone.** Its two open questions survive only in this
  ticket (Stage 0 items 1 and 4); durable decisions now live in `docs/adr/`, this
  feature in ADR 0023. Nothing else to look up.

---

## Context

The proxy exists for a **hostile** S3 endpoint: the backend can read every byte,
change any byte, swap objects, serve stale versions and lie in listings. Format
v2 makes every stored byte authenticated and unreadable. It does not touch the
one thing the backend still reads for free: **the key**.

Object keys carry whatever structure the client's naming scheme puts there, for
every S3 client — Velero and database backups with CNPG Barman included. Taking
the Velero layout as the concrete example, this is what it leaks today, in
cleartext, to whoever holds the bucket:

| Leak | Where | Why it matters |
|---|---|---|
| Backup names | `backups/<name>/…` | Naming conventions, schedules, cluster identity, which backup to target for a rollback |
| Restore names | `restores/<name>/…` | Which backups were actually restored, and when |
| **Namespace names** | `kopia/<namespace>/…` | The tenant/application inventory of the cluster, for every namespace with volume data |
| Object counts, sizes, timing | listings | Volume of data per namespace, backup cadence, growth |

kopia's own blob names are content hashes and leak nothing but the type letter
(`p`, `q`, `x`, `xn`, `_log`, `kopia.`). Velero's layout is the leak.

Sizes, counts and timing are traffic analysis and stay visible under any scheme
short of padding and cover traffic; they are out of scope. Names are not: they
are a straight, avoidable disclosure of the customer's internal structure.

**The condition on the feature** is the one the repository owner set: lookups
stay exact and reliable. No mapping index, no round trip added to the hot path,
no scheme that turns a `GET` into "ask the adversary for the translation table
first".

---

## Scope

**In**

- A deterministic, keyed, wide-block transform over **directory segments only**;
  the leaf name stays clear.
- Applying it at exactly one place: the boundary between the proxy and the
  backend SDK client, in both directions.
- Prefix, delimiter and marker handling for listings.
- Key management for the name key (generation, wrapping, startup unwrap,
  failure modes).
- Documentation of the residual leak, in the README and in
  `SECURITY_ARCHITECTURE.md`, which already carries the decision
  ([ADR 0023](../adr/0023-filename-encryption-encrypts-directory-segments.md)).

**Out**

- Encrypting the **leaf** name. Rejected by the decision, because clients list
  with prefixes that end inside the leaf (kopia is the known case; every S3
  client that does the same is affected alike), and an encrypted leaf has no
  usable prefix.
- Encrypting **bucket** names. The bucket is in the path, in the SigV4 signature
  and in the backend's own namespace; it is also deliberately outside v2's AAD
  so a ciphertext bucket can be replicated wholesale.
- Hiding sizes, counts, timing.
- Rewriting the `ListObjectsV2` response document — that is the D-11 ticket.
  This ticket maps keys and prefixes in whatever document builder exists when it
  lands; if the D-11 ticket has not landed, it maps the fields of the SDK struct
  and does not touch the document shape.
- Server-side copy. `CopyObject`
  ([operations.go:373-385](../../internal/proxy/handlers/object/operations.go#L373-L385))
  and `UploadPartCopy`
  ([multipart/copy.go:43](../../internal/proxy/handlers/multipart/copy.go#L43))
  answer 422 `NotSupportedWithEncryption` today and keep doing so; see
  "Operations that stay refused".

**Items this closes**: the "Filename encryption" decision of the findings doc
(order of work, item 6), including both open questions it names — the
cross-directory order dependency and the CopyObject / multipart-list question.
It touches P-7 (`ListMultipartUploads`, forwarded since 2026-09-11, needs the same
mapping as a listing) and D-11 (the same listing document) without closing them.

---

## Why this is cheap after v2 and expensive before it

This is the reason for the ordering, and it is not a scheduling preference.

Format v2 binds **the object key as the client named it** into the AAD of every
segment and of the trailer. The findings doc says why: it stops a hostile backend
from serving object A's ciphertext under B's name. The consequence for this
ticket is the whole design:

- The AAD contains the **client's** key, never the stored key. Name encryption
  changes only the stored key. So **the stored bytes are identical whether name
  encryption is on or off**, and enabling it on an existing bucket is a *rename*,
  not a re-encryption — a backend-side `CopyObject` of ciphertext stays
  decryptable because the client key it is bound to never changed.
- Rotating or losing the name key is a naming problem, never a data problem. The
  object payload does not depend on the name key at all.
- The transform therefore lives strictly **after** the crypto layer has taken the
  key it needs. In the code as it stands the encryption manager already takes the
  client key as associated data on the GCM path
  ([singlepart.go:31-32](../../internal/orchestration/singlepart.go#L31-L32),
  [:201-202](../../internal/orchestration/singlepart.go#L201-L202)). It also hands
  the key to `ProviderManager.EncryptDEK`
  ([:128](../../internal/orchestration/singlepart.go#L128),
  [multipart.go:450](../../internal/orchestration/multipart.go#L450)), but **that
  argument is only a log field today** — the KEK wrap takes no associated data at
  all ([providers.go:160-198](../../internal/orchestration/providers.go#L160-L198),
  over `KeyEncryptor.EncryptDEK(ctx, dek)` at
  [interfaces.go:12](../../pkg/encryption/interfaces.go#L12)). v2 is what turns the
  key binding into something real, on every segment and on the trailer.

Done in the wrong order, all three of those invert:

- Without v2's AAD rule settled, a transform applied anywhere upstream of the
  encryption manager would bind **ciphertext names** into the AAD of every
  object written. Every later change to the name key or the transform would then
  make previously stored objects **undecryptable**, and there would be no way to
  tell that from tampering.
- The paths a transform has to be threaded through — `singlepart.go`'s GCM/CTR
  split, `rangeread.go`, the sequential HMAC, the post-Complete self-`CopyObject`
  at [operations.go:1507](../../internal/proxy/handlers/object/operations.go#L1507)
  and [complete.go:225](../../internal/proxy/handlers/multipart/complete.go#L225) —
  are code v2 deletes. Every line of name plumbing written into them is thrown
  away.
- The migration story would be "re-upload the bucket" instead of "rename the
  keys".

After v2 this ticket is a new package plus one decorator. Before it, it is a
crypto-format decision taken by accident.

---

## Lookups that must survive

Checked against the two clients the e2e exercises, Velero and kopia (their
listing shapes are read from their code, not yet captured — Stage 0 item 2);
every S3 client is in scope, and a lookup shape another client adds is a new
row. Every row is a hard constraint on
the transform.

| Lookup | Who needs it | What the transform must preserve |
|---|---|---|
| Exact key on GET, HEAD, DELETE, PUT | all clients | A one-to-one, deterministic, stateless map from client key to stored key, computable without asking the backend anything |
| Prefix listing where the prefix ends **inside the leaf name** | kopia lists `p`, `q`, `x`, `xn`, `_log`, `kopia.` under its directory; `ListBlobs` builds `Prefix: s.Prefix + prefix` ([kopia s3_storage.go](https://github.com/kopia/kopia/blob/master/repo/blob/s3/s3_storage.go)) | A partial leaf must survive verbatim into the backend prefix |
| Delimiter listing | Velero `ListCommonPrefixes` with `/` | `/` must remain a separator in the stored key, and `CommonPrefixes` must map back |
| Key order with `StartAfter`/`marker` and continuation | unknown — **UNVERIFIED**, Stage 0 item 1 | Order within a directory; cross-directory order is *not* preserved (see Risks) |

---

## Alternatives rejected, and why

| Alternative | Why not |
|---|---|
| **Full per-segment deterministic encryption** (the rclone crypt model: every segment, leaf included) | Keeps exact lookup and delimiter listing, but breaks the partial-leaf prefix listing kopia relies on — an encrypted leaf has no usable prefix, so `Prefix: "…/p"` matches nothing and every kopia repository open fails. Also changes lexicographic order within a directory. |
| **Prefix-preserving or order-preserving encryption** | Preserves exactly what it is supposed to hide. There is no security argument for it against an adversary who holds the whole bucket and can compare across time. |
| **A mapping index stored in the bucket** | Every lookup then depends on an object the hostile backend can withhold, roll back to an older version, or serve selectively. It fails the reliability condition and hands the adversary a denial-of-service and a rollback oracle in one object. |
| **Encrypting the leaf but keeping a searchable prefix token** | Reintroduces the index, or leaks the prefix it makes searchable. |

**Decided form:** encrypt only the directory segments, leave the leaf clear;
deterministic, wide-block, keyed per proxy. kopia's prefix becomes
`<encrypted dirs>/<clear leaf prefix>`, Velero's common prefixes decrypt back,
exact keys map one to one, and order within a directory is untouched.

**Residual leak, stated plainly:** leaf names, sizes, counts, timing. See Risks
for what "leaf names" costs specifically in the Velero layout — it is more than
the findings doc assumed, and Stage 0 item 3 measures it.

---

## Construction

### The name key

One 64-byte key, `K_name`, per proxy deployment. It is **not** derived from the
KEK. That is deliberate:

- Rotating the active provider — which is a KEK change — is a supported
  operation (e2e scenario V9, `TestV9_ProviderRotation`,
  [scenarios_lifecycle_test.go:165](../../test/e2e/velero/scenarios_lifecycle_test.go#L165)).
  A name key derived from KEK material would rename every object in the bucket
  the moment the KEK changes, which turns a metadata-only rotation into a full
  bucket rewrite.
- Two of three KEK providers cannot produce raw key material at all: RSA has a
  key pair, Tink/KMS has a handle. There is no `ikm` to run HKDF over.

Instead the name key is wrapped by the active KEK, exactly like an object DEK:

```yaml
encryption:
  filename_encryption:
    enabled: true                       # default false
    wrapped_key: "base64(KEK-wrapped 64 bytes)"
    kek_fingerprint: "<fingerprint of the KEK that wrapped it>"
```

At startup the proxy resolves the provider by fingerprint
([providers.go:305](../../internal/orchestration/providers.go#L305)), unwraps once
via `KeyEncryptor.DecryptDEK`
([interfaces.go:16](../../pkg/encryption/interfaces.go#L16)), and holds the key for
the process lifetime. Startup **fails** when: the fingerprint names no configured
provider, the unwrap fails, or `enabled: true` is combined with the `none`
provider. No lazy unwrap on the request path, and no silent fall back to
cleartext names — a proxy that cannot decrypt names cannot serve the bucket at
all, and saying so at startup is the only honest failure mode.

Rotating the KEK re-wraps the same `K_name` under the new KEK and changes nothing
in the bucket.

### The per-segment transform

`AES-SIV-CMAC` (RFC 5297) with a 512-bit key, from
`github.com/google/tink/go/daead/subtle` — **already a dependency**
(`github.com/google/tink/go v1.7.0` in [go.mod](../../go.mod), used by the Tink KEK
provider). `NewAESSIV` requires exactly 64 bytes and the package documents why:
a 128-bit MAC key is insufficient in the multi-user setting. The instance is
constructed once and is safe to share — `EncryptDeterministically` and `s2v`
allocate their working buffers locally and never mutate the receiver.

For a key `d_1/d_2/…/d_n/leaf`:

```
stored_i = base64url_nopad( AES-SIV(K_name).EncryptDeterministically(d_i, AAD_i) )
AAD_i    = "s3ep-name-v1" || 0x00 || uint8(i) || 0x00 || stored_1/…/stored_{i-1}
stored   = stored_1/stored_2/…/stored_n/leaf
```

Properties this buys:

- **Deterministic** — the same client key always yields the same stored key, so
  exact GET/HEAD/DELETE/PUT need no state and no round trip.
- **Wide-block in effect** — SIV is a deterministic AEAD, not a block-by-block
  mode. One changed byte of a segment changes the whole output, and different
  segments are computationally unlinkable. There is no partial match, no length
  ladder beyond the length itself, and no chosen-prefix distinguisher.
- **Authenticated** — a segment the backend forged does not decrypt. Injected
  names are detectable, not confusable with real ones.
- **Position-bound** — the AAD carries the depth and the *ciphertext* of the
  parent chain, so a directory subtree the backend moves or duplicates fails to
  decrypt in its new place. Using the ciphertext parent rather than the plaintext
  parent means each segment is verifiable independently, without decrypting its
  ancestors first — which is what a listing needs.
- **The bucket is deliberately not in the AAD**, mirroring v2's reasoning: a
  ciphertext bucket can be copied wholesale to another bucket or provider for
  disaster recovery, names included, without a rename pass. The residual is in
  Risks.

**Encoding.** `base64.RawURLEncoding`: the alphabet is `[A-Za-z0-9_-]`, every
character of which is in AWS's "safe characters" set, none of which is `/`, and
none of which needs URL escaping in a key. Expansion is 16 bytes of SIV tag then
4/3: a segment of `n` bytes becomes `ceil(4*(n+16)/3)` characters
(`RawURLEncoding.EncodedLen`, no padding) — a 63-character Kubernetes namespace
becomes 106. Base32 (rclone's choice, 60 % expansion) is the
fallback **only** if a backend that folds key case ever has to be supported; S3
keys are case-sensitive by specification and such a backend is already broken for
ordinary keys.

**Length guard.** S3 caps a key at 1024 bytes. The transform inflates only the
directory part, so the effective limit on a client key is roughly
`1024 - sum_i(ceil(4*(n_i+16)/3) - n_i)`. A PUT (or any exact-key operation)
whose transformed key exceeds 1024 bytes is refused with a distinct, documented
error rather than sent to the backend to fail obscurely.

**Edge cases**, all decided by the same split rule — split on `/`, everything
before the last `/` is a directory segment, the remainder is the leaf:

| Client key | Stored key |
|---|---|
| `foo.txt` (no `/`) | `foo.txt` — unchanged, no directory segments exist |
| `a/b/c.txt` | `E(a)/E(a,b)/c.txt` |
| `a/b/` (directory marker) | `E(a)/E(a,b)/` — empty leaf, round-trips |
| `a//b.txt` | `E(a)/E(a,"")/b.txt` — an empty segment encrypts to a 22-character token |

### Cost per request

- **Exact-key operations** (GET, HEAD, PUT, DELETE, every multipart call): one
  AES-SIV per directory segment. The Velero layout, for example, is two or three
  segments, and the cost is linear in depth. Each
  is a CMAC over the 15-byte AAD header plus the parent ciphertext chain (nothing
  for the first segment, ~100 bytes for the second) and a ≤64-byte segment, then a
  short CTR pass — on the order of a microsecond in total, against a backend round
  trip in the millisecond range. **Zero per-byte cost:** the transform never touches the
  object payload, so upload and download throughput cannot move.
- **Listings** pay one decrypt per returned key per directory segment: a
  1000-key page at three segments is 3000 SIV operations. Tink's `ctrCrypt`
  re-expands the AES key schedule on every call, so this is the one place the
  cost is worth measuring rather than asserting. Where a listing page has **one**
  distinct directory path — the Velero and kopia layouts do — a small bounded LRU
  over `(parent ciphertext, segment)` collapses it to a handful of operations per
  page; a client that spreads a page over many directories gains less.
  The LRU is a work item **conditioned on the benchmark**, not built up front.
- Startup: one KEK unwrap.

---

## Where a key crosses the proxy boundary

Every site was read for this ticket. The point of the list is that it is long,
which is the argument against transforming at the call sites.

**Where the clear key enters** (must stay clear — the SigV4 signature is computed
over the client-visible path at
[s3auth_robust.go:308](../../internal/proxy/middleware/s3auth_robust.go#L308) and
[s3auth_presigned.go:189](../../internal/proxy/middleware/s3auth_presigned.go#L189),
and the encryption manager binds it as AAD):

- [object/handler.go:88-90](../../internal/proxy/handlers/object/handler.go#L88-L90),
  and the five passthrough entry points at
  [:132-171](../../internal/proxy/handlers/object/handler.go#L132-L171)
- [multipart/create.go:50-52](../../internal/proxy/handlers/multipart/create.go#L50-L52),
  [multipart/upload.go:51-53](../../internal/proxy/handlers/multipart/upload.go#L51-L53),
  [multipart/complete.go:66-68](../../internal/proxy/handlers/multipart/complete.go#L66-L68),
  [multipart/abort.go:48-50](../../internal/proxy/handlers/multipart/abort.go#L48-L50),
  [multipart/list.go:42-44](../../internal/proxy/handlers/multipart/list.go#L42-L44)
- [object/acl.go:41-43](../../internal/proxy/handlers/object/acl.go#L41-L43),
  [object/tagging.go:41-43](../../internal/proxy/handlers/object/tagging.go#L41-L43)
- [handleDeleteObjects](../../internal/proxy/handlers/object/operations.go#L841-L866):
  keys arrive in the XML body, not the path

**Where a key leaves for the backend** (must be transformed — 25 sites):

| Site | Operation |
|---|---|
| [operations.go:41](../../internal/proxy/handlers/object/operations.go#L41) | GetObject |
| [range.go:124](../../internal/proxy/handlers/object/range.go#L124), [range.go:203](../../internal/proxy/handlers/object/range.go#L203) | ranged GetObject, whole-object fallback |
| [operations.go:566](../../internal/proxy/handlers/object/operations.go#L566), [:658](../../internal/proxy/handlers/object/operations.go#L658) | PutObject, direct and streaming |
| [operations.go:741](../../internal/proxy/handlers/object/operations.go#L741) | DeleteObject |
| [operations.go:762](../../internal/proxy/handlers/object/operations.go#L762) | HeadObject |
| [operations.go:866](../../internal/proxy/handlers/object/operations.go#L866) | DeleteObjects, per object in the body |
| [operations.go:992](../../internal/proxy/handlers/object/operations.go#L992), [:1015](../../internal/proxy/handlers/object/operations.go#L1015) | Get/PutObjectLegalHold |
| [operations.go:1047](../../internal/proxy/handlers/object/operations.go#L1047), [:1070](../../internal/proxy/handlers/object/operations.go#L1070) | Get/PutObjectRetention |
| [operations.go:1100](../../internal/proxy/handlers/object/operations.go#L1100) | GetObjectTorrent |
| [operations.go:1147](../../internal/proxy/handlers/object/operations.go#L1147) | SelectObjectContent |
| [operations.go:1226](../../internal/proxy/handlers/object/operations.go#L1226), [:1254](../../internal/proxy/handlers/object/operations.go#L1254), [:1314](../../internal/proxy/handlers/object/operations.go#L1314), [:1474](../../internal/proxy/handlers/object/operations.go#L1474) | auto-multipart: Create, Abort, UploadPart, Complete |
| [operations.go:1507](../../internal/proxy/handlers/object/operations.go#L1507) | the post-Complete self-copy — **deleted by v2**, listed so its absence is confirmed, not assumed |
| [create.go:63](../../internal/proxy/handlers/multipart/create.go#L63), [:111](../../internal/proxy/handlers/multipart/create.go#L111) | CreateMultipartUpload, and the abort on init failure |
| [upload.go:227](../../internal/proxy/handlers/multipart/upload.go#L227) | UploadPart |
| [complete.go:196](../../internal/proxy/handlers/multipart/complete.go#L196), [:225](../../internal/proxy/handlers/multipart/complete.go#L225) | CompleteMultipartUpload, self-copy (**deleted by v2**) |
| [abort.go:73](../../internal/proxy/handlers/multipart/abort.go#L73) | AbortMultipartUpload |
| object ACL and tagging sub-handlers | Get/PutObjectAcl, Get/Put/DeleteObjectTagging |
| [bucket/operations.go:29](../../internal/proxy/handlers/bucket/operations.go#L29), [:63](../../internal/proxy/handlers/bucket/operations.go#L63), [:69](../../internal/proxy/handlers/bucket/operations.go#L69) | ListObjectsV2 `Prefix`, ListObjects `Prefix` and `Marker` |

**Where a key prefix hides in a payload** (deliberately left alone): bucket
lifecycle, replication, notification and logging configurations carry key
prefixes inside their bodies, and those methods sit on the same interface
([s3_backend.go:34-58](../../internal/proxy/interfaces/s3_backend.go#L34-L58)).
`PutBucketLifecycleConfiguration` with a body answers 501 today
([lifecycle.go:81](../../internal/proxy/handlers/bucket/lifecycle.go#L81)), so
nothing can be written through the proxy; a `Get` returns whatever the operator
configured on the backend, untranslated. They stay untransformed — but the
Stage 3 allowlist records them as **deliberately** untransformed, not as
key-free, so that a later implementation of the `Put` body does not inherit a
wrong answer in silence.

**Where a stored key would come back to the client** (must be mapped back):

| Site | What |
|---|---|
| [bucket/operations.go:52](../../internal/proxy/handlers/bucket/operations.go#L52), [:79](../../internal/proxy/handlers/bucket/operations.go#L79) | `Contents[].Key`, `CommonPrefixes[].Prefix`, echoed `Prefix`, `StartAfter`, `Marker`, `NextMarker` |
| [operations.go:923](../../internal/proxy/handlers/object/operations.go#L923), [:937](../../internal/proxy/handlers/object/operations.go#L937) | `DeleteObjectsOutput.Deleted[].Key` and `Errors[].Key`, echoed into the `DeleteResult` document |
| [complete.go:295-305](../../internal/proxy/handlers/multipart/complete.go#L295-L305) | `<Location>` — already built from the proxy's own scheme, host and request path, so it needs no mapping |
| `ListParts` (`handlers/multipart/list.go`) | since 2026-09-11 built from the session's part table, which holds the clear key, so it needs no mapping |
| `ListMultipartUploads` (`handlers/multipart/list.go`) | forwarded since 2026-09-11, so its document carries backend keys: `Uploads[].Key`, `CommonPrefixes`, `NextKeyMarker` |
| [response/errors.go:40-43](../../internal/proxy/response/errors.go#L40-L43) | `<Resource>`; `WriteS3Error` builds it from the bucket and key the handler passes in, which are the clear ones, so it stays correct for free |

### The boundary decorator

Transforming at 25 call sites is 25 chances to forget one, and forgetting one is
silent: the object is written under a clear name, or read from a name that does
not exist. Instead, **one decorator implements the transform once**, and no
handler ever sees a stored key.

`s.s3Backend` is the concrete SDK client
([server.go:23](../../internal/proxy/server.go#L23),
[:125](../../internal/proxy/server.go#L125)) and the handlers take the interface
`interfaces.S3BackendInterface`
([s3_backend.go:11](../../internal/proxy/interfaces/s3_backend.go#L11)). A struct
that **embeds** that interface inherits all 59 methods and overrides only the 25
that carry a key or a prefix in their input or output
([s3_backend.go:69-99](../../internal/proxy/interfaces/s3_backend.go#L69-L99)); each
override is three to six lines. It is wired in at
[router.go:39-42](../../internal/proxy/router.go#L39-L42), where the handlers are
constructed — one wrap, no handler change.

Two invariants follow, and both are testable:

1. Above the decorator, every key is the client's. Signatures, AAD, logs, error
   documents and the encryption manager are correct by construction.
2. Below it, every key is the stored one. There is exactly one place to audit.

When filename encryption is disabled the decorator is not installed at all, so
the feature costs nothing when off.

### Listings in detail

**Prefix rule.** Split the client's prefix on `/`. Everything before the last `/`
is a complete directory segment and is encrypted; the remainder is a partial leaf
and is passed through verbatim. `kopia/ns/p` → `E(kopia)/E(kopia,ns)/p`. A prefix
ending in `/` has an empty partial leaf and works out to the same rule.

**The one shape that cannot work** is a prefix that ends *inside a directory
segment*: `backups/vel` where `vel…` is a directory. Deterministic encryption is
not prefix-preserving, so no partial directory prefix can be translated. The
proxy cannot distinguish that case from a root-level partial leaf, and would
return an empty listing — a silently wrong answer. Stage 0 item 2 establishes
whether Velero or kopia emit that shape; any other S3 client can, since a
user-typed prefix is not bound to a segment boundary. If a client in use does,
the fallback
is a bounded fan-out (list the parent with `Delimiter: "/"`, decrypt the returned
common prefixes, keep those whose plaintext matches the partial segment, and
issue one listing per match) at the cost of one extra round trip plus N. It is
**not** in the base scope; it is built when a client in use needs it — Stage 0
answers that for Velero and kopia only.

**Delimiter.** Only `/` and the empty delimiter are meaningful: any other
delimiter groups on characters inside base64url ciphertext and produces
nonsense. A listing with a different delimiter is **refused** with
`InvalidArgument` rather than answered wrongly.

**Common prefixes** come back encrypted and are decrypted segment by segment. One
that does not decrypt is dropped from the response and logged at warn with a
counter — the alternative, failing the whole listing, hands the backend a
one-object denial of service. AES-SIV means the backend cannot forge a name that
decrypts, so dropping is exactly "objects this proxy did not write", which is the
same class as a foreign object in the bucket today.

**Order.** Within a directory, keys sort by the clear leaf, so order is
unchanged. Across directories, the backend sorts by ciphertext, which is a
permutation of the plaintext order. Consequences:

- `continuation-token` is opaque and backend-order-consistent; it passes through
  untouched, in both directions, and keeps working.
- `StartAfter`/`marker` is a client key. It is transformed forward and resumes
  correctly *in backend order* — which is the wrong set for a client that expects
  plaintext order across directories.
- The proxy does not re-sort. Sorting one page is a lie that looks like an order;
  sorting globally means buffering the whole listing. Backend order is returned
  and documented.

Stage 0 item 1 decides whether that is acceptable for the two clients whose
listing code can be read, kopia and Velero: kopia lists inside one directory, so
it is expected to be unaffected; Velero's `ListCommonPrefixes` usage is expected
to be order-insensitive. Both are **unverified today**, and every other S3 client
gets the documented backend order with no check at all.

### Operations that stay refused

`CopyObject` and `UploadPartCopy` answer 422 `NotSupportedWithEncryption`
([operations.go:373-385](../../internal/proxy/handlers/object/operations.go#L373-L385),
[copy.go:43](../../internal/proxy/handlers/multipart/copy.go#L43); the router
already registers the copy route ahead of the plain part route
([router.go:92-93](../../internal/proxy/router.go#L92-L93)), so `UploadPartCopy`
is no longer shadowed). This ticket keeps them refused, and
the reason is v2, not names: v2 binds the client key into the AAD, so a
backend-side copy to a *different* key produces an object whose AAD no longer
matches its name and which is undecryptable. Server-side copy under v2 can only
ever mean decrypt-and-re-encrypt through the proxy, which is a separate ticket.
If that ticket is ever written, `x-amz-copy-source` becomes another key crossing
the boundary and must go through the decorator — recorded here so it is not
missed.

The one copy that *is* valid is a rename to the **same** client key, which is
exactly the migration below.

### Migration and the mapping tool

Enabling the feature on a bucket that already holds objects is a rename pass:
for every key, `CopyObject` on the backend from the clear key to the transformed
key with the same client key, then delete the source. The stored bytes are valid
under both names because the AAD binds the client key, which does not change.
The pass runs against the backend directly (the proxy refuses copies) and needs
the transform, so the proxy binary gets a `names` subcommand
([cmd/s3-encryption-proxy/main.go:31](../../cmd/s3-encryption-proxy/main.go#L31)
is the only Cobra command today) with:

- `names wrap` — generate a 64-byte key, wrap it with the configured active KEK,
  print the `filename_encryption` config block;
- `names map <key>` and `names unmap <stored-key>` — the transform, for scripting
  a migration and for debugging a listing.

The alternative for a fresh deployment is simply to enable it before the first
object is written, which is what the README should recommend.

### Logging

The proxy logs the clear key at debug on most paths (for example
[object/handler.go:92-97](../../internal/proxy/handlers/object/handler.go#L92-L97)).
That is fine — the proxy is trusted. What must not happen is a log line carrying
**both** the clear and the stored key above debug level: many deployments ship
logs to the same cloud provider that holds the bucket, and such a line is the
mapping table this design refuses to store. Rule: the stored key appears in logs
only at debug, and never in the same entry as its plaintext.

---

## Work breakdown

### Stage 0 — pre-work; these can change the design

- [ ] **Order dependency (open question 1).** Read kopia's `ListBlobs`
      ([s3_storage.go](https://github.com/kopia/kopia/blob/master/repo/blob/s3/s3_storage.go))
      and Velero's object-store layer (`pkg/persistence`, `ListObjects` and
      `ListCommonPrefixes`) and record for each call: the prefix shape, the
      delimiter, whether a marker or `StartAfter` is used, and whether the caller
      relies on the returned order. Write the answer into this ticket.
- [ ] **Same question, empirically.** Add a temporary debug log of
      `prefix / delimiter / marker / start-after / continuation-token` to
      [handleListObjects](../../internal/proxy/handlers/bucket/operations.go#L15),
      run the full e2e (`make e2e-velero`), and collect the distinct listing
      shapes Velero and kopia actually emit. Confirm that no prefix ends inside a
      directory segment; if one does, schedule the fan-out fallback.
- [ ] **Measure the real leak (leaf names).** Dump a complete bucket listing
      after scenario V1 and record which leaf names embed the backup name.
      Velero's `object_store_layout.go` names objects such as
      `backups/<name>/<name>-logs.gz` and `<name>-resource-list.json.gz`, which
      would mean the backup name survives in the leaf even after the directory is
      encrypted, while the kopia namespace is fully hidden because kopia's leaves
      are hashes. Confirm or refute, and write the confirmed residual into this
      ticket, the README and `SECURITY_ARCHITECTURE.md`. **This determines how
      much the feature is actually worth in the Velero layout — the one layout
      the e2e can measure, not its worth for every S3 client — so it is done
      before any code.**
- [ ] **Decide the copy and multipart-list question (open question 2)** and record
      it here: `CopyObject` and `UploadPartCopy` stay 422 for the AAD reason
      above; `ListParts` answers from the session part table and needs
      no mapping; `ListMultipartUploads` is forwarded and needs the full
      listing mapping. Confirm against the v2 implementation as it actually
      landed, not as ticket 013 planned it.

### Stage 1 — the transform

- [ ] New package `internal/naming`: `Transformer` with `EncryptKey`,
      `DecryptKey`, `EncryptPrefix`, `DecryptPrefix`, built over
      `github.com/google/tink/go/daead/subtle.NewAESSIV`. No new dependency.
- [ ] Unit tests: round-trip over the edge-case table (no directory, trailing
      slash, empty segment, unicode, `&`, `<`, spaces, `+`, a 1024-byte key);
      determinism across instances; a segment moved to another depth or another
      parent fails to decrypt; a flipped ciphertext bit fails to decrypt.
- [ ] Prefix rule unit tests, including `kopia/ns/p` → `E/E/p` and the
      partial-directory case asserting the **documented** behaviour.
- [ ] Length guard: a transformed key over 1024 bytes returns a typed error.

### Stage 2 — key management

- [ ] `encryption.filename_encryption` config block, validation, and the startup
      unwrap through `ProviderManager.GetProviderByFingerprint`.
- [ ] Refuse to start: unknown fingerprint, failed unwrap, `enabled` with the
      `none` provider, `enabled` with no `wrapped_key`.
- [ ] `names wrap|map|unmap` subcommand on the proxy binary.
- [ ] Config example in `config/` showing an enabled deployment.

### Stage 3 — the boundary decorator

- [ ] `internal/proxy/backend/namemapper.go`: struct embedding
      `interfaces.S3BackendInterface`, overriding every key- and prefix-bearing
      method in both directions.
- [ ] Wire it in at [router.go:39-42](../../internal/proxy/router.go#L39-L42); not
      installed when the feature is off.
- [ ] A test that fails if a new key-bearing method is added to the interface
      without an override (reflection over the interface's method set against an
      explicit allowlist, which separates methods that carry no key at all from
      the bucket-configuration methods deliberately left untransformed).
- [ ] Handler-level test with a mock backend: for each of GET, HEAD, PUT, DELETE,
      DeleteObjects and the four multipart calls, assert the mock saw the
      **stored** key and the client saw the **clear** key.

### Stage 4 — listings

- [ ] Map `Prefix`, `Marker`/`StartAfter` forward; map `Contents[].Key`,
      `CommonPrefixes[].Prefix`, the echoed `Prefix`, `NextMarker` and
      `Uploads[].Key` back.
- [ ] Pass `continuation-token` through untouched, both directions, with a test
      that paginates 2500 objects across three directories.
- [ ] Refuse a delimiter other than `/` or empty with `InvalidArgument`.
- [ ] Drop undecryptable keys and common prefixes, log at warn, expose a counter
      in the monitoring endpoint.
- [x] `<Location>` in the CompleteMultipartUpload response is already built from
      the proxy, not echoed from the backend: scheme + `r.Host` +
      `r.URL.EscapedPath()`
      ([complete.go:295-305](../../internal/proxy/handlers/multipart/complete.go#L295-L305)),
      i.e. the client-visible path. Correct under name encryption for free.

### Stage 5 — tests that are the contract

- [ ] Integration suite (both transports): write and read back keys with 0, 1 and
      3 directory levels; kopia-shaped partial-leaf prefix listing; delimiter
      listing with common prefixes; pagination; DeleteObjects; multipart upload
      of a 3-level key; assert **on the MinIO backend directly** that no
      plaintext directory segment appears in any stored key.
- [ ] e2e: enable filename encryption in
      [values-proxy.yaml](../../test/e2e/velero/values-proxy.yaml) and run the full
      suite. `listBackendObjects`
      ([backend.go:96](../../test/e2e/velero/backend.go#L96)) and the at-rest
      assertions at
      [scenarios_atrest_test.go:39](../../test/e2e/velero/scenarios_atrest_test.go#L39),
      [:91](../../test/e2e/velero/scenarios_atrest_test.go#L91) and
      [:126](../../test/e2e/velero/scenarios_atrest_test.go#L126) use literal
      `backups/<name>/` and `kopia/` prefixes against the backend and **will
      break**: give them the transform, and add an assertion that the raw backend
      listing contains neither the namespace name nor the string `backups/`.
- [ ] Decide and record whether the e2e runs with the feature on permanently or
      as an extra scenario. Permanently is the stronger contract; an extra
      scenario keeps the suite's other assertions readable.

### Stage 6 — measurement

- [ ] Benchmark the transform: exact-key (2 and 3 segments) and a 1000-key
      listing decrypt, in ns/op and allocs/op.
- [ ] Re-run `make test-integration-performance` and compare against the numbers
      ticket 013 recorded. Expect no movement — the transform never touches the
      payload. Any movement is a bug, not a cost.
- [ ] **Only if** the listing benchmark shows the decrypt above ~1 % of a listing
      request: add a bounded LRU over `(parent ciphertext, segment)` in both
      directions and re-measure.

### Stage 7 — documentation

- [ ] README: the `filename_encryption` block in the full reference, the
      naming-conventions table (client key → stored key), the residual leak
      confirmed in Stage 0 item 3, the recommendation to enable it before the
      first object is written, the delimiter restriction, the cross-directory order
      behaviour, and the key-length limit.
- [ ] `SECURITY_ARCHITECTURE.md`: what the transform hides, what it does not,
      the deterministic-encryption residual, the name-key loss consequence, and
      the fact that the name key is as critical to back up as the KEK.
- [ ] `CLAUDE.md`: the transform boundary rule — keys are transformed only in the
      backend decorator, never above it.

---

## Success criteria

- `make test-unit` green, with the `internal/naming` tests above.
- `make test-integration` and `make test-integration-tls` green with the feature
  **on** and with it **off**; the suite runs both ways.
- `make test-integration-performance` shows no regression against the numbers
  ticket 013 recorded on upload, download or small-object throughput.
- `./start-demo.sh` with filename encryption enabled: `aws s3 cp` up and down
  through the proxy round-trips; `mc ls` against MinIO directly shows no
  plaintext directory segment.
- `make e2e-velero` green with the feature enabled, all 13 scenarios, including
  V2 and V3 (kopia restores, which is where a broken prefix listing would show
  up first) and V9 (KEK rotation, which must **not** rename anything).
- A backend listing taken during the e2e contains no namespace name and no
  `backups/` or `restores/` segment; the assertion is in the suite, not in a
  reviewer's head.
- Stage 0's four answers are written into this ticket, the README and
  `SECURITY_ARCHITECTURE.md` — including the leaf-name residual, honestly, even
  where it is larger than the findings doc assumed.

---

## Risks and open questions

- **The leaf still carries the backup name.** Velero's own layout embeds the
  backup name in most leaf names (`<name>-logs.gz`,
  `<name>-resource-list.json.gz`). If Stage 0 item 3 confirms it, then in the
  Velero layout this feature fully hides only the **kopia namespace** (whose
  leaves are hashes) and the directory occurrences of backup and restore names,
  while the backup name itself remains readable in the leaf. That is still worth
  shipping — the namespace inventory is the most sensitive of the three — but the
  README must not claim backup names are hidden. **UNVERIFIED against a real
  bucket; verify before writing any code.**
- **Cross-directory order changes.** Whether kopia or Velero depend on it is
  **UNVERIFIED**, and they are the only clients Stage 0 checks — every other S3
  client gets the documented backend order unchecked. It is Stage 0 item 1 and
  it is the one finding that could stop
  the feature. `StartAfter` resumption across directories is semantically wrong
  under the transform, and `start-after` is not even forwarded today
  ([bucket/operations.go:28-43](../../internal/proxy/handlers/bucket/operations.go#L28-L43)),
  so it cannot be tested until the D-11 listing ticket lands.
- **A partial-directory prefix returns an empty listing, not an error.** The
  proxy cannot distinguish it from a root-level partial leaf. Documented, tested,
  and fixable with the fan-out only if a client needs it.
- **Losing the name key makes the bucket unnavigable.** The objects stay
  decryptable — v2 binds the client key, not the stored one — but nothing can
  find them without re-deriving every name. It must be backed up exactly like the
  KEK, and the README must say so in those words.
- **Rotating the name key renames the whole bucket.** There is no incremental
  rotation. Wrapping it under the KEK means KEK rotation does not force it, which
  is the case that actually occurs.
- **Deterministic encryption is a dictionary target.** Anyone who can make the
  proxy write a chosen name learns that name's ciphertext. Today every configured
  client can reach every bucket
  ([config.go:74-79](../../internal/config/config.go#L74-L79) has no bucket scope),
  so a client colluding with the backend learns nothing it could not read
  directly. **If per-client bucket authorization is ever added, this becomes a
  real cross-tenant leak and the bucket has to enter the AAD** — at the cost of
  the wholesale bucket-copy property. Record the coupling now so the authorization
  ticket does not silently break it.
- **Tink's AES-SIV re-expands the AES key schedule per call.** Fine for exact-key
  operations, measurable on large listings. Measured in Stage 6, cached only if
  the measurement says so.
- **The e2e's own at-rest assertions are written against clear keys** and are
  part of the end-user contract; they get the transform, they do not get relaxed.
- **Ordering against the D-11 listing ticket is a real sequencing risk.** If this
  ticket lands first, the listing mapping has to be written twice — once against
  the SDK struct, once against the new document builder. Prefer D-11 first.
