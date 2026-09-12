# ADR 0023: Filename encryption, if it ships, encrypts directory segments only

## Status

**Accepted.** Date: 2026-09-07.

Decided and specified; **not implemented**. No filename encryption exists today: every object
key reaches the backend exactly as the client wrote it. Under an encrypting provider, key names
are the largest part of a stored object the proxy does not protect — the user metadata and the
object tags a client sets travel in the clear as well, deliberately (ADR 0007), and no feature
here changes that. The decision below fixes the shape of the feature so that neither the storage
format nor the listing work can foreclose it by accident. It does not ship in 5.0.0.

**Both dependencies have cleared, verified 2026-09-12.** The authenticated segment chain
(ADR 0003) and the listing document rewrite (ADR 0010) are both on the 5.0.0 branch: the proxy
builds the listing documents itself, in both listing versions, and states a size the backend did
not choose. What still blocks the feature is the open listing question in *Residual risks*.
Nothing about the feature itself has been built, and neither the format work nor the listing work
changed the name an object is stored under. When it lands it is **opt-in and off by default**;
enabling it on an existing bucket is a rename pass, never a re-encryption.

## Context

The backend is assumed hostile (ADR 0001). Under an encrypting provider every stored byte is
encrypted and every stored byte is authenticated. The key name is not, under any provider.
Whoever holds the bucket reads it for free.

For a backup bucket that is not a detail. Object keys carry whatever structure the client's naming
scheme puts there, and the common backup layouts put the interesting nouns in the path: backup
names and their naming convention, restore names and when they ran, and — the worst of the three —
the namespace or tenant name of every application whose volume data was backed up. Together with
object counts, sizes and timestamps that is a readable map of what is stored, on what schedule,
and from where. It is the customer's internal structure, disclosed to the storage provider without
anyone deciding to disclose it.

Sizes, counts and timing are traffic analysis. Hiding them needs padding and cover traffic and is
out of scope at any price the product is willing to pay. Names are different: they are an avoidable
disclosure.

The constraint that shapes the whole design is the one the repository owner set: **lookups stay
exact and reliable**. A `GET` must not begin by asking the adversary for a translation table, and
no round trip may be added to the hot path. That constraint is what kills the obvious schemes:

* Encrypting the whole key kills prefix listing. Clients list with prefixes that end *inside* a
  leaf name — the content-addressed uploader used for volume data lists by single-letter blob
  prefixes inside one directory — and an encrypted leaf has no usable prefix. Such a client cannot
  open its repository at all.
* A mapping object stored in the bucket makes every lookup depend on an object the hostile backend
  can withhold, serve selectively, or roll back to an older version. That is a denial of service
  and a rollback oracle in one object.
* Randomised name encryption makes an exact lookup impossible: the proxy cannot recompute the
  stored key a previous write produced.

What remains is a deterministic, keyed transform over **directory segments only**, with the leaf
left in the clear. Prefix listings that end inside a leaf keep working, delimiter listings keep
working, exact lookups are one local computation, and order within a directory is untouched. The
cost is that leaf names stay readable — stated plainly below, because in some layouts that is more
than it sounds like.

The ordering is not a scheduling preference. The segment-chain format binds **the client's key**
into the associated data of every segment (ADR 0003). Because the associated data carries the
client's key and never the stored key, name encryption changes only the stored key: the stored
bytes are byte-identical whether the feature is on or off, enabling it on a populated bucket is a
rename, and losing or rotating the name key is a naming problem, never a data problem. Applied
before that rule is settled, a transform upstream of the crypto layer would bind *ciphertext*
names into the associated data of every object written — and every later change to the name key
would make previously stored objects undecryptable, indistinguishably from tampering.

## Decision

**D1** Filename encryption is a configured feature under `encryption.filename_encryption`,
`enabled: false` by default. When it is off the proxy behaves exactly as it does today and the
feature costs nothing — no transform is installed at all.

**D2** Only **directory segments** are encrypted. The key is split on `/`: everything before the
last `/` is directory segments, the remainder is the leaf, and the leaf is stored in the clear. A
key with no `/` is stored unchanged. A trailing `/` is an empty leaf and round-trips. An empty
segment between two slashes is a segment and is encrypted like any other.

**D3** The transform is **deterministic, keyed and stateless**: the same client key always yields
the same stored key, computed locally, without asking the backend anything. The proxy stores **no
mapping index** — not in the bucket, not anywhere the backend can reach.

**D4** Each directory segment is encrypted with **AES-SIV-CMAC (RFC 5297)** under a 512-bit name
key. The associated data of a segment binds the constant version label `s3ep-name-v1`, the
segment's depth, and the
**ciphertext** of its parent chain — so a subtree the backend moves or duplicates fails to decrypt
in its new place, and each segment stays verifiable without decrypting its ancestors first, which
is what a listing needs. The **bucket is deliberately not** in the associated data, mirroring the
storage format, so a ciphertext bucket can be replicated wholesale to another bucket or provider
without a rename pass.

**D5** A segment ciphertext is encoded with **base64url without padding**. Its alphabet contains
no `/`, needs no URL escaping in a key, and is case-sensitive, which S3 keys are by specification.

**D6** The name key is **one 64-byte key per proxy deployment**, generated at random and **not
derived from the key encryption key**. It is wrapped by the active key encryption key exactly like
an object data key and configured as `wrapped_key` plus `kek_fingerprint`. It is unwrapped once at
startup and held for the process lifetime; there is no lazy unwrap on the request path.

**D7** With `enabled: true`, the proxy **refuses to start** when `wrapped_key` is absent, when
`kek_fingerprint` names no configured provider, when the unwrap fails, or when the active provider
is `exit`. There is no fall back to cleartext names: a proxy that cannot decrypt names cannot serve
the bucket, and saying so at startup is the only honest failure (ADR 0013).

**D8** The transform is applied at **exactly one place**: the boundary between the proxy and the
backend, in both directions. Above that boundary every key is the client's — signatures, associated
data, logs and error documents are correct by construction. Below it every key is the stored one.
No request handler ever sees a stored key.

**D9** For a listing, the client's prefix is split by the same rule: complete directory segments
are encrypted, the trailing partial leaf is passed through **verbatim**. A prefix that ends *inside*
a directory segment cannot be translated — deterministic encryption is not prefix-preserving — and
the proxy cannot distinguish that case from a root-level partial leaf; it returns an empty listing,
and that behaviour is documented rather than papered over.

**D10** While filename encryption is on, only `/` and the empty delimiter are accepted. Any other
delimiter would group on characters inside ciphertext and produce nonsense; such a request is
refused with `InvalidArgument` rather than answered wrongly (ADR 0007).

**D11** Keys and common prefixes returned by the backend that do **not** decrypt are dropped from
the response, logged at warn level and counted in the metrics endpoint. The whole listing is not
failed: that would hand the backend a one-object denial of service. Because the transform is
authenticated, a name the backend forged cannot decrypt, so "dropped" means exactly "not written by
this proxy".

**D12** The proxy returns **backend order** and does not re-sort. Within a directory, order is
unchanged, because keys sort by the clear leaf. Across directories the backend sorts by ciphertext,
which is a permutation of plaintext order. A continuation token is opaque and backend-consistent
and passes through untouched in both directions; `StartAfter` and `marker` are client keys,
transformed forward, and resume correctly *in backend order*. Sorting one page would be a lie that
looks like an order; sorting globally would mean buffering the whole listing. Neither is done.

**D13** An exact-key operation whose **transformed** key exceeds the 1024-byte S3 key limit is
refused by the proxy with a distinct, documented error, instead of being sent to the backend to
fail obscurely.

**D14** Enabling the feature on a bucket that already holds objects is a **rename pass**, executed
against the backend directly: copy each object from its clear key to its transformed key under the
same client key, then delete the source. The stored bytes are valid under both names because the
associated data binds the client's key, which does not change. A fresh deployment enables the
feature **before the first object is written**, which is what the documentation recommends.

**D15** Rotating the **key encryption key** re-wraps the same name key and renames nothing.
Rotating the **name key** renames the entire bucket; there is no incremental rotation.

**D16** The proxy binary carries a `names` subcommand for the operations a migration and a debugging
session need: `names wrap` generates a name key, wraps it under the configured active key encryption
key and prints the configuration block; `names map` and `names unmap` apply the transform in each
direction.

**D17** A stored key appears in logs only at **debug** level, and **never in the same log entry as
its plaintext**. Many deployments ship their logs to the same provider that holds the bucket, and a
line carrying both keys is precisely the mapping table this design refuses to store.

**D18** Bucket names, leaf names, object sizes, object counts and timestamps are **not** hidden.
Server-side copy stays refused with `NotSupportedWithEncryption` (ADR 0011). Bucket configuration
documents that carry key prefixes inside their bodies — lifecycle, replication, notification,
logging — stay untransformed, and are recorded as *deliberately* untransformed rather than as
key-free, so a later implementation of those bodies does not inherit a wrong answer in silence.

## Consequences

* **The leaf still leaks.** In layouts that put the backup name into the leaf as well as the
  directory — a widely used backup client does exactly that for its log and resource-list objects —
  this feature hides the tenant or namespace inventory and the directory occurrences of backup and
  restore names, while the backup name itself stays readable. That is still the most sensitive of
  the three, and worth shipping, but the documentation must not claim that backup names are hidden.
* **Keys get longer.** Each directory segment grows by a 16-byte authentication tag and then by the
  4/3 base64 expansion: a 63-character segment becomes 106 characters. Only the directory part
  inflates, but the 1024-byte S3 key limit is consumed by the growth, so the effective limit on a
  client key is lower and depends on its depth. D13 is the visible edge of that.
* **Listings pay per key.** An exact-key operation costs one deterministic encryption per directory
  segment — microseconds against a millisecond round trip, and **zero per-byte cost**, because the
  transform never touches the object payload. A listing pays one decryption per directory segment
  per returned key; a full page at three levels is a few thousand operations. Whether that is worth
  a cache is measured, not asserted (ADR 0020); a bounded cache keyed on the parent ciphertext and
  the segment is built only if the measurement demands it.
* **The name key becomes as critical to back up as the key encryption key.** Losing it does not
  make one byte undecryptable, and that is exactly the trap: the objects survive and the bucket
  becomes unnavigable, because nothing can reconstruct the names to ask for. This must be stated in
  those words in the user-facing documentation.
* **Deterministic means dictionary-attackable.** Anyone who can make the proxy write a name of their
  choosing learns that name's ciphertext, permanently.
* **Cross-directory listing semantics change.** A client that expects plaintext order across
  directories, or that resumes with a marker across directories, gets a different set than it would
  without the feature. The proxy documents the behaviour instead of hiding it behind a partial sort.
* **The end-to-end tests must be taught the transform.** The at-rest assertions read the backend
  directly with literal cleartext prefixes and will break; they get the transform, plus an assertion
  that the raw backend listing contains no tenant name and no cleartext backup directory. They are
  not relaxed (ADR 0019).
* **When the feature is off, none of this exists** — no transform, no boundary layer, no configuration
  burden. That is the price of it being opt-in, and it is also the reason it can ship at all.

## Alternatives Considered

| Alternative | Why it lost |
|---|---|
| **Encrypt every segment including the leaf** (the model used by common encrypting sync tools) | Keeps exact lookup and delimiter listing, but destroys the partial-leaf prefix listing that content-addressed backup clients depend on: an encrypted leaf has no usable prefix, so the listing matches nothing and the client's repository never opens. Also changes order within a directory. |
| **Prefix-preserving or order-preserving encryption** | Preserves exactly what it is supposed to hide. Against an adversary who holds the entire bucket and can compare it across time, there is no security argument left. |
| **A mapping index stored in the bucket** | Every lookup then depends on an object the hostile backend can withhold, serve selectively, or roll back. It fails the reliability condition and hands the adversary a denial of service and a rollback oracle in a single object. |
| **Encrypt the leaf but keep a searchable prefix token** | Reintroduces the index, or leaks the prefix that makes it searchable. |
| **Randomised (non-deterministic) name encryption** | Strictly stronger against correlation, and unusable: an exact `GET`, `HEAD`, `DELETE` or `PUT` cannot recompute the stored key a prior write produced without a stored mapping, which is the previous row. |
| **Derive the name key from the key encryption key** | A key-encryption-key rotation is a supported metadata-only operation; deriving names from it would rename every object in the bucket on every rotation, turning a cheap operation into a full bucket rewrite. A key encryption key need not expose raw key material at all — a KMS-backed provider hands out a handle, not bytes (ADR 0005) — so on such a provider there is nothing to derive from. |
| **Encrypt names inside the proxy's crypto layer rather than at the backend boundary** | Would bind ciphertext names into the associated data of every stored object, making the payload depend on the name key: a name-key change would render stored data undecryptable and indistinguishable from tampering. Keeping the transform strictly below the crypto layer is what makes the whole feature a rename rather than a re-encryption. |
| **Transform at each backend call site** | Every key-bearing call is one more chance to forget one, and forgetting one is silent — an object written under a cleartext name, or read from a name that does not exist. One boundary with one audit point wins. |
| **Sort listing pages back into plaintext order** | Sorting a single page produces something that looks like a global order and is not; sorting globally means buffering an entire bucket listing in the proxy. Returning the backend order and documenting it is the honest option. |

## Residual risks

* **Cross-directory listing order is the gate, and it is UNVERIFIED.** Nobody has established
  whether the S3 clients in use depend on plaintext key order across directories, or on marker
  resumption across them. This is the one finding that could stop the feature, and it is answered by
  reading the clients' listing code and by recording the listing shapes they actually emit in an
  end-to-end run — before any implementation work begins. Two clients can be checked that way; every
  other S3 client gets the documented backend order with no check at all.
* **The size of the leaf-name residual is UNVERIFIED.** How much of the backup name survives in the
  leaf has been reasoned from the layout, not measured against a real bucket. It is measured before
  code is written, because it determines what the feature is actually worth in that layout, and the
  confirmed answer — even if it is worse than assumed — goes into the user-facing documentation.
* **A partial-directory prefix returns an empty listing rather than an error.** The proxy cannot
  distinguish it from a root-level partial leaf. A bounded fan-out — list the parent with a
  delimiter, decrypt the returned common prefixes, keep the matches, issue one listing per match —
  would fix it at the cost of an extra round trip plus one per match. It is **not** in scope and is
  built only if a client in use turns out to emit that shape.
* **The dictionary property becomes a real leak if per-client authorization is ever added.** Today
  every authenticated client may reach every bucket, so a client colluding with the backend learns
  nothing it could not read from the bucket directly. If per-client bucket or prefix scoping is
  introduced, chosen-name writes become a cross-tenant oracle, and the bucket has to enter the
  associated data of the name transform — at the cost of the wholesale bucket-copy property in D4.
  The coupling is recorded here so an authorization change does not break it silently.
* **The per-listing cost is unmeasured.** The available deterministic-encryption implementation
  re-expands its key schedule on every call. Irrelevant for exact-key operations, plausibly
  significant on large listing pages. Measured before any cache is written.
* **Whether the end-to-end suite runs with the feature permanently on, or as an additional scenario,
  is open.** Permanently on is the stronger contract; a separate scenario keeps the rest of the
  suite's assertions readable.
* **Sizes, object counts, timestamps and request patterns stay visible under this feature and under
  any successor short of padding and cover traffic.** They are accepted, not mitigated.
* **The backend can still roll an object back to an older version of the same name.** Name
  encryption changes nothing there; it is the client's own consistency checking that has to catch it
  (ADR 0001).

## References

* ADR 0001 — The S3 backend is hostile, and only the proxy's own verification counts
* ADR 0002 — One data key per object, wrapped by a configured key encryption key
* ADR 0003 — Objects are stored as an authenticated segment chain
* ADR 0005 — A KMS-backed key encryption key is a provider, not a mode
* ADR 0006 — The proxy serves any S3 client
* ADR 0007 — Forward it or refuse it, never silently drop it
* ADR 0010 — Sizes and listings describe the plaintext
* ADR 0011 — The proxy owns the part layout it writes, and refuses copies it cannot re-encrypt
* ADR 0013 — A configuration key exists only if code reads it, and an unworkable configuration refuses to start
* ADR 0019 — Integration and end-to-end tests are the product; they are never skipped
* ADR 0020 — Performance is measured before and after, never asserted
* ADR 0021 — Key material and licenses are generated, never committed
* ADR 0025 — Leaving is a supported mode
* [README.md](../../README.md) — records today that object key names are stored in the clear and that encrypting them is specified and not implemented. The `encryption.filename_encryption` reference, the client-key-to-stored-key naming table, the residual leak, the delimiter restriction and the key-length limit are owed when the feature lands (2026-09-12)
* [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md) — what the backend learns anyway, where key names are out of scope until this lands. Why the name key must be backed up like the key encryption key is owed with the feature (2026-09-12)
