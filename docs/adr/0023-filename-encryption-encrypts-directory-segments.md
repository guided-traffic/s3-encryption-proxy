# ADR 0023: Filename encryption encrypts every segment of the key, with a searchable head on the leaf

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
enabling it on an existing bucket is a configuration change, never a re-encryption (D14 as amended).

**Amended 2026-09-17: the operating model.** The repository owner set two requirements that day:
the feature is switched on and off in configuration, and **both name forms stay readable** — the
names this feature encrypted and the cleartext names of objects written before it was switched on.
That is the read-compatibility mode the first version of D14 avoided by requiring a rename pass
before the first read. D1 now defines four modes, D7 narrows its exit clause to the modes that
write encrypted names, D14 makes enabling the feature a configuration change with the rename pass
as an optional tool, and D19 states how a bucket holding both forms is served. Still open on that
day, each to be taken in its own amendment: the stored form of a segment (a marker and a key
fingerprint), the primitive and its vectors, and the home of the operator commands. **Amended the
same day, D20:** the disclosure a mixed bucket would make through the proxy's own fallback requests
is closed by construction — the proxy asks for a cleartext directory only after the backend has
listed it. **Amended the same day, D21: the leaf is encrypted too**, with a keyed tag of its first
character ahead of the ciphertext, so that the one listing shape that ends inside a leaf name stays
a native backend prefix match. D2, D4, D9, D12 and D18 are amended with it, and the title of this
record changes from "encrypts directory segments only" to what it now says; the file keeps its
name because it is linked from everywhere.

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

* Encrypting the whole key with nothing searchable left in it moves prefix listing into the proxy.
  Clients list with prefixes that end *inside* a leaf name — the content-addressed uploader used
  for volume data lists by single-letter blob prefixes inside one directory — and an encrypted
  leaf has no prefix the backend can match, so every such listing becomes a scan of the whole
  directory. (This record first read that as "such a client cannot open its repository at all",
  which assumed the backend has to do the matching; corrected 2026-09-17, D21.)
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

**D1** (amended 2026-09-17) Filename encryption is a configured feature under
`encryption.filename_encryption`, whose `mode` is one of four values and is `off` by default:

* `off` — no transform is installed, and the feature costs nothing. The proxy behaves as it does
  today for a bucket that never held an encrypted name; a bucket that does hold one is served its
  stored names verbatim, and the proxy says so (a warning and a counter), so switching the feature
  off by accident on such a bucket is loud rather than silent.
* `drain` — new objects are stored under cleartext names; objects under encrypted names stay
  readable. This is the way out: names age out the way payloads age out under the exit provider
  (ADR 0025), and the name key stays configured until the last of them is gone.
* `mixed` — new objects are stored under encrypted names; objects under cleartext names stay
  readable. This is the way in for a bucket that already holds objects.
* `strict` — new objects are stored under encrypted names, and only encrypted names are read: a
  name that is not one is a name this proxy did not write (ADR 0001). This is the finished state,
  the only one in which no fallback request is ever made.

A mode is not a boolean, so that the configuration file states what the proxy does and so that a
fifth mode can be added without a breaking configuration change (ADR 0013).

**D2** (amended 2026-09-17) **Every segment** of the key is encrypted, the leaf included. The key
is split on `/`: everything before the last `/` is directory segments, the remainder is the leaf.
Directory segments and the leaf are encrypted the same way (D4) and stored in different forms
(D5, D21): the leaf carries a searchable head, a directory segment does not. A key with no `/` is a
leaf alone and is encrypted like any other leaf. A trailing `/` is an empty leaf and stays empty,
so a directory placeholder round-trips and the backend still sees it as one. An empty segment
between two slashes is a segment and is encrypted like any other. Until 2026-09-17 this decision
left the leaf in the clear; the reversal and its reason are in D21 and under *Alternatives*.

**D3** The transform is **deterministic, keyed and stateless**: the same client key always yields
the same stored key, computed locally, without asking the backend anything. The proxy stores **no
mapping index** — not in the bucket, not anywhere the backend can reach.

**D4** (amended 2026-09-17) Each segment, the leaf included, is encrypted with **AES-SIV-CMAC
(RFC 5297)** under a 512-bit name key. The associated data of a segment binds the constant version
label `s3ep-name-v1`, the segment's depth, whether the segment is a directory or the leaf, and the
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

**D7** (amended 2026-09-17) With any mode other than `off`, the proxy **refuses to start** when
no name key is configured, when its `kek_fingerprint` names no configured provider, or when the
unwrap fails: a proxy that cannot decrypt names cannot serve the bucket, and saying so at startup
is the only honest failure (ADR 0013). With the exit provider active, `mixed` and `strict` refuse
the start — writing encrypted names beside plaintext payloads would be the "looks protected while
it is not" defect ADR 0025 exists to remove — while `off` and `drain` are accepted, because reading
encrypted names is exactly what leaving needs. `off` with a configured name key refuses the start
too: a key no code reads is a configuration error, not a convenience.

**D8** The transform is applied at **exactly one place**: the boundary between the proxy and the
backend, in both directions. Above that boundary every key is the client's — signatures, associated
data, logs and error documents are correct by construction. Below it every key is the stored one.
No request handler ever sees a stored key.

**D9** (amended 2026-09-17 for the leaf) For a listing, the client's prefix is split by the same
rule: complete directory segments are encrypted, and a trailing partial **leaf** is answered from
the searchable head of D21 — a partial leaf of one character is translated into its tag and is a
native backend prefix; a longer one lists that tag's class and keeps the leaves that decrypt to a
match, behind a continuation token of the proxy's own. A prefix that ends *inside* a directory
segment cannot be translated — deterministic encryption is not prefix-preserving — and the first
version of this decision answered it with an empty listing; that half of the decision is being
re-decided on 2026-09-17 and its text is not restated here until it is.

**D10** While filename encryption is on, only `/` and the empty delimiter are accepted. Any other
delimiter would group on characters inside ciphertext and produce nonsense; such a request is
refused with `InvalidArgument` rather than answered wrongly (ADR 0007).

**D11** Keys and common prefixes returned by the backend that do **not** decrypt are dropped from
the response, logged at warn level and counted in the metrics endpoint. The whole listing is not
failed: that would hand the backend a one-object denial of service. Because the transform is
authenticated, a name the backend forged cannot decrypt, so "dropped" means exactly "not written by
this proxy".

**D12** (amended 2026-09-17) The proxy returns **backend order** and does not re-sort. Within a
directory as across directories that is the order of the stored forms, a permutation of plaintext
order — until 2026-09-17 the leaf was clear and order within a directory was unchanged; before the
leaf was encrypted it was verified for every supported client that none relies on the order of a
listing. A continuation token is opaque; where the proxy answers one listing from more than one
backend listing (the two forms of D19, the classes of D9), the token is the proxy's own and carries
its position in each. `StartAfter` and `marker` are client keys, transformed forward, and resume
correctly *in backend order*. Sorting one page would be a lie that
looks like an order; sorting globally would mean buffering the whole listing. Neither is done.

**D13** An exact-key operation whose **transformed** key exceeds the 1024-byte S3 key limit is
refused by the proxy with a distinct, documented error, instead of being sent to the backend to
fail obscurely.

**D14** (amended 2026-09-17) Enabling the feature on a bucket that already holds objects is a
**configuration change to `mixed`**, and nothing has to be renamed first: the proxy serves the
objects under cleartext names and the objects under encrypted names side by side (D19), and the
cleartext names disappear as the objects they belong to are deleted or expire. A **rename pass**
remains available as an optional operator tool (D16) for a bucket whose cleartext names would
otherwise outlive the operator's patience: copy each object from its clear key to its transformed
key under the same client key, then delete the source; the stored bytes are valid under both
names because the associated data binds the client's key, which does not change, and the pass can
run while the proxy serves. A bucket moves to `strict` once no cleartext directory-bearing name
remains, which a read-only audit proves before the mode is changed. A fresh deployment starts in
`mixed` or `strict` **before the first object is written**, which is what the documentation
recommends.

**D15** Rotating the **key encryption key** re-wraps the same name key and renames nothing.
Rotating the **name key** renames the entire bucket; there is no incremental rotation.

**D16** The proxy binary carries a `names` subcommand for the operations a migration and a debugging
session need: `names wrap` generates a name key, wraps it under the configured active key encryption
key and prints the configuration block; `names map` and `names unmap` apply the transform in each
direction.

**D17** A stored key appears in logs only at **debug** level, and **never in the same log entry as
its plaintext**. Many deployments ship their logs to the same provider that holds the bucket, and a
line carrying both keys is precisely the mapping table this design refuses to store.

**D19** (2026-09-17) In `mixed` and `drain` the proxy decides **per object** which form an object
is stored under, the way the exit provider decides per object whether an object is encrypted
(ADR 0025 D5). The form the current mode writes is looked up first, and the other form only when
the backend answers that the key does not exist; a key without a `/` has one form and is never
looked up twice. An object that exists under both forms — which an overwrite in `mixed` or
`drain` produces — is the one under the writing form; the other copy is shadowed and does not
appear in any answer. A delete removes the object under both forms, so a deleted object cannot
reappear as its shadowed copy. In these two modes an exact-key operation may therefore cost one
more backend request than in `strict`, on a miss and on a delete; `strict` is the mode in which
the constraint of the *Context* — no round trip added to the hot path — holds again in full.

**D20** (2026-09-17) In `mixed` and `drain` the proxy asks the backend for the other form of a
name only when it has reason to believe that form exists, and it learns that from the backend
itself: before it looks up or deletes the other form of `a/b/c/leaf`, or lists the other form of
a prefix under it, it has seen `a`, then `a/b`, then `a/b/c` among the directories a listing of
the respective parent returned — each answer cached briefly and bounded, negatives included. A
directory created after the feature was switched on is therefore never named in a request in its
cleartext form, and the disclosure recorded in *Residual risks* is closed by construction rather
than by documentation; a test proves it by recording every request the proxy makes. What is
cached is not the mapping index D3 refuses: it holds only cleartext directory names the backend
itself returned, it lives in the proxy's memory and nowhere the backend can reach, and a backend
that withholds a directory from a listing withholds that directory's objects too, which is a
denial of service and not an oracle (ADR 0001). The cache is bounded; above its bound the proxy
warns, counts and asks for every other form — the documented, slower behaviour, never a silent
one.

**D21** (2026-09-17) The leaf is encrypted like a directory segment, and its stored form carries,
ahead of the ciphertext, a fixed-width keyed tag of the leaf's **first character**, computed under
the name key over the parent chain and that character. The tag is what keeps the one listing shape
that ends inside a leaf name — the content-addressed uploader's single-letter blob prefixes — a
native backend prefix match: a one-character partial leaf is translated into its tag, and a longer
one lists that tag's class and filters by decrypting. What the tag discloses is exactly which
leaves of one directory share a first character, and nothing across directories, because the
parent chain is under the tag. For the backup layouts this product is aimed at that is the blob
type, which the object's size discloses anyway, or the fact that the files of one backup share the
backup's name, which their common directory discloses anyway. Directory segments carry no tag: a
partial directory name is the rarer listing shape and is answered by decrypting the parent's
listing, and a tag on directory names would cluster the tenant inventory by first letter. The
tag's width and the one-character head are constants of the stored format, not configuration;
changing either is a rename.

**D18** (amended 2026-09-17) Bucket names, object sizes, object counts, timestamps and the length
of every segment to within fifteen bytes are **not** hidden; leaf names are, since D21, except for
which leaves of one directory share a first character.
Server-side copy stays refused with `NotSupportedWithEncryption` (ADR 0011). Bucket configuration
documents that carry key prefixes inside their bodies — lifecycle, replication, notification,
logging — stay untransformed, and are recorded as *deliberately* untransformed rather than as
key-free, so a later implementation of those bodies does not inherit a wrong answer in silence.

## Consequences

* **The leaf is hidden since 2026-09-17, and the head tag is its price.** In layouts that put the
  backup name into the leaf as well as the directory — a widely used backup client does exactly
  that for its log and resource-list objects — the feature now hides the backup name, the schedule
  name and the timestamps in restore names together with the tenant inventory. What the backend
  keeps is D18: which leaves of one directory share a first character, and every segment's length
  to within fifteen bytes. The documentation may say that the backend learns no name; it must also
  say what D18 lists.
* **Keys get longer.** Every segment, the leaf included, grows by its padding to a multiple of
  sixteen bytes, a 16-byte authentication tag and the 4/3 base64 expansion, and the leaf by its
  head tag on top: a 63-character segment becomes 107 characters before whatever marks it (D5).
  The 1024-byte S3 key limit is consumed by the growth, so the effective limit on a client key is
  lower and depends on its depth. D13 is the visible edge of that.
* **Listings pay per key, and a partial leaf longer than one character pays its class.** An
  exact-key operation costs one deterministic encryption per segment — microseconds against a millisecond round trip, and **zero per-byte cost**, because the
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
| **Encrypt every segment including the leaf, with nothing searchable left** (the model used by common encrypting sync tools) | Rejected on 2026-09-07 on the ground that an encrypted leaf has no usable prefix, so a content-addressed client's listing matches nothing and its repository never opens — an argument that assumed the backend has to do the matching. The proxy can list the directory and filter by decrypting, so the client does open its repository; what this variant costs is a scan of the whole directory for every such listing, several times per repository open, which on a large repository is seconds to minutes where today it is milliseconds. The leaf is encrypted since 2026-09-17 (D21); this tag-less variant lost to the head tag on that cost. |
| **A clear first character on the leaf instead of a keyed tag** (2026-09-17) | The same listing behaviour with no primitive at all. Loses because it discloses the character itself rather than which leaves share one; the tag costs four characters and one keyed hash. |
| **Prefix-preserving or order-preserving encryption** | Preserves exactly what it is supposed to hide. Against an adversary who holds the entire bucket and can compare it across time, there is no security argument left. |
| **A mapping index stored in the bucket** | Every lookup then depends on an object the hostile backend can withhold, serve selectively, or roll back. It fails the reliability condition and hands the adversary a denial of service and a rollback oracle in a single object. |
| **Encrypt the leaf but keep a searchable prefix token** | Reintroduces the index, or leaks the prefix that makes it searchable. |
| **Randomised (non-deterministic) name encryption** | Strictly stronger against correlation, and unusable: an exact `GET`, `HEAD`, `DELETE` or `PUT` cannot recompute the stored key a prior write produced without a stored mapping, which is the previous row. |
| **Derive the name key from the key encryption key** | A key-encryption-key rotation is a supported metadata-only operation; deriving names from it would rename every object in the bucket on every rotation, turning a cheap operation into a full bucket rewrite. A key encryption key need not expose raw key material at all — a KMS-backed provider hands out a handle, not bytes (ADR 0005) — so on such a provider there is nothing to derive from. |
| **Encrypt names inside the proxy's crypto layer rather than at the backend boundary** | Would bind ciphertext names into the associated data of every stored object, making the payload depend on the name key: a name-key change would render stored data undecryptable and indistinguishable from tampering. Keeping the transform strictly below the crypto layer is what makes the whole feature a rename rather than a re-encryption. |
| **A boolean `enabled`, with encrypted names read whenever a name key is configured** (2026-09-17) | Fewer keys and literally on/off. It loses because the configuration file then does not say what the proxy does — with `enabled: false` it keeps decrypting names for as long as a key is present — and because it has no finished state: without `strict` a bucket stays in mixed operation forever, with a fallback request on every miss and the cleartext copy of an old object as a lever the backend can pull. A boolean cannot become a mode later without a breaking configuration change (ADR 0013), so the mode is the shape from the first release. |
| **A rename pass before the first read** (D14 as first written, 2026-09-17) | Made the copier a launch requirement — a second S3 write path inside the binary, holding the backend credential and delete rights on the whole bucket — and made switching the feature off on a populated bucket impossible without a second pass. Serving both forms per object removes both, at the price of one fallback request on a miss or a delete and of the leak recorded in *Residual risks*. |
| **Transform at each backend call site** | Every key-bearing call is one more chance to forget one, and forgetting one is silent — an object written under a cleartext name, or read from a name that does not exist. One boundary with one audit point wins. |
| **Sort listing pages back into plaintext order** | Sorting a single page produces something that looks like a global order and is not; sorting globally means buffering an entire bucket listing in the proxy. Returning the backend order and documenting it is the honest option. |

## Residual risks

* **Cleared 2026-09-13: no supported client relies on listing order.** Read in each client's
  listing code: the backup client re-sorts its own results, the sync tool sorts every listing, the
  content-addressed uploader lists into a map, the command-line client builds its own comparison
  lists. A permutation within a directory (D21) and across directories is therefore safe for every
  named client; every other S3 client gets the documented backend order with no check at all, and
  the listing shapes the named clients emit are still recorded in an end-to-end run before the
  listing work starts.
* **Closed 2026-09-17 by D21: the leaf-name residual.** The census of the widely used backup
  client's layout, read from its source on 2026-09-13, found that eleven of twelve backup leaf
  shapes and five of five restore leaf shapes carry the backup name, so a clear leaf left the
  directory encryption of that layout almost nothing to hide. Encrypting the leaf is what makes the
  feature worth shipping for that layout. What the backend still learns is D18, and the
  documentation says so.
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
* **Closed 2026-09-17 by D20: a bucket in `mixed` or `drain` would otherwise disclose new
  directory names through the proxy's own fallback requests.** Every request for the cleartext form
  of a key carries the cleartext name to the backend, whose access log keeps it. For a name stored
  before the feature was switched on that discloses nothing; for a directory created afterwards it
  would disclose the very name the feature hides — a backup client's maintenance deleting under a
  namespace created after the switch was the concrete case. D20 makes the proxy ask only for
  cleartext directories the backend itself has listed. What remains: the bound and the lifetime of
  what D20 caches are tuned by measurement (ADR 0020), and a bucket with more distinct cleartext
  directories than the bound is served correctly but asks for every other form, as the design
  before D20 did, and says so.
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
