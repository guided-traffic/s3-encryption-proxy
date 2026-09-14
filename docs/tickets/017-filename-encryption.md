# Ticket 017: Filename encryption, directory segments only

## Status (2026-09-13)

**Open. Not started. Unblocked technically, gated on decisions.**

The feature is specified in
[ADR 0023](../adr/0023-filename-encryption-encrypts-directory-segments.md) and
nothing of it is built. Both dependencies the ticket originally waited on have
landed: the authenticated segment chain (ADR 0003) and the listing document
rewrite (ADR 0010). What blocks it now is not code — it is **fourteen decisions,
four of which expire at the first written object**, and **one census that ADR 0023
made a precondition and nobody has run**.

This document was rewritten on 2026-09-13 after a full re-verification against
the tree at HEAD. **The previous version must not be used as a work list.** Its
boundary table was wrong in both directions, every line anchor had drifted
including the ones in its own 2026-09-07 correction pass, and its "Before you
start" section was *exactly inverted* on the most dangerous point — see the first
row of the table below.

---

## Ground truth at HEAD

Every claim here was read in the tree during the 2026-09-13 pass. Claims marked
**UNVERIFIED** could not be settled from the repository and are listed again
under *Stage 0*.

### What the previous version got wrong

| It said | Reality at HEAD | Why it matters |
|---|---|---|
| Object tagging, retention and legal hold "no longer reach the backend at all"; only `?torrent` is a live passthrough | **Exactly inverted.** Tagging, retention and legal hold are live backend passthroughs again, re-added in `36bd3fd` (`object/tagging.go:72,:100,:117`, `object/objectlock.go:27,:71,:86,:111`). `?torrent` is refused with 422 (`object/operations.go:865`), and so is `SelectObjectContent` (`:873`) | Following the old note drops **seven live key-bearing operations** and keeps one unreachable method. A client setting an object tag would write it under a cleartext key |
| "AES-SIV needs no new dependency — tink is in go.mod" | `grep -ci "tink\|x/crypto" go.mod` returns **0**. Both left the tree; the repo now has zero third-party crypto | The primitive has no source. Go 1.27.1's standard library has neither CMAC nor SIV |
| The interface has 59 methods, 25 need overriding | **52 methods**, all one uniform signature shape. ~21 carry a key/prefix/marker in a typed field | The whole audit list must be rebuilt from the interface, not adjusted |
| 25 call sites, listed with line numbers | **66** backend call sites in the handlers — 37 via `h.s3Backend`, 29 via `h.S3Backend` on `BaseSubResourceHandler` (`bucket/base.go`) | One wrap still covers all 66, but any hand-written site list is wrong by half. Classify by **interface method and input field**, never by call site |
| "Handlers are constructed at `router.go:61-64` — the one-wrap argument holds" | Handlers are built at `router.go:89-92`, and wrapping there is **wrong** — see the sweeper row below | |
| `ProviderManager.GetProviderByFingerprint` (Stage 2) | Does not exist and never did. `providers.go` exports `EncryptDEK`, `DecryptDEK`, `GetActiveFingerprint`, `GetActiveProviderAlias`, `GetActiveProviderAlgorithm`, `GetProviderAliases`, `GetLogger` | Stage 2 named a function that was never written |
| `test-integration-performance` proves no regression | That suite measures **zero** of this feature and no longer asserts on throughput (`performance_test.go:550-560`). `test/perf/` holds eight instruments, none of which lists objects | The stated success criterion cannot be satisfied. A listing instrument has to be built first, with a BEFORE column on the pre-change commit (ADR 0020 D17) |

### What holds, and is load-bearing

- **The payload cannot regress, structurally.** `Codec.aad` builds
  `FormatID ‖ objectKey ‖ index` from the **client** key captured once at
  `NewCodec` (`pkg/encryption/dataencryption/segmented_gcm.go:112-132`), fed from
  the only two call sites in the orchestration manager
  (`internal/orchestration/segmented.go:320` and `:386`). The KEK wrap takes a
  constant AAD and no object key at all
  (`pkg/encryption/keyencryption/aes.go:30-31,:106,:120`). So enabling the feature
  is a **rename**, never a re-encryption, and main goals 2 and 3 are untouched by
  construction. This is the premise the entire design rests on and it is verified,
  not inherited.
- **The KEK wrap is length-agnostic** (`aes.go:93-107`; the only length check is
  `len <= wrapSaltSize` at `:110-113`), so a 64-byte name key wraps exactly like an
  object DEK with no provider change. It also means a wrapped name key and a
  wrapped object DEK are **interchangeable ciphertexts under the same KEK** — the
  wrap AAD is the constant `s3ep-dek-wrap-v1` for both. A distinct AAD label costs
  one constant.
- **`base64url` is a fixed point under `QueryEscape`/`QueryUnescape`** (verified
  over 200k random samples); base64 std is silently corrupted by the same round
  trip. D5's choice is better founded than ADR 0023 argues, and the ADR should say
  so.

### What the tree does that ADR 0023 did not anticipate

- **D8's single boundary does not exist.** The multipart sweeper calls the
  concrete SDK client *outside* `interfaces.S3BackendInterface`:
  `internal/proxy/server.go:112` builds `s3Client`, and `:127-137` hands a closure
  over that same raw client to `SetMultipartAbandoner`, aborting with the client
  key from the session table — and `:133-136` converts `NoSuchUpload` to success
  **by design**. Wiring the transform at `router.go:89-92` leaves every swept
  upload leaking its parts at the backend, billed, with no error line anywhere, on
  both the idle sweep and the shutdown sweep. The wrap has to be at the client
  (`server.go:112`), and the closure must capture the **wrapped** value — it
  captures the local variable, not the struct field, so changing the field type at
  `:28` alone does not fix it.
- **The listing is asymmetric across one call.** Both listing arms unconditionally
  set `EncodingType: url` (`bucket/listing.go:90-93`, `:177`) and the handler
  decodes with `url.QueryUnescape` **above** the backend interface
  (`listing_params.go:44-62`). The SDK decodes nothing — there is no unescape
  anywhere in `service/s3`. So a decorator below the interface receives **raw
  client bytes on the way down and percent-encoded backend bytes on the way up, on
  the same call**, while `ListMultipartUploads` is raw in both directions. One
  shared decode/re-encode helper corrupts one of them.
- **D11's drop breaks the page's own arithmetic.** `KeyCount` and `IsTruncated` are
  copied verbatim from the backend (`listing.go:126-127`). Dropping entries without
  recomputing `KeyCount` makes the document lie. Worse: V1 and `start-after`
  clients advance by the last key of the page, so dropping the trailing entry of a
  **truncated** page makes the client re-request the same page forever. Only
  V2-with-continuation-token is safe.
- **The audit surface is fields, not methods.**
  `PutObjectInput.WebsiteRedirectLocation` and
  `CreateMultipartUploadInput.WebsiteRedirectLocation` carry a client-supplied
  object key under a different name, and the proxy sets both verbatim from
  `x-amz-website-redirect-location` (`object/storage_headers.go:35,:120,:140`).
  "Override the 21 key-bearing methods" would write a cleartext key into backend
  metadata on every upload carrying that header.
- **Reflection over the interface cannot be complete.** `ListObjectVersions` is a
  key-bearing S3 listing with **no interface method and no route** — `GET
  /{bucket}?versions` falls through to the plain object listing, which dispatches
  on `list-type` only (`bucket/listing.go:16`). `CopyObject` and `UploadPartCopy`
  are key-bearing and refused above the boundary, so they have no method either.
  The audit test needs a second, hand-maintained list of key-bearing operations
  that have no interface method, each with the reason recorded.
- **ADR 0023 D18's allowlist is incomplete and was drafted against the read side
  only.** Bucket **website** (`ErrorDocument.Key`, `IndexDocument.Suffix`,
  `RoutingRule.Condition.KeyPrefixEquals`, `Redirect.ReplaceKeyWith`/
  `ReplaceKeyPrefixWith`) and bucket **policy** (`arn:aws:s3:::bucket/prefix*`)
  carry object keys in their bodies and are missing from it. `PutBucketPolicy`
  (`bucket/policy.go:56,:111`) and `PutBucketLogging` (`bucket/logging.go:99,:120`)
  are **live write paths** that forward a client document verbatim. With names on,
  a bucket policy scoped to `arn:aws:s3:::b/backups/*` silently matches nothing.
- **`DeleteObjects` is a page-scale operation hiding in the object handler**: up to
  1000 keys forward (`object/operations.go:27-28,:736-746`), with
  `Deleted[].Key`, `Errors[].Key` **and `Errors[].Message`** echoed back
  (`:802-820`). `Errors[].Message` is a second, unguarded channel for a stored key
  to reach the client.
- **ADR 0023 contradicts itself.** D11 requires an undecryptable key to be "logged
  at warn level"; D17 says "a stored key appears in logs only at debug". Both are
  in the accepted ADR, on the one decision whose purpose is to stop the proxy
  writing the mapping table D3 refuses to store. See decision **D-M**.

---

## The gate: what is cleared and what is not

ADR 0023's *Residual risks* names cross-directory listing **order** as "the gate,
and it is UNVERIFIED". **That is the wrong half, and it is now cleared.** The
gate that survives is D9.

**Order — CLEARED for every named client.** None of them trusts backend order:

| Client | Evidence |
|---|---|
| Velero | `velero-plugin-for-aws` `object_store.go:504-507` re-sorts its own results, with a comment naming the bug that forced it |
| rclone | `fs/list/list.go:210`, `sort.Stable(entries)` |
| kopia | `repo/blob/storage.go:195-2xx` — lists inside one directory |
| s3cmd | builds its own comparison lists |

**The partial-directory prefix — BLOCKED, and the trigger has fired.** ADR 0023
D9 returns an **empty listing** for a prefix ending inside a directory segment,
and defers the fan-out fallback to "only if a client in use turns out to emit
that shape". A client in use emits it on its most ordinary invocation:

> `s3cmd` v2.4.0 (`s3cmd:1979-1983`) joins `basename(source)` onto the
> destination **without a trailing slash** and lists that prefix at `:1987`.
> `S3/FileLists.py:421-442` documents partial-prefix listing as intended
> behaviour.

So `s3cmd sync /local/dir s3://b/backups/` sees an empty remote, re-uploads the
whole tree, and **never converges** — silent and unbounded. `s3cmd` has a
release-gating e2e suite in this repository (ADR 0019). The same shape is what a
human types: `aws s3 ls s3://bucket/back`.

This is not a documentation matter. ADR 0007 D1 forbids answering a request the
proxy understood with a silent partial answer, and ADR 0010 D7 forbids it for
`prefix` specifically. D9 as written is a standing violation of both.

---

## What the feature is actually worth

ADR 0023's *Context* builds the case on three Velero nouns. **The leaf census
refutes two of them** — derived from `velero pkg/persistence/object_store_layout.go:72-138`
at tag v1.18.2, the version the e2e pins:

- **11 of 12 backup leaf shapes** embed the backup name (only `velero-backup.json`
  does not). **5 of 5 restore leaf shapes** embed it.
- A **scheduled** backup is named `<schedule>-<YYYYMMDDHHMMSS>`
  (`pkg/apis/velero/v1/schedule_types.go:139-141`), so schedule identity and exact
  backup cadence stay readable from key names alone. A default-named restore is
  `<source-backup>-<YYYYMMDDHHMMSS>`.

So in `backups/` and `restores/` the feature removes **one occurrence of a string
that eleven sibling leaves still print**. It is worth zero there.

**What it does hide, and this is the honest product claim:**

| Hidden | Where |
|---|---|
| The tenant/namespace inventory | `kopia/<namespace>/` and legacy `restic/<namespace>/` — kopia's leaves are 16 random bytes plus a session id, and keyed content hashes (`kopia repo/content/content_manager.go:762-780`), so the namespace is the only noun there |
| The operator-chosen BackupStorageLocation prefix | when one is configured |
| The CNPG/Barman server name | `<server>/base/<id>/`, `<server>/wals/<hash>/` — the clean case: every identifying noun is a directory, every leaf is a constant, an OID or a WAL name |

**And part of even that is given back through side channels the ADR does not name:**

- `E(kopia)`, `E(backups)`, `E(restores)` are **per-deployment constants** — D4
  puts an empty parent chain at depth 1, so the top-level directory set is a fixed
  fingerprint of "this is a Velero bucket".
- `kopia.repository`, `kopia.blobcfg`, `kopia.maintenance` are **constant literal
  leaves** (`kopia repo/format/format_blob.go:31`, `blobcfg_blob.go:16`,
  `repo/maintenance/maintenance_schedule.go:22`).
- The deterministic directory ciphertext is a **stable pseudonym** joining each
  hidden namespace to the cleartext backup names, write times and byte volumes in
  the sibling subtree. Whether that recovers the namespace *name* depends on the
  operator's naming convention.
- **base64url-without-padding length is a bijection on plaintext length**:
  `L = ceil(4*(16+n)/3)`, and `L mod 4 ∈ {0,2,3}` determines `(16+n) mod 3`
  uniquely, so `n` is exactly recoverable. Every hidden name discloses its exact
  byte length.

The claim the README may make is **"the namespace inventory is hidden from an
adversary who does not correlate against the cleartext half of the same bucket"**
— never "backup names are hidden", and never "the bucket's contents are hidden".
ADR 0023's *Context* must be amended to match.

---

## Decisions

Ordered by how much they change the work. **D-A through D-D expire at the first
written object** — changing any of them afterwards is a full bucket rename
(D15). They are the cheapest decisions in the project and the ones most likely to
be skipped.

### D-A — The cryptographic primitive (blocks everything)

`tink` and `golang.org/x/crypto` are both out of `go.mod`; Go 1.27.1 has no CMAC
and no SIV. Measured on Apple M5 Pro, go1.27.1, per segment:

| Option | Perf | Verdict |
|---|---|---|
| **Hand-rolled RFC 5297 AES-SIV-CMAC** over `crypto/aes`, subkeys precomputed at construction | 229 ns @depth2, 403 ns @depth3, **1 alloc** | ~200 lines of subtle crypto to own forever (CMAC subkeys, GF(2^128) doubling, S2V, xorend). **Gated by published vectors** — RFC 5297 A.1/A.2 plus Wycheproof |
| **`tink-crypto/tink-go/v2` v2.8.0** | 277 ns, 7 allocs | Maintained, reviewed, an auditor accepts it on sight. Re-adds a 4.56 MB module **and `golang.org/x/crypto`** — the exact dependency `60df187` deleted — plus protobuf, go-cmp, wycheproof, for one 175-line need |
| **Stdlib SIV composition** — `IV = HMAC-SHA256(K_mac, injective_encoding)[:16]`, `AES-CTR(K_enc, IV)` | 179 ns pooled / 308 ns concurrency-safe, 4 allocs | ~60 lines, zero deps, a sound instantiation of the same Rogaway–Shrimpton theorem. **No published vectors** — the review burden of hand-rolling with none of the verifiability |
| `secure-io/siv-go`, `jacobsa/crypto/siv` | — | Disqualified: neither has a tagged release; newest artifacts are 2018/2019 pseudo-versions |
| AES-GCM-SIV with an all-zero nonce | — | No quality Go implementation without a dependency; "nonce = zeros" in the source is a misuse magnet |

**Favourite: hand-rolled RFC 5297, in `internal/naming/`.** The performance gap is
immaterial — 404 ns against ~850 ns on a request that costs ~1920 µs — and must
not carry the decision. What carries it is **verifiability**: a seal/open round
trip agrees with itself under a wrong construction exactly as under a right one,
which is why `segmented_gcm_vector_test.go` exists and says so in its header.
RFC 5297 publishes vectors covering the 512-bit configuration; the stdlib
composition has none.

**Dissent, and it is real:** this project's own instinct is not to hand-roll
crypto, and 200 lines of GF(2^128) doubling in a security product is exactly the
code that gets one subtle thing wrong for years. A from-scratch version written
during this analysis had a real bug. If the project will not own crypto, take
`tink-go/v2`, accept the `x/crypto` re-entry and add a Renovate exception. **Reject
the stdlib composition either way** — it is the worst of both.

**Key shape:** amend D6. Use a **32-byte master with HKDF-derived subkeys**
(`prk = HKDF-Extract(SHA-256, K_name)`, `K_mac`/`K_enc` via `HKDF-Expand` with
distinct info labels) rather than a configured 64-byte value. The `64` in D6 is a
fact about a library the repo no longer contains; derivation makes key
independence **structural** instead of something a reviewer verifies.

### D-B — Is a name domain bound into the associated data?

Irreversible. ADR 0023 D4 deliberately leaves the bucket out so a ciphertext
bucket replicates wholesale.

- **Bucket out (D4 as written)** — free DR replication; names in bucket A and B are
  the same ciphertext, and a future per-client bucket-scoped authorization model
  cannot be adopted without renaming everything.
- **Bucket always in** — closes the oracle; a DR copy to a differently-named bucket
  needs a full rename pass.
- **`filename_encryption.domain`**, a string in the AAD beside the version label,
  **defaulting to the bucket name**; an operator who wants wholesale replication
  pins it to a constant.

**Favourite: the configured domain, defaulting to the bucket name.** State the
real reason and not the one ADR 0023 gives: D4's parent-ciphertext chain
**already** confines a *prefix*-scoped tenant — a client scoped to `tenantA/` can
only cause writes under parent chain `E(tenantA)`, so it never learns `tenantB`'s
depth-0 ciphertext. The domain exists to extend that confinement to **bucket**-scoped
tenancy. ADR 0023 files this as "fix it if per-client scoping is ever
introduced", which reads as something a later ticket picks up. It is not: the knob
costs one config key now and is unavailable later.

**Dissent:** a configuration key added for a threat model nobody has asked for, in
a project that refuses configuration keys on principle (ADR 0013, ADR 0017 D8).

### D-C — AAD framing (not really a choice)

The AAD must be **injective**. Length-prefix every variable field, length first,
with a **fixed-width** depth field — never `uint8`, which wraps silently at depth
256. A collision in the PRF input means two different `(AAD, segment)` pairs get
the same synthetic IV, which reuses the CTR keystream across them. ADR 0023's
sketch (`"s3ep-name-v1" || 0x00 || uint8(i) || 0x00 || parent chain`) uses `0x00`
separators over data that can contain `0x00`. **Fix it in D4 before any code.**

### D-D — Segment-length padding

Genuinely open; the three analysis lenses split three ways.

- **Accept and document** — zero cost, consistent with ADR 0023 already accepting
  sizes, counts and timestamps as visible.
- **Pad to a multiple of 16 before encryption**, length byte inside — turns "exactly
  19 bytes" into "between 17 and 32", at ≤21 extra base64 characters per segment.

**Favourite: pad.** The usual counter — "it spends the 1024-byte budget D13
already rations" — is strongest exactly where the feature is worth nothing and
weakest exactly where it is worth most. The deep trees that strain the limit are
the `backups/<name>/` shapes whose plaintext eleven sibling leaves already print;
the shallow ones — `kopia/<namespace>/` at depth 2, Barman `<server>/` at depth 1
— are the whole case for the feature and have budget to spare. And unlike object
size, hiding a *name's* length costs no cover traffic: the name is already being
encrypted. If padding is declined, scope it by depth rather than declining it
outright, and **write the decision into D5** rather than leaving it an omission.

**Dissent:** exact name length is the same family as object size and count, which
the ADR already concedes; this adds a format complication for a marginal gain.

### D-E — Where the transform is installed, and by what mechanism

| Option | Missed-site failure is… |
|---|---|
| Embed `interfaces.S3BackendInterface`, override ~21 methods (the old plan) | **Silent.** A method the interface gains later is promoted from the embedded value and forwarded untransformed. The interface gained and lost 24 methods across five commits in one week |
| **Explicit forwarder**: named `inner` field, all 52 methods implemented — 31 pure forwarders, 21 transforming | **A build error.** A 53rd method does not compile until someone classifies it |
| SDK `Initialize`-step middleware via `backendClientOptions` | **A runtime error.** `InitializeInput.Parameters` is `interface{}`, so the overrides become a type switch with no exhaustiveness |

**Favourite: the explicit forwarder**, wrapped at `internal/proxy/server.go:112`,
field type at `:28` changed to the interface, **and the abandoner closure pointed
at the wrapped value**. Compile-time exhaustiveness is the property D8 is actually
buying, and only this option delivers it. The wire point is not negotiable —
see the sweeper row in *Ground truth*.

**Plus a field-level audit test, not a method-level one** (`WebsiteRedirectLocation`),
**plus a second hand-maintained list** of key-bearing operations with no interface
method (`ListObjectVersions`, `CopyObject`, `UploadPartCopy`), each with its reason.

**Dissent:** ~200 lines of mechanical forwarding to review and keep, justified by a
hypothetical 53rd method. If that is judged too much, take the middleware — it at
least covers the abandoner by construction, which embedding does not.

### D-F — What the proxy answers for a partial-directory prefix

The feature's actual gate (see above). The failure is not a blank listing; it is
`s3cmd sync` re-uploading a whole tree forever.

- **D9 as written** — zero code, zero round trips, and a silent partial answer that
  ADR 0007 D1 and ADR 0010 D7 both forbid by name.
- **Refuse every prefix not ending at a segment boundary** — honest, one line, and
  it refuses kopia's shape too (`kopia/<ns>/p` has the same trailing partial
  component), which is the one shape the segments-only design exists to preserve.
  Unusable as a blanket rule.
- **Structural probe**: when the trailing component is partial, list the translated
  parent with `Delimiter: "/"` and a small `MaxKeys`, decrypt the returned
  `CommonPrefixes` — that is the subdirectory set — and answer from it; refuse the
  ambiguous arm; fall back to D9 only if the discovery page truncates.

**Favourite: the structural probe, refusing in the ambiguous arm for v1; fan-out
deferred. Rewrite D9 to say so.** ADR 0023's premise — "the proxy cannot
distinguish that case from a root-level partial leaf" — is **false**: a delimiter
listing bounded by a small `MaxKeys` returns the subdirectory set in one small
request. Once you *can* tell the two apart, the empty answer stops being an
unavoidable limitation and becomes a choice to lie, which ADR 0007 D1 does not
leave open.

**Dissent:** one extra round trip on the hot path of a client that lists
constantly, for a case that client never hits, in a project whose CLAUDE.md says
to stop and report an underperforming implementation. And a refusal, however
honest, is still a broken `aws s3 ls` for a human at a terminal.

**Related, and cheap: a reserved leading marker character** (`!`, outside the
base64url alphabet) on every stored **directory** segment. It does not make the
probe possible — bounding `MaxKeys` does that — but it earns its place on
**detectability**, which is D-J. Decide it there, not here.

### D-G — The listing override's contract

Four separate silent failures in two methods; three are invisible to
`make test-unit`. Decide them together:

1. **Encoding** — decode → transform → re-encode **inside the wrapper**,
   **per operation and per direction**, derived from `params.EncodingType` on the
   input rather than hardcoded. `ListObjectsV2`/`ListObjects` are raw down and
   percent-encoded up; `ListMultipartUploads` is raw both ways; everything else is
   raw. One symmetric helper corrupts a client prefix of `a+b` into `a b`.
   Measured ~139 µs per 1000-key page for the escape passes, against 26 µs for the
   memoized transform.
2. **Always `QueryUnescape` first, split on `/` second.** Whether the backend
   escapes the separator as `%2F` is **UNVERIFIED** (Stage 0), and this ordering is
   correct either way. Do not write the assumption into any ADR.
3. **Recompute `KeyCount` after D11 drops.** Leave `IsTruncated` honest.
4. **A drop never removes the last entry of a truncated page** — otherwise V1 and
   `start-after` clients loop on the same page forever.

**Rejected:** moving the transform above `decodeBackendValue` into the handler —
it breaks D8 outright and makes the listing the one place the boundary is not the
boundary. **Rejected:** dropping `encoding-type` when the feature is on — it
contradicts ADR 0010 D9, and the leaf still carries arbitrary client bytes.

### D-H — The exit path: ADR 0023 D7 versus ADR 0025

Two **accepted** ADRs make incompatible promises to the same operator, and
ADR 0023 was revised on 2026-09-12 — *after* ADR 0025 — without reconciling them.
Nothing technical enforces D7: every configured provider is registered by
fingerprint regardless of which is active (`providers.go:102-157`), and the
licence gate inspects only the **active** provider. **D7's exit clause is a policy
choice presented as a safety refusal.**

- **Keep D7, ship the reverse rename pass** as a **launch requirement** — one
  namespace at all times, no dual-namespace merge, no rollback oracle.
- **Drop D7's exit clause**: names stay mapped under `exit`, payloads stop being
  encrypted — but then the bucket is *permanently* unnavigable without the proxy,
  which voids ADR 0025's promise outright.
- **Asymmetric mapping under exit**: writes store the clear name, reads resolve
  both. The only shape that truly lets names age out — and a prefixed listing in
  the mixed state needs two backend listings merged behind one opaque continuation
  token, which cannot be done honestly.

**Favourite: keep D7, make `names unmap` a launch requirement, exempt
`names map`/`unmap`/`verify` from the licence gate — and amend ADR 0025 with an
explicit carve-out rather than claiming the pass restores its guarantee.** Names,
unlike payloads, are *how you address an object*, so they cannot age out unless
the write path stops mapping them. But be honest about what the pass is: ADR 0025
promises that leaving needs no batch operation, no tool and no licence, and a
reverse pass needs all three — plus a bucket-sized copy-then-delete that object
lock refuses on exactly the buckets SECURITY_ARCHITECTURE recommends object lock
for. **The pass is the mitigation, not the resolution.** Say both.

The licence lever is `internal/config/config.go:695`, the binding license-file
read inside `validate` — not the provider-type check at `:719`, which an
exit-active deployment already passes. A narrow loader for `names map`/`unmap`
must bypass `:695`.

### D-I — Migration mechanics

**D14's one sentence is wrong in every clause:**

- The product writes objects up to **117 GiB** through the internal producer at
  default settings and **5 TiB** client-driven (`docs/developer/multipart.md:43-44`),
  far past S3's **5 GiB** single-copy limit. The large half of a backup bucket needs
  `UploadPartCopy`.
- **A multipart copy inherits nothing**, so the four `s3ep-*` metadata keys must be
  re-supplied by hand (`internal/orchestration/metadata.go:114-117`). Losing the
  wrapped DEK is **unrecoverable**, and every generic copy tool — `aws s3 cp`
  switches to multipart above 8 MB — loses it silently on exactly those objects.
- An object under **retention or legal hold** cannot have its source deleted.
- The pass changes the **entity tag class** of every object above the copy
  threshold, from the marked-digest shape to `<hex>-N` (ADR 0032 D1/D2; `etag.Mark`
  leaves the multipart shape alone). ADR 0032 D8 exists because clients act on that
  shape. Record it as an operator-visible effect, and make the feature-on client
  e2e observe whether a supported client re-syncs afterwards.

**Favourite: offline, into a second bucket** where the source is versioned or
locked, otherwise in place. **Refuse read-compatibility mode explicitly in the
ADR** — and lead with the right reason: with a 404 fallback there is **no
observable difference between a finished migration and an unfinished one**, so the
completeness tool the operator needs cannot exist. (It also dies on pagination,
and hands the hostile backend a rollback lever, but those are secondary.)

Pre-flight **refuses the whole migration by default** when it finds a locked, held
or archived object, or a transformed key over 1024 bytes, with `--allow-partial`
available and a report naming every skipped object. Separate `--apply` from the
dry run.

`names` surface: `wrap`, `map`, `unmap`, **`migrate`**, **`verify`** (proves a
bucket is fully migrated), **`audit`** (lists undecryptable keys).

### D-J — Name-key identity, and the off-state

**Nothing in the design can tell four states apart**, and all four present
identically as a quietly smaller bucket: right key; valid-but-wrong key;
interrupted name-key rotation (D15); half-migrated bucket (D14). D11's
load-bearing sentence — *"dropped means exactly 'not written by this proxy'"* —
is **false in three of them**.

The product already has the convention: every object records `kek-fingerprint`
(`internal/orchestration/metadata.go:116`) precisely so a wrong or retired key is a
**named** failure (`providers.go:52`, `ErrUnknownFingerprint`). Nothing analogous
exists for the name key; D7 checks only that the unwrap succeeds.

**And the reverse regression nobody had analysed:** the feature switched **off** on
a bucket whose names are already mapped — one dropped Helm values block away. It
starts cleanly, hands the client **ciphertext names behind a 200**, and 404s every
exact GET. A backup client's remedy for objects it can see but not fetch is to
write them again under clear names. This falsifies D1's sentence "when it is off
the proxy behaves exactly as it does today", which is true only for a bucket that
never had it on.

Options: a fifth metadata key (a head-on collision with ADR 0009's "exactly four"
— an ADR 0009 amendment, not a detail); the **reserved marker character** of D-F
(detectability, not identity); a **fingerprint folded into the AAD domain** of D-B
(identity, at the cost of making a wrong key indistinguishable from a forged name).

**Favourite: the marker plus a fingerprint in the domain.** The marker makes the
off-state detectable at the first listing — which is the cheapest fix for the worst
operational accident — and the domain carries identity. Minimum acceptable: a
startup or first-listing check that refuses, or loudly warns, when the feature is
off and the bucket's names carry the marker.

### D-K — Memoisation

- **Per-request map** keyed on the whole ciphertext directory prefix, built in the
  response builder and discarded with the response: **26 µs** for a 1000-key page
  against 424 µs uncached — **16.1×**. One lookup per key, no lock, no eviction
  policy, no tuning. Gives up cross-request reuse, measured at ~1.2 µs per page.
- **The process-wide LRU ADR 0023 sketches**: three lookups per key, a lock on every
  listing/delete-batch/multipart-list, a size and an eviction policy to tune — and
  it holds **decrypted directory names in the heap indefinitely**, which is exactly
  the data this feature exists to keep out of the adversary's hands.

**Favourite: the per-request map, at all three page-scale sites (`ListObjectsV2`,
`ListObjects`, `DeleteObjects`, `ListMultipartUploads`). Do not build the LRU.**
The security argument settles it independently of the numbers.

**Dissent:** a process-wide LRU already exists holding something strictly more
sensitive — 1024 decrypted DEKs, keyed on `(fingerprint, objectKey, hash)`
(`providers.go:345-390`) — so the heap-hygiene argument has been conceded once
already.

Note: **the crypto is not the listing's cost.** It is 0.02 % of a request; the
feature's real listing cost is the **longer document**, ~10× the uncached transform
and ~100× the memoized one, and no cache removes it. That belongs in the ADR's
Consequences and in the README.

### D-L — The refusal surface

- **Delimiter (D10)**: refuse anything but `/` or empty in `handleListObjects`
  (`bucket/listing.go:16`) **before** the V1/V2 split, plus
  `multipart/list.go:214`. D8's invariant is about *keys* — "no request handler
  ever sees a stored key" — not about a handler knowing a flag exists, so the
  handler placement is not the violation it looks like.
- **Over-long key (D13)**: `400` at the refusal site. **`KeyTooLongError` is
  asserted from memory** — `git grep KeyTooLong` returns nothing. Verify it against
  the AWS S3 error reference before it enters an ADR; if it is not real, the answer
  is `400 InvalidArgument`.
- **Prefix-in-body writes**: refuse `PutBucketPolicy` carrying an object-scoped
  `arn:aws:s3:::<bucket>/…` resource (`400 InvalidArgument` naming the field);
  **forward** `PutBucketLogging`'s `TargetPrefix` — the two are not analogous, and
  treating them as one is the mistake: a delimiter is evaluated against keys the
  proxy wrote, `TargetPrefix` names keys the proxy never sees. Either refuse only a
  `TargetPrefix` containing `/`, or document that logs under a slashed prefix are
  invisible to listings through the proxy.
- **Extend D18's allowlist** with bucket **website** and bucket **policy** on the
  read side.

**Dissent on the policy refusal:** a substring guard over IAM policy JSON is a
heuristic in a security product — a false negative ships the silent breakage
anyway, a false positive refuses a legitimate policy.

### D-M — Resolve the D11 / D17 contradiction in the ADR

**Favourite:** the warn line **may name the stored value**, and D17 gains that
carve-out in writing — a name this proxy did not produce cannot be half of a
mapping pair. Note the alternative's consequence: read D17 strictly and D11's warn
log can carry no name at all, which makes it a duplicate of the metric D11 already
mandates — in which case **drop one of the two obligations** rather than
implementing both.

### D-N — Release label

**Favourite: minor, no `release:major` label.** Argue it from ADR 0018 D5 as a
per-change test, not a per-deployment one: an upgrade of a deployment that never
enabled the feature breaks nothing. But **do not lean on D1's "off behaves exactly
as today"** — D-J shows that is a per-bucket property, not a per-change one.

The signal problem is real and it is a **documentation** gap the project owes
anyway: the strings "back up", "backed up" and "escrow" appear **nowhere** in
`README.md` or `SECURITY_ARCHITECTURE.md` today. The sentence a new key-custody
section has to carry: *losing the KEK under `exit` still yields readable objects;
losing the name key yields readable objects nobody can address.*

---

## Stage 0 — before a line of code

Nothing below is optional, and all of it is cheap relative to the decisions it
informs.

- [ ] **Obtain a licence token out of band** (`S3EP_LICENSE_TOKEN` or
      `config/license.jwt`). `make e2e-up` aborts without one, and it is the
      precondition of the census below. Not in the repository.
- [ ] **Run the Velero leaf census against a real bucket.** ADR 0023 made it a
      precondition and it has never been run. `make e2e-up && make test-e2e-velero`,
      then dump the full backend listing. **The suite names every backup and restore
      explicitly and never creates a Schedule**, so add one Schedule-created backup
      and one default-named restore by hand — those are the two worst real-world leaf
      shapes and the suite as-is under-reports them.
- [ ] **Settle the `/` escaping question.** One raw request at the backend, not
      through the proxy: `./start-demo.sh`, PUT a directory-bearing key through the
      proxy, then
      `curl -s --aws-sigv4 … 'http://localhost:9000/<bucket>?list-type=2&encoding-type=url'`
      and read the XML. Repeat directly against LocalStack. **Not** via
      `make test-conformance` — that target drives the suite through the proxy and
      never exposes the backend's raw XML.
- [ ] **Record the listing shapes every supported client emits.** A one-line shape
      log at `bucket/listing.go:16` and `multipart/list.go` (bucket, list-type,
      prefix, delimiter, marker, start-after, token-present, max-keys, encoding-type),
      then one rclone run and one s3cmd run (5 s and 8 s warm) and one Velero run.
      The specific question left open: **does any client synthesise a marker it did
      not receive, rather than echoing one?**
- [ ] **Build the listing performance instrument and record its BEFORE column on the
      pre-change commit** (ADR 0020 D17). `test/perf/` has no listing instrument at
      all. A benchmark written by someone who already knows what the change costs is
      a different instrument from one written blind.
- [ ] **Verify `KeyTooLongError`** against the AWS S3 error reference (D-L).
- [ ] **Take D-A through D-D and D-J**, and write them into ADR 0023 **in the same
      session** — not back-filled from the code.
- [ ] **Answer the business question in D-H**: is name mapping a licensed
      capability, and may `names map`/`unmap`/`verify` run without a valid licence?

**Fix regardless of the build decision** — these are live defects this analysis
surfaced:

- [ ] The abandoner's raw-client call at `internal/proxy/server.go:127-137`.
- [ ] The three e2e assertions that would go **vacuously green** under the transform
      rather than failing — including the Velero deletion gate. They must be repaired
      **before** the transform lands, not after: a change to `test/e2e/harness/` is a
      change to all three suites and needs a real Velero run (~45 min plus the
      licence) before it lands.

---

## Staged plan

Ordering corrected against the analysis. **Chart and `envexpand` work comes before
any feature-on e2e job; the D18 amendment comes before the audit test that is built
against it; the performance instrument comes first of all.**

| Stage | Goal | Exit criterion | Effort |
|---|---|---|---|
| **0** | The list above | Every decision written into ADR 0023; census recorded; BEFORE column on the pre-change commit | 3-5 d |
| **1** | `internal/naming`: the transform, per D-A/D-B/D-C/D-D | RFC 5297 vectors green; round-trip, depth-move, bit-flip, length-guard and edge-case tests; benchmark recorded | 1 w |
| **2** | Config block, startup unwrap, **Helm chart + `envexpand`**, `names wrap` | A feature-on proxy starts in the demo stack **and in kind**; wrapped key reaches the pod from a **Secret**, not a ConfigMap | 1 w |
| **3** | D18 amendment, then the explicit forwarder + field-level audit test + the no-method list | A 53rd interface method fails the build; `WebsiteRedirectLocation` is covered; the sweeper test passes | 1 w |
| **4** | Listings, `DeleteObjects`, `ListMultipartUploads`, the D-F probe, the D-L refusals, the D-K memo | Pagination over 2500 objects across three directories; `s3cmd sync` converges | 1.5 w |
| **5** | `names map/unmap/migrate/verify/audit` — the copier | A bucket with an object above the copy threshold migrates with its four metadata keys intact and is provably complete | 2-3 w |
| **6** | Tests: the feature-on integration package, the e2e repairs, the client suites' feature-on scenario | Nothing green that does not check something | 1.5-2 w |
| **7** | README, `SECURITY_ARCHITECTURE.md` key-custody section, ADR amendments, and `docs/developer/` — **`package-map.md`, `request-paths.md`, `configuration.md`, `testing.md`, `errors.md`, `performance.md`** by name | | 0.5 w |

**Effort: 8-10 focused weeks for one person, and that is the floor.** The old
stage list implied 3-4. The distribution is the surprise: the transform is ~1 week
and the boundary ~1, but **the copier is 2-3 and the tests are 1.5-2** — and the
copier is a second S3 write path inside the binary, using the backend credential,
bypassing every proxy invariant (no SigV4 client auth, no request parser, no
checksum verifier, no drain guard) with delete rights on the whole bucket. That is
a materially new attack surface, and the feature's entire migration story rests on
it. Keeping D7 makes it a **launch** requirement, not follow-on work.

### The test matrix

Running the **existing** integration suite with the feature on would be green and
would prove nothing: almost every integration key is flat, and D2 stores a key
with no `/` unchanged. **A false green here ships a missed call site.**

**Favourite: targeted, not doubled.** One new integration package with
purpose-built directory-bearing fixtures, driven the way
`scripts/conformance-run.sh` already drives a proxy (built binary, heredoc config,
free port) — no third compose service, no committed config, no production change.
The client suites get one feature-on scenario each; they cost 5 s and 8 s.
**Do not parameterise existing tests on the flag** — ADR 0019 D4 says build tags
select which suite runs, they never soften one.

Gate performance on **deterministic quantities** — primitive calls per request,
allocations per key — not wall time.

---

## Success criteria

- `make test-unit` green, including the RFC 5297 vectors.
- The feature-on integration package green over both transports; the default-off
  configuration keeps its existing coverage unchanged.
- `make e2e-velero`, `make e2e-rclone`, `make e2e-s3cmd` green with the feature on
  — **including `s3cmd sync` converging on a second run**, which is the D-F gate.
- A backend listing taken during the e2e contains **no namespace name**; the
  assertion is in the suite, not in a reviewer's head. It must **fail** if the
  transform is not installed — the current at-rest assertions would pass vacuously.
- The listing instrument shows the document build, not the crypto, as the cost; the
  byte path shows **no movement at all**, and any movement is a bug, not a cost.
- Stage 0's answers are in ADR 0023, the README and `SECURITY_ARCHITECTURE.md` —
  **including the leaf-name residual, honestly, as the census found it.**

---

## Open question for the repository owner

**Is there a named customer asking for this?** The analysis converges on: build it
if a CNPG/Barman or data-mover-heavy customer is asking, because the tenant
inventory and the database server name are the one thing on the leak list a
customer cannot re-derive and the thing a compliance conversation is actually
about — and do not build it if the ask is generic, because in the Velero layout
the census shows it hides a duplicate of a string eleven sibling leaves still
print, at a cost of 8-10 weeks, a permanent second critical key, a copier with
delete rights on the bucket, and a doubled operational surface.
