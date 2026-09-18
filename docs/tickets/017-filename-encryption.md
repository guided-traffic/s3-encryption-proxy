# Ticket 017: Filename encryption

## Status (2026-09-17)

**Open. Not started. Gated on decisions, and the decision list was revised on
2026-09-17.**

The feature is specified in
[ADR 0023](../adr/0023-filename-encryption-encrypts-directory-segments.md) and
nothing of it is built. Both dependencies have landed: the authenticated segment
chain (ADR 0003) and the listing document rewrite (ADR 0010). What blocks it is
decisions, and on 2026-09-17 the repository owner set two requirements that
change what those decisions are:

1. **The feature is switched on and off in configuration.**
2. **Both name forms stay readable: the names this feature encrypted, and the
   cleartext names of objects written before it was switched on.**

The second requirement is the read-compatibility mode that ADR 0023 D14 (a
rename pass before the first read) and the 2026-09-13 favourite of D-I ("refuse
read-compatibility mode explicitly in the ADR") both reject. It supersedes them
as a premise. Three things follow, all worked out in the revised list below: the
copier with delete rights on the bucket leaves the critical path, the
exit-provider conflict of D-H dissolves into a mode of the same feature, and a
bucket can be migrated online. One thing is new, and it is the security finding
of the revision: **a mixed bucket served naively leaks, through the proxy's own
fallback requests, exactly the directory names the feature exists to hide.** See
F2.

**How to pick this up in the next session.** Read *Corrections and additions of
the 2026-09-17 pass* below, then go straight to
[*The decisions, revised 2026-09-17*](#the-decisions-revised-2026-09-17). Every
question there carries its options, a favourite with the reason, the dissent, and
the code it touches. **F1, F2 and F17 are decided (2026-09-17: O1, M2 and L2,
in ADR 0023); the rest is not.** F4 to F7 fix the stored form and expire at the first written object. The 2026-09-13 analysis (D-A to D-N) is kept
below the revised list because its reasoning is the source of most options;
where the revision changes a verdict, the F-entry says so and why. *Stage 0*,
the *Staged plan*, the *Test matrix* and the *Success criteria* at the end are
the revised versions and are the work list proper.

This document was rewritten on 2026-09-13 after a full re-verification against
the tree at HEAD, and every claim was re-checked or corrected on 2026-09-17.
**Versions before 2026-09-13 must not be used as a work list**: their boundary
table was wrong in both directions, every line anchor had drifted, and their
"Before you start" section was exactly inverted on the most dangerous point (see
the first row of the table below).

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

### Corrections and additions of the 2026-09-17 pass

Every line was read in the tree, in the pinned client binaries under
`test/e2e/*/`, or fetched from the named source on 2026-09-17.

| 2026-09-13 said | Reality | Why it matters |
|---|---|---|
| "RFC 5297 publishes vectors covering the 512-bit configuration" | **False.** RFC 5297 Appendix A.1 and A.2 both use a 256-bit SIV key, two AES-128 halves. Wycheproof `aes_siv_cmac_test.json` (442 tests) covers key sizes 256 and 384 only. **No published vector exists for AES-SIV under a 512-bit key** | D-A's verifiability argument does not hold for the 512-bit key as written. Python `cryptography` 48.0.0 (`AESSIV`, OpenSSL-backed) accepts a 64-byte key, verified locally, and is the independent implementation that can generate 512-bit known-answer tests. See F5 |
| `KeyTooLongError` "asserted from memory" | **Real.** The S3 API model shipped in `aws-sdk-go-v2/service/s3 v1.113.1` lists it: code `KeyTooLongError`, "Your key is too long", HTTP 400 (`types/types.go:1707-1711` in the module cache) | D13 answers `400 KeyTooLongError`. Stage 0 item closed |
| s3cmd emits a partial-directory prefix | Holds, and the listing mechanics are now read: s3cmd 2.4.0 lists with **V1 and `marker`**, takes `NextMarker` from the response when present and falls back to the last `Key`/`Prefix` (`S3/S3.py:346-347` under `test/e2e/s3cmd/venv/`); adds `delimiter=/` only when not recursive (`S3.py:392`); `sync` lists recursively with the object part of the URI as the prefix (`S3/FileLists.py:442-443`); its remote list is a dict keyed by path, so **a key listed twice keeps the last entry** | A proxy-minted `NextMarker` is honoured by the one V1 client in the suite. A duplicate in a listing makes s3cmd act on the stale entry. Both shape F3 |
| rclone | v1.75.1 pinned; `--s3-list-version` defaults to auto, which is V2 with continuation tokens for the providers in use; lists one directory at a time with `/` unless `--fast-list` | V2 with an opaque token is the easy case of F3 |
| Interface method count | **52**, as the 2026-09-13 pass said: `awk '/^type S3BackendInterface interface/,/^}/' internal/proxy/interfaces/s3_backend.go \| grep -cE '^\s+[A-Z][A-Za-z0-9]*\('`. 21 carry a key, prefix or marker: Abort/Complete/CreateMultipartUpload, DeleteObject, DeleteObjectTagging, DeleteObjects, GetObject, GetObjectLegalHold, GetObjectRetention, GetObjectTagging, GetObjectTorrent, HeadObject, ListMultipartUploads, ListObjects, ListObjectsV2, ListParts, PutObject, PutObjectLegalHold, PutObjectRetention, PutObjectTagging, UploadPart | A subagent counted 60 on 2026-09-17 and was wrong; the command is the count. The 2026-09-13 lesson stands: never hand-count, make the build count |
| Marker character | `!` is outside the base64url alphabet, on AWS's "safe characters" list, and round-trips Go's `url.QueryEscape`/`QueryUnescape` as `%21` (verified with a scratch program). `~` would pass unescaped but is on AWS's "avoid" list (from memory, unverified) | `!` is the marker candidate of F4. D-G rule 2's decode order handles the `%21` |
| The abandoner, the listing asymmetry, `KeyCount`/`IsTruncated` verbatim, the four metadata keys, the DEK cache, the `WebsiteRedirectLocation` field, the live passthroughs | All re-read and holding: `internal/proxy/server.go:29` (`s3Backend *s3.Client`), `:132-143` (closure over the raw client, `NoSuchUpload` to `nil` at `:139`); `bucket/listing.go:93,:177` (`EncodingType: url`), `:126-127`/`:206` (copied verbatim); `bucket/listing_params.go:44-48` (`decodeBackendValue`, `url.QueryUnescape`); `multipart/list.go:242-262` (markers raw, no encoding type); `object/operations.go:28` (1000 keys), `:809,:819-821` (`Deleted[].Key`, `Errors[].Key/Code/Message` echoed); `orchestration/metadata.go:114-117`; `orchestration/providers.go:23` (`dekCacheCapacity` 1024), `:57` (`ErrUnknownFingerprint`), `:346` (cache key hashes the wrapped DEK); `object/storage_headers.go:120,:140`; `bucket/policy.go:56-128`, `bucket/logging.go:56-120`, `object/tagging.go:72-130`, `object/objectlock.go:24-126` | Line anchors refreshed; the classification of D-E and D-L is unchanged |
| The payload premise | Holds: `pkg/encryption/dataencryption/segmented_gcm.go:127-131` binds `FormatID ‖ objectKey ‖ index` with the key given to `NewCodec`, called from `internal/orchestration/segmented.go:320` and `:386`; the KEK wrap AAD is the constant `aadWrap = "s3ep-dek-wrap-v1"` (`pkg/encryption/keyencryption/aes.go:31`) and carries no key | Enabling the feature is a rename, never a re-encryption. Unchanged |
| The exit provider's per-object decision | `internal/orchestration/segmented.go:290-309` (`IsSegmentedObject`: claims the format **and** the wrapped DEK is present), `:342-354` (`codecFor` returns `ErrForeignObject` otherwise); `object/operations.go:173-177` refuses a claimed-but-unreadable object with `403 InvalidObjectState` | The per-object pattern of ADR 0025 D5 is the template for the per-name decision of F1 and F2 |
| Where a wrapped key reaches the pod | The chart renders the configuration into a ConfigMap (`deploy/helm/s3-encryption-proxy/templates/configmap.yaml:9,:36`) and the AES key into `S3EP_AES_KEY` from a Secret (`templates/deployment.yaml:109-118`); the loader expands `${VAR}` only in the fields ADR 0013 names | A wrapped name key is ciphertext, not key material, but the chart pattern to follow is the Secret one, and `filename_encryption` fields must join the expanded-fields list or a `${VAR}` in them is kept verbatim |
| The e2e assertions that "go vacuously green" | One confirmed: the Velero deletion gate `test/e2e/velero/scenarios_lifecycle_test.go:141-145` asserts zero objects under the literal prefix `backups/<name>/`, which is trivially true once the directory is stored under another name. The at-rest helper **guards itself**: `test/e2e/harness/atrest.go:38-43` fails with "nothing is stored under …, so nothing was checked" when `ListStored` (`harness/stored.go:36-61`, a literal-prefix `ListObjectsV2` paginator plus `HeadObject` per key) returns nothing | The count "three" from 2026-09-13 is not confirmed; one is. Both helpers need the transform, and the harness rule applies: a change there needs a real Velero run |
| Binaries | `cmd/s3-encryption-proxy/main.go` is a cobra root with no subcommands; `cmd/keygen` and `cmd/license-tool` are separate binaries | D16's `names` surface is either a subcommand tree or a third binary; F11 |
| What is documented today | `README.md:504` ("Object key names are in the clear"), `SECURITY_ARCHITECTURE.md:77,:122,:446`, `docs/operations/integrity.md:22` (the associated data binds the client's key) | The pages Stage 7 owes |
| `test/perf/` | Seven instruments on 2026-09-17 (`cryptofloor`, `memory`, `rangeread`, `smallobject`, `throughput`, `unwrap`, `uploadpath`), none lists objects | Unchanged: the listing instrument is built first, with its BEFORE column |
| `scripts/conformance-run.sh` | Writes its proxy configuration as a heredoc (`:191-220`, credentials as `${VAR}` references) and launches `./build/s3-encryption-proxy --config` (`:222-233`) | The pattern the feature-on integration package copies (F16); and every new configuration key has to run `make test-conformance` |

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

**Superseded 2026-09-17 by F17.** The census below was the case against the
clear leaf, and it won: with the leaf encrypted the feature hides the backup
name, the schedule name and the restore timestamps as well as the tenant
inventory, and what the backend keeps is ADR 0023 D18. The section is kept
because it is the evidence, and because the side channels it names (constant
top-level directory set, constant literal leaves, the deterministic pseudonym,
segment lengths in 16-byte buckets) still hold.

ADR 0023's *Context* built the case on three Velero nouns. **The leaf census
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

## The decisions, revised 2026-09-17

This is the current decision list. It absorbs the 2026-09-13 analysis (D-A to
D-N, kept in full below it) and adds what the two owner requirements force.
**Nothing here is decided.** Each entry carries its options, a favourite with
the reason, the dissent, and the code it touches. Line anchors are of
2026-09-17. **F1 is decided** (2026-09-17, O1): F2 and F3 are therefore in scope.
**F4 to F7 fix the stored form and expire at the first written object.**

| Revised | Replaces | What changed |
|---|---|---|
| F1 | new | the operating model the read-both requirement forces — **decided 2026-09-17: O1**, the mode set |
| F2 | new | exact-key lookup in a mixed bucket, and the name leak — **decided 2026-09-17: M2**, in ADR 0023 D20 |
| F3 | D-G, the listing half of D-F | listing in a mixed bucket |
| F4 | D-J, the marker note of D-F, the key shape of D-A | the stored segment form: marker, key fingerprint, key list |
| F5 | D-A | the primitive; the vector claim corrected; the key shape simplified |
| F6 | D-C, D-B | framing, free with S2V; the bucket-in-AAD decision deferred |
| F7 | D-D | padding, verdict unchanged |
| F8 | D-E | boundary mechanism, verdict unchanged, new duties |
| F9 | D-F | partial-directory prefix, verdict moves to fan-out |
| F10 | D-H | exit path, dissolved into the mode set |
| F11 | D-I | migration off the launch path; the copier is an **extensible pass engine** (owner requirement 2026-09-17) with rename first, rewrap (040) and replicate (037) later |
| F12 | D-L | refusal surface, policy heuristic dropped |
| F13 | D-M | unchanged |
| F14 | D-K | unchanged, plus a request-scoped resolution memo |
| F15 | D-N | unchanged, plus a shape warning |
| F16 | the test matrix | mixed-bucket scenarios and the leak assertion |
| F17 | new; reverses ADR 0023 D2 | the leaf is encrypted too, with a keyed head tag — **decided 2026-09-17: L2**, in ADR 0023 D21 |

### F1 — The operating model (decided 2026-09-17: O1, the mode set)

**Decision.** `encryption.filename_encryption.mode` is one of `off`, `drain`,
`mixed`, `strict`, default `off`. `drain` writes clear names and reads both
forms. `mixed` writes encrypted names and reads both forms. `strict` writes and
reads encrypted names only, and an unmarked name is a foreign name (ADR 0001).
Mixed operation happens **inside one bucket**: the owner's two requirements
imply it, because switching the feature off on a bucket that holds encrypted
names must keep them readable, so the same proxy reads both forms in the same
bucket. Written into ADR 0023 the same day: D1, D7 and D14 amended, D19 added,
the boolean alternative and the mixed-bucket leak recorded there.

**Rejected, for the record:** a boolean `enabled` with encrypted names read
whenever a key is configured — the configuration then does not say what the
proxy does, there is no finished state without `strict`, and a boolean cannot
become a mode later without a breaking configuration change (ADR 0013 D11);
per-bucket scoping as the model — contradicts "switchable", may return later as
an additive `buckets:` list.

```yaml
encryption:
  filename_encryption:
    mode: "off"                    # default; off | drain | mixed | strict
    keys:                          # F4c: a list from the first release, first entry writes
      - wrapped_key: "base64…"     # 64-byte name key wrapped by the KEK below (F5)
        kek_fingerprint: "…"       # must name a configured aes provider
```

Rules the loader enforces, all startup refusals (ADR 0013): `mode` other than
`off` with no key; `off` with a key ("a key nobody reads"); `kek_fingerprint`
naming no configured provider; an unwrap that fails; `mixed` or `strict` while
the active provider is `exit` (F10). Transitions an operator makes: `off →
mixed → strict` on the way in, `strict → mixed → drain → off` on the way out,
each a configuration change and a restart, none a data operation; `names audit`
(F11) proves a bucket ready for `strict`. `strict` may land in a later minor
release without a break, because a new mode value is additive; the shape has to
be the mode from the first release.

**Code:** `internal/config/config.go:49-61` (`EncryptionConfig` gains a
`FilenameEncryption` struct), `setDefaults`, `validateEncryption`,
`providerConfigKeys:914-917` (the strict-keys pattern to copy), the
expanded-fields list of ADR 0013 (a `${VAR}` in `wrapped_key` must be expanded
or refused, never kept verbatim); the startup unwrap goes through the
provider registered under `kek_fingerprint` (`internal/orchestration/providers.go`
registers every configured provider by fingerprint; the wrap is length-agnostic,
`pkg/encryption/keyencryption/aes.go:93-113`, but a name key must carry its own
wrap AAD label, F5).

### F2 — Exact-key lookup in a mixed bucket, and the leak (decided 2026-09-17: M2)

**Order.** The form the current mode writes is looked up first; the other form
only on `NoSuchKey`. A key with no `/` is a leaf alone and, since F17, has two
forms like any other key. Operations that resolve a key: `GetObject`, `HeadObject`,
`DeleteObject`, the three `*ObjectTagging`, the two `*ObjectRetention`, the two
`*ObjectLegalHold`, `AbortMultipartUpload`, `ListParts`. Operations that create:
`PutObject`, `CreateMultipartUpload`, and with them `UploadPart` and
`CompleteMultipartUpload`, always the writing form, never a retry.

**Request-scoped memo.** The whole-object GET makes two backend calls
(`bytes=-65604`, then the head under `If-Match`, ADR 0003 D14;
`internal/proxy/handlers/object/tail.go:71`) and the ranged
read under the exit provider makes a `HeadObject` first
(`internal/proxy/handlers/object/range.go:359`). Without a memo each call pays
the miss again, four round trips instead of two for every old object. A
resolution struct in the request context, installed beside
`requestTrackingMiddleware` (`internal/proxy/middleware_setup.go:26`), read and
written by the forwarder of F8, keeps the handlers ignorant of stored keys (D8).

**DELETE has no signal.** S3 answers `204` whether or not the key existed, on
both forms. If only the writing form is deleted, the clear copy left behind by an
overwrite becomes visible again: a deleted backup reappears, rclone deletes it on
every run, kopia accumulates garbage it cannot explain. So a delete in `mixed`
or `drain` has to settle both forms. **A blind DELETE of the clear form is
forbidden**: on a versioned bucket, and Object Lock implies versioning on exactly
the buckets `SECURITY_ARCHITECTURE.md` recommends it for, it creates a delete
marker under the **cleartext** name, which stores the name permanently. The
sequence is therefore `HeadObject` on the other form, then `DeleteObject` only
where it exists; and when the other copy is under retention or legal hold (the
`HEAD` shows `x-amz-object-lock-*`), refuse the whole delete before touching the
writing form, or the delete is half-applied and the object reverts to the old
copy. `DeleteObjects` (`object/operations.go:736-746,:802-820`, 1000 keys) sends
the writing forms in one call and settles the other form per directory group by
the lockstep listing of F3, not by 1000 `HEAD`s.

**The leak.** This is the finding of the revision, and it is a security matter,
so it is written out. Every request for the clear form carries the cleartext key
in its request line, and the backend's access log keeps it. For objects written
before the feature was switched on that discloses nothing, their names are stored
in the clear anyway. For a directory that came into existence *after* the switch
it discloses precisely the noun the feature hides: kopia's maintenance deletes
`kopia/<namespace>/p…`, and the `HEAD` of the clear form on that delete hands
`<namespace>` to the adversary. The same holds for a `GET` miss and for phase 2
of a prefixed listing (F3). A mixed bucket served without regard to this is
confidential only for names the adversary already has.

**Decision (2026-09-17): M2, the other form's directory tree is learned from
the backend before it is asked for.** Per bucket, a set of directory paths known
to exist in the other form; to decide whether `a/b/c/leaf` may have a clear
copy, answer `a`, `a/b`, `a/b/c` in turn from one delimiter listing of each
clear parent, cached with a TTL, negatives too. The root listing discloses
nothing; a listing of `a/` discloses nothing new because the backend itself
returned `a/`; by induction no request is ever made for a clear path the backend
did not return. A directory created after the switch is never probed, and phase
2 of F3 is skipped for it. Bounded (10k entries per bucket to start, tuned by
measurement); above the bound the proxy warns, counts and probes every other
form, the documented slower behaviour. TTL in the order of a minute, populated
on demand, no ticker. Under `drain` the roles mirror: the cache holds the
*marked* tree by decrypted name, and a probe of a marked form discloses only
ciphertext. Written into ADR 0023 the same day as D20; the residual risk there
is closed by it.

**Why M2 over "always probe and bound the mixed window":** `mixed` becomes a
state that can be held, so a backup bucket drains its clear names through
retention on its own (the ADR 0025 argument applied to names) and the copier
stays optional; leak-freedom becomes a tested property — the mock-backend test
of F16 fails when any call site asks for the other form blindly — instead of a
sentence in the documentation; and D3 is untouched, because the cache lives in
memory, holds only clear names the backend returned, and a backend that
withholds entries from a listing withholds the objects too, which is a denial of
service and not an oracle (ADR 0001). Staleness is one-sided in `mixed` because
nothing creates clear directories there: a stale negative costs an old object a
`404` until the TTL, never a leak; a stale positive costs one probe of a known
name. The rejected alternative costs no code but leaves new namespace names
unprotected for a window that is months long on an Object-Lock bucket.

| Operation | `strict` | `mixed`, object under writing form | `mixed`, object under the other form or absent |
|---|---|---|---|
| `GET`/`HEAD` | 0 extra | 0 extra | +1 round trip, only when the cache says the other directory exists |
| `DELETE` | 0 extra | +1 `HEAD` when the other directory exists | +1 `HEAD`, +1 `DELETE` |
| `PUT`, multipart | 0 extra | 0 extra | 0 extra |

**Code:** the forwarder of F8; `internal/proxy/middleware_setup.go:13-33`;
`internal/proxy/handlers/object/range.go:359`; `object/operations.go:736-820`
(`DeleteObjects`); the mode and cache live in the new `internal/naming/`
package.

### F3 — Listing in a mixed bucket (replaces D-G and the listing half of D-F)

**Shape.** Split the client prefix by the D9 rule into `n` complete directory
segments and a tail; a partial-leaf tail is translated per F17 (one character
into its tag, longer into a class filter). With `n = 0` and an empty tail (root
listing) there is **one** backend listing: every returned key is decoded per
segment by its marker (F4), so a root listing of a mixed bucket is single-phase. With
`n ≥ 1` the two forms live under two stored prefixes, so the answer is built
from **two sources** in sequence: the writing form first, the other form second,
and the second is skipped when the F2 cache says that directory has no other
form. F9's fan-out adds sources of the same kind. This is one primitive, a
**multi-source paged listing with a proxy-minted continuation token**, and both
F3 and F9 are instances of it.

**Token.** The token the proxy returns is its own: `(source index, backend
token)`, opaque and base64. ADR 0023 D12 says the token "passes through
untouched in both directions"; that sentence is amended. V2 clients are exact
with this alone.

**V1.** Always emit `NextMarker`, proxy-minted and phase-carrying. S3 documents
`NextMarker` only with a delimiter, but s3cmd takes it whenever present
(`S3.py:346-347`) and rclone is on V2, so the one client that could send a bare
last-key `marker` is one nobody has named. For a bare last-key marker the phase
is decided by one `HeadObject` of the marker's writing form: present means phase
1, absent means phase 2. That is exact **only if phase 2 never emits a key whose
writing form exists**, which the next paragraph guarantees.

**Duplicates.** After an overwrite an object exists under both forms. Listing it
twice is not an option: rclone keeps the first entry it sees and s3cmd the last
(dict semantics, `FileLists.py`), so no phase order is right for both, and a
client acting on the stale copy re-uploads forever, which is the D-F failure by
another door. Phase 2 therefore drops every entry that also exists in phase 1.
Cheaply: group the page's keys by directory; for each group, one delimiter
listing of the *writing* form of that directory with `start-after` at the group's
first leaf and `max-keys` at the group size; leaves sort identically in both
forms, so the two lists are walked in lockstep and the shadowed ones dropped.
Common prefixes of phase 2 are checked the same way against the writing form of
the parent. Cost: one extra listing per directory group per page, typically one
to five.

**Arithmetic.** `KeyCount` is recomputed after drops (`bucket/listing.go:127`
copies it verbatim today), `IsTruncated` stays the backend's truth, and a page
whose last entry was dropped is refilled from the backend before it is answered,
so a V1 or `start-after` client never sees a page it cannot advance from.

**Encoding.** D-G rule 1 stands: decode, transform, re-encode inside the
forwarder, per operation and per direction (`ListObjects`/`ListObjectsV2` raw
down and `url` up, `bucket/listing.go:93,:177`, decoded above the interface at
`listing_params.go:48`; `ListMultipartUploads` raw both ways,
`multipart/list.go:242-262`). D-G rule 2 stands: unescape first, split on `/`
second, and whether the backend escapes `/` stays a Stage 0 measurement.

**Order.** Backend order within each phase (D12). Across phases, across
directories and, since F17, within a directory the order is a permutation of
plaintext order, and the gate section records that no named client relies on it.

| Option | Verdict |
|---|---|
| L1. Two phases, no dedup | Duplicates visible; `s3cmd sync` never converges; a bare V1 marker can loop on a duplicate page end |
| **L2. Two phases, lockstep dedup, proxy-minted token and `NextMarker`, `HEAD`-disambiguated bare marker** | **Favourite.** The primitive is needed for F9 regardless; `mixed` is its second instance |
| L3. List the writing form only | A silent partial answer; ADR 0007 D1 and ADR 0010 D7 forbid it by name |

**Dissent:** the lockstep costs a backend listing per directory group per page for
as long as the bucket holds clear names, and a recursive listing across many
small directories is its worst case; the bound is the page, so it is never
unbounded, but it is measured (ADR 0020), not assumed.

**Code:** `internal/proxy/handlers/bucket/listing.go:16` (dispatch on
`list-type`), `:93-135` and `:177-209` (the two arms), `listing_params.go:44-62`,
`multipart/list.go:214-290`, `object/operations.go:736-820`; the primitive is new
code in `internal/naming/` or beside the forwarder.

### F4 — The stored segment form: marker, key fingerprint, key list (expires at the first written object)

Proposed grammar of one stored directory segment:

```
directory  "!" <fp: 2 base64url chars> <base64url, no padding, of the AES-SIV output>
leaf       "!" <fp: 2 base64url chars> <tag: 4 base64url chars, F17> <base64url of the AES-SIV output>
```

| Option | What it gives |
|---|---|
| a. Bare base64url, ADR 0023 D5 | Nothing is recognisable without decrypting. A wrong key looks like an empty bucket (D-J). Rotation is a full rename (D15). The off-state accident is silent |
| b. Marker `!` alone | The off-state and an audit can *see* an encrypted name. No identity: a wrong key is still "does not decrypt" |
| **c. Marker plus a 12-bit key fingerprint** | A wrong or retired key is a **named** failure, the convention `kek-fingerprint` already sets (`orchestration/metadata.go:116`, `providers.go:57`). Rotation becomes incremental: the old key stays configured, its names remain readable, the new key writes, and a lookup tries the forms in order, which is the F2/F3 machinery with one more form. A future AAD domain (D-B) is one more form too, not a full rename |

**Favourite: c.** Three characters per directory segment buy the two properties
the owner asked for by the word "sustainable": failures that name their cause,
and a key change that is not a bucket rewrite. Two configured keys with the same
fingerprint refuse the start.

**Consequences to write down.** In `off`, a marked segment seen in any listing
is a warning and a counter ("encrypted names found, filename_encryption is off"),
and the name is handed through verbatim: that is the cheapest catch for the
dropped-Helm-values accident of D-J, and it is loud. A marked segment whose
fingerprint is configured but which does not decrypt is passed through in
`mixed` and `drain` (the bucket may legitimately hold a clear directory that
starts with `!`; the proxy shows what is stored, ADR 0007) and dropped and
counted in `strict` (D11, where an unmarked or undecryptable name is foreign by
definition). A marked segment naming an unknown fingerprint is refused by name on
an exact lookup and dropped and counted in a listing, in every mode.

**Key shape in configuration.** The fingerprint makes a *list* of keys the
natural shape (F1's sketch), and the list has to be the shape **from the first
release that ships the key**: turning a mapping into a list later refuses every
configuration written against it (ADR 0013 D11), which the project paid for once
with `s3_backends`. Single-key alternative: `wrapped_key` and `kek_fingerprint`
directly under `filename_encryption`, and rotation stays the full rename D15
describes.

**Dissent:** YAGNI, three characters on a 1024-byte budget D13 already rations,
and the fingerprint tells the backend which key wrote which directory, the same
class of disclosure as `kek-fingerprint` in object metadata. The disclosure is
accepted there already.

**Code:** new `internal/naming/` (segment codec, fingerprint = first 12 bits of
SHA-256 over the raw key, as `keyencryption/aes.go` fingerprints its key);
`internal/proxy/handlers/bucket/listing.go` and the forwarder for the off-state
warning and the counters (the metrics registry lives under `internal/monitoring/`).

### F5 — The primitive and the key form (replaces D-A)

`tink` and `golang.org/x/crypto` are out of `go.mod`, Go 1.27.1 has no CMAC and
no SIV (verified 2026-09-17). D-A's table stands with one correction: **there is
no published vector for a 512-bit AES-SIV key**, neither in RFC 5297 (A.1 and
A.2 are 256-bit) nor in Wycheproof (256 and 384).

| Option | Finding |
|---|---|
| **Hand-rolled RFC 5297 in `internal/naming/`** | ~200 lines, 1 alloc, 229-403 ns per segment (D-A's measurement). Published vectors cover the code path at 256 and 384 bits; the 512-bit key needs its own known-answer tests |
| `tink-crypto/tink-go/v2` | Re-adds `x/crypto`, 7 allocs, a 4.5 MB module for a 175-line need |
| HMAC-SIV from the standard library | 60 lines, no vectors, and no name an auditor recognises |
| A 256-bit key (two AES-128 halves) | Fully covered by RFC and Wycheproof; cryptographically adequate for names; but "AES-256" is the product's statement |

**Favourite: hand-rolled RFC 5297 with a 512-bit key, gated three ways.** The
RFC A.1 vector and the 442 Wycheproof cases prove S2V, CMAC and the CTR leg;
only the AES key schedule differs at 512 bits and that is the standard library's.
For 512 bits, known-answer tests are generated once with Python `cryptography`'s
`AESSIV` (48.0.0, OpenSSL-backed, verified to accept a 64-byte key on
2026-09-17) over the exact S2V component layout of F6, committed as a fixture
with the generator script beside it, never run in CI. Round-trip, depth-move,
bit-flip, wrong-key, empty segment and the length guard complete the set. What
S2V adds for free: it takes a **vector** of strings and is a PRF over vectors by
construction (RFC 5297 §2.4), so the injective framing D-C demanded is no longer
hand-written. **Rejected either way: the standard-library composition**, for
D-A's reason. If the project will not own crypto, take tink and the Renovate
exception. If "published vectors only" is a condition, take 256 bits.

**Key form, simplified against D-A.** 64 random bytes, wrapped exactly like an
object data key but under its **own** AAD label (`s3ep-name-wrap-v1`, one
constant beside `aadWrap = "s3ep-dek-wrap-v1"` at
`pkg/encryption/keyencryption/aes.go:31`), so a wrapped name key and a wrapped
DEK are not interchangeable ciphertexts under the same KEK. No HKDF: the two
halves are independent because they are random, and nothing else is derived from
the key. Fingerprint: SHA-256 over the 64 bytes, first 12 bits, two base64url
characters (F4). `s3ep-keygen` gains nothing; `names wrap` (F11) generates,
wraps and prints the block.

**Dissent:** D-A's own, unchanged — 200 lines of GF(2^128) arithmetic in a
security product, and a from-scratch version written during the 2026-09-13
analysis had a real bug. The three-way gate is the answer to it, not a dismissal.

**Code:** new `internal/naming/`; `pkg/encryption/keyencryption/aes.go:31,:93-113`
(wrap, unwrap, the AAD constant); the pattern to copy for the vector test is
`pkg/encryption/dataencryption/segmented_gcm_vector_test.go`, whose header says
why a self-agreeing round trip proves nothing.

### F6 — Framing, and the bucket in the associated data (replaces D-C and D-B)

**Framing is no longer a choice.** With RFC 5297 the associated data is a vector
of components, and S2V binds the vector: `["s3ep-name-v1", depth as uint32
big-endian, parent chain, segment]`, where the parent chain is the **stored**
parent segments joined by `/` (marker and fingerprint included, so a subtree
moved by the backend fails to decrypt in its new place, D4). No `0x00`
separators, no hand-rolled length prefixes; the `uint8` depth of ADR 0023's
sketch is replaced by a fixed-width field. Pin the layout with the 512-bit
fixture of F5.

**The bucket stays out of the associated data** (D4 as written) and the D-B
decision is **deferred, not taken**: on AWS bucket names are globally unique, so
a disaster-recovery replica always has another name, and a bucket-bound name
would break the most common DR layout for everyone who did not read about a
`domain` key. The threat D-B closes, chosen-name writes as a cross-tenant
oracle, needs bucket-scoped client authorisation, which ADR 0014 does not have.
F4c is what makes deferral honest: a domain, when an authorisation ADR needs
one, is one more key form with its own fingerprint, and the migration to it is
the incremental rotation of F4, not a bucket rewrite. D-B's dissent (a knob now
or never) is therefore withdrawn.

### F7 — Segment-length padding (replaces D-D)

Pad the segment to a multiple of 16 bytes before encryption, PKCS#7 inside the
plaintext, so the ciphertext length reveals a 16-byte bucket rather than the
exact length. **Favourite: pad.** D-D's argument holds and is sharpened by the
census: the names the feature hides are short and distinctive (`hr`, `sap`,
`prod`, a database server name), so an exact length is close to an identifier,
and those live at depth 1 or 2 where the key budget is idle. **Dissent:** D-D's,
unchanged. Stored length of an `n`-byte segment under F4c and F7:

| `n` | padded | ciphertext | stored characters |
|---|---|---|---|
| 0 | 16 | 32 | 46 |
| 5 | 16 | 32 | 46 |
| 15 | 16 | 32 | 46 |
| 16 | 32 | 48 | 67 |
| 63 | 64 | 80 | 110 |

Formula: `3 + ceil(4 × (16 × ceil((n + 1) / 16) + 16) / 3)` for a directory
segment, plus 4 for the leaf's head tag (F17). D13's refusal is computed from
it, before the backend is asked.

### F8 — Where the transform is installed (replaces D-E; verdict unchanged, duties added)

D-E's favourite holds: **an explicit forwarder** implementing all 52 methods of
`interfaces.S3BackendInterface` (`internal/proxy/interfaces/s3_backend.go:11-99`)
with a named `inner` field and no embedding, so a 53rd method is a build error;
wrapped where the client is built (`internal/proxy/server.go:117`,
`s3.NewFromConfig`), the field at `:29` changed to the interface, and **the
abandoner closure at `:132-143` pointed at the wrapped value**, because it
captures the local variable and aborts with the client key from the session
table. Nothing else about the wire point is negotiable (the sweeper row of
*Ground truth*).

**New duties under F1-C.** The forwarder is no longer a pure key mapper: it
owns the mode, the fallback of F2, the sources of F3, the cache of F2-M2 and the
request-scoped memo. Handlers still never see a stored key (D8), and they still
know the flag exists for the two refusals of F12.

**Tests, all four.** (1) The build itself: no embedding. (2) A **field-level**
audit over every input struct of the 52 methods, asserting each `*string` field
named `Key`, `Prefix`, `Marker`, `StartAfter`, `KeyMarker`,
`WebsiteRedirectLocation` or inside `Delete.Objects` is in the classified set
(`object/storage_headers.go:120,:140` is why it is field-level). (3) A
hand-maintained list of key-bearing operations with **no** interface method,
each with its reason: `ListObjectVersions` (no route, `GET /{bucket}?versions`
falls through to the listing dispatch at `bucket/listing.go:16`), `CopyObject`
(refused at `object/operations.go:350` on `x-amz-copy-source`),
`UploadPartCopy` (refused, ADR 0011 D9). (4) The sweeper test: an abandoned
upload is aborted through the forwarder, under the stored key.

**Dissent:** D-E's — ~200 lines of mechanical forwarding to keep, for a
hypothetical 53rd method. The middleware alternative at least covers the
abandoner by construction, which embedding does not.

### F9 — A prefix that ends inside a directory segment (replaces D-F)

The gate of the whole feature: `s3cmd sync /local/dir s3://b/backups/` lists
`backups/dir` without a trailing slash (`FileLists.py:442-443`), and a human
types `aws s3 ls s3://b/back`. D9's empty listing is a silent partial answer
that ADR 0007 D1 and ADR 0010 D7 forbid. Since F17 the *leaf* half of such a
tail is settled (tag or class filter); what is open here is the *directory*
half, the subdirectories of `backups/` whose name starts with `dir`.

| Option | Verdict |
|---|---|
| D9 as written, empty listing | Forbidden by name; `s3cmd sync` re-uploads forever |
| Refuse every prefix not on a segment boundary | Refuses kopia's `kopia/<ns>/p` shape, the one the segments-only design exists to keep |
| D-F's probe, refusing the ambiguous arm in v1 | Honest, but a refusal is still a broken `aws s3 ls` for a human, and the fan-out it defers is what F3 builds anyway |
| **Fan-out over the multi-source primitive of F3** | **Favourite.** List the writing form of the parent with `Delimiter: "/"`, decrypt the returned common prefixes, keep the ones matching the partial tail, and make each match a source; the leaves that match natively (`!…E(backups)/dir*`) are one more source; under `mixed` the clear form lists `backups/dir*` natively as another. The token carries the discovery cursor, the current source and its backend token, so a parent with more than one page of subdirectories is walked across client pages, never buffered |

**Dissent:** D-F's — one discovery round trip per client page on the hot path of
a client that lists constantly, for a shape most clients never emit. It is paid
only when the tail is partial, which the D9 split knows before any request, and
it is measured (ADR 0020). The gate stays: **`s3cmd sync` converges on its
second run.**

**Code:** `bucket/listing.go:16` and the two arms; the primitive of F3;
`test/e2e/s3cmd/` (the case that asserts convergence).

### F10 — The exit provider, `drain`, and the licence (replaces D-H)

The mode set of F1-C dissolves D-H. With the exit provider active only `off`
and `drain` are accepted; ADR 0023 D7's exit clause stays for `mixed` and
`strict`, and it is no longer a policy dressed as a refusal: writing encrypted
names under a provider that stores plaintext would be the "looks protected while
it is not" defect ADR 0025 D3 exists to remove. Under `drain` names age out
exactly as payloads do, and the name key stays configured beside the `aes`
provider that unwraps it, which is ADR 0025 D4's sentence ("do not delete the
key, said in configuration") applied one layer up. **ADR 0025 gets a carve-out
in those words**, and no claim that a reverse rename pass restores its promise.
D-H's reverse pass (`names unmap` over a bucket) is no longer a launch
requirement; it is the optional copier of F11.

**Licence.** No new logic. The gate reads the active provider
(`internal/config/config.go:771` inside `validateLicenseAndEncryption`); `mixed`
and `strict` need an encrypting provider, so they are licensed by construction,
and `drain` under `exit` is not, which matches ADR 0025 D2: the licence gates
what the proxy *writes*, never what it reads. The `names` tools of F11 check no
licence, like `s3ep-keygen`; they serve no traffic. This answers D-H's business
question without a new rule, unless the owner wants name mapping licensed on its
own, which would be a new ADR.

**Dissent:** none of substance. What is lost is D7's original strictness (a proxy
that cannot decrypt names cannot serve the bucket), and it is lost deliberately:
under `drain` it *can* decrypt them.

### F11 — Migration, the pass engine and the `names` surface (replaces D-I; owner requirement added 2026-09-17)

**Owner requirement, 2026-09-17.** The copier is built as an **extensible pass
engine**: configurable, with interfaces that later carry two more per-object
operations — re-wrapping every object's data key onto a newly rolled-out key
encryption key ([040](040-managed-buckets.md), item 4), and bringing a newly
added backend to parity with the existing one ([037](037-multiple-backends.md),
its question 4). Neither operation is built now; **the interfaces are**, and the
rename operation of this ticket is the first to use them.

**What that changes against the 2026-09-13 text.** The copier is no longer
"optional, later": its engine is in scope of this ticket as the stage after
launch, with the rename operation as its first operation, and every interface is
proven by a second, test-only operation that touches no rename code. The engine
is a Go package with **its own S3 client**, driven by an operator binary (home:
open, below). It never goes on `interfaces.S3BackendInterface` — 040's rule: a
copy verb on the interface handlers hold is one refactor away from a
client-reachable metadata-rewrite primitive — and if any of it ever runs
in-process, the precedent is the injected function value of the abandoner
(`internal/proxy/server.go:132-143`), never an exported SDK client.

**Three operations, one engine.**

| Operation | Source → target | Transfer | Metadata | Owning ticket |
|---|---|---|---|---|
| **rename** (this ticket; `names migrate`, and the reverse for a `drain` bucket) | same backend, clear key → marked key | server-side copy up to 5 GiB, `UploadPartCopy` above | copied verbatim on a single copy; **re-supplied by hand on a multipart copy**, which inherits nothing (D-I) | 017 |
| **rewrap** (040 item 4) | same backend, same key | self-copy with `MetadataDirective=REPLACE` | the four `s3ep-*` keys rewritten: new `encrypted-dek`, `kek-fingerprint`, `kek-algorithm` (`internal/orchestration/metadata.go:114-117`) | 040 — **forbidden today by ADR 0017 D3, ADR 0002 D7 and ADR 0004 D12**; their amendments are the first work item of that operation and belong to 040, not here. 040 measured that the crypto half is sound |
| **replicate** (037) | backend A → backend B, same stored key | streamed through the tool: stored bytes and metadata copied byte for byte, so both backends hold identical ciphertext (037's nonce finding: independent proxy writes differ per backend) | verbatim | 037 |

**The interfaces the engine needs**, so that the two later operations slot in
without touching the rename path:

1. **Enumeration.** A resumable listing over one bucket on one backend, with
   filters an operation declares: prefix; "unmarked directory-bearing key";
   "fingerprint other than the current one"; "absent on the target backend". It
   yields object descriptors: key, size, ETag, the metadata map, retention and
   legal-hold state, storage class.
2. **Plan.** Per descriptor, the operation decides target key, target backend,
   the metadata transform, and skip-or-act, without performing anything.
3. **Transfer.** Server-side copy (single or multipart) when source and target
   backend are the same, streamed copy when they differ; **conditional on the
   source ETag** (`x-amz-copy-source-if-match`), because 040 measured that an
   unguarded self-copy racing a client `PUT` leaves an object that answers
   `403 InvalidObjectState` and is unrecoverable; retention, legal hold and
   storage class re-supplied from the descriptor, because 040 measured that a
   self-copy silently strips WORM state.
4. **Verify.** After the copy, read the target back through the proxy's own
   codec (`pkg/encryption/dataencryption/segmented_gcm.go`): open one segment or
   the trailer under the target's metadata. A copy's `200` is not proof.
5. **Delete-source policy.** Per operation: rename deletes after verify and
   leaves a locked source in place, reported; rewrap has nothing to delete but
   must say that on a versioned bucket the noncurrent version keeps the old
   wrapping (040); replicate never deletes.
6. **Report.** Dry run against apply, one outcome per object, `--allow-partial`,
   a non-zero exit while anything is skipped; the same shape `names audit`
   prints.
7. **Configuration.** The operation and its filters, concurrency, a rate limit,
   and the backend(s) **by reference to the proxy's own configuration file**, so
   credentials are never written twice; the tool loads that file with a loader
   that stops before the licence read (`internal/config/config.go:771`).

**Constraints that stand for every operation** (D-I and 040, measured): the
5 GiB single-copy cap; a multipart copy inherits no metadata; an object under
retention or legal hold keeps its source; the entity-tag class changes above the
copy threshold (ADR 0032 D1/D2/D8) and single `CopyObject` changes a
multipart-shaped tag to single-part shape; `LastModified` changes, so a client
comparing modification times (rclone by default) re-transfers every touched
object once; a self-copy resets the storage class and the lifecycle clock;
compliance-mode Object Lock refuses the source delete outright. Migration runs
**online** under `mixed` (F1, ADR 0023 D14): the proxy serves both forms while
the copy and the delete happen.

**Not this ticket's decisions.** The rewrap operation's ADR amendments and
semantics stay in 040 (its open questions 8 to 12 and 15 are about exactly this
pass); the sync policy across backends stays in 037 (its question 4). This
ticket owns the engine's interfaces and the rename operation; a note in each of
the two tickets points here (added 2026-09-17).

**v1 surface**, unchanged: `names wrap` (generate 64 bytes, wrap under the active
KEK, print the configuration block), `names map` / `names unmap` (translate a key
or a prefix in either direction, for lifecycle rules, bucket policies and
debugging), `names audit` (read-only against the backend with its credentials:
count unmarked directory-bearing keys, marked segments with an unknown
fingerprint, marked segments that do not decrypt; non-zero exit while any
remain; the readiness check for `strict`). **Post-launch stage:** the engine
and `names migrate`, the rename operation, with a dry run, `--apply`,
`--allow-partial` and the report.

**Home of the tools — open.**

| Option | Finding |
|---|---|
| a. `s3ep-names` binary now, a pass binary later | Mirrors `cmd/keygen` and `cmd/license-tool`; two tools sharing one loader |
| **b. One operator binary, `cmd/admin` → `build/s3ep-admin`, with `names …` and `pass …` subcommands** | **Favourite.** One home for every operator action against a bucket, which the engine makes a family (names today, keys and backends later); one loader that stops before the licence read; cobra subcommands as the proxy root already uses; the proxy binary stays single-purpose. Amends ADR 0023 D16 ("the proxy binary carries a `names` subcommand") |
| c. Subcommands on the proxy binary (D16 as written) | One binary, but the root has no subcommands today and gains a second personality, and the licence gate has to be stepped around inside the binary that enforces it |

**Dissent on b:** a fourth binary in the image and the chart; and D16 is in an
accepted ADR.

**Code:** `cmd/keygen/main.go`, `cmd/license-tool/main.go` (the pattern);
`cmd/s3-encryption-proxy/main.go` (cobra root); `internal/config/config.go:771`
(the licence read a tool loader stops before); `internal/proxy/server.go:117`
(client construction); `internal/orchestration/metadata.go:114-117`;
`pkg/encryption/dataencryption/segmented_gcm.go`; 040's *Measured* table for the
constraints.

### F12 — The refusal surface (replaces D-L)

- **Delimiter (D10):** refuse anything but `/` or empty at `bucket/listing.go:16`,
  before the V1/V2 split, and at `multipart/list.go:214`. Unchanged.
- **Over-long key (D13):** `400 KeyTooLongError`, verified real (corrections
  table). Computed from the F7 formula before any backend request.
- **Prefix-bearing bodies:** **forward and document, no heuristic.** D-L's
  dissent wins: a substring guard over IAM policy JSON has both failure modes,
  and no supported client writes a bucket policy through the proxy (unverified,
  plausible). `names map` translates the prefixes an operator needs in a
  lifecycle rule, a bucket policy, a website or a logging configuration, and the
  operator page says that under `mixed` such a rule has to name both forms.
  D18's allowlist gains **website** and **policy** and is recorded as
  deliberately untransformed, as D18 asks.
- **Extend nothing else.** `?torrent` and `SelectObjectContent` stay refused;
  `ListObjectVersions` stays unrouted and is in the F8 list.

### F13 — The D11 / D17 contradiction (D-M, unchanged)

The warn line **may name the stored value** and never the plaintext beside it;
D17 gains the carve-out in writing. Under `mixed` the stored value reaches the
client anyway (F4), so the line cannot be half of a mapping pair. If D17 is
instead read strictly, D11's warn log is a duplicate of D11's counter and one of
the two obligations is dropped, not both implemented.

### F14 — Memoisation (D-K, unchanged, plus the memo of F2)

Per-request map keyed on the whole ciphertext directory prefix, built and
discarded with the response, at all four page-scale sites (`ListObjectsV2`,
`ListObjects`, `DeleteObjects`, `ListMultipartUploads`). No process-wide LRU:
D-K's security argument settles it. Plus the request-scoped resolution memo of
F2, which is a different thing: it remembers *which form* resolved, not a
decrypted name. D-K's dissent stands (the DEK cache at `providers.go:23,:346`
already holds something more sensitive); it is a reason to revisit the DEK cache,
not to add a second one.

### F15 — Release label (D-N, unchanged, plus a shape warning)

Minor. Every key is additive with `mode: "off"` as the default, and a deployment
that never enabled the feature upgrades unchanged. Two cautions: D-N's, that
"off behaves exactly as today" is a per-bucket property (F4's off-state warning
is what makes it visible); and F4's, that the `keys` list shape has to be final
in the first release that ships it, because a later reshape is a major (ADR 0013
D11, ADR 0018).

### F16 — Tests (replaces the test matrix)

D-E's "targeted, not doubled" stands: one new integration package with
directory-bearing fixtures, driven the way `scripts/conformance-run.sh:191-233`
drives a proxy (built binary, heredoc configuration, free port), never a third
compose service and never a parameter on an existing test (ADR 0019 D4). What
the revision adds, every one asserting the target (ADR 0031):

- **Mixed bucket.** Populate under `off`, switch to `mixed`: every old object
  reads, every new object stores under a marked directory, a root listing and a
  prefixed listing return the union without a duplicate over 2500 objects in
  three directories, in V1 and in V2, with `max-keys` small enough to force a
  page break inside each phase.
- **Overwrite and delete.** Overwrite an old object, then delete it: neither
  form remains, and a versioned bucket carries no delete marker under a clear
  name that never held an object.
- **The leak, as a unit test.** With the mock backend recording every request:
  a `GET` miss, a `DELETE` and a prefixed listing of a key whose directory was
  created after the switch make **no request carrying the clear form**. This is
  the assertion that makes M2 a tested property instead of a design note.
- **`drain`.** New writes clear, old encrypted names readable, the same union in
  listings.
- **`strict`.** An unmarked directory-bearing key is invisible in listings and
  `404` on `GET`; a marked segment with an unknown fingerprint is refused by
  name.
- **The gate.** `s3cmd sync` converges on its second run, on a fresh bucket and
  on a mixed one. rclone and Velero's feature-on scenario each once.
- **At rest.** The backend listing taken during the e2e contains no namespace
  name and, since F17, no backup name; the assertion **fails** when the
  transform is not installed. The Velero
  deletion gate (`scenarios_lifecycle_test.go:141-145`) learns the transform
  *before* the feature lands, because it goes vacuously green otherwise, and a
  harness change needs the real Velero run.
- **Performance.** Gate on deterministic quantities: primitive calls per request,
  allocations per key, backend requests per listing page under each mode.


### F17 — The leaf is encrypted too (decided 2026-09-17: L2, a keyed head tag)

**Decision.** The leaf is encrypted like a directory segment (same SIV, same
key, AAD with a leaf role component, F6), and its stored form carries, ahead of
the ciphertext, a fixed-width keyed tag of the leaf's **first character**:
`tag4 = base64url(HMAC-SHA256(K_tag, stored parent chain ‖ first character))[:4]`,
with `K_tag` derived from the name key, or a second 32-byte half of it (settle
with F5). Directory segments carry no tag. Written into ADR 0023 the same day:
D21 added, D2, D4, D9 (leaf half), D12 and D18 amended, the title changed (file
name kept), the census residual closed. This reverses ADR 0023's own rejection,
whose argument assumed the backend has to do the prefix matching.

```
client key   kopia/prod/p1a2b3c4
stored       <dir(kopia)>/<dir(prod)>/<leaf(p1a2b3c4)>
leaf form    <marker+fp per F4> <tag4> <base64url(SIV(pad16("p1a2b3c4")))>
```

**Listing translation** (extends F3's split): complete directory segments are
encrypted; a trailing partial leaf of one character becomes its tag and is a
native backend prefix (`kopia/prod/p` → `…/<tag(p)>`); a longer partial leaf
(`kopia/prod/xn`) lists the class `…/<tag(x)>` and keeps the leaves that
decrypt to a match, paged behind the proxy's own token (a filtered source of
the F3 primitive: resume from the backend token of the page that held the last
emitted match, skip what was emitted). An empty tail lists the directory as
today. Root-level flat keys are leaves alone and have two forms in `mixed` like
any other key.

**Why L2 over the tag-less leaf (L1):** kopia lists its blob types by
single-letter prefix on every repository open, several listings per open; under
L1 each is a scan of the whole namespace directory, on a large repository
seconds to minutes where today it is milliseconds. Under L2 the one-character
case is native by construction and the two-character cases (`xn`, `xe`) cost
the `x` class, a few pages. What the tag discloses is which leaves of one
directory share a first character — for kopia the blob type, which sizes
disclose anyway; for Velero the fact that a backup's files share its name, which
their directory discloses anyway — and nothing across directories, because the
parent chain is under the tag. A clear first character instead of the tag was
rejected: same behaviour, discloses the character itself.

**Consequences for other entries.**

- **F2:** the D20 cache also holds the clear-form *leaves* a directory listing
  returned, so a root-level flat key or a leaf inside an old directory is probed
  in the clear only after the backend listed it. Where a directory has more
  children than the bound, the proxy probes leaves of that directory and says so;
  a directory created after the switch is still never named. ADR 0023 D20 gets
  that sentence when F4 lands.
- **F3:** order within a directory is now ciphertext order too; the gate
  section's finding covers it. The lockstep dedup of phase 2 compares *stored*
  leaf forms, which still sort identically in both phases' listings of the same
  directory because both are the same deterministic function.
- **F4:** the grammar gains the leaf variant (tag between marker and
  ciphertext); a directory segment stays without a tag.
- **F7:** padding applies to the leaf; the key-length formula gains 4 for the
  leaf. A 64-character content hash leaf stores as 135 characters.
- **F9:** the leaf half of a partial tail is settled by this entry; the
  directory half (`backups/b`) stays F9's question. A tag on directory segments
  was rejected in D21: it would cluster the namespace inventory by first letter.
- **The census** (*What the feature is actually worth*, below): inverted. With
  the leaf hidden the feature hides the backup name, the schedule name and the
  restore timestamps in the Velero layout; the claim the README may make is "the
  backend learns no name", followed by D18's list.
- **Tests (F16):** a kopia-shaped listing with a one-character prefix costs one
  backend request per page, as today; a two-character prefix costs the class;
  the at-rest assertion now also asserts that no backup name appears in the
  backend listing.

**Constants, not configuration:** the head is one character and the tag four
base64url characters (24 bits). Changing either is a rename the pass engine
(F11) can run.

**Code:** `internal/proxy/handlers/bucket/listing.go:16,:93-135,:177-209`
(the split and the arms), the F3 primitive (new), `internal/naming/` (leaf
codec beside the directory codec); `test/e2e/harness/atrest.go:38-43` and
`stored.go:36-61` (the at-rest assertions that learn both forms).

---

## Decision analysis of 2026-09-13 (kept for its reasoning)

**The current list is
[*The decisions, revised 2026-09-17*](#the-decisions-revised-2026-09-17)
above.** The entries below are the analysis that list was built on. They are kept
verbatim because most options and every dissent originate here; where a verdict
changed, the F-entry names the reason. Read a D-entry when its F-entry points at
it, never as a work list of its own. Line anchors in this section are those of
2026-09-13; the corrections table above refreshes the ones that matter.

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

## Stage 0 — before a line of code (revised 2026-09-17)

Nothing below is optional, and all of it is cheap relative to the decisions it
informs. Items marked done were closed on 2026-09-17; the rest are open.

**Decisions, in this order, written into ADR 0023 in the session they are taken:**

- [x] **F1 — decided 2026-09-17: O1, the mode set `off / drain / mixed / strict`,
      mixed operation inside one bucket.** Written into ADR 0023 (D1, D7, D14, D19).
- [ ] **F4 — marker, fingerprint, key list.** Expires at the first written object;
      the list shape expires at the first release (ADR 0013 D11).
- [x] **F17 — decided 2026-09-17: L2**, the leaf is encrypted with a one-character
      keyed head tag. Written into ADR 0023 (D21; D2, D4, D9, D12, D18 amended).
- [ ] **F5, F6, F7 — primitive, framing, padding.** Expire at the first written
      object. F5 includes the 512-bit vector plan and settles where the tag key
      comes from; F6 records D-B as deferred and adds the leaf role to the AAD.
- [x] **F2 — decided 2026-09-17: M2**, the other-form directory cache is v1.
      Written into ADR 0023 (D20); the residual risk there is closed.
- [ ] **F10 — the ADR 0025 carve-out** in the words F10 gives, and whether name
      mapping is a licensed capability on its own (default: no new rule).
- [ ] **F11 — the home of the operator tools**: one `s3ep-admin` binary (favourite,
      D16 amendment), a names-only binary, or subcommands on the proxy. The engine's
      interfaces (F11, seven of them) are reviewed before Stage 8 starts.

**Measurements and census:**

- [ ] **Obtain a licence token out of band** (`S3EP_LICENSE_TOKEN` or
      `config/license.jwt`). `make e2e-up` aborts without one. Not in the repository.
- [ ] **Run the Velero leaf census against a real bucket.** `make e2e-up && make
      test-e2e-velero`, then dump the full backend listing. The suite never creates a
      Schedule, so add one Schedule-created backup and one default-named restore by
      hand; those are the two worst real-world leaf shapes. The user-facing claim the
      census supports today is "the namespace inventory is hidden", never "backup
      names are hidden".
- [ ] **Settle the `/` escaping question.** One raw request at the backend, not
      through the proxy: `./start-demo.sh`, PUT a directory-bearing key through the
      proxy, then `curl -s --aws-sigv4 …
      'http://localhost:9000/<bucket>?list-type=2&encoding-type=url'` and read the
      XML. Repeat against LocalStack. **Not** via `make test-conformance`, which never
      exposes the backend's raw XML.
- [ ] **Record the listing shapes every supported client emits.** A one-line shape
      log at `bucket/listing.go:16` and `multipart/list.go:214` (bucket, list-type,
      prefix, delimiter, marker, start-after, token-present, max-keys, encoding-type),
      then one rclone run, one s3cmd run and one Velero run. Sharpened questions:
      **does any client send a bare last-key V1 `marker` without honouring
      `NextMarker`?** s3cmd does not (`S3.py:346-347`), rclone is V2; Velero's plugin
      is unread. **Which partial-leaf prefixes does kopia emit, and how often per
      repository open?** One character is native under F17, two characters cost the
      class; the count per open is what the F17 cost claim rests on.
- [ ] **Build the listing performance instrument and record its BEFORE column on
      the pre-change commit** (ADR 0020 D17). `test/perf/` has none. It records
      backend requests per client page as well as time, because F3's cost is
      requests, not crypto.
- [ ] **Generate the 512-bit known-answer fixture** with Python `cryptography`
      once F5 and F6 are decided (the S2V layout is part of the fixture). Commit the
      fixture and the generator script; CI never runs the script.
- [x] **`KeyTooLongError` verified** against the S3 API model, 2026-09-17.
- [x] **Vector coverage established**, 2026-09-17: no 512-bit published vectors.
- [x] **s3cmd's marker handling read**, 2026-09-17: `NextMarker` honoured.

**Fix regardless of the build decision** — live defects this analysis surfaced:

- [ ] The abandoner's raw-client call at `internal/proxy/server.go:132-143`; the
      client is built at `:117`.
- [ ] The Velero deletion gate at `test/e2e/velero/scenarios_lifecycle_test.go:141-145`
      goes vacuously green under any transform of the stored name. Repair it
      **before** the transform lands. A change under `test/e2e/harness/` is a change
      to all three suites and needs the real Velero run (~45 min plus the licence).
      The at-rest helper (`harness/atrest.go:38-43`) already guards itself.

---

## Staged plan (revised 2026-09-17)

The order is corrected against the revision: the copier is gone from the launch
path, the listing primitive is the centre of gravity, and the performance
instrument still comes first of all. Chart and expanded-fields work precede any
feature-on e2e job; the D18 amendment precedes the audit test built against it.

| Stage | Goal | Exit criterion | Effort |
|---|---|---|---|
| **0** | The list above | Every decision written into ADR 0023; census recorded; BEFORE column on the pre-change commit | 3-5 d |
| **1** | `internal/naming`: the segment codec per F4, F5, F6, F7 | RFC A.1 and Wycheproof 256/384 green; the 512-bit fixture green; round-trip, depth-move, bit-flip, wrong-key, length-guard, empty-segment tests; benchmark recorded (ns and allocs per segment) | 1 w |
| **2** | Configuration block and mode set (F1), startup unwrap, the expanded-fields list, **Helm chart**, `names wrap` | A feature-on proxy starts in the demo stack **and in kind**; the wrapped key reaches the pod through a Secret; every startup refusal of F1 is a unit test | 1 w |
| **3** | D18 amendment, then the explicit forwarder (F8) with the four tests, and the abandoner fix | A 53rd interface method fails the build; `WebsiteRedirectLocation` is covered; the sweeper aborts through the forwarder | 1 w |
| **4** | The multi-source listing primitive (F3), the fan-out (F9), the fallback and memo (F2), the directory cache (F2-M2), `DeleteObjects` and `ListMultipartUploads`, the refusals (F12), the memo (F14) | Pagination over 2500 objects across three directories in V1 and V2 under `mixed`; no duplicate; the leak unit test green; `s3cmd sync` converges on a fresh and on a mixed bucket | 2 w |
| **5** | `names map`, `names unmap`, `names audit` (read-only) | `audit` proves a bucket ready for `strict` and exits non-zero otherwise | 0.5 w |
| **6** | Tests per F16: the feature-on integration package, the e2e repairs, one feature-on scenario per client suite, the `drain` and `strict` scenarios | Nothing green that does not check something; the at-rest assertion fails without the transform | 1.5-2 w |
| **7** | README key reference, `SECURITY_ARCHITECTURE.md` key-custody section ("losing the KEK under `exit` still yields readable objects; losing the name key yields readable objects nobody can address"), `docs/operations/` (configuration, s3-api, integrity, upgrading, one note per client page), `docs/developer/` (`package-map.md`, `request-paths.md`, `configuration.md`, `testing.md`, `errors.md`, `performance.md`), the ADR amendments still owed (0023 D5, D6, D15, D16 for F4/F11; D9's directory half and D11 for F9/F13; D17 for F13; D20's leaf sentence; 0025's carve-out for F10) | | 0.5-1 w |
| **8, after launch** | The pass engine (F11) with the rename operation, `names migrate` | A bucket with an object above the copy threshold migrates online with its four metadata keys intact; a conditional copy detects a concurrent client write; retention and legal hold survive; `names audit` proves completion; a second, test-only operation proves the `Enumerate`/`Plan`/`Transfer`/`Verify` interfaces without touching rename code | 2-3 w, not on the launch path |
| **later, other tickets** | rewrap (040 item 4) and replicate (037) as operations of the same engine | Each after its own ticket's decisions; rewrap after the amendments to ADR 0017 D3, ADR 0002 D7 and ADR 0004 D12 | — |

**Effort: 7-8 focused weeks for one person to launch, and that is the floor;**
the pass engine with its first operation is 2-3 more, directly after. Stage 4 is the surprise
of this revision as the copier was of the last: the listing primitive is one
piece of code with four callers (two phases, the fan-out, the lockstep dedup),
and it is the piece whose cost is requests rather than crypto.

### The test matrix

Running the **existing** integration suite with the feature on would be green
and would prove nothing: almost every integration key is flat, and D2 stores a
key with no `/` unchanged. **A false green here ships a missed call site.**
F16 is the matrix: targeted, not doubled; one new package; one scenario per
client suite; nothing parameterised on the flag (ADR 0019 D4); performance gated
on deterministic quantities.

---

## Success criteria (revised 2026-09-17)

- `make test-unit` green, including the RFC 5297 vector, the Wycheproof cases
  and the 512-bit fixture.
- The feature-on integration package green over both transports, in `mixed`,
  `drain` and `strict`; the default-off configuration keeps its existing coverage
  unchanged; `make test-conformance` green (a new configuration key).
- The leak unit test green: no clear-form request for a directory created after
  the switch.
- `make e2e-velero`, `make e2e-rclone`, `make e2e-s3cmd` green with the feature
  on, **including `s3cmd sync` converging on a second run against a mixed
  bucket**, which is the F9 gate.
- A backend listing taken during the e2e contains **no namespace name**; the
  assertion is in the suite and fails without the transform.
- The listing instrument shows requests per page as the cost, not crypto; a
  one-character partial-leaf prefix costs one backend request per page as today
  and a two-character one costs its class (F17); the byte path shows **no
  movement at all**, and any movement is a bug, not a cost.
- Stage 0's answers are in ADR 0023, the README and `SECURITY_ARCHITECTURE.md`,
  including the leaf-name residual as the census found it, and the key-custody
  sentence.

---

## Open questions for the repository owner

1. **F4.** Marker plus fingerprint plus key list, or the bare form of ADR 0023 D5?
   Irreversible at the first written object.
2. **F10.** Is name mapping a licensed capability on its own? Default: no new
   rule, the licence gates what the proxy writes.
3. **F11.** Home of the operator tools: one `s3ep-admin` binary (favourite), a
   names-only binary, or subcommands on the proxy binary?

The 2026-09-13 question "is there a named customer asking for this?" is
overtaken: on 2026-09-17 the owner stated the feature's requirements. What the
census changes is the *claim*, not the decision to build: the namespace
inventory and the database server name are what the feature hides, and the
documentation says so and no more.
