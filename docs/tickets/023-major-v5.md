# Major release 5.0.0 — the minimum scope

Work list for the next major release. It says what 5.0.0 contains **at least**, in
what order it lands, and what the operator has to do. The decisions behind every
line live in [docs/adr/](../adr/); this file adds no decisions of its own.

More may join the release when it makes sense. What must not join it is anything
that does not need it.

## Why 5 and not 4

`v4.0.0` was released on 2026-09-07 without this bundle: a pull request was merged
with a merge commit, the release automation saw the two honestly marked breaking
commits inside it, and cut a major nobody had planned. Nothing of the bundle is in
it. The current line is 4.0.x, the bundle is 5.0.0, and objects written by 3.x and
by 4.0.x are equally unreadable under the new format.

The guard that stops this happening again is [ADR 0018](../adr/0018-a-major-release-is-declared-by-a-label.md):
a check on every pull request into `main` that fails on a breaking commit unless
the pull request carries the `release:major` label. **It lands on `main` before
the bundle branch forks.**

## Branch

`feat/major-v5`, forked from `main` at or after `ed2e964`. Not from the Velero
branch — that work is already in `main`, squashed, and the branch is not an
ancestor of it.

One pull request per unit of work into the bundle branch, squash-merged. Breaking
markers are used freely there; nothing releases from that branch. Rebase onto
`main` whenever `main` moves; the end-to-end suite is the gate on every rebase.
The final pull request into `main` carries the `release:major` label, and the
computed version is checked before the merge button.

## The minimum

Every row forces an operator to do something, or changes an answer a client gets.

| What ships | Decision | What the operator does |
|---|---|---|
| The segmented AES-256-GCM storage format | [ADR 0003](../adr/0003-objects-are-an-authenticated-segment-chain.md) | Upload every object again from its source. There is no migration and no read path for the old format |
| `encryption.integrity_verification` and `optimizations.streaming_threshold` removed; `streaming_segment_size` must be a multiple of 64 KiB | [ADR 0003](../adr/0003-objects-are-an-authenticated-segment-chain.md) | Drop the two keys; check the segment size or the proxy will not start |
| One local key provider: the `rsa` provider type is gone, `aes_key` must be base64 of 32 random bytes, the wrap becomes authenticated and the fingerprint derived | [ADR 0004](../adr/0004-one-local-key-provider.md) | Move any `rsa` provider to `aes` before re-uploading. Replace a key that is not 32 random bytes — including one delivered through `${S3EP_AES_KEY}`, which nothing in this repository can be grepped for |
| Client metadata inside the configured prefix is refused with `InvalidArgument`; the prefix must be at least four characters and end in `-` | [ADR 0009](../adr/0009-the-metadata-prefix-is-the-proxys-namespace.md) | Stop writing user metadata into the `s3ep-` namespace; rename a prefix that is shorter or lacks the trailing dash, no shipped value is affected |
| The dead `s3_security` keys, `s3_backend.use_tls`, `clean_http_transfer_chunked`, `streaming_buffer_size`, `enable_adaptive_buffering` and the legacy top-level backend block are deleted; a plain-HTTP backend under an encrypting provider and a scheme-less endpoint refuse to start; the pre-signed ceiling drops to one hour; the configured clock skew applies to both authentication forms | [ADR 0013](../adr/0013-a-configuration-key-exists-only-if-code-reads-it.md), [ADR 0014](../adr/0014-authentication-is-sigv4-no-rate-limiting.md) | Drop the keys from the configuration and the deployment values; switch the backend endpoint to `https://`; set `max_presign_expiry_seconds` if URLs above one hour are in use; check client clocks |
| The whole-request and whole-response wall clocks go; `shutdown_timeout` becomes the transfer budget and the chart derives its grace period from it | [ADR 0015](../adr/0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md) | Nothing, unless a deployment relied on a transfer being killed at 30 s |
| Storage headers on `PUT` are forwarded instead of silently dropped; the tagging, retention and legal-hold sub-resources become pass-through; `PUT ?acl` and `PUT ?cors` carry their documents to the backend; SSE-C is refused with a named error; a query string containing `;` is refused with `InvalidArgument` | [ADR 0007](../adr/0007-forward-it-or-refuse-it.md) | Check that a client which sets these headers meant them: they now take effect on the backend object. Nothing for the `;` rule unless a client sends one, and no known client does |
| The location element of a completed multipart upload honours `X-Forwarded-Proto` and `X-Forwarded-Host` | [ADR 0008](../adr/0008-every-response-describes-the-proxy.md) | Nothing |
| The example configurations and the end-to-end values lose their literal keys; keys are generated at bring-up | [ADR 0021](../adr/0021-key-material-is-generated-never-committed.md) | Export the key variables, or run the bring-up script |
| `GOMEMLIMIT` ships in the chart and in compose | [ADR 0020](../adr/0020-performance-is-measured-before-and-after.md) | Re-size the pod limits if the deployment overrides them |

## Also in, and what stays out

Each of these changes an answer a client gets, so by the rule of
[ADR 0018](../adr/0018-a-major-release-is-declared-by-a-label.md) each belongs in
a major. Which major was left to judgement; the calls are below.

**In**, because the alternative is writing their tests twice or shipping a second
set of behaviour changes weeks later:

| Also in | Decision | Why here |
|---|---|---|
| Upload checksum verification ([014](014-upload-checksum-verification.md)) | [ADR 0012](../adr/0012-client-checksums-are-verified-never-forwarded.md) | Its tests are written against configuration keys the format change deletes; on the current line they would be written twice |
| The listing document and plaintext sizes ([018](018-listobjectsv2-document.md)) | [ADR 0010](../adr/0010-sizes-and-listings-describe-the-plaintext.md) | The plaintext size is only a pure function of the stored size under the new format; the document rewrite touches the same responses and lands as one change |
| Conditional request headers on writes and reads ([019](019-handler-unit-coverage.md) item 12) | [ADR 0007](../adr/0007-forward-it-or-refuse-it.md) | A silent overwrite becoming a `412` is a behaviour change; it is blocked on the format change anyway |

**Out**, each for its own reason:

| Out | Where instead | Why |
|---|---|---|
| The Helm chart round ([016](016-helm-chart-fixes.md)) | `main`, now | It closes a live deployment defect and gives continuous integration a render of the values files this release edits. Squash-merged under a non-breaking title |
| Filename encryption ([017](017-filename-encryption.md)) | A later release | Depends on the listing work and on a client-behaviour check that has not started. Enabling it later is a rename pass, not a re-encryption, so it costs an operator nothing to wait |
| Vault as a key provider ([025](025-tink-kms-hcvault.md)) | A later release | Parked: its own five decisions are deferred and recorded on the ticket. Purely additive, and with the local provider kept there is no gap at 5.0.0 |
| SSE-C on every verb ([026](026-sse-c-passthrough.md)) | A later release | Purely additive: a request that answers `501` today starts working |

## Order

1. **On `main`, before or beside the branch:** the release guard, the version
   dry-run check on pull requests (ADR 0018 D6, decided 2026-09-09), the Helm chart
   round, the metadata-prefix case fix, the pooled copy on the ranged read, the
   **full** performance
   baseline ([021](021-relative-performance-thresholds.md), ADR 0020 D17) with
   pre-release numbers on both transports, the ranged-read and small-object
   benchmarks, the unwrap microbenchmark, the memory numbers and the profiles.
2. **[013](013-storage-format-v2.md)** first on the branch — it deletes the code
   the others would otherwise be written against, and it is the largest change.
3. **[015](015-configuration-hygiene.md)** — after 013, so the example
   configurations and values files are edited once for both.
4. The client-visible corrections, in dependency order.
5. **[022](022-s3-surface-fidelity.md)** — the storage headers and the location
   element.
6. The runtime memory limit last: the memory test of 013 is re-run under it, and
   if it shows no gain the value is dropped before the merge.

## Progress (2026-09-08)

State of the work at the end of the session that opened the bundle. Delete each
row when its PR merges and the row's fact is captured where it belongs.

### On `main` — step 1, mostly landed (2026-09-09)

Merged into `main` on 2026-09-09, each squash-merged under a non-breaking title with
every gate green: the release guard (#333, ADR 0018 D3/D4; the check
`Breaking changes are declared, not discovered` is now a **required** status check on
`main`), the pooled copy on the ranged read (#334), the metadata-prefix case fix
(#335; the shared-namespace refusal of ADR 0009 stays in 013 item 4a), and the
version dry run on pull requests (#338, ADR 0018 D6). `main` has moved; **rebase
`feat/major-v5` before the first code lands** (the e2e suite is the gate on every
rebase).

**Found by #338, fixed by #339 (merged 2026-09-09):** the release tool loaded the
`release` block of `package.json`, which shadowed `.releaserc.json`; `feat!:` computed no
major, releases carried no binaries, and the coverage badge was never committed.
`release.config.mjs` is now the only configuration, the preset is pinned to the
generation the release tool is built on, and the release job builds the binaries it
attaches (ADR 0018). Not yet proven: the asset upload and the badge commit on the first
release under it — 4.0.3 went out under the old configuration minutes before the merge,
and the next `fix:` or `feat:` on `main` is the first real run. Note for every commit on
this branch: no line of a commit message may start with the words `BREAKING CHANGE`
unless it is the footer — the parser reads it as one, and the dry run computed 5.0.0 from a
sentence that did.

Still open on step 1, not started: the Helm chart round ([016](016-helm-chart-fixes.md)),
the performance baseline
([021](021-relative-performance-thresholds.md)) with pre-release numbers. **021
must run before 013 lands** — the baseline needs pre-v2 numbers, and once the
format changes there is no "before" left to measure against (ADR 0020).

### On `feat/major-v5` — the bundle branch

Forked from `main` at `2727ecc`. Only design work so far, no code from 013 yet:

- **ADR 0003 amended** (D12a, D13a) — see [013](013-storage-format-v2.md) for
  what they decide and why.
- **The segment-codec API is designed** (013 item 1), recorded in
  [013](013-storage-format-v2.md) under "Codec API — design outcome".

### The 013 item 1 blocker is settled (2026-09-09)

Where the sealed plaintext CRC32C lives (ADR 0003 D13) was unresolved and blocking,
because D13 put the checksum in header-first metadata while the value only exists
at end-of-stream. **Settled 2026-09-09 (owner):** CRC32C in the 40-byte trailer
(ADR 0003 D13), served to the client as `x-amz-checksum-crc32c` on whole-object
GET and HEAD by a tail-first read (ADR 0003 D14), no configuration key; ranged
reads carry none and the read path stays open for a bounded one (ADR 0012). The
codec API and the trailer layout can be frozen; the details are in
[013](013-storage-format-v2.md) under "Decided 2026-09-09".

## Progress (2026-09-09)

Decision session, no code. The eight open questions of the bundle were taken one by
one with the owner and written into the ADRs the same day; each ticket carries its
work item. Delete this block when the rows below are all in flight.

| Decision | Recorded in |
|---|---|
| CRC32C in the 40-byte trailer; `x-amz-checksum-crc32c` on whole-object GET and HEAD, served tail-first, no configuration key; ranged reads none, path kept open | ADR 0003 D2/D6/D9/D12a/D13/D14, ADR 0012 D10, ADR 0010 D5; [013](013-storage-format-v2.md) items 1, 2d, 3, 5 |
| A `;` in the raw query is refused with `InvalidArgument` | ADR 0007 D13; [022](022-s3-surface-fidelity.md) item 23 |
| Every declared upload checksum is verified, `Content-MD5` included; no `verify_upload_digests` key; `DeleteObjects` requires a digest | ADR 0012 D3/D4/D14; [014](014-upload-checksum-verification.md), [015](015-configuration-hygiene.md) |
| `metadata_key_prefix` must match `^[a-z0-9][a-z0-9-]{2,}-$` | ADR 0009 D2; [015](015-configuration-hygiene.md) item 14 |
| `streaming_buffer_size` and `enable_adaptive_buffering` are deleted | ADR 0013 D9; [015](015-configuration-hygiene.md) items 3 and 8, [013](013-storage-format-v2.md) item 12 |
| No migration of any kind; data is uploaded again from its source; one proxy version at a time | ADR 0017 D3/D5/D6, ADR 0001 D5, ADR 0003 D10; release notes below |
| `optimizations.multipart_short_part_buffer_size`, default 64 MiB, minimum 5 MiB; copy refusal stays unconditional under `none` | ADR 0011 D5/D9, ADR 0020 D14; [013](013-storage-format-v2.md) items 9 and 12 |
| 4.0.x and earlier are end-of-life at 5.0.0; a version dry run on every pull request; the full performance baseline before 013 | ADR 0018 D6/D11, ADR 0020 D17; [021](021-relative-performance-thresholds.md), step 1 of the order |

Measured on 2026-09-09 (Apple M5 Pro, one core, 64 KiB blocks, Go 1.27, standard
library): AES-GCM seal 9.1 GB/s, open 9.3 GB/s; AES-CTR 11.9 GB/s; HMAC-SHA256
3.5 GB/s; CRC32 12.2 GB/s; CRC32C 11.6 GB/s; SHA-1 3.5 GB/s; SHA-256 3.4 GB/s; MD5
0.95 GB/s; CRC-64 2.4 GB/s. Per-segment GCM overhead at 64 KiB against 1 MiB: 0.3 %.

## Release notes — skeleton

Filled as each unit closes. Under a `BREAKING CHANGE:` footer.

**Stored data.** Objects written by 3.x and 4.0.x are not readable. Upload them again
from the source; there is no migration of any kind. `s3ep-aes-iv` and
`s3ep-hmac` are no longer written, `s3ep-dek-algorithm` is `s3ep-gcm-seg-v2`, and
`s3ep-kek-fingerprint` values change.

**Configuration — removed.** `encryption.integrity_verification`,
`optimizations.streaming_threshold`, `optimizations.clean_http_transfer_chunked`,
`optimizations.streaming_buffer_size`, `optimizations.enable_adaptive_buffering`,
`s3_backend.use_tls`, the dead `s3_security` keys, the legacy top-level backend
block, and the `rsa` provider type.

**Configuration — refuses to start.** A segment size that is not a multiple of
65536; a backend endpoint without a scheme, or `http://` under an encrypting
provider; an `aes_key` that is not base64 of 32 random bytes; a provider of type
`rsa`; a `metadata_key_prefix` shorter than four characters, not starting with a
letter or digit, or not ending in `-`.

**Configuration — new.** `optimizations.multipart_short_part_buffer_size`, bytes,
default 64 MiB, minimum 5 MiB: the memory the proxy may hold for short last parts of
client-driven multipart uploads across all sessions; size it against the container
limit. `s3_security.max_presign_expiry_seconds`, default 3600.

**Behaviour.** Whole-object `GET` and `HEAD` answer with an
`x-amz-checksum-crc32c` over the plaintext, recorded at upload, and `HEAD` reports
the authenticated plaintext length; a whole-object `GET` above 64 KiB costs the
backend two requests;
`InvalidObjectState` for objects the proxy did not write;
`InvalidPart` for unaligned client multipart; `InvalidArgument` for client
metadata inside the proxy prefix and for a query string containing `;`; `BadDigest`
or `InvalidDigest` for a wrong or malformed upload checksum of any algorithm,
`Content-MD5` included, and `InvalidRequest` for a multi-object delete without a
digest; pre-signed URLs above the configured ceiling refused; the configured clock skew applied to header authentication; storage
headers forwarded; SSE-C refused; no wall clock on a transfer.

**Deployment.** Values files lose the removed keys; pods carry `GOMEMLIMIT` and a
termination grace period derived from `shutdown_timeout`.

**Support.** 4.0.x and every earlier line receive no further releases of any kind;
5.0.0 is the only supported line (ADR 0018 D11).

**Migration.** There is none. Objects written by earlier versions answer
`InvalidObjectState`; delete them and upload the data again from its source. Run one
proxy version at a time: an object written by a 4.0.x replica during a mixed rollout is
refused afterwards like any other. An `rsa` deployment configures an `aes` key first.

## Done when

- [ ] Every row of "the minimum" is closed on the branch, and every candidate is
      either closed there or moved out with a line saying why.
- [ ] On the branch head: `make test-unit`, `make test-integration`,
      `make test-integration-tls`, `make e2e-up && make test-e2e-velero` green.
- [ ] **Upgrade rehearsal**, documented here once: a 4.0.x stack with objects in
      the backend, upgraded in place; a read of an old object answers
      `InvalidObjectState`; a fresh upload of the same content; the round trip matches
      by SHA-256.
- [ ] `grep -rn` for every removed key and for `type: "rsa"` returns only
      `CHANGELOG.md`.
- [ ] The final pull request carries the `release:major` label and the computed
      version is verified as `5.0.0` before the merge.
- [ ] Every ADR this release touches has its `Status` updated from "decided, not
      implemented" to what actually shipped, in the same pull request.
- [ ] Each ticket listed here is **deleted** when its work lands, and
      `git grep` shows nothing outside `docs/tickets/` referencing it.
