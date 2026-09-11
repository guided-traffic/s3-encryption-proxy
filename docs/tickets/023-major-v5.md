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

**Decided 2026-09-10: every ticket of this release is worked on the bundle branch.**
Nothing is split off to `main` any more — not the performance baseline, not the Helm
chart round, not the continuous-integration cleanup. The order below still says which
work comes first, but "on `main`" in step 1 now means "first on the branch", and the
single merge into `main` at the end carries all of it. The reason is plain: two live
branches for one release buys nothing and costs a merge conflict every time either
moves.

Commits land directly on `feat/major-v5`. Breaking markers are used freely there;
nothing releases from that branch. Rebase onto `main` whenever `main` moves; the
end-to-end suite is the gate on every rebase. The final pull request into `main`
carries the `release:major` label, and the computed version is checked before the
merge button.

## State (2026-09-11, after wave 5) — read this first

Waves 0 to 5 are done. **Every decision this release carries is implemented, and
every performance claim it makes is measured.**

**What is left:**

1. **The upgrade rehearsal**, in the "Done when" box: a 4.0.x stack with objects,
   upgraded in place, an old object answering `InvalidObjectState`, a fresh upload,
   a SHA-256 round trip.
2. **The release notes**, from the skeleton below — which wave 5 corrected in two
   places but has not rewritten.
3. **The label, last.** The final pull request carries `release:major` and the
   computed version is checked before the merge.
4. **The ADR status sweep** and the ticket deletions the "Done when" box asks for.

**Decisions still owed by the owner:**

- **Work item 9 of [016](016-helm-chart-fixes.md)**, the certificate/ingress
  consistency guard — the only thing keeping that ticket alive.
- **[024](024-coverage-round-findings.md) S-3**, the unauthenticated monitoring
  listener — the only row keeping that file alive, and a decision rather than work.
- **Open questions 2, 3 and 4** below: the memory bound, whether `GOMEMLIMIT`
  ships at all, and the exit provider's metadata leak (ADR 0008 D9).
- **Open question 5's three remaining client-visible leftovers**, unchanged since
  wave 2.
- **The bundled Grafana dashboard**: four of its seven panels query metrics this
  release removed. Rebuild it, or ship it as documented.

**Gates, on the branch head:** `go build`, `go vet`, `gofmt`, `make test-unit`,
`make lint` (0 issues), `make gosec` (0 issues), `make helm-test`,
`make test-integration`, `make test-integration-tls`,
`make test-integration-performance`, and `make test-e2e-velero` — 13 scenarios,
green twice against a cluster created from scratch. The graphify graph is behind
the tree and needs its own approved run.

**Out of scope, decided 2026-09-11:**
[027](027-whole-object-read-first-window.md), how large the first read of a
whole-object `GET` should be. It is an evaluation, not work.

## The minimum

Every row forces an operator to do something, or changes an answer a client gets.

| What ships | Decision | What the operator does |
|---|---|---|
| The segmented AES-256-GCM storage format | [ADR 0003](../adr/0003-objects-are-an-authenticated-segment-chain.md) | Upload every object again from its source. There is no migration and no read path for the old format |
| `encryption.integrity_verification` and `optimizations.streaming_threshold` removed; `streaming_segment_size` must be a multiple of 64 KiB | [ADR 0003](../adr/0003-objects-are-an-authenticated-segment-chain.md) | Drop the two keys; check the segment size or the proxy will not start |
| One local key provider: the `rsa` provider type is gone, `aes_key` must be base64 of 32 random bytes, the wrap becomes authenticated and the fingerprint derived | [ADR 0004](../adr/0004-one-local-key-provider.md) | Move any `rsa` provider to `aes` before re-uploading. Replace a key that is not 32 random bytes — including one delivered through `${S3EP_AES_KEY}`, which nothing in this repository can be grepped for |
| Client metadata inside the configured prefix is refused with `InvalidArgument`; the prefix must be at least four characters and end in `-` | [ADR 0009](../adr/0009-the-metadata-prefix-is-the-proxys-namespace.md) | Stop writing user metadata into the `s3ep-` namespace; rename a prefix that is shorter or lacks the trailing dash, no shipped value is affected |
| The dead `s3_security` keys, `s3_backend.use_tls`, `clean_aws_signature_v4_chunked`, `clean_http_transfer_chunked`, `streaming_buffer_size`, `enable_adaptive_buffering` and the legacy top-level backend block are deleted; a plain-HTTP backend under an encrypting provider and a scheme-less endpoint refuse to start; the pre-signed ceiling drops to one hour; the configured clock skew applies to both authentication forms | [ADR 0013](../adr/0013-a-configuration-key-exists-only-if-code-reads-it.md), [ADR 0014](../adr/0014-authentication-is-sigv4-no-rate-limiting.md) | Drop the keys from the configuration and the deployment values; switch the backend endpoint to `https://`; set `max_presign_expiry_seconds` if URLs above one hour are in use; check client clocks |
| An unknown configuration key refuses the start and the refusal names it | [ADR 0013](../adr/0013-a-configuration-key-exists-only-if-code-reads-it.md) D11, decided 2026-09-10 | Remove every key this release deletes from the configuration and the deployment values before upgrading — a leftover is now a startup error instead of silence. Fix a misspelled key the same way |
| The `none` provider becomes the **exit** provider: `type: "none"` is refused by name, the exit provider writes plaintext on every path and still decrypts what this proxy encrypted earlier | [ADR 0025](../adr/0025-leaving-is-a-supported-mode.md) | Rename the type to `exit`, and **keep the `aes` provider that holds the old key registered beside it** — without it the objects written before the switch stay unreadable. A deployment that never used `none` does nothing |
| Both listings answer an S3 document and report the plaintext size; `max-keys` outside its range is refused or clamped; `<Owner>` is the caller; `HeadBucket` answers `404` for a bucket that does not exist | [ADR 0010](../adr/0010-sizes-and-listings-describe-the-plaintext.md), [ADR 0008](../adr/0008-every-response-describes-the-proxy.md) | Nothing, unless a client parsed the old non-S3 document by its root element, relied on a listing size matching the stored bytes, or read `HeadBucket` as an existence check that always succeeded |
| The whole-request and whole-response wall clocks go; `shutdown_timeout` becomes the transfer budget and the chart derives its grace period from it | [ADR 0015](../adr/0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md) | Nothing, unless a deployment relied on a transfer being killed at 30 s |
| Storage headers on `PUT` are forwarded instead of silently dropped; the tagging, retention and legal-hold sub-resources become pass-through; `PUT ?acl` and `PUT ?cors` carry their documents to the backend; SSE-C is refused with a named error; a query string containing `;` is refused with `InvalidArgument` | [ADR 0007](../adr/0007-forward-it-or-refuse-it.md) | Check that a client which sets these headers meant them: they now take effect on the backend object. Nothing for the `;` rule unless a client sends one, and no known client does |
| The location element of a completed multipart upload honours `X-Forwarded-Proto` and `X-Forwarded-Host` | [ADR 0008](../adr/0008-every-response-describes-the-proxy.md) | Nothing |
| The example configurations and the end-to-end values lose their literal keys; keys are generated at bring-up | [ADR 0021](../adr/0021-key-material-is-generated-never-committed.md) | Export the key variables, or run the bring-up script |
| `GOMEMLIMIT` in the chart and in compose — **conditional, see open question 3**: ADR 0020 D15 makes it depend on a measured gain and none has been measured | [ADR 0020](../adr/0020-performance-is-measured-before-and-after.md) | Re-size the pod limits if the deployment overrides them, if it ships |

## Also in, and what stays out

Each of these changes an answer a client gets, so by the rule of
[ADR 0018](../adr/0018-a-major-release-is-declared-by-a-label.md) each belongs in
a major. Which major was left to judgement; the calls are below.

**In**, because the alternative is writing their tests twice or shipping a second
set of behaviour changes weeks later:

| Also in | Decision | Why here |
|---|---|---|
| Upload checksum verification | [ADR 0012](../adr/0012-client-checksums-are-verified-never-forwarded.md) | Its tests are written against configuration keys the format change deletes; on the current line they would be written twice |
| The listing document and plaintext sizes ([018](018-listobjectsv2-document.md)) | [ADR 0010](../adr/0010-sizes-and-listings-describe-the-plaintext.md) | The plaintext size is only a pure function of the stored size under the new format; the document rewrite touches the same responses and lands as one change |
| Conditional request headers on writes and reads ([019](019-handler-unit-coverage.md) item 12) | [ADR 0007](../adr/0007-forward-it-or-refuse-it.md) | A silent overwrite becoming a `412` is a behaviour change; it is blocked on the format change anyway |
| The auto-multipart producer overlaps receive with send ([012](012-performance-audit-round2.md) item 2.0) | [ADR 0024](../adr/0024-an-upload-forwards-while-it-receives.md) | Decided 2026-09-10. It rewrites the same write paths as 013 items 6 and 7; taken later it means writing and measuring that path twice. It forces nothing on an operator, which is why it is here and not in "the minimum" |

**Out**, each for its own reason:

| Out | Where instead | Why |
|---|---|---|
| The Helm chart round ([016](016-helm-chart-fixes.md)) | `main`, now | It closes a live deployment defect and gives continuous integration a render of the values files this release edits. Squash-merged under a non-breaking title |
| Filename encryption ([017](017-filename-encryption.md)) | A later release | Depends on the listing work and on a client-behaviour check that has not started. Enabling it later is a rename pass, not a re-encryption, so it costs an operator nothing to wait |
| Vault as a key provider ([025](025-tink-kms-hcvault.md)) | A later release | Parked: its own five decisions are deferred and recorded on the ticket. Purely additive, and with the local provider kept there is no gap at 5.0.0 |
| SSE-C on every verb ([026](026-sse-c-passthrough.md)) | A later release | Purely additive: a request that answers `501` today starts working |
| How large the first read of a whole-object `GET` is ([027](027-whole-object-read-first-window.md)) | Evaluated first, then a later release, or never | Owner decision, 2026-09-11. The tail-first read of ADR 0003 D14 ships as decided; whether its first window should be larger, configurable or left alone is a measurement nobody has taken. Changing it forces nothing on an operator, so it costs nothing to wait — and taken now it would be a memory-budget decision made from one run |

## Order

1. **First, and originally planned for `main`** (now on the branch, see above)**:** the release guard, the version
   dry-run check on pull requests (ADR 0018 D6, decided 2026-09-09), the Helm chart
   round, the metadata-prefix case fix, the pooled copy on the ranged read, and the
   **full pre-v2 performance baseline** ([021](021-relative-performance-thresholds.md),
   ADR 0020 D17) — recorded locally, on one machine, with the complete instrument set.
   **The baseline is done (2026-09-09); the Helm chart round is not started.**
2. **[013](013-storage-format-v2.md)** first on the branch — it deletes the code
   the others would otherwise be written against, and it is the largest change.
3. **[015](015-configuration-hygiene.md)** — after 013, so the example
   configurations and values files are edited once for both.
4. The client-visible corrections, in dependency order.
5. **The S3-surface ticket** — the storage headers and the location
   element.
6. The runtime memory limit last: the memory test of 013 is re-run under it, and
   if it shows no gain the value is dropped before the merge. **Measured 2026-09-09: no
   mechanism for a gain exists on this workload** — the proxy settles at 98 MiB against a
   512 MiB container limit, so a 400 MiB runtime limit is never approached. By this step's own
   rule the value is dropped; open question 3 asks whether it ships anyway as an
   out-of-memory guard, which would need ADR 0020 D15 amended.

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

Still open on step 1: the Helm chart round ([016](016-helm-chart-fixes.md)), not started.
The performance baseline of [021](021-relative-performance-thresholds.md) is **recorded**
(2026-09-09) — see the progress block below.

### On `feat/major-v5` — the bundle branch

Forked from `main` at `2727ecc`. As of that date, design work only — **overtaken 2026-09-09**,
see the block dated 2026-09-09/10: the branch now carries the segment codec:

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
| A `;` in the raw query is refused with `InvalidArgument` | ADR 0007 D13; the S3-surface ticket item 23 |
| Every declared upload checksum is verified, `Content-MD5` included; no `verify_upload_digests` key; `DeleteObjects` requires a digest | ADR 0012 D3/D4/D14; [015](015-configuration-hygiene.md) |
| `metadata_key_prefix` must match `^[a-z0-9][a-z0-9-]{2,}-$` | ADR 0009 D2; [015](015-configuration-hygiene.md) item 14 |
| `streaming_buffer_size` and `enable_adaptive_buffering` are deleted | ADR 0013 D9; [015](015-configuration-hygiene.md) items 3 and 8, [013](013-storage-format-v2.md) item 12 |
| No migration of any kind; data is uploaded again from its source; one proxy version at a time | ADR 0017 D3/D5/D6, ADR 0001 D5, ADR 0003 D10; release notes below |
| `optimizations.multipart_short_part_buffer_size`, default 64 MiB, minimum 5 MiB; copy refusal stays unconditional under `none` | ADR 0011 D5/D9, ADR 0020 D14; [013](013-storage-format-v2.md) items 9 and 12 |
| 4.0.x and earlier are end-of-life at 5.0.0; a version dry run on every pull request; the full performance baseline before 013 | ADR 0018 D6/D11, ADR 0020 D17; [021](021-relative-performance-thresholds.md), step 1 of the order |

Measured on 2026-09-09 (Apple M5 Pro, one core, 64 KiB blocks, Go 1.27, standard
library): AES-GCM seal 9.1 GB/s, open 9.3 GB/s; AES-CTR 11.9 GB/s; HMAC-SHA256
3.5 GB/s; CRC32 12.2 GB/s; CRC32C 11.6 GB/s; SHA-1 3.5 GB/s; SHA-256 3.4 GB/s; MD5
0.95 GB/s; CRC-64 2.4 GB/s. Per-segment GCM overhead at 64 KiB against 1 MiB: 0.3 %.

## Progress (2026-09-09, evening)

**The performance gate leaves continuous integration, and the pre-v2 baseline is
recorded.** Decided this session, written into
[ADR 0020](../adr/0020-performance-is-measured-before-and-after.md) the same day: a
before-and-after comparison is a local act on one machine; continuous integration
measures once, publishes, and never fails on a performance number; test series belong to
the local suite. D6, D7, D8, D10, D11, D12 and D17 are amended and D18 to D22 are added — the local
baseline suite, what it records about the machine it ran on, the shape of its output, and
the rule that nothing about performance is allowed to make the pipeline longer than the
value it returns there.

The suite is built and has produced the pre-v2 baseline that
[013](013-storage-format-v2.md) will be judged against. What remains of
[021](021-relative-performance-thresholds.md) is the continuous-integration leftovers of
the cancelled gate — a disarming switch with nothing left to disarm, a duplicate
measurement run, a shared-runner module-cache wipe, an uncleaned comparison bucket, and a
summary line that does not name what it measures. None of them block the branch.

**Step 1 is therefore down to the Helm chart round**
([016](016-helm-chart-fixes.md), not started), which blocks nothing, so
[013](013-storage-format-v2.md) can begin.

### What the baseline found, and where each finding now lives

The record is `perf-baseline/20260909T175340Z-9f3fbd1/` — `run.json`, `REPORT.md`, and a
hand-written `FINDINGS.md` that reads them. Six findings came out of it. **Read the block
below dated 2026-09-09/10 as well**: the second row of this table was followed up the next
day and its consequence turned out to be the opposite of what is written here.

| Finding | Consequence | Recorded in |
|---|---|---|
| The cipher alone is **3.4× faster** than the path it replaces. **The shipped codec, with its CRC32C, is 1.74× faster** — measured after item 1 landed, and the pre-v2 prediction for a serial checksum was 1.9×. The proxy's own profile agrees on where today's cost sits: SHA-256 is 17.3 % of samples against 5.2 % for AES-CTR | The format change is a performance gain on the crypto, but a much smaller one than the primitive suggests. It is **not** where the end-to-end win comes from | [013](013-storage-format-v2.md) success criteria |
| Upload falls from 72 % to 59 % of the direct backend at exactly the 5 MiB threshold and stays there; **download is already at parity** from 5 MiB up | **Superseded 2026-09-10.** The cliff is the auto-multipart producer, not the cipher and not the self-copy. See the findings below and item 2.0 of [012](012-performance-audit-round2.md) | [013](013-storage-format-v2.md), [012](012-performance-audit-round2.md) |
| At 1 MiB and 8 MiB ranges the proxy is at 86–103 % today and an **unaligned offset costs nothing**, because AES-CTR seeks to any byte | The one row the segment chain can plausibly make worse. It now has a "before" | [013](013-storage-format-v2.md) |
| The proxy's **GET request rate does not scale with client concurrency** — flat at roughly 1770–2360 ops/s while the backend reaches 8300 | Not this release's to fix, but it is what any small-object number will be dominated by | [012](012-performance-audit-round2.md) item 6.3 |
| Settled resident memory is **98 MiB against a 512 MiB limit** (peak under load 124 MiB, cold 22 MiB), so the planned 400 MiB runtime limit — roughly 80 % of the container limit, not yet set in the chart or compose — is never approached | The predicted 3–5 % gain from `GOMEMLIMIT` has no mechanism on this workload. It may ship as an out-of-memory guard claiming no throughput benefit — the last row of "the minimum" above should be read with that in mind | ADR 0020 residual risks |
| An RSA-4096 unwrap is **3.8 ms** against 146 ns for AES-256 | The measurement behind dropping the `rsa` provider type | [013](013-storage-format-v2.md) item 15 |

One defect and one asymmetry were found in passing, neither in this release's scope: the
defect is that `HeadBucket` answers 200 for a bucket that does not exist
([018](018-listobjectsv2-document.md)); the asymmetry is that the proxy accepts an
aws-chunked chunk above 16 MiB that the backend refuses, which is a consequence of the proxy
re-framing the body and is recorded in the suite's own README.

## Progress (2026-09-09/10) — the codec is in, and the performance case changed

Two sessions. The first built the local baseline suite and recorded the pre-v2 numbers; the
second implemented the segment codec and spent the rest of the time finding out that the
performance story this release was sold on is not the one the measurements support. All three
recorded runs live under `perf-baseline/`, each with a hand-written `FINDINGS.md` beside its
generated report.

### What landed

- **The local performance baseline suite** and the decision behind it
  ([ADR 0020](../adr/0020-performance-is-measured-before-and-after.md), amended: the gate leaves
  continuous integration, comparisons are local, D18–D22 added). What remains of
  [021](021-relative-performance-thresholds.md) is continuous-integration cleanup that blocks
  nothing.
- **[013](013-storage-format-v2.md) item 1, the segment codec**, on the branch: format and
  associated data, trailer, size functions, writer, sequential reader, window planner, ranged
  reader. 30 tests, `gosec` clean, mutation-tested.
- **Two instruments that did not exist**: the backend self-copy harness and the three-leg upload
  path comparison. Both were written to answer a question this release turns on.

### Findings, in the order they change the release

**1. The upload deficit is a handler structure, not the crypto.** This is the finding that
matters most and it was not what anyone expected.

| Size | direct backend | proxy, streaming write path | proxy, auto-multipart |
|---|---:|---:|---:|
| 8 MiB | 164.9 MiB/s | **173.5 (105 %)** | 97.4 (59 %) |
| 12 MiB | 165.8 MiB/s | 172.8 (104 %) | 95.3 (57 %) |
| 16 MiB | 165.1 MiB/s | **184.4 (112 %)** | 115.3 (70 %) |

A proxy that streams is **faster than the backend it writes to**, while encrypting every byte and
crossing loopback twice. The auto-multipart producer reads a whole part into one reused buffer,
encrypts it synchronously, and only then queues it — receiving and sending are serial. Of the
33.6 ms gap at 8 MiB (82.2 ms against 48.5 ms direct), the integrity pass is 7.7 %, the
post-completion self-copy 4.9 %, and the write path the remaining 87 %. **What in the write
path is not attributed:** the single-part uploads are the worst rows and the two-part one is
better, so per-part pipelining is not it. Filed as item 2.0 of [012](012-performance-audit-round2.md).

**2. The self-copy hypothesis was wrong.** The session before had modelled the deficit as the
post-completion rewrite and derived that it would have to run at 231–372 MiB/s. Timed, it runs at
4826–7485 MiB/s. A model that fitted three measured points, and was wrong. Recorded as a
consequence in ADR 0020, because it is exactly the failure the measurement rules exist to catch.

**3. The codec is 1.74× the path it replaces, not 3.4×.** The design case was argued on the
cipher; the shipped codec carries the trailer's CRC32C, which the model never ran. The pre-v2
baseline had predicted 1.9 × for a serial checksum. **The checksum stays** (owner, 2026-09-10,
with the number in hand) — integrity is why the format exists and it is still a speed-up.
Recorded in ADR 0003's consequences.

**4. The first codec was no faster than what it replaces, and the tests did not notice.** Two
implementation choices — a per-segment checksum fold and a copy of every byte into the writer's
pending buffer — cost the entire gain. And the first test suite passed everything on the first
run while **four of eight deliberate defects survived**: the segment index could be dropped from
the associated data, both halves of the trailer check could be deleted, and the trailer's
reserved index could be collapsed onto segment 0, all without a red test. A ninth mutation, a
constant nonce, survived even the strengthened suite until a nonce-uniqueness test was added.
All fourteen are caught now.

**5. Two ADR uncertainties are settled.** The backend clamps a range whose end lies past the
object and answers a suffix range larger than the object with `206` and the whole object; a range
starting at the end is `416` (ADR 0003 residual risks). And `GOMEMLIMIT`'s predicted 3–5 % gain
has no mechanism on the measured workload: the proxy settles at 98 MiB against a 512 MiB limit
(ADR 0020 residual risks).

### What this means for 5.0.0

| Question | Where it stands |
|---|---|
| Does the format change make uploads faster at the edge? | **Not by itself.** It deletes the self-copy (≈4 % of the gap) and removes the reason parts must be encrypted in sequence, but the producer's shape is a handler structure the format change alone does not touch. **Decided 2026-09-10:** the restructuring joins the release ([ADR 0024](../adr/0024-an-upload-forwards-while-it-receives.md)), inside 013 items 6 and 7 |
| Does it make the crypto faster? | Yes, 1.74× as shipped, and that is worth about +2 % end to end |
| Does it make downloads faster? | No, and there is no room: the proxy is already at parity |
| Is the release still worth cutting? | **Yes, on its own terms.** Every row of "the minimum" is a correctness, integrity or configuration change. Performance was never the reason for this release; it was an expectation attached to it, and the expectation is now measured instead of assumed |

**The release notes must not claim an upload speed-up** until the producer is restructured **and**
the three-leg comparison has been re-run and has moved (ADR 0024 D7). The restructuring is in the
release since 2026-09-10; the claim still waits for the after-column. Written into the notes
skeleton below.

### Open questions for the owner

1. ~~**Does the producer restructuring join 5.0.0?**~~ **Decided 2026-09-10 (owner): yes.** It is
   folded into [013](013-storage-format-v2.md) items 6 and 7, which rewrite those paths for the
   format change anyway, and the rule it follows is
   [ADR 0024](../adr/0024-an-upload-forwards-while-it-receives.md): an upload forwards while it
   receives, a part is retained until the backend acknowledges it, and no speed-up is claimed
   until the three-leg comparison has been re-run and moved. See "The measurement that decided
   it" below.
2. **Is the memory bound of ADR 0020 D14 pickable from this data?** The figure it would assert on
   is the noisiest measurement in the whole record (60.8 % spread, samples between 0 and 49 MiB).
   A bound picked from it will be loose enough to be meaningless, or tight enough to flake.
3. **Does `GOMEMLIMIT` still ship?** ADR 0020 D15 makes it conditional on a measured gain, and
   there is no mechanism for one on this workload. Shipping it as an out-of-memory guard with no
   throughput claim is the honest form — but that changes what D15 says, so it is an ADR
   amendment, not just a wording change. Until it is decided, "the minimum" above, step 6 of the
   order and the release-notes skeleton all state it conditionally.

### The measurement that decided open question 1 (2026-09-10)

The recorded three-leg run stops at 16 MiB, because the **direct** leg cannot carry a larger
single `PutObject` — the backend refuses an aws-chunked chunk above 16 MiB. Both proxies re-frame
towards the backend, so the two proxy write paths can be compared with each other above that
bound; verified the same day by putting 24 MiB through each. Ad hoc, three to five repetitions,
on battery, medians:

| Size | Parts | Streaming write path | Auto-multipart | Factor |
|---|---:|---:|---:|---:|
| 8 MiB | 1 | 174.0 MiB/s | 88.8 | **1.96×** |
| 24 MiB | 2 | 178.1 | 110.8 | 1.61× |
| 64 MiB | 6 | 197.3 | 127.6 | 1.55× |
| 128 MiB | 11 | 194.4 | 135.7 | 1.43× |
| 256 MiB | 22 | 198.9 | 137.6 | 1.45× |

The 8 MiB row reproduces the recorded run's streaming leg to within 0.3 %, which is what makes
the rest of the column worth reading. At 256 MiB the three extra backend round trips are
amortised to a few percent, the self-copy is 6 % of the gap and the integrity pass 14 %, and the
deficit still stands at 1.45× — **so what is left is per byte, not per request**, and it is the
producer's serialisation. That is the evidence behind
[ADR 0024](../adr/0024-an-upload-forwards-while-it-receives.md).

These sizes now live in the three-leg instrument (with the direct leg dropped above 16 MiB), so
the "before" column of the restructuring is recorded with the full repetition count rather than
taken from this table.

## Progress (2026-09-10, evening) — every gate green, the release's work is now deletion and documentation

The format is live on every path and **all gates pass on HEAD**: `make test-unit`,
`make test-integration`, `make test-integration-tls`, `make lint` and `gosec`.
[013](013-storage-format-v2.md) carries the detail; this is what changed about
the release itself.

**Four defects found and fixed after the format landed**, none of them in the
plan. Two in the client-driven multipart path — the part layout depended on
which part arrived first, and Complete never checked the client's part list. One
on the read path — a wrapped key that fails its tag answered 500, so an SDK
retried a read that can never succeed. And one that is not the proxy's runtime at
all: **the license token was baked into every locally built container image**,
because the build context excluded neither `config/` nor the token. All four are
recorded in the ADRs that own them (0011, 0003 D10a, 0016, 0021).

**The metadata namespace is now exclusive.** The read path had accepted
unprefixed key names as backward compatibility for a format this release cannot
read anyway — and those names sit outside the filter that keeps a client out of
the proxy's namespace. ADR 0001 D5 and ADR 0009 D1 both claimed exclusivity; now
it is true.

**The documentation describes what ships.** `README.md`,
`SECURITY_ARCHITECTURE.md` and all 21 ADR status blocks were rewritten against
the tree — sixteen of them still described the state before this release, several
in the future tense for work the release had already gone past. A new
`docs/developer/` holds the subsystem overviews that had been accumulating in
`README.md` for want of anywhere else to keep them.

### What the release still owes

Everything below is decided and unbuilt, and since this is one bundle it is all
release-blocking. Ordered by how much it costs a client to live without:

1. **The listing document and plaintext sizes** (ADR 0010, [018](018-listobjectsv2-document.md)).
   Every size-comparing client re-transfers its whole dataset on every run. The
   reason this waited — that the plaintext size was not computable from the
   stored size — is spent: it is arithmetic now.
2. **The deletions** (ADR 0013, [015](015-configuration-hygiene.md), 013 items
   12–14). Two dead keys are *security* settings, and the previous format's
   decrypt path still compiles.
3. **Client checksum verification** (ADR 0012).
4. **The storage headers a PUT drops, and six refusals that answer plain text
   with no S3 error code** (ADR 0007, ADR 0008, the S3-surface ticket).
5. **`ListParts` from the part table** (ADR 0011 D6, 013 item 10) — it currently
   tells a client verifying its own upload that it has no parts.
6. **The hard-coded 30-second shutdown deadline** that overrides
   `shutdown_timeout` (ADR 0015 D4).
7. **The after-column for the performance work** (013 item 15) and **the Velero
   e2e gate**, which has not run since the format landed.
8. **Release notes and the upgrade rehearsal** (ADR 0017). The break is made; what
   proves it to an operator is not.

### Two decisions still open

- **ADR 0003 D9.** "No range costs a second backend request" holds for an
  explicit `bytes=a-b`; a suffix or open-ended range costs a `HEAD` first.
  Correct the sentence, or close the gap inside item 2d, which builds the tail
  window anyway.
- **Item 15's shape.** The recommendation is to measure the release as a whole
  and attribute nothing to ADR 0024 alone, because the format change, the
  producer restructuring and the self-copy removal are in one commit. The
  alternative — a switch in the product to serialise the producer for the
  measurement — costs code that has to come back out.

## Progress (2026-09-10, afternoon) — the format is live

[013](013-storage-format-v2.md) items 1, 2, 2b, 2c, 3, 4, 5, 6, 7, 7a, 8, 9 and 11
are done and on the branch. The proxy writes and reads the segment chain on every
path; the demo stack runs on it. Unit tests and `gosec` are green, and the
integration suites are green except the eleven multipart and single-part tests
that still assert the old format. [013](013-storage-format-v2.md) carries the
detail, the four defects the session found, and the order of what is left.

**Two things that change what this release says about itself:**

- **The producer restructuring is in** (ADR 0024). The measured deficit turned out
  to sit in a place the ADR did not name: the old producer encrypted each part
  itself before queueing it, so receiving and sending could never overlap. It now
  reads plaintext into a bounded pool of buffers and the upload workers seal while
  they send. **The three-leg comparison has not been re-run yet**, so no upload
  claim may be made — that is item 15 and the recorded before-column is
  `perf-baseline/20260910T090543Z-530472c/`.
- **A ranged read is one backend request only for an explicit `bytes=a-b`.** A
  suffix or open-ended range needs the object's length first and costs a HEAD
  ahead of the GET. ADR 0003 states one request without that qualification and
  needs the correction.

### Next steps, in order

1. **[013](013-storage-format-v2.md) item 2d — the sealed checksum on the write paths.** The
   codec already produces and verifies the trailer; this wires the per-part fold for the
   client-driven path and the tail-first read for `HEAD` and whole-object `GET`. It is the next
   item with no open decision in front of it.
2. **013 items 2, 2b, 3, 4** — the metadata set, the raw-key fallback removal, the read path, and
   the none-provider pass-through rule. Item 4 carries the forged-fingerprint hole that v2 opens
   if it is not closed.
3. **013 items 6 and 7 — the write paths, with the producer restructured**
   ([ADR 0024](../adr/0024-an-upload-forwards-while-it-receives.md), decided 2026-09-10). Record
   the three-leg comparison before the first line changes and again after, on the same machine
   and the same power source.
4. **013 item 5 — the ranged read path.** Call the codec's window planner rather than re-deriving
   the window; the note is on the item.
5. **[016](016-helm-chart-fixes.md), the Helm chart round**, on `main` whenever convenient. It
   blocks nothing and nothing blocks it.
6. **[021](021-relative-performance-thresholds.md)'s continuous-integration cleanup**, likewise.

**Convention adopted this session:** every crypto-carrying item gets a mutation round before it
is called done. A green suite on freshly written cipher code is not evidence — item 1 proved that
on itself.

### State of the branch

**Updated 2026-09-10.** The v5 work is committed: the local baseline suite, the ADR 0020
amendment, the segment codec, and the recorded runs with their findings. `go build`, `go vet`,
`gofmt` and `go test -short ./...` are clean on the branch head. `golangci-lint` is **not
installed on this machine**, so `make lint` fails for that reason rather than for a finding. The
knowledge graph under `graphify-out/` does not know about `test/perf/`, the codec or ADR 0024 and
is behind by that much.

## Progress (2026-09-10, second evening session) — the deletion round, and the breaking-change sweep

Two things happened. The release's deletion debt was paid in full, and every
open ticket was audited item by item against the tree so that no breaking change
is left outside this bundle.

### The deletion round

A reachability analysis over the proxy binary reported **206 unreachable
functions**. It now reports **none**. Production Go fell from 17,715 to 12,355
lines; `gosec` covers 75 files and reports nothing.

What went, and why it was dead: the previous storage format's entire
implementation. The HMAC and HKDF package, the envelope encryptor, the AES-CTR
and AES-GCM data encryptors, the single-part and multipart orchestration, the
streaming readers, the ranged-read entry points, the object metadata handler,
the Tink stub and its module dependency. With them went every configuration key
no code reads: `encryption.integrity_verification` and the four integrity modes,
`optimizations.streaming_threshold`, `streaming_buffer_size` and
`enable_adaptive_buffering`, `s3_backend.use_tls`, the six dead `s3_security`
keys, and the whole legacy top-level backend block with its migration. The
example configurations, the production values file and every affected test went
with them.

Also removed because nothing called them: 17 methods of the backend interface,
13 Prometheus metrics that were registered and never observed, and the dead
accessors on `Config`, `Manager`, `MetadataManager` and `ProviderManager`.

This closes [015](015-configuration-hygiene.md) items 1, 3, 7, 8 and 13a,
[013](013-storage-format-v2.md) items 13 and 14 and the deletion half of item 12,
[025](025-tink-kms-hcvault.md) work-list item 1, [012](012-performance-audit-round2.md)
item 1.3, and the `CS-2`, `CS-3` and `S-4` findings of
[024](024-coverage-round-findings.md).

### Two things that were not deletions

**A leak, found while pruning.** The background cleanup goroutine that
`optimizations.multipart_session_cleanup_interval` and
`multipart_session_max_age` configure was sweeping the *previous* format's
session map, which has been empty since the segment chain landed. The live
session map had a sweeper that nothing called. A client-driven multipart upload
that was neither completed nor aborted therefore stayed in memory for the life
of the process, holding its buffered short parts — up to
`optimizations.multipart_short_part_buffer_size` per session — and its data key.
The goroutine now sweeps the live map, and the manager's shutdown is wired into
the proxy's shutdown path so it actually stops. **This is the one behaviour
change in the round that is not a deletion, and it is a memory and key-material
fix, not a refactor.**

**The attacker-controlled failure map is gone.** Deleting the rate-limiting
knobs took the per-IP failed-attempt map with them. That map was keyed by
`X-Forwarded-For`, never expired, and drove a brute-force log line that compared
against a hard-coded 5. The security log line stays; it now records the peer
address and the raw `X-Forwarded-For` header as two separate fields instead of
collapsing them into one value a client chooses. This is what
[ADR 0014](../adr/0014-authentication-is-sigv4-no-rate-limiting.md) decided, and
it closes the `H-7` entry of `SECURITY_ARCHITECTURE.md`.

### Gates

On this tree: `go build`, `go vet`, `gofmt` and `go test -short ./...` clean;
`make test-integration` and `make test-integration-tls` green against a rebuilt
demo stack (130 tests, one expected skip — the aws-chunked trailer only appears
over TLS); `gosec` 0 issues. The three build-tagged suites vet clean.
**`make e2e-up && make test-e2e-velero` has not been run since the format landed
and is still owed.**

### The breaking-change sweep

Every open ticket was verified item by item against the tree. The finding that
matters for this release: **four breaking changes were sitting outside the
bundle**, and the rule that a breaking change belongs to a major means each
needs an answer here rather than in its own ticket.

| Where it sat | What it is | Answer |
|---|---|---|
| [016](016-helm-chart-fixes.md) items 6 and 9 | The chart round was scheduled out of the bundle, but two of its items are breaking: item 6 flips a default install's metadata prefix, and every object already stored then reads back as `InvalidObjectState`; item 9 is the certificate/ingress consistency guard, which refuses a configuration that installs today | **Recommended: the two items move into the bundle**, the rest of the chart round stays out. Not yet decided by the owner. Item 6 has to move `metadata_key_prefix` without changing the shipped default, or it is a data-loss change dressed as a chart fix |
| [025](025-tink-kms-hcvault.md) work-list 1 | Deleting the Tink stub removes a provider type an operator can write today | **Done this session.** The type is gone from the tree and from `go.mod`; configuration still refuses `type: "tink"` with a named error |
| [024](024-coverage-round-findings.md) X-2a | `WriteXML` commits `200` before marshalling can fail, so a marshalling failure reaches the client as a truncated body behind a success status. Fixing it turns that into a `500` | **Recommended: in.** It is one function, it sits in the same file the listing rewrite of [018](018-listobjectsv2-document.md) touches, and shipping a truncated body behind a `200` into a major that rewrites every XML document would be hard to defend. Not yet decided by the owner |
| the S3-surface ticket's unfolded item 3 | Two XML writers produce different bytes for the same structure; unifying them changes the response bytes of roughly twenty bucket sub-resource documents | **Open question 4 below.** The ticket says "record it, do not start it here", but a byte-level response change is exactly what a major is for, and the next major after this one is unscheduled |

Two further breaking items resolve themselves and need no decision:

- [026](026-sse-c-passthrough.md) item 1 (SSE-C forwarding) is breaking **only**
  measured against today's tree, where an SSE-C `PUT` is answered `200` and the
  headers are dropped. Measured against a 5.0.0 that ships the refusal of
  [ADR 0007](../adr/0007-forward-it-or-refuse-it.md) — item 22 of
  the S3-surface ticket, which is already in the minimum — it is
  purely additive: `501` becomes `200`. It stays out, and the reason is now
  recorded rather than assumed.
- [017](017-filename-encryption.md) contains no breaking item at all: the feature
  is opt-in and ships disabled ([ADR 0023](../adr/0023-filename-encryption-encrypts-directory-segments.md) D1).
  It stays out on its own merits.

### What the release still owes, verified against the tree

Ordered by what it costs a client. Every row was checked in the code, not read
off a ticket's status line.

1. ~~**The listing document and plaintext sizes**~~ **Landed 2026-09-10**
   ([ADR 0010](../adr/0010-sizes-and-listings-describe-the-plaintext.md)). Both
   object listings and `ListBuckets` answer an S3 document, `<Size>` is the
   plaintext size, `max-keys` is honoured and `HeadBucket` calls `HeadBucket`.
   [018](018-listobjectsv2-document.md) keeps only the listing benchmark and the
   Velero run.
2. **The S3 surface** (the S3-surface ticket,
   [ADR 0007](../adr/0007-forward-it-or-refuse-it.md),
   [ADR 0008](../adr/0008-every-response-describes-the-proxy.md)). Sixteen of 24
   entries untouched: the whole forwarding half, the `;` refusal, the
   `<Location>` fix, and the key material still in the example configurations.
3. **Client checksum verification**
   ([ADR 0012](../adr/0012-client-checksums-are-verified-never-forwarded.md)).
   Nothing of the verification exists; a wrong `Content-MD5` is still answered
   `200`.
4. **The rest of [015](015-configuration-hygiene.md)**: the clock skew that the
   header-signed path ignores, the pre-signed ceiling, the plain-HTTP backend
   refusal, and the prefix shape rule. The deletion half is done.
5. **[013](013-storage-format-v2.md)'s remainder**: the sealed checksum on the
   read side (item 2d), the write-side prefix refusal (4a), `ListParts` from the
   part table (10), the size function everywhere (11), and the performance
   after-column (15).
6. **The 30-second wall clocks** ([ADR 0015](../adr/0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md)),
   which still kill any transfer slower than they are.
7. ~~**The Velero end-to-end suite**, unrun since the format landed.~~
   **Green in continuous integration, verified 2026-09-11.**
8. **Release notes and the upgrade rehearsal** ([ADR 0017](../adr/0017-stored-data-compatibility-is-not-owed.md)).

### Open question 4 for the owner

**Does the XML-writer unification join 5.0.0?** Two writers produce different
bytes — declaration and indentation — for the same structure, across roughly
twenty bucket sub-resource documents. Unifying them is client-visible, so it
belongs in a major; the next one after this is unscheduled, and
[018](018-listobjectsv2-document.md) is about to touch the same code. The
argument against is scope: it is not a defect, only an inconsistency.

### Not fixed, and named so it is not mistaken for fixed

- **An unknown configuration key is still accepted in silence** — but no longer
  left that way. The loader is unmarshalled without `ErrorUnused`, so a
  misspelled or removed key is dropped without a word, which is why a
  configuration carrying the deleted legacy backend block fails with nothing but
  "s3_backend.target_endpoint is required" and names no migration path.
  **Decided 2026-09-10 and taken into this release** as
  [ADR 0013](../adr/0013-a-configuration-key-exists-only-if-code-reads-it.md) D11;
  the work sits in [015](015-configuration-hygiene.md). Measured before deciding:
  three of the four shipped examples pass unchanged, and the fourth was refused
  because it carried a `streaming.segment_size` block no code has ever read —
  now removed.
- **`optimizations.clean_http_transfer_chunked` was left in place.** Unlike the
  keys deleted above it has a live reader, so removing it is a behaviour
  decision rather than a deletion. It belongs to item 2.2 of
  [012](012-performance-audit-round2.md).
- **`WriteRawXML` and the mock ACL and CORS documents were left in place.** They
  have live callers today; they disappear when the forwarding half of ADR 0007
  lands, not before.
- **`go build -tags=perf ./test/perf/...` fails**, and failed before this round:
  a non-test file uses constants declared in a `_test.go` file. `go vet -tags=perf`
  and `go test -tags=perf` are the real gate and both are clean.

## Progress (2026-09-10, night) — the listing ships, and leaving becomes a supported mode

Two units landed, and the second one was not on any list: it came out of a
question about what the `none` provider was for.

### The listing (ADR 0010)

The highest-value item the release owed is done. Both object listings and
`ListBuckets` answer a real `ListBucketResult` under the S3 namespace, `<Size>`
is the plaintext length, the dropped parameters are forwarded, `max-keys` is
honoured, `<Owner>` names the calling client rather than the backend account,
and `HeadBucket` calls `HeadBucket` — so a bucket that does not exist answers
`404` instead of the `200` a `ListObjectsV2(MaxKeys: 0)` produced.

**Three planning assumptions were wrong, and the plan caught them** because it
said to capture a real response before locking the assertions down: the element
order differs from the API reference in three places, the backend does **not**
clamp `max-keys` above 1000 — so the clamp is the proxy's own behaviour and a
deliberate deviation — and `max-keys=0` answers `IsTruncated` false rather than
true. The measurements are recorded on [018](018-listobjectsv2-document.md).

### Leaving is a supported mode (ADR 0025)

The `none` provider was supposed to be the way out and was the opposite. It
needed no licence and passed writes through, but it passed **reads** through
too, without looking at the object's metadata — so the one mode meant for
leaving was the mode in which everything encrypted before the switch came back
as raw ciphertext.

It is now the **exit** provider: no licence, plaintext on every write path, and
it keeps decrypting what this proxy wrote earlier, because the object's own key
fingerprint names the provider that wrapped it. The decision is per object, so a
bucket on the way out holds both and both work. `type: "none"` is refused by
name.

**Two defects closed with it**, both found while asking what the provider meant:

- The pass-through was honoured on the single-request write path only. Under
  `none` an object above one part, and every client-driven multipart upload, was
  stored as a segment chain **with its data key in the clear beside it** — a
  bucket that looked encrypted while the key sat next to the object.
- The read path took the pass-through unwrap whenever *object metadata* named
  that fingerprint, whatever the configured provider was. A backend could choose
  a data key, store it verbatim, seal any plaintext under it, and every segment
  would authenticate: a forgery the client could not distinguish from a real
  object. It is closed by construction now — no fingerprint is special-cased on
  the read path and the exit provider refuses to unwrap at all.

### What it cost, and what it did not

A ranged read pays one extra `HEAD` **under the exit provider only**, because
the stored window of an encrypted object is not the plaintext range and the
proxy has to know which kind of object it is before it asks. Under an encrypting
provider an explicit range still costs a single backend request (ADR 0003 D9).

A listing keeps reporting the stored size under the exit provider. Inverting the
arithmetic would be exact for the objects encrypted before the switch and would
under-report some plain ones, and a synchronising client that believes the remote
copy is short may write over it; over-reporting only costs a re-transfer.

### Gates

`go build`, `go vet`, `gofmt` and `go test -short` clean; `make test-integration`
and `make test-integration-tls` green against a **rebuilt** demo stack, 132
tests; `gosec` 0 issues over 79 files. ~~The Velero end-to-end suite still has
not run since the format landed.~~ **Corrected 2026-09-11: it has, and it is
green** — the `Velero E2E (kind)` job succeeded on this branch in the two most
recent pipeline runs, after both the format and the listing landed.

### Found and left open, deliberately

- An object whose fingerprint names the exit provider is refused with `500
  DecryptionError` rather than the `403 InvalidObjectState` an unreadable wrap
  gets. The refusal is right; the status class is wrong for a permanent state.
- The pass-through ranged read answers a range that covers the whole object with
  `206` and no `Content-Range`. Pre-existing, pinned by a test.
- `HeadBucket` does not forward `x-amz-expected-bucket-owner`, so a client using
  it as a guard against a re-created bucket is not guarded.
- `ListBuckets` serialises a bucket with no creation date as the Go zero time.
- `KeyCount` in a listing is forwarded from the backend rather than counted, so
  a backend that miscounts is repeated.

## Progress (2026-09-11) — the release is audited item by item, and Wave 0 lands

Two things happened. Every open ticket and every ADR was verified against the
tree by a fan-out of twenty-four agents, each claim then checked adversarially
by a second agent, and the result is that **no item reported open was in fact
implemented** — but eleven items nobody had recorded were found, several ticket
status lines are wrong in the release's favour, and the release's own progress
blocks were wrong about the oldest gate. Then the first wave of work landed.

### Owner decisions taken this session

- **ADR 0003 D14 ships in 5.0.0.** The tail-first read and `x-amz-checksum-crc32c`
  on whole-object `GET` and `HEAD` are in the release, not deferred. The cost is
  accepted: a whole-object read above one segment becomes two backend requests.
  The gain that decided it is not the header but the length — `HEAD` reports a
  plaintext size derived from the backend's own `ContentLength` today, and under
  ADR 0001 that is an adversary's number; the trailer's is authenticated.
- **ADR 0015 D8 falls.** The request and response body budgets become
  configuration keys with a default of `0`, meaning unbounded, so D1 remains the
  shipped promise. The header budget and the idle budget keep today's values and
  become configurable with them. D8's "no new configuration key" is amended in the
  same change as the code; D1, D2 and D3 are untouched.

### What landed

- **`make lint` is green again.** It had been red on this branch since the listing
  commit, on an unused constant, and CI's `Code Linting` job failed on every push.
  Nobody saw it because `make tools` installed golangci-lint from the **v1** module
  path, whose binary refuses this repository's v2 configuration — so no developer
  could run the gate at all. Both are fixed, and the Makefile now pins the same
  coordinate CI installs with the reason written beside it.
- **The `;` query bypass is closed** (ADR 0007 D13). It was reproduced over the
  wire first: a signed `PUT /b/k?partNumber=abc;uploadId=u` answered `200` and
  replaced the object, because `net/url` drops the segment while the router splits
  on the character. The refusal sits between authentication and the handlers, so
  the parser and the router can never disagree about a query any handler sees.
- **No usable key is tracked any more** (ADR 0021). This was worse than the ticket
  said: the Containerfile copies `config/` into the final image, so **every
  published image carried a working 256-bit key**, and an operator starting the
  image with a shipped example encrypted under a key everyone has, silently and
  correctly. A generator now writes the key into the ignored `.env` and is called
  by the demo bring-up, the e2e bring-up, continuous integration and the two
  monitoring make targets. Two things nobody had listed: the chart had never wired
  the variable its own values referenced, so a default install could not start; and
  the integration suites that build a proxy in-process load `.env` themselves.
  **The published keys stay published** — D7 applies to anyone who ran under them.
- **Eleven ADR status blocks corrected.** 0003, 0011 and 0017 all said the
  segment-size alignment check was unbuilt; it landed on 2026-09-10. 0009 still
  described the unprefixed read fallback that is gone, contradicting 0001. 0008 and
  0006 still counted the listing as outstanding. 0019 D16 and 0022 named residue
  that is no longer in the tree — 0022's "worst of the set, a work-tracking label in
  a shipped example configuration" does not exist and could not be reproduced
  anywhere. 0010's index row said *Partly built* for work that shipped.

### Corrections to this ticket's own record

- **The Velero end-to-end suite is not the oldest unpaid gate. It is green.** The
  `Velero E2E (kind)` job succeeded on this branch in the two most recent pipeline
  runs, after both the format and the listing landed. Three places in this file said
  otherwise.
- **Both release guards already compute `5.0.0`** and both fail only because pull
  request #343 does not carry the `release:major` label. That is the guard working,
  not a defect, and the "Done when" box that asks for the computed version to be
  verified is satisfied on substance. The label goes on before the merge, not now:
  putting it on early spends the last check the release has.
- **The `Done when` grep gate cannot pass as written.** "returns only
  `CHANGELOG.md`" is unachievable, because the removals are deliberately documented
  in the README, the security architecture, this file and eleven ADRs. It needs
  rewording to a scoped grep over configuration, chart values and code.

### The scale of what is left, measured rather than estimated

About forty-five confirmed breaking items across eight tickets, and twelve ADRs
carrying decided-but-unbuilt rules. Ordered as the work will be taken:

| Wave | Content | State |
|---|---|---|
| 0 | Lint, the `;` refusal, key material, the stale ADR statuses | **Done 2026-09-11** |
| 1 | Configuration and startup: [015](015-configuration-hygiene.md) items 2, 4, 5, 6, 8b, 9, 10, 14, 15, and the wall clocks and shutdown deadline (ADR 0015, [012](012-performance-audit-round2.md) items 1.2 and 4.1) | **Done 2026-09-11.** [015](015-configuration-hygiene.md) has one item left, its own verification pass |
| 2 | The S3 surface: the S3-surface ticket and [024](024-coverage-round-findings.md) as **one** package — they overlap so heavily that splitting them creates the ownership holes below | **Done 2026-09-11.** 022 is deleted; 024 keeps one row, S-3, which needs a decision |
| 3 | Client checksum verification (ADR 0012) — nothing of it exists | **Done 2026-09-11.** 014 is deleted; two pre-existing defects were found on the way in and fixed |
| 4 | The format remainder ([013](013-storage-format-v2.md)): 4a, the reserved trailer part, `ListParts`, and item 2d with ADR 0003 D14 | **Done 2026-09-11.** ADR 0003, ADR 0009, ADR 0011 and ADR 0012 are fully implemented; 013 keeps the after-column and the documentation, which are wave 5 |
| 5 | The chart ([016](016-helm-chart-fixes.md)), the release notes, the upgrade rehearsal, the performance after-column | **Mostly done 2026-09-11.** The chart is 20 of 21 items, the after column exists, the two configuration remainders and the documentation are closed. Left: the upgrade rehearsal, the release notes, the label, and one undecided chart item |

### Ownership holes — closed by wave 2, except one

Every hole the audit found was a client-visible break that would otherwise have
survived 5.0.0 inside a ticket nobody owned. Wave 2 took them all as its own:

| Item | Where it landed |
|---|---|
| Conditional request headers (024 X-1, ADR 0007 D7) | **shipped**: all four preconditions on `GET`, ranged `GET` and `HEAD`, the two entity-tag ones on `PUT` and `CompleteMultipartUpload` |
| A malformed `CompleteMultipartUpload` answers `500 InternalError` (024 H-6) | **shipped**, with the seven other multipart client mistakes and the six bare plain-text refusals |
| SigV4 canonicalisation does not collapse sequential whitespace (024 H-6b) | **shipped**, mirroring `aws-sdk-go-v2`'s own canonicalisation byte for byte |
| The XML document writers produce different bytes for the same structure (022 item 3) | **shipped, and it was worse than recorded**: all twenty-one sub-resource `GET`s answered the SDK output struct XML-encoded, which no S3 client can parse. One writer left |
| Two headline metrics never reach `/metrics` (024 P-3) | **shipped**: one registry, gathered by the listener |
| The monitoring listener is unauthenticated (024 S-3) | **open, and the only thing keeping 024 alive.** No ADR answers it; see the question below |
| This file cites "019 item 12" | the citation is in this file's own history and nothing depends on it; 019 can be deleted without loss |

**[026](026-sse-c-passthrough.md) is additive from 2026-09-11.** The refusal it
depends on shipped with ADR 0007 D6: the three customer-key headers answer
`501 NotImplemented` naming the header, in front of every S3 route. Until then
026 was a breaking change parked in a ticket that stayed open — the exact thing
this release is meant to end. It is now what it was written to be: lifting a
refusal, which no client can be relying on.

### What waves 0 and 1 changed about the questions below

Three of the six are answered, by the ADRs rather than by a new decision:

- **Question 1 is closed.** ADR 0013 D7 restated ADR 0009 D2's pattern and had
  drifted from it. D7 now names ADR 0009 as the owner instead of repeating the
  rule, so the two cannot diverge again.
- **Question 2 is closed by ADR 0017 D8**, which forbids a silent fixup: a
  `max_clock_skew_seconds` of `0` is refused at startup rather than read as 900.
  The same rule now applies to the pre-signed ceiling and to the two listener
  budgets that may not be switched off.
- **Question 4 is narrower than it was.** The exit provider's metadata leak
  (ADR 0008 D9) is still open, and still bites only when the running proxy's
  prefix differs from the one an object was written with.

**One new question, from a measurement rather than a reading**, recorded in
ADR 0015's residual risks: removing the transfer wall clock does not by itself
make a slow link work. The proxy holds the backend request open while it fills a
segment, so a slow client becomes a silent backend request, and the backend
refuses one it has heard nothing on for about 25 seconds. The floor is roughly
2.6 KiB/s, and for an object below one segment it is the whole object inside that
window. Closing it is a write-path design change — delay the backend request
until there are bytes, or keep it alive another way — and it is not scheduled.

### Questions left for the owner, none of them blocking the next wave

Recorded here rather than decided, per the working agreement. Each is answered by
the ADRs where it can be; these are the ones where the ADRs disagree or are silent.

1. **ADR 0013 D7 and ADR 0009 D2 disagree on the metadata prefix pattern** — D7
   still names `^[a-z0-9-]+$`, D2 the amended `^[a-z0-9][a-z0-9-]{2,}-$`. One has to
   be amended in the same change as the validator.
2. **`max_clock_skew_seconds: 0`** is accepted at startup today and silently means
   900 on both paths — the value an operator would pick to mean "no tolerance".
   Whatever the wiring change does, it has to decide what `0` means.
3. ~~**`optimizations.clean_http_transfer_chunked`**: the release notes list it as
   removed, this file records it as deliberately kept, and the tree still reads it.~~
   **Closed 2026-09-11: this file was the wrong one of the three.**
   [ADR 0013](../adr/0013-a-configuration-key-exists-only-if-code-reads-it.md) D9
   decided the key is deleted, and its own status block lists it as the one part of
   D9 still unbuilt — so the release notes are right and "deliberately kept" was
   never a decision anyone took. The premise still holds in this tree: `net/http`
   strips the transfer encoding before a handler runs, so the decoder that key gates
   cannot fire. **The deletion is outstanding work, owned by ADR 0013 D9**, and it is
   not wave 3's: wave 3 removed `clean_aws_signature_v4_chunked`, which is a
   different key with the opposite problem — its decoder does fire, and switching it
   off stored chunk framing as object content.
4. **The exit-provider metadata leak** (ADR 0008 D9) bites only when the running
   proxy's prefix differs from the one an object was written with. Fix in 5.0.0, or
   record it as the product's answer.
5. **Four client-visible listing and read-path leftovers**: an unresolvable key
   fingerprint answers `500 DecryptionError` rather than `403 InvalidObjectState`;
   the pass-through ranged read answers `206` with no `Content-Range`, which is not
   a valid HTTP response; `HeadBucket` drops `x-amz-expected-bucket-owner`;
   `ListBuckets` serialises a missing creation date as the Go zero time and a unit
   test currently asserts that defect. All four are small. Under the release rule
   each is fixed in 5.0.0 or written down as a decision — leaving them unowned is
   the one option the rule forbids.
6. **Open questions 2, 3 and 4 of this file are still open** — the memory bound,
   whether `GOMEMLIMIT` ships, and whether the XML-writer unification joins.

## Progress (2026-09-11, afternoon) — wave 2, the S3 surface

**ADR 0007 is fully implemented.** Its forwarding half had been decided,
specified and unbuilt since 2026-09-07; every decision in it — D3 through D8 and
D12 — is in the tree now, and the `Decision` section is true in the present tense
for the first time. The S3-surface ticket is deleted; 024 keeps one
row.

### What landed, and what each of them actually was

- **The storage headers reach the backend** (D3). Ten headers were accepted,
  forwarded nowhere and answered `200 OK` with an ETag. One reader and two
  appliers now serve all three upload paths, so a single-request `PUT`, the
  internal producer and client-driven `CreateMultipartUpload` cannot answer the
  same request differently. Two headers the proxy has to parse rather than copy —
  the retain-until date and `Expires` — answer `400 InvalidArgument` when they are
  not a date, because storing the object without them is the same silent success
  one level down.
- **SSE-C is refused** (D6), in a middleware in front of every S3 route rather
  than per verb, because the refusal lifts only when every verb carries the key.
  That is what makes [026](026-sse-c-passthrough.md) additive.
- **Object tagging, retention and legal hold are passthrough** (D4). The seven
  backend operations the dead-code round removed came back with the handler arms
  that call them. `PUT ?legal-hold` used to read the body, discard it and always
  send `Status=On`, so a client releasing a hold applied one.
- **`PUT ?acl` and `?cors` carry their document in full** (D5) — and doing it
  exposed the same defect on the way out, one **no earlier pass had named**:
  every one of the twenty-one bucket sub-resource `GET`s answered the
  `aws-sdk-go-v2` output struct XML-encoded. Root element the Go type name,
  element names the Go field names, no S3 namespace, and the SDK's internal
  `ResultMetadata` inside every document. No S3 client could parse any of them.
  All twenty-one have a document of the proxy's own now, with the element names
  taken from the SDK's deserializers, which are the wire names S3 uses.
- **Conditional requests are honoured on every verb that takes one** (D7).
  `HEAD` carried no precondition at all, so it answered `200` where `GET`
  answered `304`; the date preconditions were dropped everywhere, so a
  revalidating `GET` fetched, decrypted and transferred the whole object; and no
  upload path carried one, so `If-None-Match: *` overwrote the object it exists
  to protect.
- **Fourteen refusals say what they are** (D8). Six answered a bare plain-text
  body an SDK cannot read a code out of; eight answered `500 InternalError`, so a
  client mistake was reported as a proxy failure and every SDK retried it to the
  end of its budget.
- **A permanent state of an object is no longer a 5xx.** A fingerprint naming a
  provider that is not loaded, and the exit provider's own fingerprint, answered
  `500 DecryptionError`. Retiring a key is permanent, not an outage: both are
  `403 InvalidObjectState` now, beside the wrap that does not authenticate.
- **SigV4 canonicalisation collapses whitespace** the way the signer does. A
  correctly signed request whose header carried repeated spaces was answered
  `SignatureDoesNotMatch` while the backend accepted it. The failure was a false
  negative throughout: nothing was ever accepted that should have been refused.
- **The request metrics reach a scrape.** They were registered on the proxy's own
  registry while `/metrics` served Prometheus's default one, so a proxy whose
  second goal is throughput exported no request rate and no latency at all. The
  mechanism cut both ways: the series that *were* exported carried none of the
  Kubernetes labels. One registry now.
- **One error writer**, one `<Location>` that survives an ingress, and the
  housekeeping: `make quality` in an order that can pass, the two assert-nothing
  test files gone, the hand-rolled `contains` replaced.

### Found while doing it, and not in any ticket

- **The integration suites leaked buckets.** `CleanupTestBucket` listed one page
  of objects, deleted them without a `versionId` and discarded every error, so a
  bucket that stayed behind was invisible: 315 had accumulated in the development
  MinIO, five more per run of the `s3-methods` suite. The teardown now aborts
  incomplete multipart uploads — one is enough to make `DeleteBucket` answer
  `BucketNotEmpty` on a bucket that lists no objects — pages the objects, walks
  the versions and delete markers, and says which bucket it could not remove. A
  genuine leak fell out of making it visible: the 500 MB test reassigns its
  bucket name after the context created one, orphaning the original on every run.
  A full run now leaves zero buckets behind.
- **This MinIO discards `x-amz-website-redirect-location` on a direct `PUT` too**,
  so there is no oracle for "the backend stored it". That assertion is
  differential now rather than absolute.
- **`Expires` was the last entity header still dropped.** It is forwarded under
  ADR 0007 D2 rather than D3, which does not name it.
- **The `endpoint` metric label is the route template**, not the request path, so
  no bucket or key name reaches a scrape. Worth knowing before the S-3 question
  below is answered.

### The one thing wave 2 did not decide: 024 S-3

The monitoring listener is unauthenticated. It is off by default
(`monitoring.enabled: false`), the chart's service is off by default and
`ClusterIP` when on, and pprof already lives on its own loopback listener. What
it exposes when enabled: request rate and latency by route template, build
version and commit, active connections, and
`s3ep_license_info{licensed_to, company, expires_at}`.

So the sensitive part is narrow — the licensee's name and company, plus a
deployment fingerprint. **No ADR answers this**, which is why it is the one row
keeping [024](024-coverage-round-findings.md) alive. Two options were put to the
owner: leave the listener unauthenticated (what every Prometheus exporter is, and
what makes a Kubernetes scrape work) and drop the two identifying labels, keeping
the expiry gauges an operator alarms on; or give it real authentication, which
costs a configuration key, its validation and its documentation.

### Gates

`go build`, `go vet`, `gofmt`, `make test-unit`, `make lint` (0 issues,
golangci-lint v2.13.1), `make quality` end to end, `make test-integration` and
`make test-integration-tls` all green, with no new error or warning line in
`docker logs proxy` across either run, and zero test buckets left behind.

**`make test-e2e-velero`: all 13 scenarios green, 562s** — the preflight, V1,
V1b, V2 through V10 and V8b, including the encryption-at-rest assertions read
directly from the MinIO backend and `TestV10_PresignedLogAccess`, which is the
one that catches a pre-signed download the sub-resource guard would refuse. This
is the gate that matters most for a wave that changed the request surface on
every verb, and it is a supported client exercised end to end rather than a test
of the proxy against itself.

One thing worth knowing for the next run: `e2e-up` failed once with a Helm
server-side-apply conflict on `s3ep-proxy-config`, because an earlier session's
`kubectl` owned `.data.config.yaml`. Deleting that ConfigMap and re-running
`e2e-up` resolved it; the cluster did not have to be recreated.

## Progress (2026-09-11, evening) — wave 3, the client leg

**ADR 0012 is implemented except D10.** Every checksum a client declares is
verified against the plaintext it sent, on every write path, and the upload
ticket is deleted. Its status block had said the opposite of the tree on two
counts — the trailer capture had not landed, and the verification had — and
three of its residual risks were open questions that are now measurements.

### What landed

- **The verification itself.** `Content-MD5`, `x-amz-checksum-crc32`, `-crc32c`,
  `-crc64nvme`, `-sha1` and `-sha256`, as a request header or as an aws-chunked
  trailer, on the single-request `PUT`, the internal multipart producer,
  client-driven `UploadPart`, the eight bucket configuration writes and the
  multi-object delete. A mismatch is `400 BadDigest`, a value that is not a
  digest of its length is `400 InvalidDigest`, and a trailer named in
  `X-Amz-Trailer` that never arrives is a failed verification rather than an
  absent one.
- **The verdict lands before anything is committed**, and that is a property of
  the reader rather than of the caller: it holds the final payload byte back
  until it has a verdict, so a consumer streaming straight to the backend can
  never have delivered the complete payload while verification is still open.
  Without it the pass-through write could have had its body accepted whole
  before the mismatch was known.
- **A verdict is never a 5xx.** `MapError` recognises the two sentinels ahead of
  everything else, so every existing `WriteS3Error` call site answers correctly —
  the eight bucket handlers included, which would otherwise have reported a
  client mistake as `500 InternalError` and had every SDK retry it.
- **`DeleteObjects` requires a digest** and verifies it before the document is
  parsed. The suite's batch-delete deviation test asserted the opposite; it now
  asserts the enforced behaviour.
- **The three raw-body handlers go through the parser** — `handleDeleteObjects`,
  `CompleteMultipartUpload` and `handleCreateBucket`. `handleCreateBucket` reads
  on the decoded length rather than `r.ContentLength` and refuses a malformed
  document with `MalformedXML`; two tests that pinned those as deliberate defects
  are flipped.

### Two defects found on the way in, neither about checksums

- **An object whose plaintext was an exact multiple of
  `optimizations.streaming_segment_size` was stored without its trailer.** The
  producer filled its last buffer exactly, sealed it as a *middle* part, and then
  ended on a clean EOF without closing the chain. The `PUT` answered `200`; every
  later read of that object failed authentication. Measured: a 262144-byte object
  stored as 262256 bytes against 262296 expected, exactly the 40-byte trailer
  short. With the default 12 MiB part size this is any object of exactly 12, 24 or
  36 MiB — the sizes a backup client writing fixed-size blobs produces. The
  trailer is a part of its own in that layout now.
- **An aws-chunked `PUT` without `X-Amz-Decoded-Content-Length` answered
  `500 InternalError`** whenever its framed size fitted one part. The routing
  asked `DecodedContentLength`, which for that shape returns the wire length
  including the framing, and handed it to the single-request write as the
  plaintext length. `PlaintextContentLength` exists to say whether a number really
  describes the plaintext; the routing asks it now.

Both are regression-tested, and both were reachable by a correct client.

### Measured rather than assumed

- **Per-algorithm cost**, Apple M5 Pro, one core, 128 KiB blocks, Go 1.27.1
  arm64: CRC32 12.1 GB/s, CRC32C 12.1 GB/s, SHA-1 3.5 GB/s, SHA-256 3.4 GB/s,
  CRC64NVME 2.4 GB/s, MD5 0.94 GB/s.
- **End to end that is far smaller than the per-byte figure suggests.** Fifteen
  repetitions at 8 MiB and at 20 MiB against the development stack: every
  algorithm but MD5 was inseparable from an upload declaring nothing, and MD5 cost
  about three percent. The hash runs while the request is bound by the backend
  write, so most of its cost overlaps rather than adds.
- **The CRC-64/NVME table trap is half real.** `hash/crc64` does rebuild its
  slicing-by-8 helper on every `Write` of 2048 bytes or more for a polynomial that
  is not ISO or ECMA, but on Go 1.27.1 escape analysis keeps that 16 KiB on the
  stack: what it costs is the build loop, not an allocation. The table built once
  at package load is about one percent faster, and neither form allocates. The
  ticket had claimed an allocation per read; the benchmark ships beside the
  implementation so the claim stays a measurement.
- **The backend answers a wrong `Content-MD5` on a plain `PUT` with
  `400 BadDigest`**, the same as the proxy. On a multi-object delete it checks
  only that the digest header is present, never that it matches, so the proxy is
  the stricter of the two. The other five algorithms were not compared.

### The configuration key that made the check optional is gone

`optimizations.clean_aws_signature_v4_chunked: false` made the proxy store chunk
framing as object content — a pre-existing fault this wave surfaced rather than
introduced, because under it the verifier would hash the framing and blame a
correct client for a `BadDigest`. **Owner decision, 2026-09-11: the key is
deleted.** Its only reachable effect was to corrupt data, so a key whose one
setting does that is worse than no key (ADR 0013). aws-chunked decoding is
unconditional now, which means no configuration can turn a declared checksum into
accept-and-discard. A configuration file still carrying the key does not start,
and its name is in the error (ADR 0013 D11).

Removed from the two example configurations, the Velero values, `README.md`,
`CLAUDE.md`, `SECURITY_ARCHITECTURE.md` and ADR 0012, and added to the release
notes' removed-key list. Not to be confused with
`optimizations.clean_http_transfer_chunked`, which is a different key with the
opposite problem and whose deletion ADR 0013 D9 already owns — see open question 3.

### Gates

`go build`, `go vet`, `gofmt`, `make test-unit`, `make lint` (0 issues),
`make test-integration` and `make test-integration-tls` all green, with no new
error or warning line in `docker logs proxy` across either run. The TLS run is the
one that matters here: it is the only one where `aws-sdk-go-v2` emits the
checksum-trailer framing itself.

**`make test-e2e-velero`: all 13 scenarios green, 569s**, against the branch head.

One thing that cost a full cycle and is worth knowing. `e2e-up` failed with the
Helm server-side-apply conflict on `s3ep-proxy-config` that this file already
recorded once, and the failure is not inert: the release stays on the old
configuration, the new image crash-loops on it, and the **old pod keeps serving**.
A suite run in that state reports on a binary that is not under test — twelve
scenarios "passing" against the previous build, with two failing only because
requests reached the crash-looping endpoint. The conflict is persistent, so every
later bring-up hits it again.

`e2e-up` now clears the ConfigMap and retries the upgrade once, the way the
stuck-release branch beside it already does. Worth keeping in mind when reading a
gate: `make e2e-up 2>&1 | tail -N && make test-e2e-velero` takes its exit status
from `tail`, so the `&&` cannot see the failure. Run the bare targets.

The crash itself was the removal working: the pod refused to start with
`'optimizations' has invalid keys: clean_aws_signature_v4_chunked` (ADR 0013 D11).

## Progress (2026-09-11, night) — wave 4, the format remainder

**Four ADRs are fully implemented for the first time: 0003, 0009, 0011 and
0012.** What is left of [013](013-storage-format-v2.md) is the performance
after-column and the documentation, both wave 5, and neither is format work.

### What landed

- **A client metadata key inside the proxy prefix is refused** (ADR 0009 D6),
  `400 InvalidArgument` naming the key, before any backend request — so a refused
  upload stores no object and opens no multipart upload. All three write paths
  call one exported collector rather than a check each of them could forget,
  which is how the case-sensitivity hole survived on one path once already. It
  applies under the exit provider too, where such a key would otherwise let a
  client forge the format markers the read path looks for. The silent drop is
  gone, and with it the last thing ADR 0009 was waiting for.
- **The trailer's part number is reserved** (ADR 0011 D4). A client-driven upload
  has 1..9999 and part 10000 is answered `400 InvalidArgument` **when the part is
  sent**, instead of the backend refusing the object's closing part at completion
  after every byte has been transferred. The pass-through provider keeps all
  10000: there the backend owns the part layout.
- **`ListParts` answers from the session part table** (ADR 0011 D6) — the
  plaintext length per part (ADR 0010) and the entity tag `UploadPart` answered
  with, the held last part included, because the client uploaded it and was given
  a tag for it. `part-number-marker` and `max-parts` are honoured, a parameter
  that is not a non-negative number is `400 InvalidArgument`, and an upload id
  with no session — or one naming another bucket or key — is `404 NoSuchUpload`.
  It used to answer a fabricated empty document with `200` for any upload id at
  all. **`ListMultipartUploads` is forwarded**; both verbs went back onto
  `S3BackendInterface` and its mocks.
- **A whole-object read takes the object's end first** (ADR 0003 D14, ADR 0012
  D10). `HEAD` is one `GetObject(Range: bytes=-40)` — the same one backend
  request a `HeadObject` cost — and a whole-object `GET` reads `bytes=-65604`
  first and, only above one segment, the remainder under `If-Match` on the first
  answer's entity tag. Every stored byte is fetched exactly once. Both verbs state
  the plaintext length the **trailer** authenticates rather than the one the
  backend reports about itself, and both serve `x-amz-checksum-crc32c`. A ranged
  read carries none. No configuration key.

### What the tail-first read changed about failures

Three faults moved from a body that stops early to a refusal before the response
begins, all `403 InvalidObjectState`: a trailer that does not open, a truncation,
and a stored length the trailer contradicts. The integration suite measured the
old shape as 192 KiB of authentic plaintext released before the failure; it is
zero now. A fault **inside a segment** is unchanged — the status is out by then,
and that is ADR 0003 D8 rather than a gap.

### Measured, and worth the owner's attention

Three runs of the proxy-vs-backend comparison before the change and three after,
same machine, same stack. Encrypted download throughput, median of three:

| Object | Before | After |
|---|---|---|
| 100 KB | 53 MB/s | 33 MB/s |
| 500 KB | 144 MB/s | 120 MB/s |
| 1 MiB | 176 MB/s | 170 MB/s |
| 10 MiB | 267 MB/s | 266 MB/s |
| 1 GiB | ~248 MB/s | ~262 MB/s |

The whole cost is the one extra backend round trip, about 1.2 ms against this
backend: invisible above roughly 10 MiB, and dominant below half a megabyte,
where a 100 KB download is about 40 % slower. Average download efficiency against
the backend moves from ~96 % to ~88 %, carried entirely by the two smallest
sizes. Uploads and ranged reads are untouched, and kopia — the client that reads
with small ranges — is on the ranged path, which still costs one request.

**Owner decision, 2026-09-11: this leaves the release.** The size of the first
read is one constant — one segment plus the trailer — and whether it should be
larger, configurable, or left alone is a question worth answering but not worth
holding 5.0.0 for. It moves to [027](027-whole-object-read-first-window.md),
which writes down the five options with what each costs and the seven questions
an evaluation has to answer first. Nothing about it is scheduled, and the shipped
constant is what ADR 0003 D14 names.

### Gates

`go build`, `go vet`, `gofmt -l`, `make test-unit`, `make lint` (0 issues),
`make quality` end to end, `make test-integration` and `make test-integration-tls`
all green, with no new error or warning line in `docker logs proxy` across either
run. `make test-integration-performance` green, and it is where the table above
comes from.

**`make test-e2e-velero`: all 13 scenarios green, twice — 577s and 550s** against
the branch head.

**`make gosec`: 0 issues, and it was 1 before this wave.** The finding predates
wave 4 — it is already there at the wave-3 tip — and `main` is clean, so a change
between waves 1 and 3 made gosec's taint analysis reach `xml.Unmarshal` in
`CompleteMultipartUpload`. Six other handlers that parse a client document
already carried the annotation for the same rule with the same reason; that one
was missed. It matters beyond tidiness: the `gosec` job is one of the eight the
release workflow needs.

### Test surface the change moved

Twenty-one unit tests mocked `HeadObject` for a verb that no longer calls it, and
every whole-object GET fixture had to start honouring the Range it is asked for —
a mock that answers the whole object to `bytes=-40` hands the reader the wrong
forty bytes. `ObjServeStored` in the object package's test helpers is that fixture
now, and it registers the exact three ranges the read path issues. Four
integration tests pinned the behaviour that changed: the tamper table, the forged
envelope, and both multipart listings.

## Progress (2026-09-11, wave 5) — the chart, the after column, and a defect the measurement found

**Six of the seven wave-5 items are closed.** What is left is the upgrade
rehearsal, the release notes themselves, and the label — plus one chart item the
owner has not decided.

### What landed

- **`optimizations.clean_http_transfer_chunked` is gone** (ADR 0013 D9), with the
  decoder it gated and that decoder's base type. The premise was re-proved before
  the deletion rather than argued: `net/http` deletes the `Transfer-Encoding`
  header from a server request unconditionally before dispatch, answers an
  unsupported value itself, and rejects the header outright on the HTTP/2
  listener. Three shipped examples and the Velero values carried the key, not the
  one example the ADR named; all four lost it in the same change, because ADR 0013
  D11 would otherwise have refused the start of the demo stack and the e2e cluster.
- **`multipart_short_part_buffer_size` is in the shipped files** at last, and
  `values-production.yaml` gained the `optimizations:` block it never had.
  `config/exit-example.yaml` says in a comment why it does **not** carry the key:
  under the exit provider a client-driven upload registers no session, so the cap
  bounds nothing there, and writing it would document a control that does not act.
  The memory formula has one home, `docs/developer/performance.md`, with all four
  terms — including the 65604-byte tail buffer ADR 0003 D14 added, which no
  existing statement of the formula knew about.
- **The chart round ([016](016-helm-chart-fixes.md)): twenty of twenty-one work
  items.** A config or credential change now rolls the pods, the probe scheme is
  derived from the config the pod will actually receive, the Service can pin a
  node port, both unrenderable values files render *and start the real binary*,
  and the misplaced `metadata_key_prefix` moved under `encryption:` at the shipped
  default. The helm-unittest suite is rewritten to eighteen tests and a new
  `helm-chart` job gates `semantic-release` — the chart used to be packaged and
  released without ever being rendered. The e2e drops three workarounds it was
  carrying for the chart's defects, generates a kopia repository password instead
  of using the one published in Velero's source, and scans the Velero-side backup
  and restore logs, which nothing was reading.
- **`DEVELOPER.md` exists** and `CLAUDE.md` is 265 lines shorter for it
  ([013](013-storage-format-v2.md) item 16). Two documents had disagreed about
  whether the file should exist at all.
- **The after column exists** ([013](013-storage-format-v2.md) item 15):
  `perf-baseline/20260911T103132Z-cc62c05/`, every instrument at `ok`, with a
  written `FINDINGS.md`. ADR 0020 and ADR 0024 record it; the upload claim this
  release has been holding may now be made.

### The upload deficit is gone, and it is the release's one performance claim

Proxy upload throughput as a share of the same client writing to the backend
directly, median of seven, same machine as the pre-v2 column:

| Object | HTTP before | HTTP after | TLS before | TLS after |
|---|---|---|---|---|
| 1 MiB | 71 % | 93 % | 77 % | 122 % |
| 5 MiB | 59 % | 111 % | 56 % | 120 % |
| 8 MiB | 60 % | 107 % | 59 % | 106 % |
| 128 MiB | 60 % | 96 % | 46 % | 96 % |

The upload-path instrument says where it came from: the **multipart leg** gains
33 to 47 %, the **single-request leg** — which never enters the producer — is 0 to
8 % *slower*, which is the segment chain plus ADR 0012's checksum verification.
Peak resident memory fell from 130 MB to 109 MB against an unchanged 512 MB
container limit. Downloads and the crypto floor are unchanged.

**Nothing below roughly 15 % end to end may be claimed at all.** Three full runs
were taken within one hour, two of them on identical code, and the end-to-end rows
moved by that much; an image rebuild immediately before a run costs about the same.

### The measurement found a defect no gate would have caught

**A ranged read was closing the backend body with bytes unread**, which makes Go's
transport drop the connection instead of pooling it — so every ranged read paid a
new connection and, under TLS, a new handshake. The cause is the provisional
window: an explicit range is fetched as if every segment of it were full, plus a
trailer, and the reader then consumes exactly the real window.

Measured: a 1 MiB ranged read through the proxy at **155 MB/s** against a backend
serving the same range at 220, where before this storage format it was 207 against
217. With the remainder drained before the close: 207. It showed on three of the
four range shapes and on both transports, worst at 1 MiB and still 3 to 9 % at
8 MiB.

It is the path kopia reads on. It had been in the release since the segment chain
landed — the wave-3 run of the same day records the same 154 MB/s — and every
functional suite passed throughout. ADR 0003's status block records it.

### One thing that was blocking the measurement, and was itself a regression

**`/metrics` had stopped exporting every `go_*` and `process_*` series.** Moving
it off `prometheus.DefaultGatherer` onto the proxy's own registry took the default
collectors with it, so a scrape carried seven `s3ep_*` series and nothing else: no
heap, no goroutine count, no resident memory, no CPU, no file descriptors. v4.0.3
had all of them. ADR 0020 D14's memory instrument reads
`process_resident_memory_bytes`, which is why the newest baseline before this wave
records it as skipped. Both collectors are registered again.

### Gates

`go build`, `go vet`, `gofmt -l`, `make test-unit`, `make lint` (0 issues),
`make gosec` (0 issues), `make test-integration` and `make test-integration-tls`
green with no error or warning line in `docker logs proxy`,
`make test-integration-performance` green — it is where the table above comes
from — and `make helm-test`: lint, four override values files rendered, the
Velero e2e values rendered, 18 unit tests.

**`make e2e-up && make test-e2e-velero`: 13 of 13 green, twice**, against a kind
cluster created from scratch — which the chart work required, because the warm one
still held four kopia repositories bound to Velero's published default password.

### TLS at the Service, decided and built the same day (ADR 0026)

The owner's architecture note settled work item 9 and opened something larger.
The proxy is deployed **beside its client, inside the cluster** — Velero in a
namespace, a proxy next to it, reached at
`s3ep-proxy.<ns>.svc.cluster.local` — and an Ingress is the exception, not the
rule. The chart had **no TLS value of any kind** for that leg: the only way to
turn the listener on was to hand-write a volume, a volume mount and three
configuration lines whose paths have to agree, which is exactly what the e2e has
been doing since it existed. A workaround that old is the missing feature being
paid for over and over.

`serviceTLS` now issues a certificate for the four Service names the chart
computes, or mounts one the operator brings, mounts it, adds the `tls:` block to
the rendered configuration, and the probe scheme follows. The **e2e runs the whole
suite through it**, on the bring-your-own arm. The cert-manager arm ships with a
render test and no run, because the kind cluster has no cert-manager — named in
the ADR rather than left to be discovered.

Work item 9 landed with it, in the stronger form the owner asked for: an enabled
Ingress must carry TLS for **every host it serves**, not merely have one entry.

**It found a defect in the e2e that predates it.** `patchProxyConfig` read the
**rendered ConfigMap** back and fed it in as `config` on the next upgrade — so it
was round-tripping keys the chart *adds* to the render rather than the values the
operator supplied. `tls:` is the first such key the e2e actually carries, which is
why the guard caught it now; `license_file:` has the same shape and would have
duplicated silently in any deployment using a chart-managed licence. It reads
`helm get values` now.

### What wave 5 did not do, and why

- **The bundled Grafana dashboard still queries three removed metric series**, so
  four of its seven panels have nothing to draw. It is not one of the chart
  ticket's twenty-one items and rebuilding it is additive; the chart README states
  it plainly, and `monitoring.grafana.dashboard.enabled` is `false` by default.
- **`handleDeleteLogging` in the bucket handler is unreachable** — the router does
  not route `DELETE ?logging`, and S3 has no such verb. Dead code, found while
  verifying the sub-resource matrix, left alone as out of scope.

## The upgrade rehearsal, run 2026-09-11

Run once, as the "Done when" box asks, and recorded here rather than in a ticket
that gets deleted. The proxy under 4.0.3 was **built from the `v4.0.3` tag**, and
both legs used the same MinIO, the same bucket and — deliberately — **the same,
freshly generated key encryption key**, so that every refusal below is provably
about the storage format and not about key material.

**Leg 1 — write under 4.0.3.** Three objects covering all three write paths:
24 bytes, 1 MiB (single request) and 32 MiB (the multipart producer). Read back
through 4.0.3, all three match their source by SHA-256.

**Leg 2 — the configuration refuses the upgrade before the data does.** Starting
5.0.0 against the *unchanged* 4.0.3 configuration file fails at startup and names
both offending keys:

```
's3_backend' has invalid keys: use_tls
'encryption' has invalid keys: integrity_verification
A key this version does not define stops the start instead of being ignored.
Remove it, or fix the spelling; keys removed by a release are listed in its notes
```

That is ADR 0013 D11 doing exactly what it was decided for: an operator who
upgrades without reading the notes is stopped by name, not left with a proxy that
silently ignores a control they believe is on.

**Leg 3 — the old objects are refused, not mis-served.** With the configuration
migrated (the two keys dropped, nothing else changed, same KEK), all three objects
answer **`403 InvalidObjectState`** on `GET`. The refusal happens at the format
gate — the stored `dek-algorithm` is not `s3ep-gcm-seg-v2` — before any key is
looked at, which is why the identical key does not change the outcome.

**Leg 4 — a fresh upload of the same content round-trips.** The same three files
uploaded again through 5.0.0 and read back: all three match their source by
SHA-256.

**What an operator has to take from it:** drop the removed keys from the
configuration first, or the proxy will not start; then delete the old objects and
upload the data again from its source. There is no migration, and nothing about
the old objects is recoverable through this proxy.

## Release notes — skeleton

Filled as each unit closes. Under a `BREAKING CHANGE:` footer.

**Stored data.** Objects written by 3.x and 4.0.x are not readable. Upload them again
from the source; there is no migration of any kind. `s3ep-aes-iv` and
`s3ep-hmac` are no longer written, `s3ep-dek-algorithm` is `s3ep-gcm-seg-v2`, and
`s3ep-kek-fingerprint` values change.

**Configuration — removed.** `encryption.integrity_verification`,
`optimizations.streaming_threshold`, `optimizations.clean_aws_signature_v4_chunked`,
`optimizations.clean_http_transfer_chunked`,
`optimizations.streaming_buffer_size`, `optimizations.enable_adaptive_buffering`,
`s3_backend.use_tls`, the dead `s3_security` keys, the legacy top-level backend
block, and the `rsa`, `tink` and `none` provider types. A configuration file
still carrying any of them does not start: ADR 0013 D11 ships in the same
release, so a removed key is refused by name rather than ignored.

**Configuration — renamed.** The `none` provider is now `exit`
([ADR 0025](../adr/0025-leaving-is-a-supported-mode.md)) and it is a different
thing, not a new label. It needs no licence, it stores new objects as the client
sent them on every write path, and — unlike `none` — it **keeps decrypting what
this proxy encrypted earlier**. That works only while the provider holding the
old key stays registered beside it, so an operator renaming the type must also
add that provider. `type: "none"` is refused at startup with a message that says
so.

**Metrics — removed.** Thirteen series that were registered and never observed:
`s3ep_s3_operations_total`, `s3ep_s3_operation_duration_seconds`,
`s3ep_encryption_operations_total`, `s3ep_encryption_duration_seconds`,
`s3ep_bytes_transferred_total`, `s3ep_multipart_uploads_total`,
`s3ep_multipart_upload_parts_total`, `s3ep_proxy_performance_seconds`,
`s3ep_download_throughput_mbps`, `s3ep_encryption_providers_info`,
`s3ep_hmac_operations_total`, `s3ep_hmac_performance_seconds` and
`s3ep_hmac_throughput_mbps`. Each had always reported zero; a dashboard panel
built on one was always empty. What remains is `s3ep_requests_total`,
`s3ep_request_duration_seconds`, `s3ep_active_connections`, `s3ep_server_info`
and the three license series — **and, restored in this release, the Go runtime
and process collectors** (`go_*`, `process_*`): moving `/metrics` onto the
proxy's own registry had silently taken heap, goroutine, resident-memory, CPU and
file-descriptor series with it.

**The chart's bundled Grafana dashboard predates all of this.** Four of its seven
panels query three of the removed series and have nothing to draw. It is disabled
by default (`monitoring.grafana.dashboard.enabled`), and the chart README says so;
rebuilding it against the current metric set is not in this release.

**Logging — changed.** The authentication security event no longer carries
`client_ip` or `failed_count`. It carries `remote_addr`, the peer address, and
`x_forwarded_for`, the raw header, as two separate fields: the previous single
value was chosen by the client. The "Potential brute force attack detected" line
is gone with the per-IP counter behind it.

**Configuration — refuses to start.** Any key the proxy does not define, named
in the error — a key removed by this release, or one that is simply misspelled,
now stops the start instead of being ignored (ADR 0013 D11); a segment size that
is not a multiple of
65536; a backend endpoint without a scheme, or `http://` under an encrypting
provider; an `aes_key` that is not base64 of 32 random bytes; a provider of type
`rsa`; a `metadata_key_prefix` shorter than four characters, not starting with a
letter or digit, or not ending in `-`.

**Configuration — new.** `optimizations.multipart_short_part_buffer_size`, bytes,
default 64 MiB, minimum 5 MiB: the memory one **open** client-driven upload may
hold for a short last part — the ceiling is that value times the number of open
uploads, not a total across them (ADR 0011). Size it against the container limit;
the four terms are in `docs/developer/performance.md`. `s3_security.max_presign_expiry_seconds`, default 3600.

**Behaviour.** Whole-object `GET` and `HEAD` answer with an
`x-amz-checksum-crc32c` over the plaintext, recorded at upload, and both report
the plaintext length the object's own trailer authenticates; a whole-object `GET`
above 64 KiB costs the backend two requests, which is worth about 1.2 ms and shows
up as roughly 40 % on a 100 KB download and as nothing above 10 MiB; a damaged
trailer, a truncation and a stored length the trailer contradicts are refused
before the response begins rather than delivered as a body that stops early;
a client-driven multipart upload has 9999 part numbers, not 10000, and part 10000
is refused when it is sent; `ListParts` answers from the proxy's own part table
with plaintext sizes and `ListMultipartUploads` is forwarded, where both used to
be a fabricated empty document and a `501`;
both listings answer a real
`ListBucketResult` under the S3 namespace with the plaintext size per entry, a
`max-keys` outside its range clamped or refused, `<Owner>` naming the calling
client, and `HeadBucket` answering `404` for a bucket that does not exist;
`InvalidObjectState` for objects the proxy did not write;
a client-driven multipart upload that is neither completed nor aborted is now
released by `optimizations.multipart_session_cleanup_interval` — before, it held
its buffered parts and its data key until the process ended;
`InvalidPart` for unaligned client multipart; `InvalidArgument` for client
metadata inside the proxy prefix — refused now, not silently dropped — and for a
query string containing `;`; `BadDigest`
or `InvalidDigest` for a wrong or malformed upload checksum of any algorithm,
`Content-MD5` included, and `InvalidRequest` for a multi-object delete without a
digest; pre-signed URLs above the configured ceiling refused; the configured clock skew applied to header authentication; storage
headers forwarded; SSE-C refused; no wall clock on a transfer.

**Deployment — the Helm chart.** A configuration change, a rotated credential or a renewed
licence now **restarts the pods**: the pod template hashes the rendered ConfigMap and the
rendered Secret, where before `helm upgrade` reported success and left the old values running.
An externally managed ConfigMap or Secret still cannot be hashed, and the chart README says
so. The **probe scheme is derived from `tls.enabled`** in the configuration the pod receives,
so a TLS pod no longer fails to become Ready with no hint as to why; `probes.scheme` overrides
it for `configMap.useExistingConfigMap`. The Service can pin **`service.nodePort`**.
`values-development.yaml` and `values-monitoring.yaml` could not be rendered at all and are
rewritten in the current schema — the development file loses a committed AES-256 key and a
plain-HTTP backend, the monitoring file loses the legacy top-level backend block, and both
gain the `s3_clients` block the loader requires. `metadata_key_prefix` moves from the provider
`config:` block, where it was silently dropped, to `encryption:` at the shipped default
`s3ep-`; no stored object changes. A `helm template` of a values file that does not parse now
**fails the render** instead of crashlooping the pod.

**New in the chart: `serviceTLS`** (ADR 0026). The proxy can serve TLS on its own in-cluster
Service without a hand-written volume: the chart issues a cert-manager certificate for the four
Service names it computes, or mounts one supplied as `serviceTLS.existingSecret`, and turns the
listener on. Off by default; nothing changes for a deployment that does not set it. `clusterDomain`
is new with it and defaults to `cluster.local`.

**The chart refuses three configurations that render today**: an enabled Ingress with no TLS, or
with a host no `ingress.tls` entry covers; a cert-manager `Certificate` nothing consumes; and
`serviceTLS` together with a `tls:` block written into `config` by hand. Each names the values
involved.

Values files lose the removed keys; pods carry a termination grace period
derived from `shutdown_timeout`. **Whether `GOMEMLIMIT` ships is undecided** — open question 3
below. ADR 0020 D15 makes it conditional on a measured gain and no gain has been measured: the
proxy settles at 98 MiB against a 512 MiB container limit, so a limit at 400 MiB is never
approached. If it ships, it ships as an out-of-memory guard with no throughput claim, and the
row in "the minimum" above and step 6 of the order both need rewording.

**Performance — measured, and bounded by its own record.** The after column exists
(`perf-baseline/20260911T103132Z-cc62c05/`, every instrument recorded, on the machine that
took the pre-v2 column), so the claim this release has been holding may be made:

- **Uploads are between 30 % and 120 % faster** above 1 MiB. Against the same client writing
  to the backend directly, the proxy moved from 46-72 % of it to 78-125 %; above 4 MiB it is
  faster than the direct leg, because the backend refuses an aws-chunked chunk above 16 MiB
  while the proxy re-frames into a multipart upload it overlaps (ADR 0024).
- **A single-request `PUT` is 0 to 8 % slower** — the segment chain plus the upload checksum
  verification this release adds. It is the write path that does not go through the producer.
- **Downloads, ranged reads and the crypto floor are unchanged**, and peak resident memory
  fell from 130 MB to 109 MB against an unchanged 512 MB container limit.

**Nothing below roughly 15 % end to end is a claim at all**: three full runs an hour apart on
this machine, two of them on identical code, moved by that much. And no part of the gain can
be attributed to one decision, because the format change, the producer restructuring and the
self-copy removal landed in one commit.

**Support.** 4.0.x and every earlier line receive no further releases of any kind;
5.0.0 is the only supported line (ADR 0018 D11).

**Migration.** There is none. Objects written by earlier versions answer
`InvalidObjectState`; delete them and upload the data again from its source. Run one
proxy version at a time: an object written by a 4.0.x replica during a mixed rollout is
refused afterwards like any other. An `rsa` deployment configures an `aes` key first.

## Done when

- [ ] Every row of "the minimum" is closed on the branch, and every candidate is
      either closed there or moved out with a line saying why.
- [x] On the branch head, 2026-09-11: `make test-unit`, `make test-integration`,
      `make test-integration-tls` and `make e2e-up && make test-e2e-velero` (13 of
      13, twice, against a cluster created from scratch) all green, plus
      `make lint` and `make gosec` at 0 issues, `make helm-test`, and
      `go vet` under each of the three build tags.
- [x] **Upgrade rehearsal**, run 2026-09-11 and recorded above: a 4.0.3 proxy
      built from its tag, three objects covering all three write paths, the
      configuration refused by name, all three objects answering
      `InvalidObjectState`, and a fresh upload round-tripping by SHA-256.
- [x] **No removed key survives where it would act.** The original wording —
      "returns only `CHANGELOG.md`" — is unsatisfiable and, taken literally, would
      have someone delete the removal statements from `README.md`, the security
      architecture and eleven ADRs. The check that means something is scoped to
      shipped configuration, deployment values and non-test Go source:
      ```bash
      grep -rn -e integrity_verification -e streaming_threshold \
        -e clean_aws_signature_v4_chunked -e clean_http_transfer_chunked \
        -e streaming_buffer_size -e enable_adaptive_buffering -e use_tls \
        -e 'type: "rsa"' -e 'type: "tink"' -e 'type: "none"' \
        --include="*.yaml" --include="*.yml" --include="*.go" \
        config/ deploy/ test/ internal/ pkg/ cmd/ | grep -v _test.go
      ```
      **Zero hits, 2026-09-11.** The `_test.go` exclusion is deliberate: three
      tests name a removed key on purpose, to assert that it is refused.
- [ ] The final pull request carries the `release:major` label and the computed
      version is verified as `5.0.0` before the merge.
- [ ] Every ADR this release touches has its `Status` updated from "decided, not
      implemented" to what actually shipped, in the same pull request. **Swept
      2026-09-11**: ADR 0003, 0008, 0013, 0015, 0020 and 0024 corrected, and the
      index row for 0015. What is still marked outstanding is outstanding — ADR
      0005 (no KMS provider), 0023 (filename encryption), 0016's shared token,
      0019's single client, 0020's continuous-integration half, and 0008 D9's
      exit-provider metadata leak, which is an open question below.
- [ ] Each ticket listed here is **deleted** when its work lands, and
      `git grep` shows nothing outside `docs/tickets/` referencing it.
