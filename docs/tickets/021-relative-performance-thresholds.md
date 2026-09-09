# Ticket 021: Performance thresholds relative to a MinIO baseline, then enforced

## Status (2026-09-06)

**Open.** The performance package already measures both legs — proxy and direct
MinIO — for every size in `TestPerformanceComparison`, computes an efficiency
percentage from them, and then throws the assertion away because
`SKIP_PERFORMANCE_CHECKS: "true"` is set on every CI step that runs it. This
ticket turns that number into an enforced ratio: fix the one thing that would
make enforcement flake for a non-performance reason (the comparison bucket is
never cleaned, so every repeat run measures against a fuller MinIO), give the
measurement enough repetitions and the right ordering to survive a shared
self-hosted runner, record real numbers from at least three runs on that runner,
write the thresholds down, and delete the skip knobs.

It carries the "relative baseline, then enable" decision of the Velero path
review, now [ADR 0020](../adr/0020-performance-is-measured-before-and-after.md),
and it takes the second of the two alternatives the coverage gap named ("either
run `test/integration/performance-test` with `-p 1` in a separate step **or**
make the threshold relative to a plain-MinIO baseline measured in the same
run"). The gap is recorded as **closed** by the `-p 1` half — this ticket does
not reopen it, it does the threshold work that decision asks for. It depends on nothing, but it
interacts with **storage format v2 ([ticket 013](013-storage-format-v2.md),
written and open)**: v2 replaces AES-CTR + HMAC-SHA256 with segmented AES-GCM
and adds a ranged-read benchmark, so every ratio moves. The ordering recommendation is in
[Ordering against storage format v2](#ordering-against-storage-format-v2) — land
this first anyway, and re-pick the numbers as the closing step of v2.


## Before you start

- Every `release.yml` line number here is stale, and the job changed shape: it now
  collects proxy coverage, uploads it, and rebuilds both proxies uninstrumented
  (`up -d --build --force-recreate`, [release.yml:285-300](../../.github/workflows/release.yml#L285-L300))
  between the integration steps and the performance steps. The skip knob is at
  :270, :281, :331 and :415, the badge grep at :351 and :384. The 60-minute budget
  ([release.yml:178](../../.github/workflows/release.yml#L178)) is unchanged but has
  less slack than "the repetitions are paid for by removing the duplicate" assumes —
  redo that arithmetic before adding repetitions.
- Success criterion 2 says the small sizes cannot move on the upload leg because
  they go through `PutObject`. At exactly 5 MB they can: the demo config runs
  `integrity_verification: "strict"` ([aes-example.yaml:109](../../config/aes-example.yaml#L109)),
  and `handlePutObject` routes any HMAC-enabled PUT of ≥ 5 MiB into
  `putObjectAutoMultipart` ([operations.go:446-451](../../internal/proxy/handlers/object/operations.go#L446-L451)),
  so `processPartOrdered` is reached. The test's own `len(data) > 5*1024*1024`
  branch decides the client side only.
- "The non-trailer aws-chunked path" overstates what the plain-HTTP leg covers: it
  carries no aws-chunked framing at all. Measured, a full TLS run hits the buffered
  chunked path 718 times and a plain-HTTP run zero
  ([ADR 0019](../adr/0019-integration-and-e2e-tests-are-the-product.md)). Corrected
  in place.
- Renaming `Encryption Overhead` is not free: the workflow's fallback extraction
  greps `Encryption Overhead:` and reports "data extraction failed" without it
  ([release.yml:353](../../.github/workflows/release.yml#L353)), and `performance.sh`
  matches the string again at [:432-433](../../performance.sh#L432-L433). Both move
  with the rename, along with the positional `grep -A 3` at
  [performance.sh:279](../../performance.sh#L279).
- The old decision and finding labels this ticket cited no longer resolve; they now
  read as the decision itself, [ADR 0020](../adr/0020-performance-is-measured-before-and-after.md)
  or [ADR 0013](../adr/0013-a-configuration-key-exists-only-if-code-reads-it.md).
  Corrected in place.

## Settled

- The gate runs against both proxy endpoints, not only the plain-HTTP one: the
  plain-HTTP leg exercises no chunked upload framing at all, so a regression
  confined to the trailer-framed path would pass unnoticed.
- Renaming the misleading summary line is its own commit, because the strings
  around it are a parsed interface.
- The two overlapping throughput tests are folded into one.
- The smallest two sizes are gated at a deliberately loose threshold and the table
  says so, rather than being quietly given a meaningless number.
- The module-cache wipe is deleted from `performance.sh`; it wipes a shared
  runner's cache for every other job.
- The recorded table names the key provider and the integrity setting it was
  recorded under.

---

## Context

Absolute throughput thresholds on a shared self-hosted runner fail on load, not
on regressions. That is why they were never switched on: the number the
assertion compares against is a property of the machine at that minute, not of
the code. `TestPerformanceComparison/100MB` failing at 17.6 % inside the full
suite and passing alone (coverage gap 7) was exactly that failure mode — the
suite was the load. `make test-integration-performance` with `-p 1` removed the
load the suite itself created; it did nothing about the load a second CI job,
a Renovate run, or another developer's e2e cluster puts on the same box.

A ratio against a plain-MinIO leg measured in the same run removes the
common-mode part of that noise. If the machine is half as fast for ten minutes,
both legs are half as fast and the ratio is unchanged. What survives is what we
actually want to gate on: *the proxy got slower relative to the storage it sits
in front of*.

This matters more than a normal test-hygiene ticket because of what is about to
land. CLAUDE.md puts performance second only to encryption-at-rest, and the v2
storage format rewrites the entire crypto path. Its own success criterion is
"the existing 1 GB benchmark does not regress on upload or download, small-object
throughput does not regress". Without an enforced gate that criterion is
evaluated by a human reading two log files. With one, it is a red CI step.

---

## Scope

**In scope**

- `test/integration/performance-test/` — both files.
- The `test-integration-performance` target in the [Makefile](../../Makefile#L105-L111).
- The performance steps of the `integration-tests` job in
  [release.yml](../../.github/workflows/release.yml#L278-L372).
- [performance.sh](../../performance.sh) where it sets the skip knob and where it
  parses test output by hardcoded source line number.
- Closes the enforcement half of
  [ADR 0020](../adr/0020-performance-is-measured-before-and-after.md). The
  coverage gap is already closed by the `-p 1` half; this is the alternative it
  also named, not a reopening.

**Out of scope**

- Storage format v2 itself ([ticket 013](013-storage-format-v2.md)). This ticket
  does not change any proxy code.
- The parallel-stream benchmark (ticket 012, item 6.2) and the small-object/QPS
  benchmark (item 6.3). They do not exist yet. When they do, they are born with a
  baseline leg and a row in the threshold table — the harness this ticket builds
  is what they plug into.
- Absolute-throughput tracking over time (a stored time series). Named as
  deliberately rejected in [What a ratio cannot catch](#what-a-ratio-cannot-catch).
- Runner sizing and the 60-minute job timeout, except where this ticket's own
  changes move the runtime budget.
- The 30 s `ReadTimeout`/`WriteTimeout` on the listener
  ([server.go:138](../../internal/proxy/server.go#L138)). Not fixed here — but it is not neutral for this ticket either. The upload leg is
  split into 5 MiB part requests by `manager.Uploader`, so it never approaches the
  deadline; a 1 GB **download** is one response under one 30 s `WriteTimeout`, so
  below ~35 MB/s on that leg the request fails outright instead of producing a low
  ratio. The 010 closing number (120 MB/s) leaves 3.4× headroom. Expect it when a
  recorded run shows a hard error at 500 MB or 1 GB rather than a bad number.

---

## Current state, verified

### Which tests already measure a direct-to-MinIO baseline

Exactly one.

| Test | File | Baseline leg? | Asserts on it? |
|---|---|---|---|
| `TestPerformanceComparison` | [performance_test.go:452](../../test/integration/performance-test/performance_test.go#L452) | **yes** — `tc.MinIOClient` at [:550](../../test/integration/performance-test/performance_test.go#L550), same sizes, same client settings, same subtest | computes efficiency at [:553-554](../../test/integration/performance-test/performance_test.go#L553), asserts at [:593](../../test/integration/performance-test/performance_test.go#L593) and [:597](../../test/integration/performance-test/performance_test.go#L597), both disarmed by the env knob at [:587](../../test/integration/performance-test/performance_test.go#L587) |
| `TestStreamingPerformance` | [performance_test.go:49](../../test/integration/performance-test/performance_test.go#L49) | no — proxy only | no assertion of any kind beyond a SHA-256 round-trip check |
| `TestStreamingVsStandardPerformance` | [streaming_test.go:140](../../test/integration/performance-test/streaming_test.go#L140) | no — despite the name, one leg only | measures a duration at [:161](../../test/integration/performance-test/streaming_test.go#L161), logs it, drops it |
| `TestStreamingMultipartUpload` | [streaming_test.go:25](../../test/integration/performance-test/streaming_test.go#L25) | n/a — correctness test, uses `MinIOClient` only to read the ciphertext at rest | not a timing test |
| `BenchmarkStreamingUpload` / `BenchmarkStreamingDownload` | [performance_test.go:277](../../test/integration/performance-test/performance_test.go#L277), [:347](../../test/integration/performance-test/performance_test.go#L347) | no | never executed — nothing in the Makefile or CI passes `-bench` |

`TestStreamingPerformance` and `TestPerformanceComparison` measure **the same
thing twice**: the same ten sizes (100 KB … 1 GB,
[:82](../../test/integration/performance-test/performance_test.go#L82) and
[:499](../../test/integration/performance-test/performance_test.go#L499)), the same
proxy endpoint, and the same upload style. `manager.Upload` with
`PartSize = 5 MiB` ([:172](../../test/integration/performance-test/performance_test.go#L172))
falls back to a single `PutObject` for any body at or below the part size, which
is precisely the branch `measureComparisonPerformance` takes explicitly at
[:628](../../test/integration/performance-test/performance_test.go#L628) /
[:643](../../test/integration/performance-test/performance_test.go#L643). Above
5 MiB both use `manager.Upload`, PartSize 5 MiB, Concurrency 3. So the gated run
pays for ten sizes twice, and only one of the two copies can ever be gated.

### The thresholds as they stand

```go
minEfficiency := 20.0                                    // performance_test.go:578
if os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != "" {
    minEfficiency = 15.0                                 // :582
}
if os.Getenv("SKIP_PERFORMANCE_CHECKS") == "true" { ... } // :587
```

One number for every size, from 100 KB to 1 GB, relaxed by a quarter in CI, and
switched off there anyway. A 100 KB round trip is dominated by per-request fixed
cost — SigV4 canonicalisation, DEK generation, KEK wrap, HKDF — and a 1 GB round
trip by the bulk crypto floor. A single threshold that both must clear can only
be set low enough to be meaningless for one of them. Today it is 15 %: the proxy
would have to be **more than six times slower** than plain MinIO before CI
noticed, and even that is switched off.

`SKIP_PERFORMANCE_TESTS` at
[:454](../../test/integration/performance-test/performance_test.go#L454) skips the
comparison test outright. Nothing in the repository sets it.

### Where the knob is set

| Location | What it disarms |
|---|---|
| [release.yml:265](../../.github/workflows/release.yml#L265) | `make test-integration` — the perf package is not in `INTEGRATION_PKGS` ([Makefile:83](../../Makefile#L83)), so this one has no effect at all |
| [release.yml:276](../../.github/workflows/release.yml#L276) | `make test-integration-tls` — same, no effect |
| [release.yml:288](../../.github/workflows/release.yml#L288) | `make test-integration-performance` — **this is the one that matters** |
| [release.yml:372](../../.github/workflows/release.yml#L372) | the `performance.sh` reporting step |
| [performance.sh:164](../../performance.sh#L164) | exported inside the script itself, so the reporting run stays advisory regardless of the environment |

### Two defects that block enforcement

**(a) The encrypted comparison bucket is never cleaned.**
`TestPerformanceComparison` clears `performance-test-bucket` on the proxy and
`performance-test-bucket-unencrypted` on MinIO
([:478-479](../../test/integration/performance-test/performance_test.go#L478)),
then creates and writes to `performance-test-bucket-**encrypted**`
([:482](../../test/integration/performance-test/performance_test.go#L482)) and
`-unencrypted` ([:489](../../test/integration/performance-test/performance_test.go#L489)).
The `-encrypted` bucket is never in the clear list. Object keys carry
`time.Now().UnixNano()` ([:546](../../test/integration/performance-test/performance_test.go#L546)),
so nothing is ever overwritten. The deferred cleanup at
[:465-473](../../test/integration/performance-test/performance_test.go#L465) is
gated on `CLEANUP_AFTER_PERFORMANCE_TEST` and, when it does run, calls
`tc.CleanupTestBucket()` — which cleans `tc.TestBucket`, the random
`test-bucket-<nanos>` created by `NewTestContextWithTimeout`
([minio_test_helper.go:128](../../test/integration/minio_test_helper.go#L128)) and
never written to by this test.

That is ~1.7 GB of ciphertext per comparison run, and the CI job runs the
comparison twice (the `make` step and `performance.sh`), so ~3.3 GB inside one
job; with the repetitions this ticket adds, ~5 GB. It does **not** accumulate
across CI runs: the job brings the stack up with `up -d --build`
([release.yml:206](../../.github/workflows/release.yml#L206)) and tears it down with
`docker compose ... down -v`
([release.yml:457](../../.github/workflows/release.yml#L457)), which destroys the
MinIO volume. Where it does accumulate without bound is the long-lived
`./start-demo.sh` stack — every local iteration and the deliberate-slowdown check
of success criterion 2 — and, inside one CI job, between the first and the second
comparison run. A baseline leg measured against a MinIO whose bucket is larger
every time is not a baseline. Fix it because the measurement depends on it, not
because a CI disk is filling.

Also note `clearPerformanceTestBucket`
([:238](../../test/integration/performance-test/performance_test.go#L238)) issues a
single un-paginated `ListObjectsV2`, so it clears at most 1000 keys per call.

**(b) `performance.sh` parses test output by source line number.**
[performance.sh:300](../../performance.sh#L300) greps for `performance_test.go:110:`
to find the streaming results table. Line 110 today is
`t.Log("=== QUICK MODE: ...")`
([performance_test.go:110](../../test/integration/performance-test/performance_test.go#L110)),
which in the full mode CI runs never prints at all; the per-size result line has
drifted to [:128](../../test/integration/performance-test/performance_test.go#L128).
The streaming section of every generated report is therefore already empty. Any
edit to this file moves the number again.

The other scrapers are string-based and must keep working:
[performance.sh:243](../../performance.sh#L243) matches the table rows printed at
[performance_test.go:557](../../test/integration/performance-test/performance_test.go#L557),
and [release.yml:341](../../.github/workflows/release.yml#L341) greps
`Average Upload Efficiency: <n>%` out of
[printComparisonSummary](../../test/integration/performance-test/performance_test.go#L705)
to build the performance badge. **Those two literal strings are an interface.**

---

## Design

### The measurement

Per size, per repetition, measure both legs and take the ratio of that
repetition. Then assert on the **median of the ratios**, not on the ratio of the
medians and not on a single pair.

```
for rep := 0; rep < reps; rep++ {
    // alternate the order: always measuring the proxy first would hand the
    // MinIO leg a warm page cache for an object of the same size, and would
    // give any monotonic warm-up drift a fixed sign
    if rep%2 == 0 {
        enc, plain = measure(proxyClient), measure(minioClient)
    } else {
        plain, enc = measure(minioClient), measure(proxyClient)
    }
    upRatio[rep]   = enc.upload   / plain.upload
    downRatio[rep] = enc.download / plain.download
}
assert median(upRatio)   >= threshold[size].upload
assert median(downRatio) >= threshold[size].download
```

Why median of ratios: a load spike cancels in the ratio only if it covers both
legs of that repetition. A spike that lands inside one leg produces one bad
ratio, and the median discards it. Averaging would not. `reps = 3` is the
smallest count for which a median exists and one outlier is survivable.

Cost: three repetitions of both legs over all ten sizes moves roughly
`3 × 2 × 2 × 1.67 GiB ≈ 20 GiB` through the loopback. At the 010 closing numbers
(80 MB/s up, 120 MB/s down through the proxy; MinIO faster) that is on the order
of five minutes, plus per-request overhead on the small sizes. Affordable — and
it is paid for by removing the duplicate below.

### `measureComparisonPerformance` keeps its shape

[performance_test.go:621](../../test/integration/performance-test/performance_test.go#L621)
already takes a client and returns upload/download throughput. It is the leg
function. Nothing about its per-size upload-style rule
([:628](../../test/integration/performance-test/performance_test.go#L628)) changes:
both legs must keep using the same client settings, or the ratio measures the
SDK rather than the proxy.

### Which test gets a baseline leg, and which stops running in CI

- `TestPerformanceComparison` — has one. It becomes the single **gated**
  measurement.
- `TestStreamingPerformance` — does **not** get a baseline leg. It is the
  profiling harness ticket 012's measurement protocol names
  ([ticket 012](012-performance-audit-round2.md), "Measurement protocol" and
  "Done criteria"), and it is otherwise a duplicate of the comparison test's
  proxy leg. It stays in the tree, run by hand alongside a pprof capture, and
  leaves the CI step via `-run`. That removes ten redundant sizes from the gated
  run and pays for the repetitions.
- `TestStreamingVsStandardPerformance`
  ([streaming_test.go:140](../../test/integration/performance-test/streaming_test.go#L140))
  — its name promises a comparison it does not make, and the duration it
  measures is never asserted on. Its end-user contract, a 20 MiB client-driven
  multipart round trip that hashes equal, is a strict subset of
  `TestStreamingMultipartUpload`
  ([streaming_test.go:25](../../test/integration/performance-test/streaming_test.go#L25)),
  which additionally asserts the object is ciphertext at rest — the only
  difference is 20 MiB (4 parts) versus 10 MiB (2 parts). Raise
  `TestStreamingMultipartUpload` to 20 MiB
  ([:35](../../test/integration/performance-test/streaming_test.go#L35)) and delete
  the duplicate: no coverage is lost, and the trap of a half-a-comparison test
  sitting next to the ratio work goes with it. **If the reviewer would rather
  keep it, keep it** — it costs about a minute of runtime and nothing else; it
  must not, however, be left with a name that claims a baseline it has not got.
- The two `Benchmark*` functions
  ([:277](../../test/integration/performance-test/performance_test.go#L277),
  [:347](../../test/integration/performance-test/performance_test.go#L347)) are
  never executed by any target. They are not gated and this ticket does not
  change them; noted so nobody mistakes them for coverage.
- The kopia-shaped **ranged-read benchmark** (4 KiB / 64 KiB / 4 MiB reads from a
  20 MiB object) does not exist yet. v2 adds it. It must be born with a
  direct-MinIO leg — a ranged GET of the same window against the same object
  written directly — and a row in the table below.
  [Ticket 013](013-storage-format-v2.md) already specifies the benchmark under
  its Success criteria ("New benchmark, kopia-shaped ranged reads": reads/s,
  MB/s, p50/p99 and backend byte amplification) but names **no baseline leg** for
  it. That requirement has to be added there; it is one of the two edits this
  ticket owes 013, the other being the re-pick checkbox.

### The threshold table

One row per size, two numbers per row, filled from at least three recorded runs
on the actual self-hosted runner. **Do not invent these numbers.** They live in
one `map[string]ratioThreshold` in the test file, next to a comment pointing at
this table.

Derivation rule, so the next person can re-derive them mechanically:

```
threshold = floor_to_0.05( min_over_runs(observed_ratio) × 0.80 )
```

20 % headroom below the worst of at least three runs. A real regression has to
be worse than the worst noise the runner produced across three runs before it
trips, which is the trade that keeps a gate credible.

Two rules that go with it:

- If the worst observed ratio for a size comes out below **0.30** — the proxy
  more than three times slower than the storage behind it — that is a finding,
  not a threshold. Report it (CLAUDE.md: stop and report an underperforming
  implementation) before locking a number in.
- Record the **absolute** MB/s of both legs alongside the ratio. A future reader
  needs to be able to tell "the ratio held but everything got slower" from a
  proxy regression, and the ratio alone cannot say that.

| Size | Run 1 up / down | Run 2 up / down | Run 3 up / down | min | **threshold up / down** | abs. proxy MB/s (up / down) | abs. MinIO MB/s (up / down) |
|---|---|---|---|---|---|---|---|
| 100 KB | | | | | | | |
| 500 KB | | | | | | | |
| 1 MB | | | | | | | |
| 3 MB | | | | | | | |
| 5 MB | | | | | | | |
| 10 MB | | | | | | | |
| 50 MB | | | | | | | |
| 100 MB | | | | | | | |
| 500 MB | | | | | | | |
| 1 GB | | | | | | | |
| ranged 4 KiB (v2) | | | | | | | |
| ranged 64 KiB (v2) | | | | | | | |
| ranged 4 MiB (v2) | | | | | | | |

Runner and stack identification for the three runs (fill in with the numbers):
CI run URLs, `docker-compose.demo.yml` MinIO CPU cap
([2.0](../../docker-compose.demo.yml#L42)), proxy memory limit (512 M), proxy
endpoint used (`http://127.0.0.1:8080`,
[minio_test_helper.go:40](../../test/integration/minio_test_helper.go#L40)) and
MinIO endpoint (`https://127.0.0.1:9000`,
[minio_test_helper.go:38](../../test/integration/minio_test_helper.go#L38)).

### What a ratio cannot catch

State this in the test file, not only here:

- **A uniform slowdown.** If MinIO regresses, or the runner is re-provisioned on
  slower disks, both legs move together and the gate stays green. Deliberate:
  the alternative is an absolute threshold, which is the thing that flakes. The
  absolutes are logged and end up in the badge; the gate is the ratio.
- **A regression smaller than the headroom.** With 20 % headroom, a 10 % loss
  passes. Accepted: a gate that catches 10 % on this runner would be red half
  the time for reasons unrelated to the code.
- **Anything outside the measured shapes.** Ten object sizes, one upload style
  per size, whole-object reads, one concurrency, one client transport. Ranged
  reads are not covered until v2 adds them; small-object QPS is not covered until
  ticket 012 item 6.3 exists.
- **The transport asymmetry.** The proxy leg runs client→proxy over plain HTTP
  and proxy→MinIO over TLS; the baseline leg runs client→MinIO over TLS. Both
  legs carry exactly one TLS hop, but not the same one, and the proxy leg carries
  an extra plaintext hop. The ratio is therefore "proxy path versus direct path",
  not "cost of encryption". Do not describe it as the latter in the badge or the
  README.

### Enforcement: delete the knobs, do not default them

`SKIP_PERFORMANCE_CHECKS` and `SKIP_PERFORMANCE_TESTS` both go, along with the
`CI`/`GITHUB_ACTIONS` relaxation at
[performance_test.go:581](../../test/integration/performance-test/performance_test.go#L581).
Reason: a control that exists only in configuration or documentation is worse
than no control
([ADR 0013](../adr/0013-a-configuration-key-exists-only-if-code-reads-it.md)). An env var that turns the gate off will be
set the first time the gate goes red, and CLAUDE.md forbids skipping or disabling
integration tests. The package is already behind the `integration` build tag and
already skips itself when MinIO or the proxy are unreachable
([`EnsureMinIOAndProxyAvailable`](../../test/integration/minio_test_helper.go#L407)) —
that is the whole of the legitimate skip logic.

`QUICK_MODE`
([performance_test.go:103](../../test/integration/performance-test/performance_test.go#L103),
[:520](../../test/integration/performance-test/performance_test.go#L520)) stays: it
is a local-iteration convenience, CI never sets it, and
[performance.sh:166](../../performance.sh#L166) deliberately does not export it.
The threshold table still has to cover all ten sizes.

### CI steps

Today the job runs the ten sizes **four** times: `TestStreamingPerformance` and
`TestPerformanceComparison` in the `make test-integration-performance` step
([release.yml:283](../../.github/workflows/release.yml#L283)), then both again
inside `performance.sh` ([release.yml:290](../../.github/workflows/release.yml#L290),
`go test -run="TestPerformanceComparison|TestStreamingPerformance"` at
[performance.sh:187](../../performance.sh#L187)) — a run that additionally does
`go clean -cache -testcache -modcache` ([performance.sh:170](../../performance.sh#L170))
and a full rebuild on a shared runner. The job budget is
`timeout-minutes: 60` ([release.yml:183](../../.github/workflows/release.yml#L183))
for integration + TLS integration + both performance runs.

Consolidate: the enforced `make test-integration-performance` step tees its
output to a file, and the reporting step generates the markdown report and the
badge from **that** output instead of re-running the tests. One measured run per
CI job, one set of numbers, and the badge stops being able to disagree with the
gate. This is in scope because the repetitions this ticket adds have to come out
of somewhere, and because two runs with different enforcement in one job is
exactly the ambiguity that made the thresholds advisory in the first place.

---

## Ordering against storage format v2

v2 ([ticket 013](013-storage-format-v2.md)) replaces the CTR + HMAC-SHA256 two-pass path with a
single segmented AES-GCM pass, deletes the post-Complete self-`CopyObject`
([complete.go:223](../../internal/proxy/handlers/multipart/complete.go#L223)), makes
client-driven parts independent, and adds 28 bytes per 64 KiB segment. Every
ratio in the table moves — upward on the large sizes if the expectation holds,
by an unknown amount on the small ones — and the ranged-read rows do not exist
before it.

**Recommendation: land this ticket first, with pre-v2 numbers, and re-pick the
table as the closing step of the v2 ticket.**

Why that way round and not "wait for v2 and pick once":

- The threshold picking is the cheap half. Three recording runs are three
  ordinary CI runs on a PR; the second round costs one PR that edits one map.
- Not enforcing until v2 means the single largest change to the crypto path in
  the project's history is developed and merged with no gate at all — and v2's
  own success criterion is precisely "the 1 GB benchmark does not regress,
  small-object throughput does not regress". With this ticket landed, that
  criterion is a CI step v2 has to turn green; without it, it is two log files
  and a judgement call.
- A pre-v2 table is also the evidence v2 needs: the "before" column of its own
  performance argument, recorded by the same harness on the same runner, rather
  than numbers quoted from ticket 010 on different hardware.

The re-pick is an explicit checkbox on the v2 ticket, not an afterthought here:
after v2 lands, three fresh runs, new table, same derivation rule, plus the three
ranged-read rows. If v2 makes a size *faster*, the threshold moves up with it —
a gate that keeps yesterday's number after a known improvement stops catching
tomorrow's regression.

---

## Work breakdown

**Decided 2026-09-09 (repository owner, ADR 0020 D17): the baseline is prepared in full
before 013 lands**, so that every statement about the difference between the two formats
rests on a number taken by the same instrument on the same runner. This ticket therefore
grows beyond the threshold work; the items below stay, and these join them, all on the
pre-v2 commit:

- [ ] **Both transports.** Record and gate the plain-HTTP and the TLS listener; the table
      carries both.
- [ ] **The kopia-shaped ranged-read benchmark**, with a direct-to-MinIO leg: 4 KiB, 64 KiB
      and 4 MiB ranges at random offsets of a 20 MiB object, reads/s, MB/s, p50/p99, bytes
      fetched per byte returned. Created here, not in 013 item 15; 013 only re-runs it.
- [ ] **The small-object request-rate benchmark** (012 item 6.3): 4 KiB and 256 KiB objects
      at concurrency 16, QPS and p50/p99, both legs.
- [ ] **`BenchmarkDEKUnwrap`** for the `aes` provider, so the single-unwrap obligation of
      024 P-1 / ADR 0020 D5 has its "before".
- [ ] **The memory test of 013** run on the pre-v2 commit, its numbers recorded here: a
      bound the old code fails measures GC noise, not the format.
- [ ] **CPU profiles** of the 1 GB upload and download and of the ranged-read benchmark,
      archived with the run URLs, so the "HMAC-SHA256 disappears, GHASH does not replace all
      of it" expectation of 013 can be confirmed or refuted from data.
- [ ] **Smallest sizes: a deliberately loose threshold, named as such in the table.**
      Settled; not report-only.
- [ ] **Rename the "Encryption Overhead" summary line** to what it measures, in its own
      commit, before the table is filled; adjust the two parsers with it.

- [ ] **Fix the leaking comparison bucket.** Clear `-encrypted` as well as
      `-unencrypted` before the run, page `clearPerformanceTestBucket`
      ([performance_test.go:238](../../test/integration/performance-test/performance_test.go#L238))
      through continuation tokens, and delete the objects the run wrote at the
      end of it. Drop `CLEANUP_AFTER_PERFORMANCE_TEST` and
      `CLEANUP_OBJECTS_AFTER_PERFORMANCE_TEST`: cleaning up is not optional when
      the run repeats three times and CI runs it on every push to `main` and every
      PR against it. Verify against a long-lived `./start-demo.sh` stack — not in
      CI, where `down -v` hides it — that MinIO's volume stops growing across two
      consecutive runs.
- [ ] **Take `TestStreamingPerformance` out of the gated step**, leaving it in the
      tree as ticket 012's profiling harness. The `-run` filter belongs in the CI
      step, **not** in `test-integration-performance` itself: ticket 013 names
      `make test-integration-performance` as the way it runs the 1 GB benchmark for
      its own no-regression criterion, so that target has to keep running the test.
      Update the comment at [Makefile:105-108](../../Makefile#L105-L108) to say what
      each invocation now runs and why.
- [ ] **Fold `TestStreamingVsStandardPerformance`**: raise
      `TestStreamingMultipartUpload` to 20 MiB and delete the duplicate
      ([streaming_test.go:140](../../test/integration/performance-test/streaming_test.go#L140)).
      CLAUDE.md forbids disabling, skipping or removing integration tests — this is
      a fold, not a removal (the 20 MiB round trip moves into a test that also
      asserts ciphertext at rest), and it needs the reviewer's explicit yes for
      exactly that reason. Reviewer may veto; if kept, it gets a name that does not
      claim a baseline.
- [ ] **Add the repetition and ordering machinery** to
      `TestPerformanceComparison`: `reps = 3`, alternating leg order, per-repetition
      ratios, median. Keep the per-size table row
      ([:557](../../test/integration/performance-test/performance_test.go#L557)) and
      the `Average Upload/Download Efficiency:` summary lines
      ([:705-708](../../test/integration/performance-test/performance_test.go#L705))
      byte-compatible — `performance.sh` and the badge step parse both.
- [ ] **Print one machine-readable line per measurement** (size, leg absolutes,
      each repetition's ratio, the median, the threshold, pass/fail) so filling
      the table from a CI log is copy-and-paste, not arithmetic.
- [ ] **Replace the assertions with ratio assertions** against a
      `map[string]ratioThreshold` seeded with placeholder values that fail loudly
      if the table has not been filled — never with a value low enough to pass by
      accident.
- [ ] **Fix `performance.sh`'s line-number scraper**
      ([performance.sh:300](../../performance.sh#L300),
      [:310](../../performance.sh#L310), [:312](../../performance.sh#L312)) to match on
      a stable marker string emitted by the test instead of
      `performance_test.go:110:`.
- [ ] **Consolidate the CI steps**: tee the enforced run's output, generate the
      report and badge from it, delete the second full run from
      [release.yml:290](../../.github/workflows/release.yml#L290) /
      [performance.sh:187](../../performance.sh#L187). Record the resulting job
      wall-clock against the 60-minute budget.
- [ ] **Record three runs** on the actual self-hosted runner with the assertions
      still disarmed, and fill the table in this ticket — run URLs included.
- [ ] **Fill the thresholds** from the derivation rule; report anything below
      0.30 rather than encoding it.
- [ ] **Delete `SKIP_PERFORMANCE_CHECKS`** from
      [performance_test.go:587](../../test/integration/performance-test/performance_test.go#L587),
      [performance.sh:164](../../performance.sh#L164) and all four
      [release.yml](../../.github/workflows/release.yml#L265) occurrences; delete
      `SKIP_PERFORMANCE_TESTS`
      ([:454](../../test/integration/performance-test/performance_test.go#L454)) and
      the CI relaxation branch
      ([:581](../../test/integration/performance-test/performance_test.go#L581)).
- [ ] **Inject a deliberate slowdown locally and confirm the gate catches it**
      (see success criteria).
- [ ] **Write down where the numbers came from**, so the next person who sees a
      red performance step knows whether to fix the code or re-record the table:
      the table above plus a comment on the threshold map pointing at it.
      `DEVELOPER.md` does not exist in this tree yet (the documentation standard
      wants it, like `SECURITY_ARCHITECTURE.md`); when it is created, the
      derivation rule and the re-record procedure belong in its build/test
      section.
- [ ] **Add the re-pick checkbox to [ticket 013](013-storage-format-v2.md)** — it
      is already written, so this is an edit to its work breakdown and success
      criteria, not something to wait for: three fresh runs and a new table after
      v2 lands, plus the three ranged-read rows and the direct-MinIO leg its
      ranged-read benchmark currently does not have.

---

## Success criteria

1. **Three consecutive green CI runs with enforcement on.** The
   `Run performance integration tests in isolation` step
   ([release.yml:283](../../.github/workflows/release.yml#L283)) has no
   `SKIP_PERFORMANCE_CHECKS` in its environment, the thresholds are the ones in
   the table, and three consecutive runs pass. The workflow triggers only on
   `push` to `main` and on `pull_request` against it
   ([release.yml:3-10](../../.github/workflows/release.yml#L3-L10)), so that means
   three runs on the open PR carrying this work against `main`. Not three re-runs of the same commit — three runs, so that runner load
   varies between them.
2. **A deliberate slowdown is caught.** Locally, with the demo stack up:
   - *download leg*: `copyWithPooledBuffer`
     ([helpers.go:28](../../internal/proxy/handlers/object/helpers.go#L28)) is a
     three-line wrapper around `io.CopyBuffer` and has no loop of its own, so the
     injection is to replace that call with an explicit read/write loop that also
     runs a throwaway `sha512.Sum512(buf[:n])` per chunk — a real second hash
     pass, the shape an accidental regression actually takes;
   - *upload leg*: one throwaway `sha512.Sum512(partData)` per part in
     `processPartOrdered`
     ([multipart.go:242](../../internal/orchestration/multipart.go#L242)), which
     already holds the whole part in a buffer. Note it is only reached above
     5 MiB — below that the comparison test uses `PutObject`, so the small sizes
     cannot move on this leg;

   rebuild via `./start-demo.sh`, run `make test-integration-performance`, and
   record which sizes go red. At least the sizes at and above 10 MB must fail on
   the affected leg. If none do, the headroom is too generous and the derivation
   rule needs revisiting — write down which sizes failed and by how much, then
   revert the injection.
3. **`make test-integration` and `make test-integration-tls` unchanged and
   green.** This ticket touches no proxy code; both suites are the control.
4. **`make test-unit` green**, plus
   `go vet -tags=integration ./test/integration/performance-test/...` clean.
   `make test-unit` runs without the `integration` tag, so it does not compile this
   package at all — `go test ./test/integration/performance-test/...` matches no
   packages. The tagged vet run is the compile check; `make test-unit` is only the
   regression check on everything else.
5. **The Velero e2e is unaffected**: `make e2e-up && make test-e2e-velero`
   (`./test/e2e/velero`) green, 13/13 scenarios. It shares the runner with the
   performance job; the consolidation must not have changed what the perf step
   leaves behind on MinIO.
6. **MinIO's volume does not grow across two consecutive
   `make test-integration-performance` runs** — measured, not assumed.
7. **The badge still renders.** `performance.sh` produces a report with a
   populated streaming section and a `Average Upload Efficiency:` line, and
   [release.yml:341](../../.github/workflows/release.yml#L341) extracts a non-zero
   number from it.

---

## Risks and open questions

- **The ratio is blind to a uniform slowdown.** Accepted, documented above. If
  MinIO or the runner regresses, nothing goes red. The absolutes are logged for
  the human who eventually notices; no alerting is proposed here.
- **Three runs may not be three samples.** If CI is idle at the same time of day
  for all three, the "worst observed" is not worst-case and the first busy run
  after enforcement is red. Mitigation: prefer three runs that visibly differ in
  wall-clock; if the first enforced week produces a false red, re-record rather
  than lowering the number by feel — and write the re-record into the table so
  the history is visible.
- **Unverified: how much of the observed variance the ratio actually removes.**
  The premise of this whole ticket — that noise on this runner is common-mode
  across both legs — is reasoned, not measured. The three recording runs are the
  measurement; if the per-repetition ratios within one run scatter as widely as
  the absolutes do across runs, the premise is wrong and the design needs
  revisiting (more repetitions, or gating only the large sizes where the
  measurement window is long enough to average the noise out). **Check this
  explicitly when the first table is filled.**
- **Small sizes may be too noisy to gate at all.** A 100 KB round trip is
  milliseconds; scheduler jitter is a large fraction of it. **Settled 2026-09-09
  (ADR 0020 D17):** gate them at a deliberately loose threshold and say so in the
  table; not report-only. The small-object/QPS benchmark joins this ticket. Do not
  quietly pick a threshold of 0.05 and call it enforced.
- **v2 will move every number**, and if it slips, the pre-v2 table ages against
  unrelated changes. Re-record whenever a change is expected to move throughput,
  not only after v2.
- **The transport asymmetry** (plain-HTTP client leg on the proxy path, TLS on
  the baseline path) means the ratio is not "cost of encryption". The badge
  currently labels it `performance` and the summary calls it
  `Encryption Overhead` ([performance_test.go:710](../../test/integration/performance-test/performance_test.go#L710)).
  **Settled 2026-09-09 (ADR 0020 D17):** rename the summary line to what it
  measures, touching the strings [release.yml:341](../../.github/workflows/release.yml#L341)
  and [performance.sh:243](../../performance.sh#L243) parse, in one commit of its
  own, before the table is filled.
- **The perf package never runs against the TLS proxy endpoint.**
  `test-integration-performance` ([Makefile:109](../../Makefile#L109)) does not set
  `S3EP_TEST_PROXY_ENDPOINT`, so the gated numbers only ever cover the
  plain-HTTP listener, which carries no aws-chunked framing at all. A regression that
  only affects the `STREAMING-UNSIGNED-PAYLOAD-TRAILER` path — the default for
  every modern SDK over HTTPS, and the path BUG-001 hid in — would not be
  caught. Settled above: both transports are gated, which doubles the run and
  doubles the table.
- **`go clean -modcache` in `performance.sh`**
  ([performance.sh:170](../../performance.sh#L170)) wipes the shared runner's module
  cache for every other job. Consolidating the CI steps removes it from the CI
  path. Settled above: it is deleted outright.
