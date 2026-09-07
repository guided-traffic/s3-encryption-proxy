# Ticket 012: Performance Improvements Round 2 — Post-010 Audit Findings

## Status (2026-06-11)

**Open.** Findings produced by a multi-agent audit (8 independent lenses: upload
path, download path, crypto primitives, HTTP/network, concurrency/pipelining,
pprof residuals, format-level changes, end-to-end bottleneck), every finding
adversarially verified against current `main` (post-010 squash merge) and the
archived pprof profiles in [docs/tickets/010-tier4.1/](010-tier4.1/). 15 findings
confirmed, 4 rejected with rationale (see "Explicitly not doing" at the bottom).

**Update 2026-09-06, from the Velero round.** Three of the confirmed findings
were closed there, for correctness reasons rather than for the throughput they
were filed under, so the tiers below are not all still open:

- **1.1**, the SDK flexible checksums, in `1e6c017` (F-4).
- **3.2**, the blanket `501` on ranged GET, in `df12c84` (F-6) — kopia reads its
  pack blobs with small ranged GETs, so every Velero volume restore failed
  without it. The CTR seek landed as `NewCTRStreamAt` / `NewCTRRangeReader`
  ([aes_ctr.go:250-296](../../pkg/encryption/dataencryption/aes_ctr.go#L250))
  rather than as an offset parameter on the existing constructor. It carries a
  security consequence this ticket never weighed: a ranged AES-CTR read is not
  covered by the whole-object HMAC, which is D-1 and is why
  [013](013-storage-format-v2.md) exists.
- **3.3**, the HEAD half, in `646932b` (F-7). The List half is still open and is
  [018](018-listobjectsv2-document.md).

Everything else stands as written, unverified since 2026-06-11. The two items
the Velero work cites are **1.2** (the 30 s timeouts) and **3.1** (the multipart
completion rework, which is also what removes the >5 GiB failure); the label
index in [README.md](README.md#label-index) points here for both.

## Before you start

Re-checked against the tree on 2026-09-07. Everything not listed here is still
unverified since 2026-06-11.

- **1.2** says the monitoring server drops `WriteTimeout` while pprof is on.
  pprof now runs on its own loopback listener
  ([pprof.go](../../internal/monitoring/pprof.go)) and carries that reasoning;
  the monitoring server sets both 30 s timeouts unconditionally. Corrected below.
- **1.3** still describes the tree — the five Info logs, the `%T` sniff,
  `shouldValidateHMACEarly`/`validateHMACEarly` and the ~250 unreachable lines
  are all present, at drifted line numbers. Only "zero test callers" is false:
  the coverage round added tests for `DecryptMultipartWithHMACVerification` and
  `hmacGatedDecryptionReader`, so those go with the code.
- **2.1**: the `Content-MD5` fix and the deletion of `handleStandardUploadPart`
  landed; `Manager.UploadPartStreamingBuffer` survives, test-only. Ticked below.
- **2.1** step 1 no longer costs ×2–3: `Parser.ReadBody` is one pre-sized read
  capped at 32 MiB (`maxBodyPrealloc`,
  [parser.go](../../internal/proxy/request/parser.go)), which also answers the
  allocation-DoS note for that path. The redundant copy left is
  `processPartOrdered`.
- **2.1** side defect half closed: a PUT whose `partNumber` is not a number is
  refused before any body read
  ([handler.go:148-165](../../internal/proxy/handlers/object/handler.go#L148));
  empty `uploadId` and an out-of-range part number still buffer the body first.
- **2.2** deletion list half done: `aws_chunked_decoder.go` is gone, the HTTP
  half (`RequiresChunkedDecoding`, `ProcessChunkedData`, `readLine`,
  `CreateOptimalReader`, `clean_http_transfer_chunked`) still exists and
  `parser.go` still routes through it.
- The rejection of a segmented format at the bottom is **reversed**: the
  segmented authenticated chain is adopted on integrity grounds
  ([ADR 0003](../adr/0003-objects-are-an-authenticated-segment-chain.md)). Its
  activation condition is void and Range-GET phase 2 is gated on that format,
  not on 6.2. Marked below.
- "HMAC-verified-before-release" in the Goal and in **4.2** is not a property of
  this tree: `hmacValidatingReader` releases every byte but the last chunk before
  it verifies, and is not built at all without a `Content-Length`. That invariant
  arrives with the segmented format. Corrected below.
- **6.1**'s plaintext-backend baseline is superseded by a decision, not yet by
  the tree: startup on an `http://` backend under an encrypting provider is to be
  refused with the 5.0.0 configuration cleanup
  ([ADR 0013](../adr/0013-a-configuration-key-exists-only-if-code-reads-it.md)),
  which leaves the pass-through provider as the only way to measure it. `use_tls`
  is still dead config and goes with the same ADR.
- **6.4**: `SetBlockProfileRate`/`SetMutexProfileFraction` are still called
  nowhere, but the gate belongs at `monitoring.NewPprofServer`
  ([main.go:196-204](../../cmd/s3-encryption-proxy/main.go#L196)), not beside the
  monitoring port.
- **1.1**'s "nothing outstanding" contradicted two unchecked boxes; both are
  closed below.

## Settled

- The optional knob that re-enables the SDK checksums is moot: the integrity
  mode it was paired with does not survive the segmented format (ADR 0003).
- The five per-read informational log lines go with the code the segmented
  format deletes; no metrics counter replaces them.
- The backend HTTP client keeps HTTP/1.1 and does not attempt HTTP/2, to avoid
  flow-control stalls on the backend leg.
- Part-size and concurrency defaults are re-picked after the performance
  baseline exists, not before.
- The benchmark-only compose profile lifts the memory and CPU caps on **both**
  proxy containers.
- Block and mutex profiling is switched on at the profiling listener, which is
  loopback-only (ADR 0013).
- This document is restructured as a fate table at the top — which tiers are done,
  which dissolve into the segmented format, which are members of the next major
  release, which land on the main line — with the audit text kept below it as
  the evidence.

---

## Context

Ticket [010](010-performance-improvements.md) finished with:

- upload **~80 MB/s**, download **~120 MB/s** (1 GB, local MinIO loopback, fresh proxy)
- proxy alloc_space **9.94 GB** per 1 GB round-trip
- proxy CPU: "crypto floor" ~42 %, syscalls ~23 %, memclr 11.7 %, memmove 7.2 %, GC ~8 %
- open follow-up: `io.ReadAll` = **64.6 % of alloc_space** on the upload-side
  v4-chunked body path

This audit root-caused that residual and found that two headline numbers from
010 were misattributed:

1. **The 1 GB benchmark exercises the client-driven multipart handler**
   ([internal/proxy/handlers/multipart/upload.go](../../internal/proxy/handlers/multipart/upload.go)),
   **not** the optimized `putObjectAutoMultipart` path. The benchmark client
   (`manager.NewUploader`, PartSize 5 MB — see
   [test/integration/performance-test/performance_test.go:170-180](../../test/integration/performance-test/performance_test.go#L170-L180))
   drives `UploadPart` requests, and that handler never received the streaming
   treatment from 010. It materializes every part **4–6×** in memory. That is
   the 6.4 GB `io.ReadAll` residual.
2. **The "42 % crypto floor" includes ~10 points of backend TLS.** pprof `-peek`
   shows `gcmAesEnc` (5.78 %) + `gcmAesDec` (4.34 %) sit 100 % under
   `crypto/tls` record AEAD (the proxy→MinIO HTTPS hop), not under the data-GCM
   path (the 1 GB object is CTR). The true data-crypto floor is ~32 %.

Additionally, the SDK's flexible checksums are silently enabled (~6 % flat CPU),
and several correctness bugs with direct performance consequences were found
(>5 GiB multipart fails, Range GETs 501, 30 s transfer kill switch, HEAD size
mismatch).

**Goal:** eliminate the upload-side buffering chain, reclaim the free CPU wins,
fix the perf-adjacent correctness bugs, and establish honest benchmarks —
while preserving the integrity guarantees this tree actually has (AEAD on the
GCM path, streaming memory bound ~110 MiB peak @ 1 GB). There is no
verify-before-release on the CTR path today.

---

## Measurement protocol (apply to every tier)

- [ ] Before starting a tier: fresh proxy via `./start-demo.sh`, run
      `TestStreamingPerformance` @ 1 GB, record upload/download MB/s (3 runs)
- [ ] Capture proxy-side profiles during the run (pprof enabled in
      [config/aes-example.yaml](../../config/aes-example.yaml)). **D-22 moved
      pprof off the published monitoring port onto `127.0.0.1:6060` inside the
      container**, so `localhost:9090` now answers 404 and the image is
      distroless with no shell to `docker exec` into. Use a throwaway container
      that shares the proxy network namespace:
      ```bash
      docker run --rm --network container:proxy curlimages/curl \
        -s 'http://127.0.0.1:6060/debug/pprof/profile?seconds=25' > proxy-cpu.out
      docker run --rm --network container:proxy curlimages/curl \
        -s 'http://127.0.0.1:6060/debug/pprof/allocs' > proxy-allocs.out
      go tool pprof -top -nodecount=20 proxy-cpu.out
      ```
- [ ] Archive before/after snapshots under `docs/tickets/012-tierN/`
- [ ] Full `make test-integration` green before declaring a tier done
- [ ] Compare against the 010 closing numbers (80 / 120 MB/s, alloc_space
      9.94 GB), not against the 010 header numbers

---

## Tier 1 — Free wins (S effort each, do first)

### 1.1 Disable AWS SDK flexible checksums — **done in `1e6c017` (F-4), 2026-09-05**

**File**: [internal/proxy/server.go:158-172](../../internal/proxy/server.go#L158-L172)
(was `:124-127` when this item was written)

Closed, and left here as the record of what was measured. Both options are
`WhenRequired` today and the comment above them now says why, at length. The two
checklist boxes that were still open are closed below rather than done — one
dropped, one never measured; the "related bug" underneath it turned out not to
exist and is written up as such.

What it was, on 2026-06-11: the comment read "Disable checksum validation for
MinIO compatibility" while the code set
`aws.RequestChecksumCalculationWhenSupported` /
`aws.ResponseChecksumValidationWhenSupported` — which **enables** default
flexible checksums: CRC32 over every PutObject/UploadPart ciphertext body
(plus aws-chunked trailer re-framing of the upload), and forced `ChecksumMode`
on every GetObject so each downloaded byte is CRC64-NVME-validated
(including ~8000 rebuilds of the 16 KiB slicing-by-8 table per 1 GB, because
CRC64-NVME is not a stdlib-cached polynomial).

Profile evidence ([docs/tickets/010-tier4.1/proxy-cpu-top20.txt](010-tier4.1/proxy-cpu-top20.txt)):
`crc64.update` 3.90 % + `makeSlicingBy8Table` 1.16 % + `crc32.ieeeUpdate`
0.8 % ≈ **5.9 % flat proxy CPU**. This is a third integrity pass: the proxy
already computes HMAC-SHA256 over plaintext, and the backend hop runs TLS.

- [x] Set `o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired`
      ([server.go:171](../../internal/proxy/server.go#L171))
- [x] Set `o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired`
      ([server.go:172](../../internal/proxy/server.go#L172))
- [x] Fix the comment to match reality
      ([server.go:158-170](../../internal/proxy/server.go#L158))
- [x] Optional config knob for deployments running `integrity_verification: off`
      that want SDK CRC back — **dropped 2026-09-07**: the mode it serves does not
      survive the segmented format (ADR 0003)
- [x] Verify no integration test asserts `Checksum*` headers on GET responses —
      and the response side is now asserted the other way round, by
      `TestWriteGetObjectResponse_EmitsOnlyTheAllowlist` and
      `assertNoChecksumHeaders`
      ([object_test.go](../../internal/proxy/handlers/object/object_test.go))
- [x] Before/after pprof: never captured for this change, and closed unmeasured

**The "related bug" underneath this item was refuted, not fixed. Do not
re-open it.** The claim was that
`internal/proxy/handlers/object/operations.go` forwards the backend's
ciphertext `Checksum*` headers onto a decrypted plaintext body. No response
path ever emitted such a header, on any backend: responses are composed from an
allowlist rather than proxied, and `grep -rn x-amz-checksum internal/ pkg/`
finds no `w.Header().Set` at all. What sat at the cited lines was dead field
copying — two `GetObjectOutput` literals restating about 25 fields of which the
writer reads five — cut down to what is emitted in `c359091`. The same finding
is recorded as N-6 (d) in the [label index](README.md#threat-model-findings-n-1-to-n-10),
and it is why ticket [014](014-upload-checksum-verification.md) touches the
upload path only. The trap that produced it: an SDK output struct carrying
`Checksum*` fields is not evidence that a header reaches the wire.

**Expected impact when this was written:** ~6 % flat proxy CPU reclaimed (hash
samples, not GC-absorbed), identity-framed uploads with exact Content-Length on
the proxy→S3 hop. Best effort-to-win ratio in this ticket. The change landed for
a correctness reason rather than this one — the SDK failed outright against a
plain-HTTP backend on an unseekable ciphertext stream — and the predicted CPU
saving was never measured.

**Risks:** with `integrity_verification: strict/hybrid` (not the default, which
is `off`), corruption
detection moves from upload-time CRC reject to first-GET HMAC failure —
acceptable, document it. Operations that mandate checksums (DeleteObjects)
still get them with `WhenRequired`.

### 1.2 Replace 30 s blanket HTTP timeouts (kills any transfer slower than 30 s)

**Decided 2026-09-07 (owner; [023](023-major-v5.md) decision 10).** Rides
5.0.0 as a member of the bundle, not `main`. Shape: delete `ReadTimeout` and
`WriteTimeout`, set `ReadHeaderTimeout` 30 s, keep `IdleTimeout`;
`shutdown_timeout` is the documented transfer budget on exit and replaces the
fixed 30 s context at [server.go:254](../../internal/proxy/server.go#L254) (that
context only produces an error log today — what hard-closes an in-flight
transfer is process exit after the drain loop in
[main.go:233-270](../../cmd/s3-encryption-proxy/main.go#L233) times out); the
Helm chart sets `terminationGracePeriodSeconds` = `shutdown_timeout` + 5
(it sets none today, so Kubernetes kills at 30 s whatever the budget says;
compose already has `stop_grace_period: 45s`). The fourth checkbox below
("document or extend") is answered: extend, with `shutdown_timeout` as the one
knob.

**File**: [internal/proxy/server.go:138-140](../../internal/proxy/server.go#L138)

`ReadTimeout: 30s` / `WriteTimeout: 30s` are wall-clock budgets for the ENTIRE
body read / response write. A 5 GB GET at 120 MB/s takes ~42 s → connection
reset mid-stream. Effective object-size cap = 30 s × client bandwidth
(~3.6 GB at 1 Gbps, ~375 MB at 100 Mbps). Benchmarks pass only because 12 MB
parts finish in <1 s. The pprof listener
([internal/monitoring/pprof.go](../../internal/monitoring/pprof.go)) drops
`WriteTimeout` for exactly this reason — a profile response streams for the
requested duration and would otherwise be cut mid-profile — while the monitoring
server keeps both 30 s timeouts. The same reasoning, one listener over, that
never reached the data plane.

**This is a correctness bug for any S3 client moving a large object over a real
link, not only a throughput cap.** Velero, for example, crosses the 30 s wall clock in both directions:
`velero backup download` streams one large tarball over whatever link the
operator has, so the `WriteTimeout` resets the connection mid-download at
exactly `30 s x client bandwidth`; and a node-agent (kopia) upload over a slow
link that moves less than one part per 30 s dies on the `ReadTimeout`. The same
30 s disconnect used to have a second, silent consequence — it cancelled the
post-completion encryption-metadata self-copy, which ran on the request context,
leaving a committed multipart object in the bucket as ciphertext with no
`s3ep-*` metadata. That half is closed: the copy now runs on
[`utils.CleanupContext`](../../internal/proxy/utils/utils.go#L119-L128)
(a `context.WithoutCancel` of the request context plus a 30 s budget), called at
[complete.go:226](../../internal/proxy/handlers/multipart/complete.go#L226). The
data-loss path is gone; the killed transfer is not.

- [ ] Replace with `ReadHeaderTimeout: 30 * time.Second`, keep `IdleTimeout: 60s`
- [ ] Drop `ReadTimeout`/`WriteTimeout`
- [ ] Slow-loris protection: extend per-connection deadlines per copy iteration
      via `http.NewResponseController` in the object handlers — on BOTH
      `r.Body` reads and response writes (a trickling PUT must not pin a
      goroutine forever)
- [ ] Conscious decision: long transfers now outlive the 30 s graceful-shutdown
      context in `Start()` ([server.go:252](../../internal/proxy/server.go#L252))
      and get hard-closed on exit — document or extend
- [ ] Integration test: GET/PUT that takes > 30 s (rate-limited reader) survives

**Expected impact:** availability fix, zero loopback throughput change.
Must-fix before any real-network or > 3 GB object claims.

### 1.3 Remove dead code + demote surviving per-GET Info logs

**Files**:
[internal/orchestration/streaming_io.go](../../internal/orchestration/streaming_io.go),
[internal/orchestration/singlepart.go](../../internal/orchestration/singlepart.go),
[internal/orchestration/multipart.go](../../internal/orchestration/multipart.go),
[internal/proxy/handlers/object/operations.go](../../internal/proxy/handlers/object/operations.go)

Verified dead / wasteful on the documented GET hot path:

1. **Five Info-level logrus entries per HMAC-validated CTR GET** that survived
   the 010 demotion: `singlepart.go:506` ("Created HMAC-validating decryption
   reader"), `streaming_io.go:217` ("Last chunk detected"), `:229` ("Validating
   HMAC..."), `:239` ("HMAC validation SUCCESSFUL"), `:178` ("Completed secure
   streaming").
2. **Constant-false `%T` sniff per GET**:
   [operations.go:361](../../internal/proxy/handlers/object/operations.go#L361)
   `strings.Contains(fmt.Sprintf("%T", output.Body), "streamingDecryptionReader")`
   — no such type exists anywhere; body is always `*orchestration.readCloserWrapper`;
   both branches do identical work.
3. **Hardwired-false early-HMAC machinery**: `shouldValidateHMACEarly`
   ([operations.go:221-227](../../internal/proxy/handlers/object/operations.go#L221-L227))
   returns false on all paths yet does metadata lookups + a Debug log per GET;
   `validateHMACEarly` (`:231-266`, whole-object `io.ReadAll`) is unreachable.
4. **~250 lines with zero callers** (grep-verified, also zero test callers):
   `DecryptMultipartWithHMACVerification` (multipart.go:755-825),
   `createStreamingDecryptionReader` (:831-846), and the entire
   `hmacGatedDecryptionReader` (streaming_io.go:254-381) built in 010 Tier 2.6.
   Production CTR GETs all use `hmacValidatingReader`, which is strictly better
   (decrypts in place in the caller's buffer, no per-chunk copy). Delete, don't tune.

- [ ] Demote the 5 Info logs to Debug (decide consciously: this removes the only
      default-visible per-object HMAC-success line; failures still log at Error —
      consider a Prometheus counter if success visibility is wanted)
- [ ] Delete the `%T` sniff, collapse `writeGetObjectResponse` to one branch
      (keep WriteHeader → copy → Close ordering; note the pre-existing benign
      double-close via the defer in `handleGetObjectStreamingDecryption`)
- [ ] Delete `shouldValidateHMACEarly` + `validateHMACEarly`
- [ ] Delete `DecryptMultipartWithHMACVerification`,
      `createStreamingDecryptionReader`, `hmacGatedDecryptionReader` + tests
- [ ] `go vet` / compiler pass for orphaned imports

**Expected impact:** tens of µs + a handful of allocs per GET (visible only on
small-object/high-RPS workloads); main value is removing dead/misleading code
from the hot path so future optimization doesn't target code that never runs
(two audit lenses independently wasted effort proposing tuning of the dead
gated reader).

---

### 1.4 D-29 — the pooled copy buffer is switched by the monitoring flag (024 P-2)

Assigned 2026-09-07 from [024](024-coverage-round-findings.md), decided.

`copyWithPooledBuffer` ([helpers.go](../../internal/proxy/handlers/object/helpers.go))
hands `io.CopyBuffer` a pooled 128 KiB buffer. `io.copyBuffer` checks `dst.(io.ReaderFrom)`
**first** and, when it matches, calls `dst.ReadFrom(src)` and ignores the buffer. With
monitoring off, `dst` is `*http.response`, which is a `ReaderFrom`: the pooled buffer is
ignored. With monitoring on, `monitoring.responseWriter`
([middleware.go](../../internal/monitoring/middleware.go)) embeds the writer and overrides
only `WriteHeader`, so it *hides* `ReadFrom`: the pooled buffer is used. The optimisation
this ticket's predecessor measured is therefore active in exactly one of the two modes, and
it is the mode with the extra wrapper. The same wrapper also drops `Flusher`, `Hijacker` and
`Unwrap`, so `http.NewResponseController` does not work while monitoring is on.

Decided: **make the pooled path apply in both modes first, then measure, then delete the
loser.** Concretely: wrap `dst` in a type that does *not* expose `ReadFrom` on both paths so
the pooled buffer is always the copy path; add `Unwrap`, `Flush` and `Hijack` passthroughs
to `responseWriter`; then run the performance suite twice — pooled path versus the
`net/http` `ReadFrom` path (which uses its own 32 KiB pool) — with monitoring on and off,
and keep whichever wins. Nothing is chosen ungauged: the defect was that a measured choice
had come to depend on an unrelated flag, and the cure is a measured choice that does not.

Related, not decided: P-1 (the double DEK unwrap) is **not** patched here — D-28 leaves it
to [013](013-storage-format-v2.md), which rewrites the path and inherits the measurement.

---

**Done 2026-09-07 — and the premise above is wrong about this tree.**

`s3Router.Use(s.loggingMiddleware)` at [router.go:58](../../internal/proxy/router.go#L58)
is **unconditional**, and `middleware.Logger.Middleware` wraps every S3 response in its own
`responseWriter` ([logging.go:30-63](../../internal/proxy/middleware/logging.go#L30)) —
the same shape as the monitoring one, embedding `http.ResponseWriter` and overriding only
`WriteHeader`. So `dst` hid `io.ReaderFrom` in **both** monitoring modes and the pooled
128 KiB buffer was already always used. The flag-dependence 024 P-2 and the table above
describe **does not exist**; there was no performance defect here.

What is real is the other half of the finding, and it is twice as broad as recorded: both
wrappers dropped `Unwrap`, `Flush` and `Hijack`, on **every S3 route, monitoring or not**,
so `http.NewResponseController` has never worked on this proxy. That is the thing that
blocks item 1.2's per-transfer write deadline, and it was attributed to a flag that turns
out not to matter.

(One smaller correction: `io.copyBuffer` checks `src.(io.WriterTo)` *before*
`dst.(io.ReaderFrom)` ([io.go:407-416](https://pkg.go.dev/io)); the item has the order
backwards. No type in this repository implements `WriteTo` today, so the source side is
not live — but a future body type that grows one bypasses the pooled buffer from the other
direction.)

**What was done.**

1. `copyWithPooledBuffer` now wraps `dst` in an unexported `writerOnly`
   ([helpers.go](../../internal/proxy/handlers/object/helpers.go)), so the pooled buffer is
   the copy path by construction rather than by accident of middleware composition. The
   wrapper never leaves the function, so nothing downstream loses a capability.
2. `Unwrap`, `FlushError`, `Flush` and `Hijack` were added to **both** wrappers.
   `FlushError` as well as `Flush`, because `http.ResponseController` prefers it and a bare
   `Flush` would silently swallow a flush error. Neither wrapper declares `ReadFrom`, and a
   test asserts that it stays undeclared: adding it would put the copy path back under the
   control of how many middlewares are in the chain, which is the defect this removes.
3. `BenchmarkGetResponseCopy`
   ([copy_bench_test.go](../../internal/proxy/handlers/object/copy_bench_test.go)) is the
   measurement instrument. It had to be written: no benchmark in the repository could
   resolve a response-buffer change, and after change 1 the `ReadFrom` path is unreachable
   through the server in every configuration, so the A/B does not exist as a deployment.

**The measurement, and the loser.** Apple M1 Ultra, darwin/arm64, `-benchtime 20x -count 6`,
64 MiB body, `httptest` over loopback, mean MB/s ± sd:

| cell | MB/s | ±sd | B/op | allocs/op |
|---|---|---|---|---|
| `h1/readfrom/no-wrapper` | 4204 | 222 | 48 304 | 83.0 |
| `h1/readfrom/forwarding-wrapper` | 4348 | 174 | 48 693 | 83.8 |
| `h1/pooled32k/wrapper` | 4381 | 224 | 15 373 | 79.2 |
| **`h1/pooled128k/wrapper`** | **4585** | 177 | 31 863 | 79.2 |
| `h1/pooled512k/wrapper` | 4283 | 276 | 102 084 | 79.2 |
| `tls/readfrom/no-wrapper` | 1593 | 38 | 33 142 | 121.5 |
| `tls/pooled128k/wrapper` | 1525 | 48 | 59 729 | 123.2 |

The decision rule was fixed before the run: keep the pooled buffer unless a `ReadFrom` cell
beats the 128 KiB pooled cell by more than 3 % in MB/s *and* does not lose on allocations,
in the plain-HTTP/1 cell — the only cell where `ReadFrom` can differ at all. It does not:
**the pooled 128 KiB buffer is 8.3 % faster and allocates a third less** (31.9 KB/op against
48.3 KB/op). The shipped size is also the right one — 32 KiB is 4.4 % slower, 512 KiB is
6.6 % slower and allocates three times as much. **The loser is `ReadFrom`, and deleting it
means never declaring it on the wrappers**, which is what the code and its test now enforce.

Two honesties about the instrument. `httptest` over loopback exaggerates syscall cost
relative to a real network path; that is the right bias for this question, because syscall
count and per-request allocation are exactly what separate the two paths, and the wrong
instrument for absolute MB/s. And the TLS pair is the one cell where `ReadFrom` looks
ahead, by 4.3 % — within about one standard deviation, on a path that is 3× slower overall
because TLS, not the copy, is the cost. It is also unreachable in production for the reason
this whole entry starts with.

**Noticed while measuring, not fixed, reported rather than smuggled in.** The ranged-read
response at [range.go:273](../../internal/proxy/handlers/object/range.go#L273) still uses a
bare `io.Copy`, so it is the one GET body copy that never got the pooled buffer — and it is
the path every ranged read takes — aws-cli/boto3 parallel downloads, kopia's pack-blob reads on a Velero volume restore. One-line change,
outside D-29's scope, needs an owner word.

## Tier 2 — Upload-path streaming rewrite (the 64.6 % `io.ReadAll` residual)

The three changes below share one root cause and should land as one coherent
change set. Combined expected impact: alloc_space on a 1 GB client-driven
multipart upload drops from **~9.9 GB to ~1–1.5 GB**; memclr (11.7 % CPU,
81 % attributed to `io.ReadAll` via `-peek`), memmove (7.2 %, 94 % this chain)
and ~8 % GC largely disappear; **expect ~10–20 % upload throughput gain** on
the loopback bench plus lower per-part latency (ciphertext can leave for S3
without waiting for multi-pass buffering).

### 2.1 Stream the client-driven multipart UploadPart handler

**File**: [internal/proxy/handlers/multipart/upload.go](../../internal/proxy/handlers/multipart/upload.go)

Current chain per part (verified, cum 9.90 GB = 99.6 % of alloc_space):

1. `upload.go:78` `Parser.ReadBody` → full-body materialization (×2–3, see 2.2)
2. `multipart.go:245-250` copies the part into a fresh 12 MiB buffer (see 2.3)
3. `upload.go:411` `io.ReadAll(encResult.EncryptedData)` re-copies the
   **already-in-memory** ciphertext (`*bytes.Reader` from `multipart.go:329`)
   with append-doubling growth — 100 % redundant
4. Side defect: `ReadBody` runs **before** uploadId/partNumber validation
   (`upload.go:88`), so invalid requests still buffer the full body

- [ ] Replace `ReadBody`/`ResetBody` (`upload.go:78,86`) with
      `requestParser.StreamingReader(r)` (header-only aws-chunked detection via
      `isAWSChunkedRequest`,
      [streaming_aws_decoder.go:141](../../internal/proxy/request/streaming_aws_decoder.go#L141)
      — already production-proven on the single-part PUT path) +
      `requestParser.DecodedContentLength(r)` for the plaintext part length
- [ ] Move uploadId/partNumber validation **before** any body read
- [ ] Feed the stream to `UploadPartStreaming`/`ProcessPart`: read once into a
      single exact-size buffer (`make([]byte, n)` + `io.ReadFull`; segment-size
      fallback when length unknown), run `HMAC.Add` + `CTREncryptor.EncryptPart`
      in place
- [ ] Delete the `io.ReadAll` at
      [upload.go:203](../../internal/proxy/handlers/multipart/upload.go#L203)
      (the second site at `:310` went with `handleStandardUploadPart`); pass
      `encResult.EncryptedData` (a seekable `*bytes.Reader` — SDK can sign/retry
      without re-buffering) directly as `UploadPartInput.Body` with
      `ContentLength` = part length (CTR is length-preserving)
- [x] Delete dead `handleStandardUploadPart` — done; `upload.go:174` is now
      `handleStreamingUploadPart`. Its callee `Manager.UploadPartStreamingBuffer`
      survives with no production caller and still has to go
- [x] Fix in passing: stop forwarding client `Content-MD5` (computed over
      plaintext) with the encrypted body — done, no `ContentMD5` reaches the
      backend and both handler test files assert it

**Risks / implementation notes:**
- **None-provider path**: `manager.go:226-235` returns the live request stream
  as `EncryptedDataReader`; without the ReadAll the SDK would get a
  non-seekable body. Buffer once (exact-size) for the none provider too, or
  handle unsigned-payload/no-retry semantics explicitly.
- **Attacker-controlled allocation**: `make([]byte, n)` from client-supplied
  `X-Amz-Decoded-Content-Length` is an up-front alloc DoS — cap the initial
  allocation (e.g. `min(n, segment_size)`) and grow, or `io.ReadFull` with a
  sanity limit.
- The streaming decoder is **strict** where `ProcessChunkedData` was lenient on
  malformed chunk lines — malformed bodies that previously slipped through will
  now 400. Acceptable behavior change; note it in the changelog.
- Out-of-order parts still buffer plaintext in `PendingParts` — unchanged, but
  re-verify the RSS bound after the change.

### 2.2 Kill the destructive body-sniff; header-based chunked detection everywhere

**Files**: `internal/proxy/request/aws_chunked_decoder.go:27-58` (the file has
since been deleted; detection became header-based with F-1 on the Velero branch,
so this item is **done** — kept for the reasoning),
[internal/proxy/request/parser.go](../../internal/proxy/request/parser.go)

`AWSChunkedDecoder.RequiresChunkedDecoding` decides "is this aws-chunked?" by
reading 1 KiB from `r.Body` and then — since request bodies are never
`io.Seeker`s — **`io.ReadAll`-ing the entire remaining body** and rebuilding it
via append + `bytes.NewReader`, just to look for `;chunk-signature=`. This
fully buffers EVERY body routed through `Parser.ReadBody`, chunked or not
(profile: 1.02 GB flat / 3.16 GB cum = 31.7 % of alloc_space; happens with the
default `clean_aws_signature_v4_chunked: true`). `parser.go:40/61` then
ReadAlls again; chunked bodies pay a third copy in `ProcessChunkedData`
(plus per-chunk `make([]byte, chunkSize)`). Affected beyond the multipart
handler: small-object PUT (`operations.go:508` → `putObjectDirect`),
CompleteMultipartUpload XML, and 8 bucket XML subresource handlers.

A correct, zero-cost header detector already exists in the same package:
`isAWSChunkedRequest` (checks `Content-Encoding: aws-chunked` /
`X-Amz-Content-Sha256: STREAMING-*`) — and is mandated by SigV4 signing, so it
is strictly **more** correct than the body sniff.

**Latent corruption bug fixed for free:** `STREAMING-UNSIGNED-PAYLOAD-TRAILER`
uploads carry no `;chunk-signature=` → the sniff misses them → raw chunked
framing would be stored as object data. The header detector +
`streamingAWSChunkedReader` handle them correctly.

- [ ] Rewrite `Parser.ReadBody`: detect via `isAWSChunkedRequest(r)`; when
      chunked, decode via `newStreamingAWSChunkedReader` into a buffer pre-sized
      from `X-Amz-Decoded-Content-Length`; when not chunked and
      `ContentLength >= 0`, `make([]byte, ContentLength)` + `io.ReadFull`
      instead of `io.ReadAll`
- [ ] Cap pre-sizing from client-controlled headers (same DoS note as 2.1)
- [ ] Preserve `ResetBody` double-read semantics for downstream consumers
      (`operations.go:516`, `upload.go:86`)
- [ ] Delete dead machinery per the no-backward-compat rule:
      `RequiresChunkedDecoding`, `ProcessChunkedData`, byte-at-a-time `readLine`
      (`aws_chunked_decoder.go:114-130`), `CreateOptimalReader`, and the
      default-off `HTTPChunkedDecoder` path
      ([http_chunked_decoder.go](../../internal/proxy/request/http_chunked_decoder.go))
      — net/http already transparently de-chunks `Transfer-Encoding: chunked`
- [ ] Remove `clean_http_transfer_chunked` from config struct/validation/docs
- [ ] Integration: verify aws-chunked **signed** and **unsigned-trailer**
      variants end-to-end with AWS SDK clients

**Expected impact:** body alloc churn per small PUT drops from ~4–5×
(non-chunked) / ~6–8× (aws-chunked) to ~1×; removes the sniff's ~3.2 GB cum on
the 1 GB bench (overlaps 2.1); deletes ~250 LOC of legacy decoder.

### 2.3 Exact-size part buffers + pool (fix the silent 3× in processPartOrdered)

**Files**: [internal/orchestration/multipart.go:245](../../internal/orchestration/multipart.go#L245),
[internal/proxy/handlers/object/operations.go:1244-1377](../../internal/proxy/handlers/object/operations.go#L1244-L1377)

Three compounding defects (profile: `processPartOrdered` flat 2.45 GB ≈ 2.4×
per 1 GB of parts — 010 Tier 2.5's "single exact-size allocation" is defeated
at runtime):

(a) buffer pre-sized to `GetStreamingSegmentSize()` = 12 MiB regardless of
actual part size (SDK default 5–8 MB) — every part allocates an oversized,
freshly **zeroed** buffer (feeds memclr 11.7 %);
(b) `bytes.Buffer.ReadFrom` requires `MinRead` (512 B) spare capacity before
each read → a part that exactly fills the buffer triggers `grow()` on the final
EOF-probing iteration: ~2× cap alloc + full-part memmove (≈3× total per part);
(c) auto-multipart route: `putObjectAutoMultipart` already owns the bytes in
the reused `partBuf` yet wraps them in `bufio.NewReader(bytes.NewReader(...))`
(`operations.go:1358`), forcing `ProcessPart` to re-copy — needed today only
because `partBuf` is overwritten while up to `concurrency` encrypted parts are
in flight.

- [ ] Add an orchestration entry point that takes ownership of a slice:
      `ProcessPartBytes(uploadID, partNumber, data []byte)` — `HMAC.Add` +
      in-place `EncryptPart` (already in-place per 010 Tier 1.1), return the
      same slice. Share this API with 2.1.
- [ ] Plumb known part length (`Parser.DecodedContentLength` / `io.ReadFull`)
      through `Manager.UploadPart`/`ProcessPart`; fallback cap =
      `segmentSize + bytes.MinRead` ONLY when length is unknown (this one-line
      cap is also the interim mitigation if the full change slips)
- [ ] `putObjectAutoMultipart`: replace single reused `partBuf` with a pool of
      `1 + concurrency` (or `concurrency + 2`) part buffers — **buffered
      channel, not `sync.Pool`** (multi-MiB buffers must not be GC-dropped;
      channel gives a hard RSS bound): producer takes buffer → `io.ReadFull` →
      hand off; upload worker wraps in `bytes.NewReader` for the SDK and
      returns the buffer to the pool after `UploadPart` completes
- [ ] Buffer lifetime audit: return-to-pool only after the SDK call fully
      returns (incl. retries); exactly-once return on cancel/abort paths;
      in-place encryption mutates the plaintext slice — no caller reuse after
      handoff; none-provider snapshot path reworked accordingly
- [ ] `PendingParts` (out-of-order, client-driven route) holds handed-off
      slices — prevent double-return (simplest: pool only on the
      auto-multipart route, exact-size allocs elsewhere)
- [ ] Re-verify peak RSS @ 1 GB ≤ previous bound (expected: explicit
      `(concurrency+1..2) × 12 MiB ≈ 60–72 MiB` + overhead)

**Tier 2 checkpoint:**
- [ ] Re-run 1 GB bench (3 runs) + pprof; expect alloc_space ~9.9 → ~1–1.5 GB,
      `io.ReadAll` gone from top, memclr/memmove collapsed
- [ ] Full `make test-integration` green on fresh proxy
- [ ] Archive profiles in `docs/tickets/012-tier2/`

---

## Tier 3 — Real-backend correctness with perf consequences

### 3.1 Multipart completion: metadata at CreateMultipartUpload, HMAC via tagging (fixes >5 GiB failure)

**Files**: [internal/proxy/handlers/multipart/complete.go:223-241](../../internal/proxy/handlers/multipart/complete.go#L223-L241),
[internal/proxy/handlers/object/operations.go:1468-1481](../../internal/proxy/handlers/object/operations.go#L1468-L1481),
[internal/proxy/handlers/multipart/create.go:60-63](../../internal/proxy/handlers/multipart/create.go#L60-L63)

Both completion paths issue **self-CopyObject** with `MetadataDirective=REPLACE`
after `CompleteMultipartUpload` to attach encryption metadata. The comment at
`operations.go:1454` claiming S3 doesn't propagate initiate-time metadata is
**false** — initiate-time metadata is the canonical way to set metadata on
multipart objects (S3 and MinIO both). Consequences on real AWS S3:

- CopyObject is a full server-side rewrite → completion latency grows with
  object size, write amplification ×2 (doubled versions on versioned buckets)
- CopyObject is hard-capped at **5 GiB** → every multipart upload > 5 GiB
  currently FAILS at the final step, **after** all bytes transferred and
  CompleteMultipartUpload committed — leaving a stored object with no
  encryption metadata, undecryptable through the proxy. Correctness bug.

All metadata except the whole-object HMAC is fixed at `InitiateSession`
([multipart.go:137-186](../../internal/orchestration/multipart.go#L137-L186));
`EncryptDEK` (`:450`) depends only on the session DEK and can run at initiate.

- [ ] Pass static metadata (encrypted-dek, aes-iv, dek-algorithm,
      kek-algorithm, kek-fingerprint) in `CreateMultipartUploadInput.Metadata`
      — requires generating session DEK/IV **before** the backend
      CreateMultipartUpload call (today the session is keyed by the uploadID
      the backend returns → two-phase init or pre-generated crypto material
      bound to uploadID afterward)
- [ ] Delete self-CopyObject in BOTH handlers
- [ ] Attach late-bound HMAC post-completion via `PutObjectTagging` (base64
      HMAC-SHA256 = 44 chars, fits the 256-char tag limit; metadata-only, no
      rewrite, no size cap); skip entirely when `integrity_verification: off`
- [ ] GET path: detect CTR objects, issue `GetObjectTagging` **concurrently**
      with `GetObject`, inject HMAC into the metadata map consumed by
      `GetHMAC`. One clear rule for single-part CTR (HMAC in metadata) vs
      multipart (HMAC in tags) — compat is waived, pick the simple rule
- [ ] Document the crash window between Complete and PutObjectTagging: strict
      mode refuses such an object (availability), hybrid serves unverified —
      strictly better than today's window (object with NO metadata at all)
- [ ] Deployment note: backend credentials need
      `s3:PutObjectTagging`/`s3:GetObjectTagging`
- [ ] Note: proxy's client-facing tagging endpooints return NotImplemented
      ([tagging.go](../../internal/proxy/handlers/object/tagging.go)) → tag
      namespace is proxy-owned; consumes 1 of 10 tag slots
- [ ] Test: assert CopyObject is no longer called (MinIO can't exercise the
      5 GiB limit; the loopback bench will NOT show a win — same-key copy on
      MinIO is a metadata-only xl.meta update)

**Expected impact:** real S3 — removes a size-proportional rewrite per
multipart PUT (seconds→minutes for multi-GB objects), halves backend write
amplification, fixes the > 5 GiB failure. Loopback: ~zero. GET of CTR objects
pays one extra small RTT, parallelized with the GetObject.

### 3.2 Range GET support, phase 1 (CTR counter-seek) — **done in `df12c84` (F-6), 2026-09-05**

The item below is the analysis as written; the checkboxes are closed history.
Read the note in [Status](#status-2026-06-11) before acting on it.

**Files**: [internal/proxy/handlers/object/operations.go:31-41](../../internal/proxy/handlers/object/operations.go#L31-L41),
[pkg/encryption/dataencryption/aes_ctr.go:177-199](../../pkg/encryption/dataencryption/aes_ctr.go#L177-L199)

Any GET with a `Range` header → 501, before metadata is even fetched — **even
for none-provider/unencrypted objects**. Breaks: boto3/aws-cli default parallel
downloads (objects > 8 MB `multipart_threshold` fail outright), s5cmd,
mountpoint-s3/goofys, parquet/columnar readers, video seeking. Yet AES-CTR is
seekable by construction: counter block = IV + offset/16 (128-bit big-endian
add), discard `offset % 16` keystream bytes. Offset math is valid because CTR
ciphertext is 1:1 with plaintext (IV lives in metadata, multipart is one
continuous CTR stream). `NewAESCTRStatefulEncryptorWithIV` exists but always
starts at byte 0.

- [ ] Add offset parameter to `NewAESCTRStatefulEncryptorWithIV`
      (128-bit big-endian counter add with carry; `offset/16` block seek +
      `offset%16` keystream discard — off-by-one unit tests mandatory)
- [ ] Handler: forward `Range` to backend GetObject, parse `ContentRange` from
      the backend response for the actual offset, counter-seek, decrypt
- [ ] Response plumbing: 206 + `Content-Range` + `Accept-Ranges` in
      `writeGetObjectResponse` (currently hardcodes 200)
- [ ] Suffix ranges (`bytes=-N`) via backend ContentRange; reject multi-range
      (`multipart/byteranges`) requests explicitly
- [ ] HMAC policy: **strict → keep rejecting ranges** (whole-object HMAC cannot
      verify a partial read); **hybrid → treat HMAC-bearing objects like
      strict** (serving unverified ranges would silently break hybrid's
      abort-on-failure promise; CTR is malleable), passthrough only for legacy
      no-HMAC objects; **lax → serve + log "range served unverified"**;
      **off → serve**
- [ ] GCM objects (< 5 MiB): fetch fully, decrypt+verify (AEAD intact), slice
      the requested range server-side
- [ ] None-provider objects: pure Range passthrough
- [ ] Integration tests: ranged GET across providers/modes, boundary offsets
      (0, 15, 16, 17, last byte, suffix)

**Phase 2 — parallel ranged GETs (deferred, do NOT start):** K parallel
segment-range GETs with per-worker counter-seeked decryptors promises 4–8×
client-observed GET throughput against real S3 (single connection caps
~50–90 MB/s) — but is gated on a segmented-integrity format change (rejected
for now, see bottom) and on benchmark evidence. Revisit only with that data.

### 3.3 HEAD/List return ciphertext size for GCM objects — **HEAD done in `646932b` (F-7); List still open**

The List half is [018](018-listobjectsv2-document.md), which needs the plaintext
size to be a pure function of the stored size and therefore waits on
[013](013-storage-format-v2.md).

**File**: [internal/proxy/handlers/object/operations.go:745-784](../../internal/proxy/handlers/object/operations.go#L745-L784)

GET corrects plaintext length (`ContentLength − 28`, `operations.go:288`);
`handleHeadObject` writes the backend ContentLength **verbatim** → every object
< 5 MiB HEADs as plaintext+28. `aws s3 sync`/rclone compare sizes via HEAD/List
→ perpetual re-transfer of every GCM object (silent bandwidth/cost
amplification). Also a hard prerequisite for SDK download managers that plan
ranged GETs from HEAD size (3.2).

- [ ] Subtract GCM overhead (28) in HEAD based on the dek-algorithm metadata
      already present in the response
- [ ] Audit the ListObjects passthrough for the same size mismatch; fix or
      document if List sizes can't be corrected cheaply (XML rewrite)
- [ ] Integration test: HEAD size == GET body length for GCM + CTR + none

---

## Tier 4 — Network/transport tuning

### 4.1 Stop discarding SDK transport defaults on the insecure_skip_verify path

**File**: [internal/proxy/server.go:144-152](../../internal/proxy/server.go#L144-L152)

When `insecure_skip_verify` is set (every shipped example config), the code
swaps in a bare `&http.Client{Transport: &http.Transport{TLSClientConfig: …}}`
— discarding all SDK BuildableClient tuning and inheriting Go zero values:
`MaxIdleConnsPerHost = 2` while the UploadPart pool runs 4+ concurrent backend
requests (surplus connections closed when idle, re-dialed with FULL TLS
handshake — no session cache), no IdleConnTimeout, **no dial/TLS-handshake
timeouts at all**, 4 KiB transport buffers.

- [ ] Build via `awshttp.NewBuildableClient().WithTransportOptions(...)`:
      **mutate** the existing `t.TLSClientConfig` (don't replace — keeps the
      SDK's `MinVersion=TLS1.2`), set `InsecureSkipVerify: true`,
      `ClientSessionCache: tls.NewLRUClientSessionCache(32)`
- [ ] `t.MaxIdleConnsPerHost = max(16, multipart_upload_concurrency)`,
      `t.MaxIdleConns = 64`, `t.IdleConnTimeout = 90s`,
      `t.ReadBufferSize = t.WriteBufferSize = 128 << 10`
- [ ] Decide `ForceAttemptHTTP2` explicitly (SDK default true; current bare
      transport is h1.1-only — h1.1 avoids h2 flow-control stalls; set false
      to preserve)
- [ ] Apply the same pooling values on the verified-TLS path
- [ ] Restores dial (30 s) + TLS handshake (10 s) timeouts — also a
      reliability fix (currently unbounded)

**Expected impact:** zero on loopback (handshake CPU was 0.07 % there). Real
networked TLS deployments: eliminates ~2 full TCP+TLS reconnects + slow-start
restarts per part batch at concurrency 4 (worse up to 32); better tail latency.

### 4.2 Fill the 128 KiB pooled buffer before writing to the client (GET)

**File**: [internal/proxy/handlers/object/helpers.go:28-32](../../internal/proxy/handlers/object/helpers.go#L28-L32)

Every reader in the GET chain is pass-through for large reads, but the
proxy→MinIO leg is TLS → each `body.Read` returns at most one ~16 KiB TLS
record → `io.CopyBuffer` issues one client write per read: **~65k write
syscalls per GB**, the 128 KiB pooled buffer never fills. `Syscall6` is the
top CPU item (23.4 %).

- [ ] Replace `io.CopyBuffer` in `copyWithPooledBuffer` with fill-then-write:
      keep reading `buf[filled:]` until ≥ half full (or EOF/error), then one
      `dst.Write`
- [ ] Preserve io.Copy semantics exactly: `(n>0, io.EOF)`, `n==0,err==nil`
      reads, write already-filled bytes before propagating a read error —
      cover with HMAC-strict integration tests incl. tamper cases
- [ ] Test `hmacValidatingReader` with shrinking tail slices (it sizes
      `lastChunkBuf`/near-end heuristic from `len(p)`, which now varies across
      fill iterations — analyzed correctness-neutral, verify)
- [ ] Drop the redundant default-4 KiB bufio wrap at
      [singlepart.go:311](../../internal/orchestration/singlepart.go#L311)
      (pass-through only; pure cleanup, no measurable gain)

**Expected impact:** 4–8× fewer client-write syscalls on GET; realistic ~1–3 %
proxy CPU on loopback (client writes are a fraction of the Syscall6 bucket).
The CTR reader chain is untouched — it does not verify before release today,
and this change does not make that worse.
Win disappears if the proxy ever terminates TLS to clients (Go TLS writes one
record per syscall anyway); bench + demo are plain-HTTP client-side.

### 4.3 Go runtime container tuning (GOMEMLIMIT/GOGC + GOMAXPROCS)

**Decided 2026-09-07 (owner; [023](023-major-v5.md) decision 8).** Ship
`GOMEMLIMIT` only: an explicit chart value (`runtime.goMemLimit`, rendered as
the `GOMEMLIMIT` env of the proxy container) and a compose env, default 80 % of
the memory limit — `400MiB` for the shipped 512 Mi
([values.yaml:86-87](../../deploy/helm/s3-encryption-proxy/values.yaml#L86),
[docker-compose.demo.yml:86-89](../../docker-compose.demo.yml#L86), both proxy
containers). `GOGC` stays at its default; `GOGC=off` is excluded while any
client-controlled full-body allocation exists. The `GOMAXPROCS` / automaxprocs
sub-item is void: the tree builds with Go 1.27.1 and since Go 1.25 the Linux
runtime derives `GOMAXPROCS` from the cgroup CPU limit itself
(`GODEBUG=containermaxprocs`, verified in the toolchain's godebugs table). The
gate is 013's memory test and benchmark re-run under the new value, on
`feat/major-v5` as the last step; no gain means the value is dropped before
the merge. The README documents the 80 % rule next to the limit.

**Files**: [docker-compose.demo.yml:86-89](../../docker-compose.demo.yml#L86),
Helm values, Containerfile

Proxy container: 512 MiB memory limit, no GOGC/GOMEMLIMIT anywhere; live heap
~100 MiB at default GOGC=100 → GC every ~100 MiB allocated ≈ 100 cycles per
1 GB round-trip at today's alloc rate (gcBgMarkWorker cum 7.74 %). Helm limits
the proxy to **cpu: 500m** with no GOMAXPROCS/automaxprocs → on a typical
multi-core node the runtime spins N procs against a 0.5-core CFS quota →
periodic ~100 ms throttle freezes mid-stream.

**Sequencing: land AFTER Tier 2** (which removes most of the garbage — re-tune
against the new alloc rate).

- [ ] Set `GOMEMLIMIT=400MiB` + conservative `GOGC=200-300` in compose +
      Helm + docs (NOT `GOGC=off` while any client-controlled full-body alloc
      remains — near-limit operation enters GC-thrash regime)
- [ ] Add `uber-go/automaxprocs` (or explicit GOMAXPROCS env) — Helm
      production path is the real beneficiary
- [ ] Re-verify peak RSS @ 1 GB; document that steady-state RSS rises by
      design (~110 → 300–400 MiB) and that this shifts bench baselines

**Expected impact:** 3–5 % proxy CPU in profiles; < 2–3 % loopback throughput
(proxy isn't CPU-saturated there); real value in CFS-limited production.

---

## Tier 5 — Small-object (GCM) path

No loopback-bench movement expected from this tier; value is latency + GC
pressure under high-RPS small-object workloads (the actual user of the GCM
path). Needs the Tier 6.3 benchmark to verify — implement after it exists.

### 5.1 GCM GET unwraps the DEK twice; second unwrap bypasses the cache

**Files**: [internal/orchestration/singlepart.go:192,222](../../internal/orchestration/singlepart.go#L192),
[pkg/encryption/envelope/envelope.go:84](../../pkg/encryption/envelope/envelope.go#L84)

`DecryptGCMStream` calls cached `providerManager.DecryptDEK` (:192) — result
feeds only a **dead** HMAC branch (GCM objects never carry hmac metadata;
`SetHMAC` is called only from `EncryptCTR` and multipart `FinalizeSession`).
The actual decrypt (:222) goes through `envelopeEncryptor.DecryptDataStream`,
which calls `keyEncryptor.DecryptDEK` **raw** (envelope.go:84) — bypassing the
DEK cache. Every GCM GET pays one wasted cached unwrap + one full uncached KEK
op. RSA-2048 KEK: ~0.2–1 ms RSA-OAEP private-key op per GET, repeat GETs never
hit the cache. Becomes a billable network KMS call per GET once real
KMS/Tink lands.

- [ ] Use the cached DEK and call the AES-GCM data decryptor directly
      (pattern: CTR path); remove the envelope hop from GET
- [ ] Delete the unreachable HMAC branch in `DecryptGCMStream` (AEAD provides
      integrity)
- [ ] CRITICAL: the cached DEK is cache-owned/read-only
      (providers.go:203-208) — must NOT replicate envelope.go's defer-zeroing
      on it (would corrupt subsequent cache hits → silent decrypt failures);
      `aes.NewCipher` copies the key schedule, direct use is safe
- [ ] Keep nil IV (nonce extracted from ciphertext prefix) and objectKey as
      AAD — wrong values fail loudly, add a unit test anyway

### 5.2 GCM []byte fast path (~3× object-size alloc → 1×)

**Files**: [pkg/encryption/dataencryption/aes_gcm.go:62,92](../../pkg/encryption/dataencryption/aes_gcm.go#L62),
[internal/proxy/handlers/object/operations.go:533](../../internal/proxy/handlers/object/operations.go#L533)

PUT: `putObjectDirect` holds the full plaintext as `[]byte`, wraps it in
bufio+bytes readers, `EncryptStream` ReadAlls it back (~2× via append growth),
then `gcm.Seal(nonce, nonce, data, aad)` with a cap-12 dst allocates a third
full-size buffer. GET: `DecryptStream` ReadAlls with doubling growth (no size
hint, although the handler knows `ContentLength − 28` at `operations.go:288` —
the size can't reach `DecryptStream` through the interface), then one more
bufio wrap (aes_gcm.go:122). `gcm.Open` into `ciphertext[:0]` is already
in-place.

- [ ] Optional capability on the GCM encryptor only (type-asserted
      `EncryptBytes`/`DecryptBytes` — avoids threading a parallel API through
      all 3 layers): single buffer with 12-byte nonce prefix + 16-byte tag
      headroom, Seal genuinely in place
- [ ] In-place Seal requires exact-overlap slices (`buf[:12]` dst,
      `buf[12:12+n]` plaintext) or crypto/cipher panics — unit test
- [ ] Decrypt: plumb known size (combine with 5.1 — manager calls the GCM
      decryptor directly and can pass `output.ContentLength`), exact-size
      `make` + `io.ReadFull`, Open in place, return `bytes.NewReader` without
      bufio; guard absent ContentLength (fallback ReadAll)
- [ ] Return the nonce directly from the bytes path instead of the
      mutex-guarded `lastNonce`/`GetLastIV` side channel (existing latent
      concurrency hazard — don't inherit it)
- [ ] Keep none-provider passthrough branch (`operations.go:572-576`) intact

---

## Tier 6 — Honest measurement (prerequisites for judging everything above)

### 6.1 One-time baseline without backend TLS

The bench currently measures ~10–16 % proxy CPU of TLS re-encryption of
already-encrypted payload to a loopback MinIO with `insecure_skip_verify`
(zero endpoint auth value). Note: `s3_backend.use_tls` is **dead config** —
parsed (config.go:291) but never consulted; the scheme comes solely from
`target_endpoint`.

- [ ] Add a compose override/profile with `target_endpoint: http://minio:9000`
      and a second MinIO service (or override) without `--certs-dir` (MinIO
      can't serve both schemes from one process); fix healthcheck +
      `MinIOEndpoint` in
      [test/integration/minio_test_helper.go:26](../../test/integration/minio_test_helper.go#L26)
- [ ] Re-run the 1 GB baseline once on it; record the true data-crypto floor
      (~32 % expected) so future profiles aren't misread
- [ ] Keep TLS the default for integration tests + real S3 (don't weaken the
      suite); document plaintext-backend as a co-located-deployment option
      (SigV4 headers + bucket/key names travel plaintext on that hop)
- [ ] Either remove dead `use_tls` from config or wire it up — don't leave it
      lying

### 6.2 Parallel-stream benchmark (proxy capacity, not single-stream artifact)

The 80/120 MB/s figures are one object stream from the macOS host through
Docker Desktop port-forwarding against a MinIO deliberately capped at 2 CPUs
(compose:39-42); the proxy averages 0.55 cores during the run. At the crypto
floor the proxy has ~5–10× aggregate headroom that single-stream numbers
cannot show.

- [ ] Add a parallel variant to the perf test: N = 4–8 objects concurrently,
      report aggregate MB/s — use ~100–200 MB objects or a raised memory limit
      in a bench-only profile (4–8 × 60 MiB streaming bound vs the 512 MiB
      container limit, else the benchmark OOM-kills the proxy)
- [ ] Bench-only compose profile that lifts the MinIO 2-CPU cap (cap was
      deliberate for reproducibility — keep the default profile unchanged so
      the existing number series stays comparable)
- [ ] Optional: run the perf client inside the compose network (removes Docker
      Desktop host→VM forwarding from the measurement)

### 6.3 Small-object / high-QPS benchmark

The entire perf dataset is one single-stream 1 GB test, yet four findings
(5.1, 5.2, 1.3 logs, 4.3) only pay off under small-object RPS, and the
per-request fixed-cost path (SigV4 canonicalization in
[s3auth_robust.go:300-425](../../internal/proxy/middleware/s3auth_robust.go#L300-L425),
middleware stack, per-PUT DEK generation + KEK wrap + HKDF) has never been
profiled.

- [ ] New integration benchmark: 4 KiB / 256 KiB / 1 MiB objects at
      concurrency 16–64, report QPS + p50/p99 latency
- [ ] Capture CPU/heap profiles during the run; expected outcome: ceiling set
      by auth canonicalization allocs, logging, per-object KEK/DEK setup —
      not bulk crypto
- [x] ~~Found in passing, needs an own decision: the entire `s3_security`
      rate-limiting/IP-blocking config block is parsed in config.go but
      referenced nowhere else. File as separate ticket.~~ **Filed**: it is N-5,
      the decision was taken on 2026-09-06 (delete the knobs and the unbounded
      failed-attempt map, keep the security log line), and the work is
      [015](015-configuration-hygiene.md). The README already says the proxy
      does not throttle (**No rate limiting**, under Security).

### 6.4 Block/mutex profiles (attribute the unexplained ~9 % scheduler CPU)

`runtime.futex` 5.28 % flat + `findRunnable` 9.18 % cum are unattributed;
`SetBlockProfileRate`/`SetMutexProfileFraction` are called nowhere, so the
already-registered `/debug/pprof/block|mutex` endpoints return empty profiles.

- [ ] Config-gated `runtime.SetBlockProfileRate` / `SetMutexProfileFraction`
      in [cmd/s3-encryption-proxy/main.go](../../cmd/s3-encryption-proxy/main.go)
      (alongside the existing `pprof_enabled`)
- [ ] Capture block+mutex profiles + a 5–10 s `go tool trace` during the 1 GB
      bench; suspects: logrus shared mutex, multipart session map, UploadPart
      workers idling behind the serial producer
- [ ] Answers directly whether upload is stall-bound vs CPU-bound — ranks the
      rejected concurrency ideas with data instead of guesses

### 6.5 Part-size × concurrency sweep

Defaults (12 MiB segments, 4 workers) were never swept; both knobs exist.
Peak memory = `partSize × (1 + concurrency)`.

- [ ] Sweep {8, 16, 32, 64 MiB} × concurrency {4, 8, 16} on loopback AND a
      latency-injected backend (tc netem or real S3)
- [ ] Record throughput/RSS curve; update defaults + document the RSS formula

---

## Explicitly not doing (rejected by adversarial review — do not re-propose without new evidence)

1. **Segmented AEAD / per-part MAC format change.** Cost is real (HMAC-SHA256
   is a second sequential pass; serial MAC forces part ordering and
   end-of-stream-only verification), construction is sound (STREAM-style),
   and compat is waived — but the win today is ~0.05 cores on a 0.55-core
   load, invisible on the bench and irrelevant against network-bound real S3.
   L-effort format change (ciphertext/plaintext size mapping across
   HEAD/GET/listing, migration, crypto review) not justified by any measured
   bottleneck. **Activation condition:** parallel-stream benchmark (6.2)
   shows CPU saturation with the MAC still a top profile item. Also gates
   Range-GET phase 2.
   **Reversed 2026-09-07:** the segmented authenticated chain is adopted on
   integrity grounds
   ([ADR 0003](../adr/0003-objects-are-an-authenticated-segment-chain.md)) — the
   activation condition above is void, and Range-GET phase 2 is gated on that
   format instead.
2. **GET read-ahead goroutine (overlap backend read with client write).**
   Structure verified serial, but the premise fails: the identical chain
   measured 218 MB/s on other hardware (chain is not the ~120 MB/s ceiling),
   and kernel socket buffers already overlap the legs for a continuous
   stream. Not worth a concurrency change on the integrity-critical path.
3. **KEK `Fingerprint()` memoization.** Real (SHA-256 + hex per call, 1–3×
   per request) but ~200–600 ns — profile-invisible. Audit conclusion stands:
   KEK-layer op counts are already minimal.
4. **Auto-multipart producer double-buffering (overlap client read with
   crypto).** Producer chain caps at ~1.3–1.4 GB/s vs 80 MB/s measured —
   overlapping recovers ≤ ~6 % even if the client link were the gate, which
   it isn't. Revisit only if post-Tier-2 profiles show the producer goroutine
   saturated.

---

## Expected overall gain

| Stage | Loopback bench | Real S3 / production |
|---|---|---|
| Tier 1 | +~6 % CPU back (checksums); availability fixes | same + no 30 s transfer kill |
| Tier 2 | alloc 9.9 → ~1–1.5 GB/GB; **upload +10–20 %** | same + lower per-part latency |
| Tier 3 | ~flat | >5 GiB multipart works; ranged GETs work (boto3/aws-cli/sync unblocked); no completion rewrite |
| Tier 4 | +1–3 % CPU (syscalls); GC −3–5 % | no TLS-redial churn; no CFS throttling |
| Tier 5 | flat | small-object latency/GC under RPS (verify via 6.3) |
| Tier 6 | — | honest yardsticks for everything above |

---

## Done criteria

- [ ] All tiers merged or explicitly deferred with a note
- [ ] `TestStreamingPerformance` regression-free at every size (100 KB → 1 GB)
- [ ] Full `make test-integration` green on a fresh proxy
- [ ] Before/after pprof archived per tier under `docs/tickets/012-tierN/`
- [ ] No increase in peak RSS during 1 GB upload/download (streaming preserved);
      expected: explicit pool bound ≈ `partSize × (1 + concurrency)` + overhead
- [ ] New benchmarks (parallel-stream, small-object QPS) exist and their
      baseline numbers are recorded in this ticket
- [ ] Aggregate throughput number from 6.2 recorded as the new capacity
      yardstick
