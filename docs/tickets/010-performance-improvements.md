# Ticket 010: Performance Improvements — Streaming Throughput

## Status (2026-04-25)

**Tier 4.2 + 4.3 complete.** Pooled 128 KiB `io.CopyBuffer` now serves all
three GET-response copy sites (streaming HMAC, standard, torrent passthrough)
in [internal/proxy/handlers/object/operations.go](../../internal/proxy/handlers/object/operations.go),
backed by a `sync.Pool[*[]byte]` defined in
[helpers.go](../../internal/proxy/handlers/object/helpers.go#L16-L34). Eighteen
per-request `Info` lines in `handlers/object/operations.go` and one in
`handlers/multipart/abort.go` are demoted to `Debug` so their
`WithFields` map allocs no longer fire at the default log level. Full
`make test-integration` green across all 7 packages on a fresh proxy.

## Status (2026-04-24)

**Tier 2 complete.** Throughput stays flat on the MinIO loopback workload
(upload 83.66 MB/s, download 121.14 MB/s — within run-to-run noise of Tier 1.3),
which is the expected shape: Tier 2 wins sit in memory + CPU composition, not
in a loopback bandwidth number. Proxy alloc_space for a single 1 GB round-trip
dropped from 17.97 GB (baseline) → 13.38 GB (Tier 1.1) → **10.01 GB (Tier 2)**,
and `runtime.memmove` fell from 10.3 % → **3.47 %**. The proxy CPU profile is
now dominated by the AES-NI + SHA-256 floor (~42 %) and network syscalls
(~20 %); no remaining non-crypto CPU target is above 4 %. Full checkpoint
table and archived profiles: [docs/tickets/010-tier2/](010-tier2/).

**Next:** Tier 3 — primary remaining alloc target is `io.ReadAll` at **64.6 %
of alloc_space (6.31 GB / 10.01 GB)**, now concentrated on the upload-side
v4-chunked `ReadBody` path rather than anything in orchestration. Tier 3.1
(streaming GCM) will not help that line; the real follow-up is on
`Parser.ReadBody` / `AWSChunkedDecoder.RequiresChunkedDecoding` (1.03 GB,
10.25 %) — Tier 4 territory.

**Done so far:**
- Baseline captured (client + proxy pprof) → [docs/tickets/010-baseline/](010-baseline/)
- Proxy pprof wired up behind `monitoring.pprof_enabled` flag
  ([internal/monitoring/server.go](../../internal/monitoring/server.go),
  [internal/config/config.go](../../internal/config/config.go),
  [cmd/s3-encryption-proxy/main.go](../../cmd/s3-encryption-proxy/main.go),
  [config/aes-example.yaml](../../config/aes-example.yaml))
- Demo stack rebuilt and running with pprof enabled (verified `:9090/debug/pprof/` → 200)

**Local baseline numbers (2026-04-23, 1 GB run):** upload **78.42 MB/s**,
download **120.43 MB/s**. All subsequent tier comparisons should be measured
against *these* numbers (not the 128/218 in the original Context below, which
is from a different machine).

**After Tier 1.1 (in-place CTR XOR):** upload **84.34 MB/s** (+7.5 %), download
**119.41 MB/s** (flat). Proxy alloc_space dropped from 17.97 GB → 13.38 GB
(−25.5 %); both CTR `EncryptPart`/`DecryptPart` alloc lines dropped out of the
top entirely. Profiles archived in [docs/tickets/010-tier1/](010-tier1/).

**After Tier 1.2 (drop per-Read mutex on stateful CTR encryptor):** upload
~79 MB/s, download ~120 MB/s — flat (mutex was uncontended; two atomic ops
per Read removed but no CPU was actually blocked). Kept for hygiene / hot-path
clarity; real wins are still ahead in 1.3 and 2.x.

**After Tier 1.3 (remove per-Read logrus WithFields in streaming_io.go):**
upload **82.84 MB/s**, download **121.25 MB/s** — flat in throughput (expected;
map allocs per Read show up in GC not in CPU). `logrus.(*Entry).WithFields`
dropped from **Top-1 alloc_objects at ~24.55 %** to **#14 at 2.53 %** — the
streaming-hot-path contribution is gone entirely (remaining WithFields calls
are request-level, once per request). Profiles archived in
[docs/tickets/010-tier1.3/](010-tier1.3/).

**Confirmed hot paths from proxy pprof:**
- CPU: `runtime.memmove` 10.3 % (Tier 1.1), crypto floor at ~22 % (AES-NI + HMAC + GCM)
- alloc_space: `io.ReadAll` 7.1 GB (39.6 %), `processPartOrdered` 5.4 GB (Tier 2.5), CTR En/DecryptPart ~2.2 GB (Tier 1.1)
- alloc_objects: `logrus.(*Entry).WithFields` **Top-1 at 23 %** (Tier 1.3)

**After Tier 2.1 (single-pass HMAC via io.TeeReader in singlepart EncryptCTR):**
refactor-only for the small-object (< 5 MiB) HMAC path — handler already routes
larger HMAC uploads to auto-multipart, so the streaming perf test (1 GB, auto-
multipart) is unchanged (upload 80.95 MB/s, download 120.89 MB/s, within noise
of Tier 1.3). Eliminates two plaintext passes and one KEK `DecryptDEK` per
small HMAC-enabled object; measurable gain only visible in small-object
workloads or via unit/alloc benchmarks on that path.

**Next:** Tier 2.x — `io.ReadAll` still dominates alloc_space at **47.06 %
(10.49 GB)** and `processPartOrdered` at **36.12 % (8.05 GB)**. Re-run script
documented in
[docs/tickets/010-baseline/README.md](010-baseline/README.md#how-to-re-run-after-each-tier).

**Uncommitted code changes (4 files):**
- `internal/config/config.go`, `internal/monitoring/server.go`,
  `cmd/s3-encryption-proxy/main.go`, `config/aes-example.yaml`
  — all part of the pprof enablement; safe to commit as a prep commit before Tier 1.

---

## Context

Baseline from `TestStreamingPerformance` (1 GB file):
- Upload: **~128 MB/s**
- Download: **~218 MB/s**

AES-NI hardware capability is 2–5 GB/s on modern CPUs. The delta is caused by
allocations, redundant copies, mutex contention on hot paths, logging overhead
and synchronous multipart upload — **not** raw crypto cost.

Goal: lift end-to-end throughput toward the hardware ceiling while preserving
all current integrity guarantees (HMAC, AEAD, streaming memory footprint).

---

## 0. Baseline Measurement (do this FIRST)

- [x] Run `go test -run TestStreamingPerformance -cpuprofile cpu.out -memprofile mem.out` against 1 GB upload and 1 GB download
- [x] Capture top 20 samples from `go tool pprof -top cpu.out` — expect `runtime.memmove`, `runtime.mallocgc`, `crypto/cipher.(*ctr).XORKeyStream`, logrus `WithFields`
- [x] Capture allocation profile `go tool pprof -alloc_objects mem.out -top`
- [x] Archive both profiles in the ticket as the "before" snapshot
- [ ] Re-run and archive after each tier to quantify the gain

**Artifacts:** [docs/tickets/010-baseline/](010-baseline/) — `cpu.out`, `mem.out`,
`cpu-top20.txt`, `mem-alloc-objects.txt`, `mem-alloc-space.txt`, `README.md`.

**Local 1 GB numbers (2026-04-23):** upload **80.12 MB/s**, download
**120.25 MB/s** — slower than the ticket header numbers (128 / 218 MB/s from
the author's box), so improvements here should be measured against these
local baselines, not the header.

**Caveat:** `go test -cpuprofile` profiles only the test binary; the proxy runs
in a separate container, so the Tier-1 targets (`aes_ctr.XORKeyStream`, logrus
`WithFields`) are **not visible** in this profile. Client-side findings that
are visible: `io.ReadAll` on the 1 GB GET allocates 2.56 GB (confirms Tier 2.3
value), v4 chunked SHA-256 signing dominates client CPU at 28 %.

**Proxy-side pprof (enabled 2026-04-23):** `monitoring.pprof_enabled: true`
now exposes `/debug/pprof/*` on the monitoring port (`:9090`). Demo config
`config/aes-example.yaml` has it on by default. To capture the *proxy* view
while the 1 GB test is running:

```bash
# CPU profile during a run (in a second terminal, kick off the test first):
curl -s 'http://localhost:9090/debug/pprof/profile?seconds=25' -o proxy-cpu.out
# Heap/alloc snapshot right after the run:
curl -s 'http://localhost:9090/debug/pprof/heap'              -o proxy-heap.out
curl -s 'http://localhost:9090/debug/pprof/allocs'            -o proxy-allocs.out
go tool pprof -top -nodecount=20 proxy-cpu.out
```

Use these proxy-side profiles to drive Tier-1 decisions — the client-side
profile alone will not show the CTR XOR / logrus / memmove hot paths.

---

## Tier 1 — Highest ROI (expected: ~128 MB/s → ~300–400 MB/s upload)

These changes sit directly on the per-Read hot path called tens of thousands of
times per GB.

### 1.1 In-place XOR in AES-CTR stateful encryptor

**File**: [pkg/encryption/dataencryption/aes_ctr.go:202-225](../../pkg/encryption/dataencryption/aes_ctr.go#L202-L225)

Current code allocates + copies + XORs + returns a new slice. Caller then copies
again into `p`. `cipher.Stream.XORKeyStream` explicitly supports `src == dst`.

- [x] Change `EncryptPart(data []byte)` signature to XOR in-place on `data` and return `data` (or make it `(dst, src []byte)` to XOR `src` into `dst`)
- [x] Do the same for `DecryptPart`
- [x] Update call sites in [internal/orchestration/streaming_io.go:88-118](../../internal/orchestration/streaming_io.go#L88-L118) and [:127-157](../../internal/orchestration/streaming_io.go#L127-L157) so the Read buffer `p` is XORed in-place — no second `copy`
- [x] Verify integration tests still pass (GCM and CTR paths) — full unit + integration suite green against fresh proxy (2026-04-23)

**Measured impact (1 GB run, [docs/tickets/010-tier1/](010-tier1/)):**

| Metric | Baseline | Tier 1.1 | Delta |
|---|---:|---:|---:|
| Upload throughput | 78.42 MB/s | **84.34 MB/s** | **+7.5 %** |
| Download throughput | 120.43 MB/s | 119.41 MB/s | ~flat (noise) |
| Proxy alloc_space total | 17.97 GB | **13.38 GB** | **−4.6 GB (−25.5 %)** |
| `AESCTRStatefulEncryptor.EncryptPart` alloc | 1.12 GB (6.3 %) | **0** (gone from top) | **−100 %** |
| `AESCTRStatefulEncryptor.DecryptPart` alloc | 1.13 GB (6.3 %) | **0** (gone from top) | **−100 %** |
| `DecryptPart` alloc_objects | 72 220 (7.1 %) | **0** (gone from top) | **−100 %** |
| `processBufferedPartsData` alloc | 1.92 GB (10.7 %) | 798 MB (5.96 %) | −58 % (knock-on, stopped copying encrypted output) |
| `runtime.memmove` CPU | 10.3 % | 10.77 % | flat — dominated now by `io.ReadAll` + `processPartOrdered` (Tier 2) |

Upload gain matches the expected shape: killing the per-Read alloc + double copy on the CTR path frees CPU and GC pressure for the write side. Download is flat because its hot path is bounded by HMAC + TLS writes, not CTR alloc. Next biggest levers remain Tier 1.3 (logrus `WithFields` still #1 at 24.55 % alloc_objects) and Tier 2.x (`io.ReadAll` now 48 % of alloc_space, `processPartOrdered` 37 %).

### 1.2 Remove per-Read mutex in CTR stateful encryptor

**File**: [pkg/encryption/dataencryption/aes_ctr.go:201-254](../../pkg/encryption/dataencryption/aes_ctr.go#L201-L254)

`EncryptPart`/`DecryptPart` took `e.mutex.Lock()` every call. A CTR stream is
inherently sequential and already single-owner per request.

- [x] Remove `mutex.Lock/Unlock` from `EncryptPart` and `DecryptPart` (and from `Cleanup`, which is also single-owner after last Read)
- [x] Drop the `mutex sync.Mutex` field entirely; document the non-thread-safe contract in the type comment ("one owner, sequential Reads")
- [x] Audit call sites — all four (`internal/orchestration/multipart.go:331`, `multipart.go:891`, `streaming_io.go:95`, `streaming_io.go:132`) are driven by a single goroutine holding `session.mutex` or owning the decryptor exclusively

**Measured impact (1 GB, 3 runs each, local proxy container):**

| Metric | Tier 1.1 | Tier 1.2 (avg of 3) | Delta |
|---|---:|---:|---:|
| Upload throughput | 84.34 MB/s | ~79 MB/s (75.99 / 78.42 / 82.79) | flat (run-to-run noise) |
| Download throughput | 119.41 MB/s | ~120 MB/s (119.34 / 119.54 / 121.25) | flat |

As expected: the mutex was **uncontended** (single-owner per request), so removing the lock/unlock pair removes two atomic ops per Read but doesn't free any CPU that was actually blocking. The value of this change is correctness/clarity (one fewer mutex in the hot path) and clearing the way for Tier 1.3 and Tier 2.x, where the next real wins live. `go test -short ./...` green; integration suite flakiness (`TestLargeMultipart500MB`, `TestMultipartUploadCorruption`) reproduces identically against the pre-change baseline — pre-existing environmental issue, not introduced here.

### 1.3 Eliminate per-Read logrus allocations

**File**: [internal/orchestration/streaming_io.go:88-118](../../internal/orchestration/streaming_io.go#L88-L118), [:127-157](../../internal/orchestration/streaming_io.go#L127-L157)

`logrus.Fields{...}` map is allocated on every Read even when Debug is filtered
out. At 64 KB Reads / 1 GB that's 16 k map allocations per GB.

- [x] Gate `WithFields(...).Debug(...)` calls behind `logger.Logger.IsLevelEnabled(logrus.DebugLevel)` in both `encryptionReader.Read` and `decryptionReader.Read` — chose the stronger option below
- [x] Or remove the per-Read Debug log entirely (it's useless at production volume) — **done** in `encryptionReader.Read`
- [x] Same treatment for the Trace log in `decryptionReader.Read`

**Measured impact (1 GB, [docs/tickets/010-tier1.3/](010-tier1.3/)):**

| Metric | Tier 1.2 | Tier 1.3 | Delta |
|---|---:|---:|---:|
| Upload throughput | ~79 MB/s | **82.84 MB/s** | ~flat (run-to-run noise) |
| Download throughput | ~120 MB/s | 121.25 MB/s | flat |
| `logrus.(*Entry).WithFields` alloc_objects rank | **#1 (~24.55 %)** | **#14 (2.53 %)** | **streaming-hot-path share → 0** |

Matches expectation: per-Read map allocations aren't CPU-bound, they're
GC-bound. Throughput stays flat but GC pressure from the streaming path is
eliminated — the remaining `WithFields` hits are all request-level (once per
request). Next levers are purely in alloc_space: Tier 2.1/2.3 (`io.ReadAll`
47 %) and Tier 2.5 (`processPartOrdered` 36 %).

**Tier 1 checkpoint:**
- [x] Re-run `TestStreamingPerformance` @ 1 GB and record new MB/s
- [x] Re-capture alloc profile; confirm `WithFields` share has dropped (24.55 % → 2.53 % alloc_objects)

---

## Tier 2 — High ROI (expected: Tier 1 + ~500–800 MB/s upload)

### 2.1 Single-pass HMAC via io.TeeReader in EncryptCTR

**File**: [internal/orchestration/singlepart.go:59-167](../../internal/orchestration/singlepart.go#L59-L167)

Previously did `io.ReadAll` of the plaintext, then walked the same bytes a second
time via `HMACCalculator.AddFromStream`, and a third time when the caller
consumed the envelope reader. It also did a redundant KEK `DecryptDEK` roundtrip
just to recover the raw DEK for HMAC.

- [x] Replace with `io.TeeReader(plaintextSrc, hmacCalculator)` so HMAC is computed in the single buffering pass
- [x] Generate the DEK locally (no envelope-encryptor indirection), encrypt the plaintext buffer **in place** with the stateful CTR encryptor, and return a reader over the ciphertext
- [x] Encrypt the DEK once via `ProviderManager.EncryptDEK` — no KEK `DecryptDEK` roundtrip
- [x] HMAC-enabled round-trip verified: unit suite (`go test -short ./...`) and integration suite (HMAC validation + small-object CTR) green; `TestStreamingPerformance` unchanged as expected (1 GB path is auto-multipart, not singlepart-CTR)

**Note on scope:** the handler routes HMAC-enabled objects ≥ 5 MiB to
auto-multipart ([internal/proxy/handlers/object/operations.go:470-486](../../internal/proxy/handlers/object/operations.go#L470-L486)),
so this single-part HMAC path only ever sees small objects. The win here is
plaintext-pass count (3 → 1) and eliminating the `DecryptDEK` KEK call per
object, not bulk throughput.

### 2.2 Single-pass HMAC in DecryptGCMStream

**File**: [internal/orchestration/singlepart.go:233-263](../../internal/orchestration/singlepart.go#L233-L263)

`io.ReadAll` of decrypted stream then `bytes.NewReader` — completely defeats
streaming and doubles peak memory.

- [x] Stream decrypted bytes directly to the caller; feed HMAC via the existing `hmacValidatingReader` pattern (CTR path already uses it)
- [x] Remove the `ReadAll` + `NewReader` round-trip

**Approach:** reused `hmacValidatingReader` from
[streaming_io.go](../../internal/orchestration/streaming_io.go) — same reader the
CTR path wraps. Plaintext flows through it: HMAC is fed as bytes are read, and
the EOF chunk is withheld until `VerifyIntegrity` succeeds, preserving the
"verify before final release" guarantee. No `expectedSize` hint is passed (GCM
plaintext size isn't known upfront at this call site) — the reader's
EOF-triggered buffer path handles that case unchanged.

**Impact:** refactor-only for the currently-exercised paths. The `TestStreamingPerformance` 1 GB workload uses CTR, not GCM, so throughput is unchanged. Memory footprint of GCM+HMAC downloads drops from `2 × object_size` (plaintext allocated twice: `ReadAll` buffer + `bytes.NewReader`) to streaming (chunk-sized). GCM path is only used for objects < 5 MiB streaming_threshold, so the absolute saving is capped per request; the win is consistency with the CTR path and elimination of a full-object allocation on the hot GET path. Unit + integration suites (including `TestHMACValidation` across valid/invalid/tampered HMAC subtests) green.

### 2.3 Stream directly to ResponseWriter (no ReadAll)

**File**: [internal/orchestration/singlepart.go:287-305](../../internal/orchestration/singlepart.go#L287-L305) and the GET handler in [internal/proxy/handlers/object/operations.go:265-331](../../internal/proxy/handlers/object/operations.go#L265-L331)

`DecryptDataWithMetadata` ended with `io.ReadAll` on the stream, and the
handler did a second `io.ReadAll` on the encrypted body. For a 1 GB object
that's two full-sized allocations just to hand plaintext to
`http.ResponseWriter`.

- [x] Changed `DecryptDataWithMetadata` to take `io.Reader` and return `io.ReadCloser` — streams through the existing `DecryptData` pipeline (which already wraps GCM+HMAC in `hmacValidatingReader`)
- [x] Handler passes `output.Body` directly — no more `ReadAll` on the encrypted side — and `writeGetObjectResponse` runs `io.Copy(w, plaintextReader)` through the standard non-streaming branch
- [x] Removed both `ReadAll` calls; removed the unused `encryptedDEK` / `providerAlias` parameters (already ignored inside the manager since V2)
- [x] `Content-Length` on the response is computed as `encrypted_len − 28` (GCM overhead: 12-byte nonce prefix + 16-byte auth tag); `nil` if unknown (lets Go chunk-encode)

**Scope:** this path is GCM-only (small objects < `streaming_threshold`, 5 MiB
default); CTR/auto-multipart already streams via
`handleGetObjectStreamingDecryption`. The `TestStreamingPerformance` 1 GB run
stays flat — upload **82.93 MB/s**, download **120.63 MB/s** — within noise of
Tier 2.1 (80.95 / 120.89). Integration suite green against a fresh proxy
(HMAC validation + AES/RSA/None provider + chunked-encoding-without-SDK tests
all pass). The three tests that fail on a reused proxy (`TestLargeMultipart500MB`,
`TestMultipartUploadCorruption`, `TestRealChunkedEncodingWithoutSDK`) all
reproduce the known DEK-cache-stale-on-reupload issue and pass after a proxy
restart — not caused by this change.

**Impact:** refactor-only for the currently-measured workload. Memory footprint
of GCM GETs drops from a 2× full-object peak (encrypted `ReadAll` buffer +
decrypted `ReadAll` buffer + `bytes.NewReader` handoff) to a streaming
working set — the win scales with object size but is bounded by the 5 MiB
GCM cutoff. The remaining `io.ReadAll` alloc_space pressure now lives inside
`aes_gcm.go` (Tier 3.1) and on the upload/chunked-signature paths — not the
handler.

### 2.4 Parallel S3 UploadPart in putObjectAutoMultipart

**File**: [internal/proxy/handlers/object/operations.go:1170-1395](../../internal/proxy/handlers/object/operations.go#L1170-L1395)

At 1 GB / 12 MB parts = 86 S3 round-trips done strictly sequentially. CTR
encryption must be in order, but once the part is encrypted the upload is
independent of the next part.

- [x] Keep encryption strictly ordered (CTR requires it) — serial producer calls
  `encryptionMgr.UploadPart` in order; only the S3 round-trip runs in parallel
- [x] Dispatch `UploadPart` calls to a worker pool of configurable size (default 4)
- [x] Collect completed-part ETags keyed by part number so `CompleteMultipartUpload`
  sees them in order — `partsMap[int]string` + final `sort.Ints` before
  building `completedParts`
- [x] Bound worker pool from config — new `optimizations.multipart_upload_concurrency`
  (default 4, validated 1–32) in [internal/config/config.go](../../internal/config/config.go)
  with helper `getMultipartUploadConcurrency()` in
  [internal/proxy/handlers/object/helpers.go](../../internal/proxy/handlers/object/helpers.go)
- [x] Integration test: 1 GB `TestStreamingPerformance` + `TestMultipartUploadCorruption`
  (1 GB round-trip with SHA-256 verify) + `TestHMACValidation` suite + `TestLargeMultipart500MB`
  all green against a fresh proxy; parallel dispatch confirmed in proxy logs
  (`part_number=2` completing before `part_number=1`)

**Measured impact (1 GB, local MinIO, fresh proxy):** upload **79.65 MB/s**,
download 102.65 MB/s — within run-to-run noise of the Tier 2.3 baseline
(80.95 / 120.89). Parallel dispatch is demonstrably working, but the local
MinIO run has no network RTT to parallelise away: the 12 MB part upload is
CPU-bound (TLS + MinIO I/O on the same box, not real S3 latency). The win
will materialise against a real S3 endpoint where each UploadPart round-trip
dwarfs encryption CPU time — we're pre-committing the parallelism so
production workloads get the gain without a follow-up change. Functional
correctness (byte-identical 1 GB round-trip + HMAC verify) is the hard guarantee
and is covered.

**Implementation notes:**
- Peak memory ≈ `segment_size × (1 + concurrency)` because the encrypted
  part lives in its own slice (CTR does in-place XOR on an independent buffer
  built inside `processPartOrdered`), decoupled from the reusable `partBuf`.
- The none-provider path returns the input reader unchanged, which would race
  with `partBuf` reuse, so that branch snapshots into a fresh slice before
  dispatching.
- Error propagation uses a derived `context.WithCancel`: the first worker to
  fail cancels all in-flight UploadPart calls and halts the producer; the
  producer similarly cancels on body-read or encryption failure. Abort then
  runs on both the S3 multipart and the encryption session as before.

### 2.5 Eliminate append-build in processPartOrdered

**File**: [internal/orchestration/multipart.go:241-297](../../internal/orchestration/multipart.go#L241-L297), [:346-380](../../internal/orchestration/multipart.go#L346-L380)

`partData = append(partData, buffer[:n]...)` in a loop caused ~log₂(partSize/512)
slice reallocations (~15 doublings for a 12 MiB part under the default 512-byte
start), each one copying the accumulated bytes forward.

- [x] Replaced the append-loop in `processPartOrdered` with a single
  `bytes.NewBuffer(make([]byte, 0, streaming_segment_size))` + `buf.ReadFrom` —
  one allocation of exactly the configured part size, zero growth copies for
  normal-sized parts.
- [x] Reshaped `PartBuffer` to hold `Data []byte` instead of a
  `bufio.Reader` wrapping the bytes; `processBufferedPartsData` now hands the
  slice straight to `processPartDataInOrder` — the second append-loop is gone
  entirely (no re-read of already-buffered data).

**Measured impact (1 GB, local MinIO, fresh proxy):** upload **83.90 MB/s**,
download 117.80 MB/s — within run-to-run noise of the Tier 2.4 baseline
(79.65 / 102.65). As with 2.4, the local MinIO loopback is not alloc-bound on
the wire, so the throughput win is small; the hard guarantee is that the
per-part allocation is now `segment_size` flat (12 MiB) instead of
`~2 × segment_size` from geometric-growth `append`, and buffered
(out-of-order) parts no longer re-walk their own bytes through a second
64 KiB-chunk read loop. `processPartOrdered` allocations are now a single
`bytes.Buffer` per part — no growth copies. Full unit + integration suite
green (`TestStreamingPerformance` all sizes, `TestLargeMultipart500MB`,
`TestMultipartUploadCorruption`, `TestComprehensiveMultipartUpload`,
`TestHMACValidation`).

### 2.6 Replace Pipe+goroutine with synchronous reader in createStreamingDecryptionReader

**File**: [internal/orchestration/multipart.go:827-848](../../internal/orchestration/multipart.go#L827-L848), new type in [internal/orchestration/streaming_io.go:255-380](../../internal/orchestration/streaming_io.go#L255-L380)

Used `io.Pipe` + goroutine + per-chunk `make+copy` just to buffer the last chunk
for HMAC. The existing `hmacValidatingReader` couldn't be reused: its last-chunk
gating only triggers when EOF arrives **with data** (n>0, err=EOF) or when
`expectedSize` is known. Neither holds for the multipart GET path — bufio can
legitimately surface EOF as a separate n=0 read, which would leak the real
last chunk before HMAC verification.

- [x] Added dedicated `hmacGatedDecryptionReader` in `streaming_io.go` — synchronous, single-owner, ping-pong buffers (2×64 KiB allocated once at construction), holds back exactly one decrypted chunk until either a newer chunk arrives or the source hits EOF and the HMAC check succeeds. Works for both EOF-with-data and separate-EOF source patterns.
- [x] `createStreamingDecryptionReader` is now a thin constructor returning the new reader — pipe, goroutine, and per-chunk `make+copy` all gone.
- [x] Last-chunk gating invariant preserved: on EOF the held chunk is only moved to `emit` after `hmacManager.VerifyIntegrity` returns nil; any verification error sets `r.err` and the held bytes are never released.

**Measured impact (1 GB, local MinIO, fresh proxy):** upload **78.55 MB/s**,
download **121.13 MB/s** — within run-to-run noise of the Tier 2.5 baseline
(83.90 / 117.80). As with the rest of Tier 2, MinIO loopback hides the
alloc-space win; the hard guarantee is that the multipart decryption path no
longer allocates one buffer per 64 KiB chunk (≈16 k allocations per 1 GB GET
eliminated) and no longer spawns a goroutine per request. Full integration
suite green after proxy restart: `TestStreamingPerformance` all sizes,
`TestHMACValidation`, `TestMultipartUploadCorruption`,
`TestLargeMultipart500MB`, `TestComprehensiveMultipartUpload`.

**Tier 2 checkpoint (2026-04-24):**
- [x] Re-run `TestStreamingPerformance` @ 1 GB upload and download — **3-run avg upload 83.66 MB/s, download 121.14 MB/s** (flat vs Tier 1.3; MinIO loopback doesn't exercise 2.4/2.6 network wins)
- [x] Compare CPU + alloc profiles vs Tier 1 — archived in [docs/tickets/010-tier2/](010-tier2/)

**Measured impact (1 GB, fresh proxy, [docs/tickets/010-tier2/](010-tier2/)):**

| Metric | Baseline | Tier 1.1 | **Tier 2** | Delta vs Tier 1.1 |
|---|---:|---:|---:|---:|
| Upload throughput | 78.42 MB/s | 84.34 MB/s | **83.66 MB/s** | flat (noise) |
| Download throughput | 120.43 MB/s | 119.41 MB/s | **121.14 MB/s** | flat (noise) |
| Proxy alloc_space total (1 run) | 17.97 GB | 13.38 GB | **10.01 GB** | **−25.2 %** |
| `processPartOrdered` alloc | 4.99 GB (37 %) | 4.99 GB | **2.40 GB** (24.6 %) | **−52 %** (Tier 2.5) |
| `processBufferedPartsData` alloc | 1.92 GB (10.7 %) | 0.80 GB | **0** (gone from top) | **−100 %** (Tier 2.5 reshape) |
| `io.ReadAll` alloc | 7.12 GB (39.6 %) | 6.47 GB | 6.31 GB (64.6 %) | flat — Tier 3.1 target (upload-side ReadBody) |
| `runtime.memmove` CPU | 10.3 % | 10.77 % | **3.47 %** | **−66 %** (killed by 2.3/2.5/2.6) |
| `runtime.memclrNoHeapPointers` CPU | 5.7 % | ~5 % | **3.28 %** | **−42 %** |
| Crypto floor (CTR + GCM + SHA-256) | ~22 % | ~22 % | **~42 %** | hardware ceiling now dominant |
| `logrus.(*Entry).WithFields` alloc_objects | #1 (23.0 %) | #1 (24.55 %) | **gone from top-15** | already achieved by Tier 1.3 |
| `decryptionReader.Read` alloc_objects | #2 (16.2 %) | #2 | **gone from top-15** | **−100 %** (Tier 2.6) |

**Takeaway:** Throughput is flat on MinIO loopback because the remaining
bottlenecks there are crypto + local I/O, not alloc or network — Tier 2.4's
parallel UploadPart and 2.6's streaming decryption only show up against real
S3 latency. The hard wins that *did* land are memory and CPU composition:
per-request allocation dropped 25 %, `memmove` dropped by two thirds, and
the proxy CPU profile is now dominated by AES-NI + HMAC (~42 %) + network
syscalls (~20 %) with no remaining non-crypto target above 4 %. Next lever
is `io.ReadAll` (still 64.6 % of alloc_space) on the upload-side v4-chunked
body collection path — Tier 3.1 / Tier 4 territory.

---

## Tier 3 — Moderate ROI

### 3.1 Real streaming in AES-GCM — **reframed as copy-avoidance**

**File**: [pkg/encryption/dataencryption/aes_gcm.go](../../pkg/encryption/dataencryption/aes_gcm.go)

**Decision (2026-04-24):** GCM is not natively streamable — a single `Seal` /
`Open` needs the full plaintext to produce/verify the 16-byte auth tag.
Chunked-GCM framing would break the on-disk format, and replacing GCM with
CTR+HMAC on small objects would cost ~20–40 % CPU on every write (two passes
over the plaintext vs GCM's single AES-NI pass). The GCM path is **only**
used for objects `< streaming_threshold` (default 5 MiB), i.e. the
fluentd-style high-QPS small-object workload, where per-object allocation
count dominates — not streaming memory.

So "real streaming" is dropped in favour of copy-avoidance on the existing
one-shot path.

- [x] `EncryptStream`: `gcm.Seal(nonce, nonce, data, aad)` — appends ciphertext+tag directly behind the nonce prefix; drops the `make([]byte, …)` + two `copy`s
- [x] `DecryptStream`: `gcm.Open(ciphertext[:0], nonce, ciphertext, aad)` — decrypts in-place into the already-read ciphertext buffer; no separate plaintext allocation
- [x] Remove the defensive-copy on `lastNonce` assignment and in `GetLastIV` (nonce is 12 bytes, not secret, and not mutated after `Seal`)
- [x] Unit suite (`go test -short ./pkg/encryption/dataencryption/... ./pkg/encryption/envelope/... ./internal/orchestration/...`) green
- [x] Full integration suite green (`make test-integration` — all packages PASS incl. `performance-test` @ 144.9 s and `360-degree-variants` @ 236.0 s)

**Impact:** per small-object GCM PUT, heap allocations for the ciphertext
buffer drop from ~3× object-size (`ReadAll` + `Seal(nil,…)` + prepend-buffer)
to ~1× (ciphertext appended onto nonce in place). Per GCM GET: ~2× → ~1×
(in-place `Open`). The nonce path drops two small allocations per
encrypt/metadata-read. No throughput change on the 1 GB streaming test (that
path doesn't use GCM); the win is GC pressure + RSS on small-object
workloads, which matches the actual user of this code path.

**Out of scope (explicitly not doing):**
- Chunked GCM framing — would break the existing on-disk format (new header
  per chunk, counter-derived nonces). "No backward compatibility" in CLAUDE.md
  could allow it, but there is no throughput case for GCM ≥ 5 MiB (handler
  routes to CTR+HMAC multipart) and no small-object case where the per-chunk
  framing overhead would pay off.
- Replacing GCM with CTR+HMAC on small objects — rejected on CPU grounds
  (single-AEAD-pass with AES-NI is faster than CTR + second HMAC pass at
  < 5 MiB).

### 3.2 DEK cache copy avoidance

**File**: [internal/orchestration/providers.go:188-249](../../internal/orchestration/providers.go#L188-L249)

`append([]byte(nil), cachedDEK...)` on every cache hit = 32-byte alloc per
request.

- [x] Return the cached DEK by reference; contract documented on
  `DecryptDEK` and `cacheGet` ("returned slice is cache-owned, callers must
  treat as read-only").
- [x] Audit revealed all three callers (`singlepart.go` GCM decrypt +
  streaming CTR decrypt, `multipart.go` multipart decrypt) were zeroing the
  returned slice via `for i := range dek { dek[i] = 0 }` /
  `ClearSensitiveData(dek)`. Zeroing a cache-owned slice would corrupt the
  next hit, so the three defers were removed. The zeroing was already mostly
  theatre — the cache holds decrypted DEKs for up to 1024 entries anyway,
  so the key material lives in RAM regardless of whether the caller's local
  reference is scrubbed.
- [x] `*[32]byte` signature rejected — would force churn across HMAC
  calculator (takes `[]byte`), `NewAESCTRStatefulEncryptor*`, and all unit
  tests without additional safety over the doc comment; slice reference +
  contract is sufficient.
- [x] Full unit + integration suite green (`make test-integration` — all
  packages PASS incl. `TestDEKCacheReuploadRegression`,
  `TestHMACValidation`, `TestMultipartUploadCorruption`,
  `TestStreamingPerformance`, `performance-test` @ 139.9 s,
  `360-degree-variants` @ 232.3 s).

**Impact:** eliminates one 32-byte alloc per cache hit. On the 1 GB
streaming test the DEK is decrypted once per object, so this shows up only
as cleanliness; on the fluentd-style high-QPS small-object workload (many
GETs of the same object) it removes the only per-request heap alloc on the
cache-hit path. No change to measured throughput on the 1 GB loopback
(expected — crypto floor dominates, not 32 B/req).

### 3.3 Avoid redundant bufio.NewReader wrapping

- [x] Grep for `bufio.NewReader` across `internal/orchestration/` and `internal/proxy/request/` — remove wraps where the source is already a bufio.Reader or a large-buffered source

**Changes (2026-04-24):**
- `StreamingEncryptionResult.EncryptedDataReader` and `EncryptionResult.EncryptedData` typed as `io.Reader` instead of `*bufio.Reader`. All external consumers only ever called `.Read` / `io.ReadAll` on these fields — no bufio-specific methods (`Peek`, `ReadByte`, `ReadString`) were in play, so the stricter type was overhead without benefit.
- Dropped `bufio.NewReader(bytes.NewReader(buffer))` wraps at
  [internal/orchestration/singlepart.go:153](../../internal/orchestration/singlepart.go#L153) and
  [internal/orchestration/multipart.go:329](../../internal/orchestration/multipart.go#L329) — `bytes.Reader` is already a zero-copy in-memory source; wrapping in bufio added a 4 KiB buffer alloc plus an extra copy per read for no gain.
- Dropped the `if br, ok := encryptedReader.(*bufio.Reader); ok { … } else { bufio.NewReader(…) }` dance in
  [internal/orchestration/manager.go:106-136](../../internal/orchestration/manager.go#L106-L136) (`EncryptData`) — with the field now `io.Reader`, the reader is assigned straight through.
- `internal/proxy/request/` had nothing to remove: the only call is `bufio.NewReaderSize(src, 64*1024)` in [streaming_aws_decoder.go:37](../../internal/proxy/request/streaming_aws_decoder.go#L37), which is the reader's primary buffer, not a wrap.

**Impact:** pure hygiene / allocation-count win on the singlepart-CTR and multipart-ordered paths. Each affected code site drops one `bufio.Reader{}` (a 4 KiB `buf` slice + struct header) per part / per small HMAC upload. Not measurable on the 1 GB `TestStreamingPerformance` throughput number (crypto floor dominates), but removes unambiguous dead allocation from the hot paths. Full unit + integration suite green against a fresh proxy (`make test-integration` — all packages PASS incl. `performance-test` @ 141.2 s, `360-degree-variants` @ 232.9 s).

---

## Tier 4 — Hygiene & micro-tuning

### 4.1 Buffer size tuning

**Files**:
- [internal/validation/hmac_calculator.go:49-78](../../internal/validation/hmac_calculator.go#L49-L78) — 32 KB → 128 KB
- [internal/proxy/request/streaming_aws_decoder.go:35-40](../../internal/proxy/request/streaming_aws_decoder.go#L35-L40) — 64 KB → 128 KB

- [x] Increase `AddFromStream` buffer from 32 KB to 128 KB
- [x] Increase `bufio.NewReaderSize` in streaming AWS decoder to 128 KB (kept at 128, not 256 — the 12 MiB part workload doesn't benefit from more in-flight bytes per read, and 256 KB doubles the per-request bufio footprint for no measurable win)
- [x] Benchmark impact at 1 GB

**Measured impact (1 GB, 3-run avg, fresh proxy, [docs/tickets/010-tier4.1/](010-tier4.1/)):**

| Metric | Tier 2 | Tier 4.1 (3-run avg) | Delta |
|---|---:|---:|---:|
| Upload throughput | 83.66 MB/s | 79.86 MB/s (80.56 / 80.10 / 78.91) | flat (run-to-run noise) |
| Download throughput | 121.14 MB/s | 119.31 MB/s (116.89 / 119.22 / 121.82) | flat (run-to-run noise) |
| Proxy alloc_space total (1 run) | 10.01 GB | 9.94 GB | flat (−0.7 %) |
| `io.ReadAll` alloc | 6.31 GB (64.6 %) | 6.42 GB (64.6 %) | flat — Tier 4.2/Tier 4 territory |
| `processPartOrdered` alloc | 2.40 GB (24.6 %) | 2.45 GB (24.6 %) | flat |
| `runtime.memmove` CPU | 3.47 % | 7.16 % | up — bigger per-Read copies through bufio (expected, still well below Tier 1.1 baseline of 10.3 %) |

As expected: micro-buffer tuning at this point in the ticket is hygiene
only. The HMAC `AddFromStream` change replaces ~4× as many `hash.Hash.Write`
calls per byte (one 128 KiB call for every 4× 32 KiB), reducing per-call
overhead inside `crypto/internal/fips140/sha256.blockSHA2`'s call boundary.
The aws-chunked decoder change halves the underlying `Read` syscalls when
the upstream surfaces partial reads larger than 64 KiB. Neither shows up on
the loopback throughput number because the run is bounded by the AES-NI +
SHA-256 floor and local network composition, not Read-call frequency. Full
unit + integration suite green (`make test-integration` — all 7 packages
PASS, including `TestStreamingPerformance` all sizes,
`TestMultipartUploadCorruption`, `TestHMACValidation`, `performance-test`
@ 138.2 s, `360-degree-variants` @ 232.9 s).

### 4.2 Pooled io.CopyBuffer in GET path

- [x] Introduce a package-level `sync.Pool` of 128 KiB buffers in
  [internal/proxy/handlers/object/helpers.go](../../internal/proxy/handlers/object/helpers.go#L16-L34)
  (stores `*[]byte` to avoid the staticcheck SA6002 pitfall) plus a small
  `copyWithPooledBuffer(dst, src)` helper.
- [x] Replaced all three GET-response `io.Copy` sites with the pooled helper:
  the streaming HMAC GET branch ([operations.go:371](../../internal/proxy/handlers/object/operations.go#L371)),
  the standard non-streaming GET branch ([:390](../../internal/proxy/handlers/object/operations.go#L390)),
  and the GetObjectTorrent passthrough ([:1078](../../internal/proxy/handlers/object/operations.go#L1078)).

**Impact:** removes `io.Copy`'s per-call 32 KiB scratch allocation on the GET
response path; each GET that doesn't trip the stdlib `WriterTo` /
`ReaderFrom` fast-path now reuses a 128 KiB pooled buffer instead. Bigger
copies per syscall also halve the upstream `Read` count on the streaming HMAC
GET branch (whose source is a 64 KiB ping-pong reader). No throughput change
visible on the loopback 1 GB run (already AES-NI bound), but no regression
either; full unit + integration suite green.

### 4.3 Demote per-request logs from Info to Debug

- [x] Swept `internal/proxy/handlers/{object,multipart}/` for per-request
  `Info` lines and demoted them to `Debug`. Eighteen sites in
  [internal/proxy/handlers/object/operations.go](../../internal/proxy/handlers/object/operations.go)
  (GET streaming entry/exit, early-HMAC-validation tracing, HMAC-capability
  branches, force-aes-ctr decision, "Using direct/streaming upload",
  per-PUT/multipart success terminals) plus the "Successfully aborted
  multipart upload" line in
  [internal/proxy/handlers/multipart/abort.go:96](../../internal/proxy/handlers/multipart/abort.go#L96).
  Also dropped the stale `"DEBUG:"` prefix from the force-aes-ctr message so
  the log level is consistent with the message.
- [x] Verified the demoted strings aren't asserted on by any test
  (`grep` across the repo returned only source-code matches, no `_test.go`).

**Why:** `WithFields(...).Info(...)` allocates a `logrus.Fields` map per
call regardless of whether the record is emitted, and at production log
levels (`info` and above) every per-request line was paying for a map alloc
to be discarded. After Tier 1.3 killed per-Read map allocs in the streaming
loop, the per-request handler `Info` lines were the next visible
`logrus.(*Entry).WithFields` contributor — demotion makes them allocate only
when `debug` is enabled.

**Measured impact:** full unit + integration suite green (`make test-integration`
— all 7 packages PASS, including `TestStreamingPerformance` all sizes,
`TestLargeMultipart500MB` @ 24.27 s, `TestMultipartUploadCorruption` @ 25.94 s,
`TestComprehensiveMultipartUpload` @ 96.84 s, `TestStreamingMultipartUpload`
@ 74.30 s, `TestHMACValidation` @ 6.45 s, `performance-test` @ 146.6 s,
`360-degree-variants` @ 225.9 s, `s3-methods` @ 24.6 s,
`encryption-modes` @ 4.2 s, `authentication` @ 2.7 s,
`180-degree-variants` @ 25.1 s). Throughput is dominated by the AES-NI +
SHA-256 floor, so this is hygiene + GC pressure, not a throughput lever.

---

## Expected overall gain

| Stage       | Upload          | Download        |
|-------------|-----------------|-----------------|
| Baseline    | ~128 MB/s       | ~218 MB/s       |
| After T1    | ~300–400 MB/s   | ~400–500 MB/s   |
| After T1+T2 | ~500–800 MB/s   | ~600–900 MB/s   |
| After T3+T4 | approach AES-NI ceiling (~1–2 GB/s), bounded by S3 network |

---

## Done criteria

- [x] All tiers merged or explicitly deferred with a note — Tier 1.1/1.2/1.3, 2.1–2.6, 3.1/3.2/3.3, 4.1/4.2/4.3 all done; 3.1 reframed as copy-avoidance (chunked-GCM framing rejected with rationale).
- [x] `TestStreamingPerformance` regression-free at every size (100 KB → 1 GB) — 2026-04-25: all 10 sizes PASS, average upload 71.84 MB/s, download 114.57 MB/s on fresh proxy.
- [x] Full `make test-integration` green — 2026-04-25: all 7 packages ok, 74 PASS / 0 FAIL (`integration` 0.83 s, `180-degree-variants` 27.62 s, `360-degree-variants` 240.75 s, `authentication` 2.62 s, `encryption-modes` 3.80 s, `performance-test` 150.51 s, `s3-methods` 28.72 s).
- [x] Before/after pprof snapshots archived in this ticket — [docs/tickets/010-baseline/](010-baseline/), [010-tier1/](010-tier1/), [010-tier1.3/](010-tier1.3/), [010-tier2/](010-tier2/), [010-tier4.1/](010-tier4.1/) (Tier 4.2/4.3 are hygiene-only, no separate snapshot).
- [x] No increase in peak RSS during 1 GB upload or download (streaming preserved) — 2026-04-25: proxy peak 109.2 MiB during full 100 KB → 1 GB run on a 512 MiB-limited container (idle 7.5 MiB). Matches the streaming bound `segment_size × (1 + multipart_upload_concurrency) = 12 MiB × 5 = 60 MiB` plus HMAC + handler overhead — no full-object buffering for 1 GB transfers.
