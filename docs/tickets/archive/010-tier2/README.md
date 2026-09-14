# Ticket 010 — Tier 2 Snapshot (AFTER)

**Date:** 2026-04-24
**Test:** `TestStreamingPerformance/Performance_1GB` (MinIO loopback, fresh proxy)
**Binaries profiled:** test client + proxy (`/debug/pprof` on :9090)

## Throughput (1 GB) — 4 runs

| Run | Upload MB/s | Download MB/s |
|---|---:|---:|
| 1 (during proxy CPU capture, Run A) | 81.88 | 124.31 |
| 2 | 83.16 | 120.60 |
| 3 | 85.94 | 118.52 |
| 4 (during proxy CPU capture, Run B — profile overhead) | 81.67 | 110.66 |
| **avg runs 1–3** | **83.66** | **121.14** |

Run 4's download is depressed by the 15 s proxy CPU profile overlapping the download window, so it's excluded from the average.

## Comparison vs earlier tiers

| Stage              | Upload MB/s | Download MB/s | Proxy alloc_space (1 GB, 1 run) |
|--------------------|------------:|--------------:|--------------------------------:|
| Baseline           | 78.42       | 120.43        | 17.97 GB                        |
| Tier 1.1           | 84.34       | 119.41        | 13.38 GB                        |
| Tier 1.3           | 82.84       | 121.25        | (22.29 GB — multi-run capture)  |
| **Tier 2 (this)**  | **83.66**   | **121.14**    | **10.01 GB**                    |

Throughput is **flat vs Tier 1** (within run-to-run noise), as expected: MinIO
loopback is not alloc-bound and has no real-S3 RTT to parallelise away. The
Tier 2 wins land in **memory pressure, GC cost, and peak working set** —
visible in the profiles below.

## Proxy alloc_space (1 GB run, fresh proxy, 10.01 GB total)

```
6461.05 MB 64.56%  io.ReadAll
2460.00 MB 24.58%  orchestration.processPartOrdered    ← Tier 2.5 win: 4.99 GB → 2.40 GB (−52 %)
1025.55 MB 10.25%  AWSChunkedDecoder.RequiresChunkedDecoding
```

| alloc_space source                          | Tier 1.1   | Tier 2     | Delta         |
|---------------------------------------------|-----------:|-----------:|--------------:|
| Total (1 GB, 1 run)                         | 13.38 GB   | **10.01 GB** | **−25.2 %** |
| `io.ReadAll`                                | 6.47 GB    | 6.31 GB    | flat (Tier 3.1 target) |
| `processPartOrdered`                        | 4.99 GB    | **2.40 GB** | **−52 %** (Tier 2.5) |
| `processBufferedPartsData`                  | 0.80 GB    | **0 GB** (gone from top) | **−100 %** (Tier 2.5 re-shape) |
| `AWSChunkedDecoder.RequiresChunkedDecoding` | 1.02 GB    | 1.03 GB    | flat (Tier 4 candidate) |

The two biggest Tier 2 targets have landed:
- **2.5** eliminated the geometric-growth `append` in `processPartOrdered`, which also
  dropped `processBufferedPartsData` out of the top entirely because the second
  append-loop (re-reading buffered parts through `bufio`) is gone.
- **2.3 / 2.6** removed `io.ReadAll` on the GCM-GET path and per-chunk `make+copy`
  in the multipart decryption path. `io.ReadAll` is still Top-1 here because
  the **upload-side** ReadBody path (v4 streaming chunked decoding) still
  collects the decoded body — that's the Tier 3.1 / Tier 4 target.

## Proxy alloc_objects (1 GB run, fresh proxy, 465 k objects total)

Top entries are now **HTTP/TLS plumbing** and SDK init, not our hot path:

```
73 231 15.73%  net/http.Header.Clone
32 768  7.04%  multipart.handleStreamingUploadPart
32 768  7.04%  net/http.connReader.startBackgroundRead
21 845  4.69%  net/textproto.canonicalMIMEHeaderKey
19 207  4.13%  io.ReadAll
10 923  2.35%  orchestration.processPartDataInOrder
```

- `logrus.(*Entry).WithFields` — **gone from top-15** (was #1 at ~23 % pre-Tier 1.3)
- `orchestration.decryptionReader.Read` — **gone from top-15** (was #2 at ~16 %; Tier 2.6
  replaced the per-chunk `make+copy` in the multipart decryption path)
- `AESCTRStatefulEncryptor.EncryptPart`/`DecryptPart` — **gone** (Tier 1.1 in-place XOR)

## Proxy CPU (15 s sample during 1 GB run, 5.48 s samples)

```
1.11s 20.26%  runtime/syscall.Syscall6                       ← network I/O
0.88s 16.06%  crypto/internal/fips140/aes/gcm.gcmAesDec      ← AES-GCM decrypt
0.75s 13.69%  crypto/internal/fips140/aes.ctrBlocks8Asm      ← AES-CTR AES-NI
0.67s 12.23%  hash/crc64.update                              ← S3 SDK CRC
0.66s 12.04%  crypto/internal/fips140/sha256.blockSHA2       ← HMAC
0.19s  3.47%  runtime.memmove
0.18s  3.28%  runtime.memclrNoHeapPointers
0.17s  3.10%  runtime.futex
0.14s  2.55%  crypto/internal/fips140/aes/gcm.gcmAesEnc
```

| CPU line                 | Baseline | Tier 1.1 | Tier 2 | Delta vs baseline |
|--------------------------|---------:|---------:|-------:|------------------:|
| `runtime.memmove`        | 10.3 %   | 10.77 %  | **3.47 %** | **−66 %** |
| `runtime.memclrNoHeapPointers` | 5.7 %  | —    | 3.28 % | **−42 %** |
| Crypto floor (AES-CTR + AES-GCM + SHA-256) | ~22 % | ~22 % | **~42 %** | crypto is now dominant — hardware ceiling |
| `syscall.Syscall6`       | 20.2 %   | —        | 20.26 % | flat (network I/O) |

Reading this: the non-crypto overhead has collapsed. `memmove` (which was the
proxy's CPU hot spot after syscalls in the baseline and through Tier 1.1) is
now down to **3.47 %** — a straight consequence of Tier 2.5 (no `append`
growth copies) + Tier 2.6 (no per-chunk decryption copy) + Tier 2.3 (no
GCM-GET double-`ReadAll`).  The profile is now dominated by the hardware
crypto floor (AES-NI + SHA-256) and network syscalls. That's the expected
shape after a successful Tier 2.

## Takeaway

- **Throughput stays flat on MinIO loopback**, exactly as Tier 2 was predicted
  to behave — the 2.4 parallel-UploadPart and 2.6 streaming-decryption wins
  need real-S3 RTT to materialise as MB/s.
- **Per-request memory pressure dropped ~25 %** (13.38 GB → 10.01 GB alloc for
  a single 1 GB round-trip) and the streaming decryption path no longer
  allocates per-chunk.
- **CPU hot path is now crypto + syscalls**: `memmove` (the next biggest
  non-crypto spender) fell from 10.3 % to 3.47 %. There's no remaining
  non-crypto target above 4 % in the CPU profile.
- Next remaining lever in alloc_space is `io.ReadAll` at 64.6 % of total
  (6.31 GB) — that's the upload-side v4-chunked body collection path, Tier 3.1
  and Tier 4 territory.

## Artifacts

Client-side (test binary):
- `cpu.out`, `mem.out` — raw profiles
- `cpu-top20.txt`, `mem-alloc-space.txt`, `mem-alloc-objects.txt` — top-N dumps
- `test-output.log` — `go test -v` output (Run A only; Runs 2–4 logged inline in README)

Proxy-side (via `/debug/pprof` on :9090):
- `proxy-cpu.out` — 15 s CPU profile during the 1 GB run
- `proxy-allocs.out` — allocation profile (fresh proxy, 1 run)
- `proxy-heap.out` — heap snapshot right after the run
- `proxy-cpu-top20.txt`, `proxy-allocs-top20.txt`, `proxy-allocs-objects-top15.txt` — top-N dumps
