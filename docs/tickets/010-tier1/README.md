# Ticket 010 — Tier 1.1 Snapshot (in-place CTR XOR)

**Date:** 2026-04-23
**Change:** In-place XOR in `AESCTRStatefulEncryptor.{En,De}cryptPart` +
removed redundant `copy(p[:n], ...)` in
`internal/orchestration/streaming_io.go` `encryptionReader.Read` /
`decryptionReader.Read`.

## Throughput (1 GB `TestStreamingPerformance/Performance_1GB`)

| Run | Upload | Download |
|---|---:|---:|
| Baseline (010-baseline, combined) | 78.42 MB/s | 120.43 MB/s |
| **Tier 1.1 (this run)** | **84.34 MB/s** | 119.41 MB/s |
| Delta | **+7.5 %** | ~flat (noise) |

Raw output: [test-output.log](test-output.log).

## Proxy alloc_space (cumulative over the run)

| Line | Baseline | Tier 1.1 | Delta |
|---|---:|---:|---:|
| `io.ReadAll` | 7.12 GB (39.6 %) | 6.47 GB (48.3 %) | −9 % |
| `processPartOrdered` | 5.44 GB (30.3 %) | 4.99 GB (37.3 %) | −8 % |
| `processBufferedPartsData` | 1.92 GB (10.7 %) | 798 MB (5.96 %) | **−58 %** |
| `AESCTRStatefulEncryptor.DecryptPart` | 1.13 GB (6.3 %) | — (out of top) | **−100 %** |
| `AESCTRStatefulEncryptor.EncryptPart` | 1.12 GB (6.3 %) | — (out of top) | **−100 %** |
| **Total alloc_space** | **17.97 GB** | **13.38 GB** | **−25.5 %** |

The drop in `processBufferedPartsData` is a knock-on: that function used to
copy the encrypted output; the in-place path removes one half of that pair.

## Proxy alloc_objects

| Line | Baseline | Tier 1.1 |
|---|---:|---:|
| `logrus.(*Entry).WithFields` | 232 783 (23.0 %) | 199 889 (24.55 %) — still #1 (Tier 1.3 target) |
| `decryptionReader.Read` | 163 842 (16.2 %) | 98 305 (12.07 %) |
| `AESCTRStatefulEncryptor.DecryptPart` | 72 220 (7.1 %) | — (out of top) |

## Proxy CPU (25 s sample during run)

| Symbol | Baseline | Tier 1.1 |
|---|---:|---:|
| `runtime.memmove` | 10.3 % | 10.77 % (flat) |
| `crypto/.../aes.ctrBlocks8Asm` | 8.6 % | 9.65 % |
| `runtime.memclrNoHeapPointers` | 5.7 % | 8.09 % |
| syscalls | 20.2 % | 21.54 % |

`runtime.memmove` doesn't drop yet because `io.ReadAll` and
`processPartOrdered` still dominate the copy budget. Those are Tier 2 targets.

## Archived artifacts

- `cpu.out`, `mem.out` — client-side profiles
- `proxy-cpu.out`, `proxy-allocs.out`, `proxy-heap.out` — server-side profiles
- `proxy-cpu-top20.txt`, `proxy-allocs-top20.txt`,
  `proxy-allocs-objects-top15.txt` — top-N text dumps
- `test-output.log` — raw `go test -v` output
