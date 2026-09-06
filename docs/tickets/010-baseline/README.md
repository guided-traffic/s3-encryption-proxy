# Ticket 010 — Baseline Snapshot (BEFORE)

**Date:** 2026-04-23
**Test:** `TestStreamingPerformance/Performance_1GB`
**Binaries profiled:** test client (`performance-test.test`) AND proxy (`s3-encryption-proxy` via `/debug/pprof`)

## Throughput (1 GB) — two runs (client-only profile + combined)

| Run              | Upload         | Download        |
|------------------|----------------|-----------------|
| Client-only      | 80.12 MB/s     | 120.25 MB/s     |
| Combined (proxy pprof during run) | 78.42 MB/s | 120.43 MB/s |

> Note: these numbers are from this machine's run; the ticket header values
> (128 MB/s up / 218 MB/s down) are from the ticket author's original machine.
> Re-compare against these local numbers after each tier.

## Archived artifacts

Client-side (test binary):
- `cpu.out`, `mem.out` — raw profiles
- `cpu-top20.txt`, `mem-alloc-objects.txt`, `mem-alloc-space.txt` — top-N text dumps
- `test-output.log` — raw `go test -v` output

Proxy-side (via `/debug/pprof` on :9090):
- `proxy-cpu.out` — 25 s CPU profile captured during the 1 GB run
- `proxy-allocs.out` — allocation profile (cumulative since proxy start)
- `proxy-heap.out` — heap snapshot right after the run
- `proxy-cpu-top20.txt`, `proxy-allocs-top20.txt`, `proxy-allocs-objects-top15.txt` — top-N dumps

## Proxy-side pprof setup (done 2026-04-23)

Added `monitoring.pprof_enabled` config flag that wires `net/http/pprof` onto
the monitoring mux (port 9090). Demo config has it on. See
[internal/monitoring/server.go](../../../internal/monitoring/server.go) and
[config/aes-example.yaml](../../../config/aes-example.yaml).

## Proxy hot paths — Tier targets confirmed

**CPU (25 s sample during 1 GB run, 12.57 s total samples):**

```
2.54s 20.2%  internal/runtime/syscall/linux.Syscall6       ← network I/O
1.30s 10.3%  runtime.memmove                                ← Tier 1.1 target
1.08s  8.6%  crypto/internal/fips140/aes.ctrBlocks8Asm     ← AES-NI floor
0.86s  6.8%  crypto/internal/fips140/sha256.blockSHA2      ← HMAC
0.82s  6.5%  hash/crc64.update                              ← S3 client CRC
0.80s  6.4%  crypto/internal/fips140/aes/gcm.gcmAesDec     ← GCM path
0.71s  5.7%  runtime.memclrNoHeapPointers                   ← buffer clearing
```

**Alloc space (cumulative, 17.97 GB during run):**

```
 7.12 GB 39.6%  io.ReadAll                                           ← Tier 2.x
 5.44 GB 30.3%  orchestration.processPartOrdered                     ← Tier 2.5 append-build
 1.92 GB 10.7%  orchestration.processBufferedPartsData
 1.13 GB  6.3%  dataencryption.AESCTRStatefulEncryptor.DecryptPart   ← Tier 1.1 in-place XOR
 1.12 GB  6.3%  request.AWSChunkedDecoder.RequiresChunkedDecoding
 1.12 GB  6.3%  dataencryption.AESCTRStatefulEncryptor.EncryptPart   ← Tier 1.1 in-place XOR
```

**Alloc objects (cumulative, 1.01 M objects during run):**

```
232 783  23.0%  logrus.(*Entry).WithFields                            ← Tier 1.3 target
163 842  16.2%  orchestration.(*decryptionReader).Read                ← inside the Tier 1.3 callsite
 72 220   7.1%  AESCTRStatefulEncryptor.DecryptPart
 32 768   3.2%  logrus.(*TextFormatter).printColored                  ← still allocates at non-Debug levels
```

Every planned Tier 1/2 target is now visible in the proxy profile and can be
measured tier-by-tier.

## Client-side notes (for completeness)

`go test -cpuprofile` profiles the test binary; the dominant items there are
v4 chunked SHA-256 signing (28 % CPU) and `io.ReadAll` of the 1 GB GET body
(2.56 GB alloc\_space) — both expected, not proxy regressions.

## How to re-run after each tier

```bash
TIER=docs/tickets/010-tier1 ; mkdir -p "$TIER"

# Start the 1 GB test in the background (writes client-side profiles):
go test -tags=integration ./test/integration/performance-test \
    -run 'TestStreamingPerformance/Performance_1GB' -count=1 -v -timeout=30m \
    -cpuprofile=$TIER/cpu.out -memprofile=$TIER/mem.out \
    | tee $TIER/test-output.log &

# Give it ~4 s to warm up, then capture 25 s of proxy CPU in parallel:
sleep 4
curl -s 'http://localhost:9090/debug/pprof/profile?seconds=25' -o $TIER/proxy-cpu.out
wait
curl -s 'http://localhost:9090/debug/pprof/allocs' -o $TIER/proxy-allocs.out
curl -s 'http://localhost:9090/debug/pprof/heap'   -o $TIER/proxy-heap.out

# Top-N dumps:
go tool pprof -top -nodecount=20 $TIER/cpu.out         > $TIER/cpu-top20.txt
go tool pprof -alloc_space -top -nodecount=20 $TIER/mem.out > $TIER/mem-alloc-space.txt
go tool pprof -top -nodecount=20 $TIER/proxy-cpu.out   > $TIER/proxy-cpu-top20.txt
go tool pprof -alloc_space -top -nodecount=20 $TIER/proxy-allocs.out > $TIER/proxy-allocs-top20.txt
go tool pprof -alloc_objects -top -nodecount=15 $TIER/proxy-allocs.out > $TIER/proxy-allocs-objects-top15.txt
```

> The proxy `allocs` profile is cumulative since the proxy started. To get a
> clean delta, restart the proxy (`docker restart proxy`) before each tier run.
