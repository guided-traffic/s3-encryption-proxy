# What this run says

The measurements are in `REPORT.md` and `run.json`. This file is the reading of them,
written the day they were taken. It states what the numbers support, what they only
suggest, and what they cannot answer.

Every measured figure below is the median of 7 repetitions in `run.json`, with four
exceptions that are marked where they appear: the cold and first-load memory readings and
the container limit are single values (`n` is 1); the CPU-profile percentages come from one
30 s capture and are not in `run.json` at all; the ratios and the serialised CRC write rate
are derived; and the figures under "Two measurement bugs" come from discarded runs. Where a
row is marked unstable in `REPORT.md` it is said so here.

Run `20260909T175340Z-9f3fbd1`, label `pre-v2`, 7 repetitions, 454 s.
Commit `9f3fbd11351f` on `feat/major-v5`. **`run.json` records the working tree as dirty**;
it does not record which files differed, so that is all the run itself can attest.
Apple M5 Pro, 18 cores, 64 GiB, Go 1.27.1, macOS 26.6.2, on mains.
Load average rose from 4.49 to 8.44 across the run, which is the run itself.

Stack: the demo compose environment, `aes` provider, `integrity_verification: strict`,
`streaming_threshold` 5 MiB, `streaming_segment_size` 12 MiB,
`multipart_upload_concurrency` 4, proxy containers capped at 512 MiB.

**This is the "before" column for the storage format change.** Reproduce the "after" with
`make perf-baseline` on the post-change commit, on this machine, then `make perf-compare`.

## 1. The segment chain is 3.4× faster than the path it replaces

In process, median of 7 repetitions at 128 MiB:

| Path | encrypt | decrypt |
|---|---:|---:|
| current, at or above the threshold — AES-CTR then HMAC-SHA256 | 2429 MiB/s | 2400 MiB/s |
| current, below the threshold — whole-object AES-GCM | 8239 MiB/s | 8694 MiB/s |
| **the segment chain — AES-GCM in 64 KiB segments** | **8150 MiB/s** | **8692 MiB/s** |

- Against the large-object path: **3.4× on write** (8150 / 2429) and **3.6× on read**
  (8692 / 2400). **These are the cipher alone.** The codec that shipped on 2026-09-09 measures
  1.74× and 1.77× once its CRC32C is included — see the `segment-codec` run beside this one.
  The rows in this run are a model, and they are labelled "candidate" for that reason.
- Against whole-object AES-GCM: **parity**, −1.1 % on write and −0.02 % on read.
  Segmenting at 64 KiB costs bytes, not time.
- The two decrypt rows are noisy: `v1_gcm_whole_decrypt` scatters 10.8 % and
  `v2_gcm_seg_decrypt` 23.1 %. Their near-equality is the honest reading; a claim that
  either is faster than the other would not survive the scatter. The encrypt rows are
  tight (8.5 % and 1.3 %).

The HMAC is the entire difference. Measured alone at 128 MiB, HMAC-SHA256 runs at
**3092 MiB/s** while AES-CTR runs at **10475 MiB/s**, so the current large-object path can
never exceed the HMAC no matter how fast the cipher is.

**The CRC32C the trailer adds is not free, and this corrects a first reading of it.** It
runs at **11131 MiB/s**, which is 0.73 of the sealing pass per byte. Run as a separate
serial pass over the plaintext it takes the combined write rate from 8150 to about
**4705 MiB/s** — 42 % slower, 73 % more CPU time per byte. That is still comfortably above
the 2429 MiB/s the current path achieves, so the segment chain plus a serial CRC is roughly
**1.9× faster** than today rather than 3.4×. Whether the full 3.4× is reachable depends on
folding the checksum into the same pass over the data instead of taking a second one. This
is a design consequence, not a measurement artefact.

**The proxy's own CPU profile confirms the HMAC cost outside the microbenchmark.**
Captured over 30 s under large-object load, 11.79 s of samples. The capture itself is at
`../profiles-pending/proxy-cpu.pprof` **but is not committed** — profiles are reproducible and
large, so the numbers below are the record and the file is not:

| Symbol | flat |
|---|---:|
| `internal/runtime/syscall/linux.Syscall6` | 34.86 % |
| `crypto/internal/fips140/sha256.blockSHA2` | **17.30 %** |
| `runtime.memclrNoHeapPointers` | 7.55 % |
| `runtime.memmove` | 5.68 % |
| `crypto/internal/fips140/aes.ctrBlocks8Asm` | **5.17 %** |
| `crypto/internal/fips140/aes/gcm.gcmAesEnc` | 4.07 % — **TLS records, backend hop** |
| `crypto/internal/fips140/aes/gcm.gcmAesDec` | 3.90 % — **TLS records, backend hop** |

**The two GCM rows are not object encryption.** `pprof -peek` reaches them only through
`crypto/tls.(*xorNonceAEAD)`: they are the TLS records of the proxy-to-backend hop. Counting
them as object crypto is exactly the misattribution that this project has already made once
and that the measurement rules were written to prevent, so it is spelled out here.

The object crypto is the other two rows: SHA-256 at 17.30 %, reached through
`hmac.(*HMAC).Write` and therefore genuinely the integrity pass, and AES-CTR at 5.17 %.
Together 22.5 % of samples, of which the HMAC is **77 %** — **3.3× the AES-CTR it protects**.
The segment chain deletes that pass and takes the same property from the cipher.

`memclrNoHeapPointers` at 7.55 % is buffer zeroing and is not explained here; it is a
candidate for the next profiling round, not a finding.

## 2. Upload falls off a cliff at exactly the threshold; download is at parity

Proxy against a direct backend, same run, median of 7:

| Size | upload, plain HTTP | upload, TLS | download, plain HTTP | download, TLS |
|---|---:|---:|---:|---:|
| 4 MiB | 72.2 % | 75.3 %* | 87.5 % | 84.6 % |
| 5 MiB | **59.3 %** | **56.5 %** | 98.1 % | 100.3 % |
| 8 MiB | 60.2 % | 59.2 % | 100.9 % | 96.5 % |
| 32 MiB | 56.4 % | 55.5 % | 103.0 % | 110.7 % |
| 128 MiB | 60.1 %* | 46.1 %* | 102.9 % | 108.6 % |

\* marked unstable in `REPORT.md`. Both 128 MiB upload rows scatter badly (14.3 % and
24.5 % on the proxy leg) and so does the 4 MiB TLS upload row (10.0 %). Every download row
in this table is stable.

5 MiB is `streaming_threshold`. At and above it, with integrity verification on, a write
leaves the whole-object AES-GCM path and enters the two-pass CTR-plus-HMAC pipeline with
its post-completion self-copy. On plain HTTP the crossing costs **12.9 points** (72.2 →
59.3) and the ratio then stays at 60.2 % (8 MiB) and 56.4 % (32 MiB) — the only stable larger
rows. The TLS
column falls 18.8 points, but its 4 MiB "before" point is itself unstable, so the size of
the TLS crossing is not established — only that it happens.

Downloads are a different story: from 5 MiB up the proxy is within a few percent of the
direct backend, between **96.5 % and 110.7 %**, sometimes just below it. Ratios above 100 %
are not the proxy being faster than the storage behind it — they are read-ahead and backend
variance — and they mean "no measurable cost", not "a gain".

**The consequence for the format change, and it is not the obvious one.** The crypto headroom
of finding 1 is nearly worthless end to end: at these rates the crypto occupies 3.8 % of the
proxy's per-byte time at 8 MiB, 5.0 % at 32 MiB and 6.1 % at 128 MiB, so a 3.4× crypto is worth
+2.7 %, +3.7 % and +4.5 %. Download gains nothing — it is already at parity.

What the cliff points at instead is the **second write**. 5 MiB is where the upload leaves the
single-`PutObject` path and enters the multipart pipeline that, after completion, copies the
object to itself to attach metadata that only exists once the last part is encrypted. Modelling
the residual after the wire as one more full write gives 231 MiB/s at 8 MiB, 278 at 32 MiB and
372 at 128 MiB — plausible backend copy rates, and consistent with the cliff sitting exactly at
the routing boundary. **This is a hypothesis: the self-copy was not timed in isolation.**

If it holds, deleting the second write and the two-pass crypto together takes upload from 92 to
at most 153 MiB/s at 8 MiB and from 148 to at most 247 at 128 MiB — **about 1.7×**, of which
roughly four points are the crypto. Time the self-copy directly before believing the
apportionment.

## 3. The proxy barely gets faster when the client asks for more at once

Small-object GET request rate, 1 KiB objects, with the proxy leg's scatter:

| | c1 | c8 | c32 |
|---|---:|---:|---:|
| proxy, plain HTTP | 1778 ops/s (2.7 %) | 2357 ops/s (8.4 %) | 1930 ops/s (12.9 %) |
| direct MinIO | 2974 ops/s | 8304 ops/s | 7835 ops/s |
| proxy, TLS | 1766 ops/s (2.6 %) | 2108 ops/s (6.1 %) | 1952 ops/s (9.6 %) |
| direct MinIO | 2957 ops/s | 8363 ops/s | 7548 ops/s |

The backend scales by **2.8×** from one client to eight (2974 → 8304 ops/s on plain HTTP,
2957 → 8363 on TLS). The proxy gains **1.3×** on plain HTTP (1778 → 2357) and **1.2×** on TLS
(1766 → 2108) — a fifth and a tenth of what the backend does with the same clients — and gives
it back at concurrency 32 (1930 and 1952). The ceiling sits between roughly 1770 and 2360
operations per second on both transports, so it is not a transport effect.

Nor is it bandwidth. At 64 KiB the proxy runs at 1100–1176 ops/s with a single client and
1539–1761 ops/s at concurrency 8 and 32 — 69 to 110 MiB/s, against the roughly 250 MiB/s
the same proxy sustains on one large stream and far below the crypto floor of finding 1.

The gap to the backend widens with concurrency: **1.67× at c1, 3.5–4.0× at c8, and
3.9–4.1× at c32**. The proxy's own scatter is 2.6–8.4 % at c1 and c8, so the threefold gap
there is far outside what noise could explain. At c32 the proxy leg itself scatters 12.9 %
on plain HTTP, so that column is weaker evidence — but it points the same way.

`REPORT.md` flags the c8 rows unstable on the strength of the *direct* leg (18.3 % and
36.1 %), which is what a saturated MinIO looks like; the c32 plain-HTTP row is flagged on
both legs.

This is per-request serialisation. Where it lives has **not** been established: the CPU
profile in finding 1 was taken under large-object load, not under this one. Attributing it
is open work — it needs a profile captured while this instrument runs, which the suite does
not do today.

**The PUT rows are a mixed bag and no shape is claimed from them.** 20 of the 36 recorded
series scatter by a tenth or less, and `REPORT.md` marks 8 of its 18 PUT rows stable — but
the unstable ones are exactly the small-object, low-concurrency cells where a shape would
have to show. There is a suggestion of a peak at concurrency 8 and a fall at 32; it is not
recorded as a finding, because the cells that would carry it are the noisy ones.

## 4. Ranged reads cost little today, and alignment costs nothing

At 1 MiB and 8 MiB ranges the proxy runs between **85.6 % and 103.2 %** of the direct
backend across both transports and all four offset kinds. At 64 KiB ranges the span is
wider and lower (from 66.6 %), but 5 of those 8 rows are marked unstable in `REPORT.md`,
the 66.6 % cell among them — read them as request overhead rather than as range handling,
and not as a comparison point.

A deliberately unaligned offset — 64 MiB + 4097 bytes — is indistinguishable from an
aligned one at 1 MiB and above, because AES-CTR seeks to any byte.

**This is the row to watch after the format change.** A segment chain cannot seek to an
arbitrary byte: an unaligned range has to fetch and open the segment the range starts in.
The `range_mid_unaligned` numbers here are the only "before" for that, and they were
measured before the code that will make them interesting existed.

Today's ranged read is also not covered by the whole-object HMAC, which is the integrity
gap the format change closes.

## 5. Memory: the container limit is nowhere near reached

Bytes from `run.json`, converted at 1 MiB = 1048576 bytes:

| | | |
|---|---:|---|
| cold, before this run touched the proxy | 22.4 MiB | |
| peak during the first load | 140.7 MiB | what reaching the settled level costs |
| settled idle between repetitions | 97.7 MiB | |
| peak under load | 124.1 MiB | |
| the load's own cost above settled idle | 23.2 MiB | scatters 60.8 %, so read it as an order of magnitude |
| container limit | 512.0 MiB | from the compose file |

The settled level is under a fifth of the limit.

**This casts doubt on the runtime memory limit's predicted CPU gain.** A limit at about
80 % of 512 MiB is roughly 400 MiB; this workload peaks at 124 MiB and never approaches it,
so the collector has no reason to behave differently and there is no mechanism for a 3–5 %
gain to appear. The honest outcome may be to ship the limit as an out-of-memory guard and
claim no throughput benefit. A workload that does approach the limit has not been measured.

Nothing here is asserted. The bound that turns these numbers into a test is work the format
change carries.

## 6. RSA unwrap is four orders of magnitude off the local key provider

| | wrap | unwrap |
|---|---:|---:|
| AES-256 | 340 ns | **146 ns** |
| RSA-2048 | 20.4 µs | **629 µs** |
| RSA-4096 | 101.2 µs | **3.80 ms** |

An RSA-4096 unwrap is 26 000× an AES-256 unwrap. The wrap column is far closer — 60× and
298× — because wrapping uses the public exponent; it is the read path that pays. On a read path that unwraps per object,
that is the whole request budget. This is the measurement behind the decision to keep one
local key provider.

## What this run cannot tell you

- **Where the request-rate ceiling of finding 3 lives.** No profile was taken under
  small-object load.
- **Whether the end-to-end numbers reproduce.** Only one full run is kept. The in-process
  instruments were compared across two runs of identical code, but that second run was not
  retained, so its spread cannot be recomputed from the tree.
- **Anything about a real network.** Every leg is loopback on one machine, against a MinIO
  deliberately capped at 2 CPUs.
- **Anything about shapes not measured**: other concurrencies, mixed read/write load, many
  buckets, many distinct objects defeating the key cache, or object sizes between the ones
  listed.

## Two measurement bugs were found and fixed before this run

Both would have misrepresented the segment chain, in opposite directions. They are recorded
because the next person to add an instrument will make the same mistake. The figures below
come from the discarded runs that exposed them and cannot be recomputed from this tree.

1. **The whole-object GCM variants allocated a destination on every repetition while the
   segmented variant reused one.** That measured the allocator, not the cipher: the
   whole-object rows scattered by 50–70 % and read far slower than they are.
2. **The segmented decrypt allocated per segment** — two thousand allocations for a 128 MiB
   object — while the whole-object decrypt reused one buffer. With that alone fixed,
   segmented decrypt read well below whole-object decrypt; it is in fact at parity.

Every variant now seals or opens into a buffer it reuses, and a primed pass runs before
timing starts. **A comparison between two crypto paths is only valid if both allocate the
same amount**, which for a throughput number means both allocating nothing.
