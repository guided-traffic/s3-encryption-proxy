# The segment codec, measured

The `pre-v2` run beside this one predicted the storage format change from a **model** of the
segment chain: raw `crypto/cipher` calls in 64 KiB blocks, no framing, no trailer, no
checksum. This run measures the **shipped codec** — the writer and reader of the authenticated
segment chain (ADR 0003) — against the path it replaces.

Same machine as the `pre-v2` run, 7 repetitions, stack-free instruments only.

## The prediction was 3.4×. The measurement is 1.75×.

Encrypt and decrypt, in process, proxy-side only:

| Plaintext | current (AES-CTR + HMAC) | segment codec | factor |
|---|---:|---:|---:|
| 1 MiB, encrypt | 2147 MiB/s | 4023 MiB/s | **1.87×** |
| 12 MiB, encrypt | 2558 MiB/s | 4474 MiB/s | **1.75×** |
| 128 MiB, encrypt | 2561 MiB/s | 4452 MiB/s | **1.74×** |
| 128 MiB, decrypt | 2538 MiB/s | 4486 MiB/s | **1.77×** |

The gap between the model and the codec is the **CRC32C**, which the model did not run. The
`pre-v2` findings already predicted this in the abstract — "1.9× rather than 3.4× if the
checksum is a separate serial pass" — and the codec lands at 1.75×, the remaining tenth being
segment framing, the trailer and per-segment bookkeeping.

The model rows (`v2_gcm_seg_*`, 8706 and 9288 MiB/s at 128 MiB here) remain in the suite as the ceiling
a perfect implementation would approach. They are not a target: the checksum is decided.

## A 1.7× that was nearly a 1.0×

The first working codec measured **2565 MiB/s** — no faster than the path it replaces. Two
implementation choices cost the entire gain:

1. **A per-segment CRC combine.** The checksum was folded segment by segment with the GF(2)
   matrix construction that exists for the multipart path, where parts genuinely arrive
   independently. Measured on its own, folding per 64 KiB runs at **4523 MB/s** against
   **12107 MB/s** for a running checksum over the same bytes — 2.7× slower, and applied to
   every byte of every object. The fold belongs at part granularity, once per part; within one
   stream the checksum simply continues.
2. **A copy of every byte into the writer's pending buffer**, even when the caller handed over
   a whole segment. At 64 KiB a memmove is a large fraction of the cipher pass.

Both are fixed. The lesson is not about either bug: it is that **an instrument comparing a
model against a real path measures the model.** The codec was written from a design whose
performance case had been argued on the primitive, and the primitive was never the thing that
would ship.

## What this does and does not change

- The end-to-end apportionment in the `pre-v2` findings **stands, and gets smaller**. The
  crypto occupies 3.8–6.1 % of the proxy's per-byte upload time; a 1.75× crypto is worth about
  **+1.6 % to +2.6 %** end to end, not the +2.7 % to +4.5 % a 3.4× would have bought.
- ~~**The self-copy remains the whole story on upload.**~~ **Superseded 2026-09-10**: the
  self-copy was timed the next day and is about a twentieth of the upload gap, not the whole of
  it. See the `upload path decomposition` run.
- Download still has no room: the proxy is already at parity with the backend.

## Not measured here

- Anything end to end. This is the codec in process, with no transport, no backend and no
  handler around it.
- The multipart fold. The per-part combine is still the right construction there and its cost
  at part granularity is negligible; it has not been benchmarked.
- Whether the remaining tenth between the codec and the serial model is worth chasing. The
  candidates are the per-segment associated-data allocation (measured at 8.8 ns, roughly a
  tenth of a percent over a 128 MiB object) and the nonce slice in the seal path.
