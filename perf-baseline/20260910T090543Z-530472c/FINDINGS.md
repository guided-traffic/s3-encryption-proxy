# The "before" column for the producer restructuring

This run exists for one reason: [ADR 0024](../../docs/adr/0024-an-upload-forwards-while-it-receives.md)
decides that the auto-multipart producer overlaps receiving with sending, and a decision like that
is worth nothing without the column it will be judged against.

Same machine as every other run in this directory, **on mains**, 7 repetitions, clean working
tree at `530472c`. Two instruments only — the three-leg upload comparison and the self-copy
harness. **All twelve upload rows are stable** (relative standard deviation 1.0 % to 6.3 %), which
is what makes the factors below readable.

## What is new against the run of the same morning

That run (`20260910T062529Z`) stopped at 16 MiB, because the **direct** leg cannot carry a larger
single `PutObject`: the backend refuses an aws-chunked chunk above 16 MiB. Both proxies re-frame
the body towards the backend, so the two proxy write paths go through where the direct leg cannot
follow — verified by putting 24 MiB through each. The instrument now carries 24, 64 and 256 MiB
with the direct leg dropped; those rows carry no backend ratio and say so.

| Size | Parts | Streaming write path | Auto-multipart | Factor | against direct |
|---|---:|---:|---:|---:|---|
| 8 MiB | 1 | 164.7 MiB/s | 89.9 | **1.83×** | 106.3 % / 58.1 % |
| 12 MiB | 1 | 167.7 | 85.4 | **1.96×** | 105.3 % / 53.6 % |
| 16 MiB | 2 | 170.8 | 108.3 | 1.58× | 104.1 % / 66.1 % |
| 24 MiB | 2 | 178.9 | 109.3 | 1.64× | — |
| 64 MiB | 6 | 190.2 | 125.3 | 1.52× | — |
| 256 MiB | 22 | 201.4 | 139.2 | 1.45× | — |

## What the shape of that column says

**The deficit is per byte, not per request.** At 256 MiB the multipart route's four backend calls
are amortised into nothing worth naming: the self-copy is about 30 ms of a 573 ms gap, create and
complete are milliseconds. The integrity pass, which only the auto-multipart leg pays here, is
about 14 %. What is left — three quarters of the gap at the largest size measured — scales with
the bytes, and the only per-byte difference between the two legs is that one forwards while it
reads and the other does not.

**Cross-part concurrency is already doing what it can.** The factor is worst where no overlap is
possible at all (one part: 1.83× and 1.96×) and settles near 1.45× from six parts upward, where
four upload workers overlap *transfers* with each other but never with the receive. More parts
help and then stop helping. That is the signature of a serialisation inside one part, not between
parts, and it is why the fix is D1 and D2 of ADR 0024 rather than more workers.

**The proxy is faster than the backend it writes to, on every streaming row.** 104 % to 110 % of a
direct `PutObject` while encrypting every byte and crossing loopback twice. Whatever the
multipart path is paying for, it is not the cipher and not the extra hop.

## Against the battery run of the same morning

The three sizes both runs share reproduce within noise: auto-multipart at 58.1 / 53.6 / 66.1 %
here against 59.0 / 57.5 / 69.8 % on battery, streaming at 106.3 / 105.3 / 104.1 % against
105.2 / 104.2 / 111.7 %. The battery did not distort the comparison; it made both legs slower
together. **This run, not that one, is the "before" for the restructuring** — same power source as
the run that will follow it, clean tree, and it covers the sizes above 16 MiB.

## What this run does not tell you

- **Why**, in the sense of a profile. No CPU or blocking profile was taken under this load; the
  attribution is by substitution and by the shape of the size sweep. If the restructuring does not
  move these rows, the mechanism was misidentified and the blocking profile — enabled nowhere in
  the tree today — is the next step, before any further change.
- Anything about a real network. Every leg is loopback on one machine against a MinIO capped at
  two CPUs. Concurrent part transfers may hide more of the serialisation where latency is real.
- Anything about the client-driven multipart path, which is a different producer with the client
  dictating part boundaries.
- The self-copy rows are re-timed here (4267–8325 MiB/s, the 8 and 32 MiB rows scattering 14 %)
  and confirm the earlier measurement's order of magnitude. They are a single-leg harness, not a
  comparison.
