# The after column, 2026-09-11

This is the run ADR 0020 has been owed since the segment chain landed: every
instrument of D17 at `ok`, on the same machine as the pre-v2 column, against the
5.0.0 branch at `cc62c05`.

**Before columns.** `20260909T175340Z-9f3fbd1` (label `pre-v2`) for everything,
and `20260910T090543Z-530472c` (`pre-v2-uploadpath`) for the upload-path
instrument, which the first run predates. Two earlier post runs of the same day
are kept and named below; this one is the record because the machine was quiet
for it.

## What may be claimed

**The upload deficit is gone.** Proxy throughput as a share of the same client
writing to the backend directly, median of seven:

| Object | HTTP before | HTTP after | TLS before | TLS after |
|---|---|---|---|---|
| 256 KiB | 68 % | 78 % | 81 % | 121 % |
| 1 MiB | 71 % | 93 % | 77 % | 122 % |
| 4 MiB | 72 % | 110 % | 75 % | 125 % |
| 5 MiB | 59 % | 111 % | 56 % | 120 % |
| 8 MiB | 60 % | 107 % | 59 % | 106 % |
| 32 MiB | 56 % | 83 % | 55 % | 83 % |
| 128 MiB | 60 % | 96 % | 46 % | 96 % |

Above 4 MiB the proxy now writes faster than the client can write to the backend
itself. That is not a paradox: the backend refuses an aws-chunked chunk above
16 MiB, so the direct leg sends one large request while the proxy re-frames into
a multipart upload it can overlap — which is exactly what ADR 0024 restructured
the producer to do.

**Absolute upload throughput, HTTP / TLS, MiB/s, three post runs against the
pre-v2 column.** The spread between the three is the machine, not the code; the
direction is the same in all three.

| Object | before | after (3 runs) |
|---|---|---|
| 5 MiB | 88 / 86 | 177, 166, 162 / 181, 168, 176 |
| 8 MiB | 92 / 90 | 169, 153, 163 / 199, 162, 165 |
| 32 MiB | 121 / 108 | 202, 184, 174 / 205, 178, 183 |
| 128 MiB | 148 / 107 | 250, 224, 231 / 245, 204, 238 |

**The upload-path instrument separates the pipeline from the cipher**, and it is
the multipart leg that moved: +34 %, +33 %, +47 % and +44 % at 16, 24, 64 and
256 MiB against `pre-v2-uploadpath`. The single-request leg, which does not go
through the producer at all, is 0 to 8 % *slower* — the cost of the segment chain
and of the upload checksum verification that ADR 0012 added. Both legs seal the
same chain, so the difference between them is the pipeline and nothing else.

**Memory fell.** Peak resident 130 MB → 109 MB, cold-load peak 148 MB → 105 MB,
cold start 23.5 MB → 22.7 MB. The container limit is 512 MB and is nowhere near
approached, which is the measurement ADR 0020 D15 asks for before `GOMEMLIMIT`
may be claimed to do anything.

**Downloads are unchanged**, inside the instruments' own noise floor at every
size. So is the crypto floor: the segment codec runs at 6.5–8.9 GB/s where the
whole-object v1 path ran at 7.9–8.7, and both are far above any transport here.

## What may not be claimed

- **Nothing about objects of 1 KiB.** Every instrument swings by tens of percent
  at that size across the three runs; the numbers are impressions.
- **Nothing from a single run.** Three full runs were taken on this machine
  within one hour and the end-to-end rows moved by up to 15 % between them, with
  no code change in between on the paths concerned. Anything under about 15 %
  end to end is the machine.
- **No attribution of the upload gain to ADR 0024 alone.** The format change, the
  producer restructuring and the removal of the backend self-copy landed in one
  commit, and the instrument cannot separate them.

## What the run found

**A ranged read was leaving the backend connection unusable.** An explicit range
is fetched as a *provisional* window — planned as if every segment were full,
plus one trailer — and the reader then consumes exactly the real window, so a few
bytes were always left unread. Closing an HTTP body that is not at EOF makes Go's
transport drop the connection instead of pooling it, so every ranged read paid a
fresh connection, and under TLS a fresh handshake.

Measured before the fix, 1 MiB ranged read through the proxy against the same
range read directly: 155 MiB/s against 220, where pre-v2 it was 207 against 217.
With the body drained before close: 193, then 207 on this run — parity with the
pre-v2 column and with the direct leg.

It is the path kopia reads on, and it had been in the release since the segment
chain landed: the wave-3 run of the same day records 153.8 MiB/s at the same
point, so it was not introduced by the tail-first read of wave 4. The fix is
`closeDrained` in the object handler's ranged path.

The 64 KiB ranged rows remain 4–12 % below the pre-v2 column on HTTP and at
parity on TLS. At that size the instrument's own spread is 13 %, so this is not
a finding; it is the size at which the instrument stops resolving.

## How it was run

`./start-demo.sh`, then both proxies restarted cold and left to settle, then
`S3EP_PERF_ALT_PROXY=http://127.0.0.1:8090 PERF_LABEL="post-v2-wave5" make
perf-baseline`. The alternate proxy is `config/aes-example.yaml` with
`streaming_segment_size: 5368709120`, run from the same image on the demo
network, which is what gives the upload-path instrument its single-request leg.

The two earlier runs of the same day are `20260911T101344Z-cc62c05`
(`post-v2-wave5`, before the ranged-read fix) and `20260911T102319Z-cc62c05`
(`post-v2-wave5-drained`, with the fix but taken minutes after an image rebuild,
and uniformly 5–15 % low on rows the fix does not touch). Both are kept because
the pair is what establishes the between-run spread this report leans on.
