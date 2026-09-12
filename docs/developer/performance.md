# Performance

The rule is [ADR 0020](../adr/0020-performance-is-measured-before-and-after.md):
**measured before and after, never asserted.** A performance claim without two
recorded columns is an opinion.

The instrument set and how to run it are documented where they live:
[`test/perf/README.md`](../../test/perf/README.md). That page has the commands,
the environment traps and what each target measures. This page is the part that
is easy to get wrong.

## Before you change a hot path

Record the before column first. Not after the change, not from memory, not from
an earlier run on a different day — the whole value of the number is that the
only thing that differs between the two columns is your change.

Recorded runs live in `perf-baseline/<timestamp>-<commit>/`. `run.json`,
`REPORT.md` and the hand-written `FINDINGS.md` are committed, so a comparison can
be reconstructed later; the profiles a run captures are not. The record also
carries the commit and whether the working tree was clean. Record from a clean
tree — otherwise the commit in the directory name does not identify what ran.

## What ruins a comparison

**A different power source.** A laptop on battery throttles. If the before column
was recorded on mains, the after column has to be too, or the numbers are noise
wearing a lab coat.

**A different Go toolchain.** Timings shift between releases, and the baseline
targets pin nothing — `make perf-baseline` runs whatever `go` is on your path.
The run records the version instead, and `make perf-compare` prints both machine
lines and says the runs are not comparable when they differ. That is a warning,
not a refusal: it compares them anyway.

**A cold-versus-warm proxy.** The memory instrument records a cold reading and a
settled one, and the cold reading is only cold once. Restart the proxy containers
before a run you intend to keep.

**Other suites competing for the backend.** The recording run has to be the only
thing using the demo stack; the integration `performance-test` package has its own
Makefile target for the same reason (see [testing.md](testing.md)).

**A renamed row.** `make perf-compare` pairs measurements on instrument,
transport, operation, subject and size. Rename an operation or drop a size and the
two halves print as `only in before` and `only in after` — visible, but not a
comparison. The crypto floor's rows were renamed when the segment chain landed:
the rows measuring the old format were deleted rather than kept as a comparison
against nothing, and the `v2_` prefix on the surviving ones went with them. Its
rows in the recorded runs therefore no longer pair with a new run's.

## What the instrument can and cannot separate

The three-leg upload comparison writes the same object three ways: straight to the
backend, through a proxy on the single-request write path, and through a proxy on
the internal multipart producer. It exists to separate the pipeline's cost from
the cipher's, and it is what showed the deficit to be per byte rather than per
request: in the recorded run the streaming proxy reached 104–106 % of a direct
`PutObject` while encrypting every byte, and the multipart producer stayed 1.45×
to 1.96× behind it, worst where a single part leaves nothing to overlap. That is
the measurement [ADR 0024](../adr/0024-an-upload-forwards-while-it-receives.md)
was written from.

Which write path an object takes is decided by its plaintext length against
`optimizations.streaming_segment_size` (`12582912` # default) and by nothing else,
so the second leg needs a second proxy whose segment size is above every size
measured — `S3EP_PERF_ALT_PROXY`, with the recipe in
[`test/perf/README.md`](../../test/perf/README.md). Without it the instrument
records itself as skipped rather than putting the same object through the same
path twice.

Use that recipe, not one you remember. The configuration is unmarshalled without
a strict-key check, so a key this release deleted is ignored without a word: a
second proxy set up from an older recipe starts happily and routes exactly like
the first one. The instrument cannot tell, and records three legs of which two
are the same path.

Only 16 MiB carries all three legs. Above it the direct leg cannot follow — the
backend refuses an aws-chunked chunk larger than that, while both proxies decode
the framing and re-frame towards it — so 24, 64 and 256 MiB compare the two proxy
write paths with each other and carry no backend ratio.

What the instrument **cannot** do is attribute a change to one commit when several
landed together. The segment chain, the producer restructuring and the removal of
the post-completion self-copy are one commit ("read and write the segment chain
end to end"), so a before/after across them measures the release, not any one of
them. Say so in the report rather than implying an attribution the numbers do not
support.

## The after column, and what it is allowed to say

**It exists since 2026-09-11**: `perf-baseline/20260911T103132Z-cc62c05/`, every
instrument of ADR 0020 D17 at `ok`, on the machine that took the pre-v2 column.
Its `FINDINGS.md` is the written record — read that before quoting a number from
anywhere else. The pairs are `20260909T175340Z-9f3fbd1` for everything and
`20260910T090543Z-530472c` for the upload-path instrument.

Three things that run settled and that a later change has to keep true:

- **The upload deficit is gone.** Against the same client writing to the backend
  directly, the proxy moved from 46-72 % to 78-125 %; above 4 MiB it is faster
  than the direct leg, because the backend refuses an aws-chunked chunk above
  16 MiB and the proxy re-frames into a multipart upload it overlaps.
- **The single-request write path is 0-8 % slower**, which is the segment chain
  plus ADR 0012's checksum verification. It is the leg that does not go through
  the producer, so the two legs together are what separates the pipeline from the
  cipher.
- **Downloads and the crypto floor are unchanged** inside the noise floor.

Two things to know before you take another one:

- **Four of the upload-path sizes pair; two cannot.** The before column has 8 and
  12 MiB rows on the multipart leg because routing then sent every object of 5 MiB
  or more onto the multipart producer whenever integrity verification was on, and
  the demo config had it on. Today the only thing that decides is the size against
  the segment size, so at 8 and 12 MiB both proxies take the single-request path
  and the instrument no longer measures them. 16, 24, 64 and 256 MiB pair.
- **One run is not a column.** Three full runs were taken within an hour on
  2026-09-11 with no code change between two of them, and the end-to-end rows moved
  by up to 15 %. An image rebuild immediately before a run costs about that much on
  its own. Quiesce the machine, restart the proxies cold, and read the spread of at
  least two runs before believing anything under 15 % end to end.

## Memory, what one request costs

The six terms below are the whole of what the proxy holds per in-flight request.
Add them for the concurrency the deployment expects and size the container limit
against the sum; `GOMEMLIMIT`, when it is set at all, belongs above that number.

| Term | Size | Held for | Where |
|---|---|---|---|
| auto-multipart `PUT` free list | `streaming_segment_size` × (1 + `multipart_upload_concurrency`) | one `PUT` above the segment size | [`operations.go`](../../internal/proxy/handlers/object/operations.go), `putObjectAutoMultipart` |
| client-driven upload, short last part | up to `multipart_short_part_buffer_size` | one **open** upload, until Complete or the sweeper | [`segmented_session.go`](../../internal/orchestration/segmented_session.go), [ADR 0011](../adr/0011-the-proxy-owns-the-part-layout.md) |
| client-driven `UploadPart`, a part the proxy holds | the whole part | one in-flight `UploadPart` that is short or unaligned | [`upload.go`](../../internal/proxy/handlers/multipart/upload.go), `readWholePart` |
| client-driven `UploadPart`, a part it streams | one segment plus framing | one in-flight `UploadPart` of at least 5 MiB, segment-aligned | [`upload.go`](../../internal/proxy/handlers/multipart/upload.go), `uploadStreamedPart` |
| response copy buffer | 128 KiB, pooled | one `GET` body | [`helpers.go`](../../internal/proxy/handlers/object/helpers.go), `copyWithPooledBuffer` |
| whole-object read, tail buffer | 65604 bytes (`HEAD`: 40) | the whole `GET` response | [`tail.go`](../../internal/proxy/handlers/object/tail.go), [ADR 0003 D14](../adr/0003-objects-are-an-authenticated-segment-chain.md) |

The two `UploadPart` terms are exclusive: the declared plaintext length picks one
of them, and before 2026-09-12 every part took the first. The second term is the
one that is not per request: an upload that is neither
completed nor aborted keeps its short part and its data key until
`optimizations.multipart_session_cleanup_interval` sweeps it. The cap is not a
total across sessions — the ceiling is the cap times the number of open uploads,
and back pressure against it is a `503 SlowDown`, not a refusal.

A single-request `PUT` at or below `streaming_segment_size` holds none of the
first term: it seals as the backend pulls and buffers one segment at a time.

## Reporting

State what was measured, on what machine, against which recorded column, and what
the instrument could not separate. A number without those four is not reusable by
the next person.

Resident memory is recorded like everything else here, and nothing asserts on it:
the memory bound of ADR 0020 D14 is not a test, and the explicit `GOMEMLIMIT` of
D15 is set nowhere in the tree. A memory regression is caught by somebody reading
the run, or not at all.
