# Ticket 027: The first read of a whole-object GET — evaluate before building

## Status (2026-09-11)

**Evaluation only. Nothing here is scheduled, and none of it is in 5.0.0.**
Owner decision, 2026-09-11: the question is worth answering but not worth
holding the release for, so it leaves the bundle ([023](archive/023-major-v5.md)) and
becomes this file. The work is to find out whether the change is worth making at
all — not to make it.

What is already decided and shipped stays as it is: a whole-object read takes the
object's end first, and the size of that first read is the constant ADR 0003 D14
names. **Any change to it is an amendment to that ADR, not a code edit.**

**Correction, 2026-09-12: option C below has since been built** — not as this
evaluation's outcome, but as one of the free costs removed in the 5.0.0
performance round. It changed *when* the second backend read is issued, not the
window ADR 0003 D14 fixes, so the question this file exists for is unchanged.
What it bought is recorded under option C and under question 2.

## Why this exists

A whole-object `GET` reads the object's end before its beginning, because the
trailer is the only authenticated statement an object makes about itself. The
first read asks for one segment plus the trailer — 65604 bytes — and an object
that fits in it costs one backend request. Anything larger costs a second
request for the remainder.

The second request is one backend round trip, and it is measurable. Three runs of
the proxy-versus-backend comparison before the change and three after, same
machine, same stack, encrypted download throughput, median of three:

| Object | Before | After |
|---|---|---|
| 100 KB | 53 MB/s | 33 MB/s |
| 500 KB | 144 MB/s | 120 MB/s |
| 1 MiB | 176 MB/s | 170 MB/s |
| 10 MiB | 267 MB/s | 266 MB/s |
| 1 GiB | ~248 MB/s | ~262 MB/s |

About 1.2 ms against this backend: invisible above roughly 10 MiB, dominant below
half a megabyte, where a 100 KB download is about 40 % slower. Uploads and ranged
reads are untouched — kopia, the client that reads with small ranges, is on the
ranged path and still costs one request per range.

**Both columns are the tree before option C.** They are the read before and after
ADR 0003 D14 made it tail-first, measured on 2026-09-11; the two backend reads
were still serialised in both. Since they overlap, the "After" column is
pessimistic for every size in it that needs a second request — by the 44–100 µs
named under option C, which is noise at 10 MiB and above. No row here was
measured against the tree as it stands.

## What the shape of the code is today

Three facts the evaluation rests on, verified in this tree:

- The first read is issued in `fetchObjectTail`
  ([tail.go](../../internal/proxy/handlers/object/tail.go)), the second in
  `serveWholeObject` ([operations.go](../../internal/proxy/handlers/object/operations.go)),
  under `If-Match` on the first answer's entity tag.
- **The object's stored length arrives in the headers of the first answer**, in
  its `Content-Range`, and the code reads it before it touches the body. Since
  option C that is where the second request is issued from: `fetchObjectTail`
  calls back with the stored length and the entity tag before it reads the tail,
  and `serveWholeObject` starts the remainder there.
- The bytes of the first read are held until the response ends, because they are
  the **last** bytes written. A slow client on a large object pins them for the
  whole transfer.

## The options, and what each one actually costs

**A. Leave it.** One request up to 64 KiB, two above. 64 KiB pinned per in-flight
whole-object read. This is what ships.

**B. A larger first window, as a constant.** One request up to the new size. Costs
that many bytes pinned per in-flight read, and — on its own — adds the transfer
time of the window to time-to-first-byte for every object *above* it: about 4 ms
for 1 MiB against this backend.

**C. Issue the second request on the first answer's headers**, instead of after
its body. **Built 2026-09-12 and measured; this is what the tree does now.** The
round trip overlaps the first read's transfer rather than following it, with no
configuration and no extra memory, as predicted. What the prediction got wrong is
the size: the quarter-millisecond above was arithmetic, and the measurement is
**44–100 µs per read across 70 KiB–256 KiB, 1.4 to 3.6 points of the
proxy-versus-backend ratio**. An object served by one request issues nothing
extra and is unchanged.

Two costs, as built. The second request is in flight before the trailer is
opened, so a trailer that does not authenticate wastes it — a foreign object does
not, because that is decided on the first answer's metadata, before the request
is issued. And the answer is collected and its body closed rather than cancelled,
so a refused read waits for it before writing the error.

**D. A configuration key over the window.** B, decided per deployment. It needs a
startup rule — a multiple of 65536 and at least 65604, or the read breaks — and a
memory formula beside `optimizations.multipart_short_part_buffer_size`. Note the
precedent only half applies: that key is a **bound** against unbounded memory
(ADR 0011 D5), while this one would be tuning, and a tuning key is set once and
never revisited.

**E. Trailer only, whole object second.** Fetch the last 40 bytes, then the whole
object in one stream. Always two requests — even for a 1 KB object — but nothing
beyond 40 bytes is pinned and the second read is a clean sequential stream. Worse
than A for small objects, better for memory on large ones. Listed because it is
the honest third point of the triangle, not because it looks good.

## Open questions — what the evaluation has to answer

1. **Does anybody read whole objects in the 64 KiB … 1 MiB band?** This is the
   question that decides the rest. Velero's volume data goes through kopia, which
   reads ranged; its metadata objects are small. If the band is empty for the
   deployments in scope, the answer is A and this ticket is archived. Needs a
   size distribution from a real deployment, not a guess.
2. **How much does C alone buy, measured? Answered, 2026-09-12: 44–100 µs per
   read across 70 KiB–256 KiB, 1.4 to 3.6 points of the proxy-versus-backend
   ratio.** It does not close the gap. The second backend request was measured on
   the same machine at about 300 µs over the direct leg — an object served by one
   request costs the proxy 229–300 µs over it, one that needs two costs
   545–628 µs — so C recovers between a seventh and a third and the rest is still
   there. B and D are not settled by it; what C removed is the reason to hurry
   them.
3. **What bounds the number of concurrent whole-object reads?** Nothing in the
   proxy does today. A per-request buffer that scales with a configurable window
   multiplies against a number nobody caps, which may make bounding concurrency
   the prerequisite rather than the window the lever.
4. **Is the pinning avoidable at all?** E says yes, at the price of a second
   request for every object. Is there a fourth shape that keeps one request for
   small objects *and* pins nothing on large ones?
5. **Constant or key?** If a key survives question 1 and 3: its validation, its
   default, its memory formula, and which document carries them. If a constant:
   the number, and the worst-case memory it implies at the concurrency of
   question 3.
6. **Does every backend answer a suffix range?** The whole tail-first read depends
   on it. Verified against the MinIO release the demo stack runs; **not** verified
   against AWS S3 itself or any other S3-compatible target. This is a property of
   what ships today, not of the change, and the evaluation is the natural place to
   check it.
7. **How does the window interact with the memory work that is already open?**
   The proxy settles at 98 MiB against a 512 MiB container limit, whether
   `GOMEMLIMIT` ships is undecided, and the memory test in the local baseline
   suite records and asserts nothing. A window that scales memory per request
   should not be decided before those are.

## What has to be measured before a decision

- A read benchmark across the band that matters — 64 KiB, 128 KiB, 256 KiB,
  512 KiB, 1 MiB, 2 MiB — in the local baseline suite (`test/perf/`), because the
  proxy-versus-backend comparison starts at 100 KB and is too coarse for this.
  The instrument has to exist before the argument.
- Memory under N concurrent whole-object reads at each candidate window, against
  the same container limit the deployment uses.
- ~~C, measured rather than reasoned about, on the same instrument.~~ **Done,
  2026-09-12**, against the demo stack — the numbers are under question 2. Not on
  the same instrument: the band benchmark the first bullet asks for was never
  built, so 128 KiB, 512 KiB and 2 MiB are still unmeasured against C.

## Success criteria

The evaluation is done when the answer to question 1 exists as data, questions 2
and 3 exist as measurements, and the outcome is recorded — either as an amendment
to ADR 0003 D14 naming the new window and why, or as a decision to keep the
constant, with the numbers that made it the right one. Then this file is archived.

**Not done when:** the window is changed because the number looked better in one
run.
