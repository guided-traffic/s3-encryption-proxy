# Ticket 028: The 5.0.0 performance round — what landed, what is left

## Status (2026-09-12)

**Everything below is in the working tree and nothing is committed.** All four
pieces are built; what is left is the commit. Green on this machine: `test-unit` (19 packages), `test-integration`,
`test-integration-tls`, `make lint` (0 issues), `make gosec` (0 issues).

This file exists because the round grew past what one commit message can carry.
It started as an analysis of the reported encryption overhead and turned into
four separate pieces of work. All four are built and verified; the only thing
outstanding is the commit, and the proposed split is in the "Done when" box.

## Why the round started

The pipeline reported a download overhead climbing from 17 % to 32 % over a day,
against an upload overhead that stayed near 12 %. The question put was whether
15 % is reachable in both directions without weakening anything, and why
download looked worse than upload when decrypting and verifying should not cost
more than encrypting and hashing.

**The premise did not survive the arithmetic.** Across four pipeline runs, the
proxy's own absolute throughput barely moved — 163.58 → 163.67 MB/s on upload,
339.54 → 341.75 MB/s on download. What moved was the baseline the ratio divides
by. Recomputed byte-weighted (total bytes over total time) rather than as an
unweighted mean of ten per-size ratios, the newest of those runs reads 83.0 %
upload and **90.4 % download** — download already the better of the two, and
already inside the target.

The reported number is dominated by the six sizes at or below 10 MB, which are
1.16 % of the bytes moved and about 60 % of the score. Those rows measure
per-request latency, not the cost of encrypting a byte.

## What was measured, and what it ruled out

All on one machine (Apple M5 Pro, 18 cores), demo stack, against the recorded
crypto floor of ADR 0020's instrument set.

- **Cryptography is not the bottleneck and cannot become one at these rates.**
  The shipped codec runs at 4257 MiB/s decrypting and 4263 MiB/s encrypting;
  AES-GCM alone at 8776 MiB/s and CRC32C at 11501 MiB/s. The local link caps at
  about 245 MB/s whatever the concurrency, so the codec has roughly 17× headroom.
  A CPU profile of a sustained `GET` puts `gcmAesDec` at 2.2 % and
  `castagnoliUpdate` at 0.8 %; the rest is I/O.
- **Three suspicions were falsified.** The backend connection is *not* burnt per
  request — MinIO's own `PassiveOpens` counter stayed flat across 40 reads.
  Debug logging costs 2–5 %, not more. And there is no per-byte download deficit
  measurable here: at 12 MiB and above the proxy tracks the direct leg at
  98–103 %.
- **The download deficit is a fixed per-request cost.** Measured across the
  one-segment boundary: an object served by one backend request costs the proxy
  229–300 µs over the direct leg; one that needs a second request costs 545–628 µs.
  The second backend request is worth about 300 µs.

## Piece 1 — the benchmark measured itself wrong (done)

`test/integration/performance-test/performance_test.go`.

- **The encrypted bucket was never emptied.** The test cleared
  `performance-test-bucket` — which it never writes to — and
  `performance-test-bucket-unencrypted`, while writing to
  `performance-test-bucket-encrypted`. Counted before the fix: 90 objects /
  15.2 GiB on the encrypted side against 10 / 1.7 GiB on the plain side. A
  compounding bias against the proxy, worse in a pipeline that runs the
  comparison twice per job.
- **`io.ReadAll` sat inside the download timer.** Its doubling buffer was part of
  what was being called download time. Now drained to `io.Discard`; the length
  check stays.
- **The summary prints byte-weighted efficiency** next to the unweighted mean of
  ratios, plus a `Legs:` line naming both endpoints.

**Deliberately not done, both need a decision rather than a patch.** Pinning
`minio/minio:latest` by digest — no digest pin exists anywhere in this
repository, and a pinned image stops receiving security updates until Renovate
lifts it. And switching the proxy leg to TLS so both legs run the same transport:
today the proxy leg is plain HTTP and the backend leg is HTTPS, which puts two
different SDK checksum code paths in one comparison. The asymmetry is now visible
in the `Legs:` line and switchable with `S3EP_TEST_PROXY_ENDPOINT`.

## Piece 2 — four costs that were free to remove (done)

| Change | Where | Measured |
|---|---|---|
| `readAllSized` reserved exactly the hint, so `bytes.Buffer.ReadFrom`'s final read reallocated to 2× and copied the whole payload | [parser.go](../../internal/proxy/request/parser.go) | per 5 MiB part: 15.7 MB and 306 µs → 5.25 MB and 63 µs |
| The two backend reads of a whole-object `GET` were serialised; the second is now issued from the first answer's headers | [tail.go](../../internal/proxy/handlers/object/tail.go), [operations.go](../../internal/proxy/handlers/object/operations.go) | 70–256 KiB reads: 44–100 µs each, +1.4 to +3.6 points; one-request objects unchanged |
| Part writers kept a running CRC32C nothing read | [segmented_gcm_io.go](../../pkg/encryption/dataencryption/segmented_gcm_io.go) | one full pass per uploaded byte on both multipart paths |
| Three `regexp.MustCompile` per authenticated request | [s3auth_robust.go](../../internal/proxy/middleware/s3auth_robust.go) | hoisted to package variables |

`EncryptReader.Checksum()` now returns `(Checksum, bool)` so a part reader cannot
silently report a checksum it does not keep. The compiler found the one caller.

**The headline metric cannot resolve any of this.** Three A/B rounds of the
pipeline's own comparison gave 85.3 % against 84.5 % download — the change is
inside the noise, exactly as `docs/developer/performance.md` warns. The targeted
instruments above are what the claims rest on.

## Piece 3 — a client-driven part is forwarded while it is received (done)

ADR 0024 D1 already bound this path and it did not meet it: `UploadPart` read
each part into memory in full before any of it moved. A part whose declared
plaintext length covers whole segments and clears 5 MiB is now sealed as the
backend pulls it; a short or unaligned part is still held, because it is sealed
at Complete with the trailer.

64 MiB object, 8 MiB parts, against the same client writing to the backend
directly:

| Workers | Buffered | Streamed |
|---|---|---|
| 1 | 90.5 % | **99.9 %** |
| 2 | 96.1 % | **99.8 %** |
| 3 | 102.7 % | 103.6 % |
| 6 | 88.9 % | 99.9 % |

Above two workers the local link saturates. The client's own concurrency is what
used to hide the proxy's serialisation, which is why the size matrix — three
workers throughout — cannot see this change at all.

**It required amending ADR 0012 D7**, which promised that on a failure *no part
reaches the backend*. It now promises that no part is **stored**. A write that
forwards while it receives has opened its backend request before the payload
ends; what keeps the part from existing is the byte the verifier holds back, so
the request cannot deliver the Content-Length it promised. Verified against the
backend: a mismatched `Content-MD5` on an 8 MiB part answers `400 BadDigest`, and
a `ListParts` asked of the backend directly reports zero parts. The buffered path
answers identically. ADR 0024 records that D5's retained-copy retry cannot cover a
streamed part, and that it was never built for any path.

**Two defects were found while building it, both fixed:**

- A part whose body the backend did not pull in full would have had its sealed
  length and checksum entered in the part table, producing an object that stores
  cleanly and never authenticates. The handler now compares the sealed length
  against the declared one and refuses.
- The first fix removed a failed part from the table, which made the proxy
  **stricter than S3**: a client that retried a part, saw the retry refused and
  then completed with the ETags it already held got a `400` where S3 gives a
  `200`, and the upload was left open. A streamed part is now entered in the
  table only once the backend has stored it, so a failed attempt leaves the table
  as it found it. `TestMpuUploadKeepsAStoredPartWhenALaterAttemptFails` guards it.

## Piece 4 — nothing is abandoned any more (done)

**This was the one place this proxy left data nobody could reach.** Two paths led
there and both are closed.

`CleanupExpiredSegmentedSessions` deletes the proxy's in-memory session and does
not touch the backend. After it runs, the multipart upload and every part already
stored in it sit at the backend consuming space, invisible to `ListObjects`, with
the client answered `NoSuchUpload` on its next request. Complete and Abort are
both clean; the sweeper and process exit are not.

**The sweeper measures `CreatedAt`, not activity.** `sessionPart.uploadedAt` is
written on every part and read only by `ListParts`. So an upload that is actively
transferring is dropped one hour (default) after `CreateMultipartUpload`. 10 000
parts of 8 MiB is 78 GiB, which over a 20 Mbit/s link is about nine hours — a
large backup over a narrow link reaches it, and cannot resume.

It is also a server wall clock on a transfer, which is what ADR 0015's title
rejects; D1 covers one request, and nothing covers the sequence of requests that
makes one object. No ADR governs session expiry at all.

Both keys carry `validate:"min=..."` tags that are never evaluated and appear in
no `validateOptimizations` check. `multipart_session_max_age: 0` is accepted and
makes every session expire on the first tick after it is created.

### What was built

1. **Expiry measures inactivity, not age** (ADR 0028 D1). `lastTouched` moves on
   every part; the sweeper measures against it. This had to come first: aborting
   on the creation clock would have destroyed live uploads instead of stale ones.
2. **The sweeper ends the backend upload before it forgets the session**
   (ADR 0028 D2–D4), outside the session lock, under a context bounded by the
   sweep interval, retrying five times before giving the session up.
3. **So does shutdown** (ADR 0029). The first version of this ticket said the
   opposite, and it was wrong: the session holds the data key and the part table,
   both process-local, so once the process exits nobody can finish the upload —
   not the client, not another replica. There is no work to protect, only storage
   nobody can reach. `Manager.Shutdown` now ends every session it still holds,
   with **what is left** of `shutdown_timeout` rather than a fresh copy, because
   the chart derives the pod's grace period from the same number.

ADR 0029 writes down the whole graceful-shutdown contract, and two parts of it
were rebuilt rather than merely recorded:

- **The listener is no longer taken down at the start.** `drainGuardMiddleware`
  answers every new S3 request `503 ServiceUnavailable` with `Retry-After` while
  the socket stays open, in front of authentication and in front of the request
  tracker. A client that arrives before a load balancer has rotated this instance
  out now retries against another replica instead of meeting a refused
  connection. The listener closes last, once there is nothing left to serve.
- **The proxy exits as soon as the work is done** (D7). The drain used to poll
  once a second; it now ends at the moment the last in-flight request finishes,
  and an instance with nothing in flight does not wait at all.

**Configuration:** the criterion changed meaning, so it got a new key,
`multipart_session_idle_timeout`, and `multipart_session_max_age` fails the start
naming the replacement (ADR 0028 D6). Reusing the name would have handed an
operator who configured 3600 a different behaviour with nothing to notice.

### Verified

Against the running stack, not derived. A proxy holding one in-flight multipart
upload was sent `SIGTERM`:

| | Observed |
|---|---|
| readiness and S3 routes during the drain | `503`, `Retry-After: 1`, polled every 100 ms until the listener closed |
| the open multipart upload | `Ended the multipart uploads this process was holding ended=1 left=0`; `ListMultipartUploads` asked of MinIO directly reports it gone |
| a 1 GiB download in flight when the signal arrived | `DOWNLOAD COMPLETE: 1073741824 bytes` |
| shutdown, nothing in flight, 8 s budget | **769 µs** (it was 1.0027 s under the old poll) |
| shutdown, 1 GiB download mid-transfer | **2.78 s** — what was left of that download |

Unit tests cover the idle clock, the sweeper's abort and its retry cap, the
shutdown sweep, an abort the backend refuses, an expired budget, and the drain
guard in all three of its states.

Recorded as a residual in ADR 0029: exiting early makes the clean-refusal window
as short as the drain, so on an idle instance it is effectively nil. A `preStop`
sleep in the chart is what would put a floor under it, and it is not built.

### Outside this ticket, worth saying to an operator

A bucket lifecycle rule `AbortIncompleteMultipartUpload` is the standard answer
to the same problem and catches what the sweeper never sees — process exit,
crash, OOM kill. It works in days rather than minutes and the proxy does not own
the bucket configuration, but it belongs in the operator documentation.

## Related record

Ticket [027](027-whole-object-read-first-window.md) is the evaluation of the
whole-object read's first window. Piece 2 above changed that path — the two reads
now overlap — without changing the window size ADR 0003 D14 fixes, so 027's
question is unchanged and its measured numbers predate the overlap.

## Done when

- [x] The benchmark's bucket bug, timer and summary corrected
- [x] The four free costs removed, each with a measurement
- [x] The client-driven part upload forwards while it receives, ADR 0012 and
      ADR 0024 amended, the refusal verified end to end against the backend
- [x] The sweeper expires on inactivity and ends what it abandons; shutdown ends
      what it is still holding; ADR 0028 and ADR 0029 record both, and
      `multipart_session_idle_timeout` replaces the old key
- [x] Committed in four: the benchmark corrections; the free costs; the session
      and shutdown cleanup with ADR 0028 and ADR 0029; the streamed part upload
      with ADR 0012 and ADR 0024. The last two were committed in that order
      because they share `segmented_session.go`, and the other order leaves an
      intermediate commit that does not build
- [ ] Deleted, once 5.0.0 is cut. It is listed from
      [023](023-major-v5.md) until then because the branch is still open
