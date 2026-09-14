# 029 — The multipart idle clock moves only at part boundaries

A client-driven multipart upload is expired and ended at the backend while one of
its parts is still arriving, if that part takes longer than
`optimizations.multipart_session_idle_timeout`.

Found 2026-09-12 while correcting the developer documentation, which claimed the
opposite. The page states it correctly now; this is the work.

## What happens

`lastTouched` is written in exactly four places, and none of them is during a
part's body:

| Where | When it fires |
|---|---|
| `SealPart` | after the whole part body has been read into memory |
| `SealStreamingPart` | before the backend pulls a single byte |
| `RecordStreamedPart` | after the backend has stored the part |
| `RecordETag` | after the backend answered |

So the clock measures the gap **between** parts. Within one part it does not
move, and both upload shapes are exposed:

- **A held part** — short, unaligned, or any part under the exit provider — is
  read whole by `readWholePart` before `SealPart` is reached. The clock still
  carries the previous part's time for the entire read.
- **A streamed part** has the clock set when sealing starts, and the transfer
  then runs unlocked for as long as it takes. The session mutex is not held
  across it: `SegmentedUpload.SealStreamingPart` only builds a `SealedPart` that
  holds the reader, and the backend pulls later.

The sweeper finds the session idle and, since ADR 0028 D2, **ends the upload at
the backend** — under the request that is writing to it. Everything after that
answers `404 NoSuchUpload`. Before ADR 0028 the session was only forgotten, so
this got worse when the leak was fixed.

Reachable with a large part on a slow link: 5 GiB below roughly 1.5 MB/s against
the 3600-second default. Rare, and the owner's assessment on 2026-09-12 is that
it may never be worth the full fix.

## Owner decision, 2026-09-12

**Not scheduled.** The case is rare, and an operator on a slow link with large
objects can raise `optimizations.multipart_session_idle_timeout`, which has a
minimum of 1 and no maximum.

**That mitigation has a hole, and item 1 is what closes it.** It assumes the
operator can tell this is what happened. Today they cannot: a *successful* sweep
logs nothing at all — the Warn and Error lines in
`CleanupExpiredSegmentedSessions` fire only when the backend refuses the abort —
and the only other trace is an aggregated `expired_sessions` count at **Debug**,
which a default `log_level: "info"` never emits. The client sees
`404 NoSuchUpload` and the log is silent.

## Already done, 2026-09-12 — the mitigation works now

The two items that made the owner's workaround usable landed in 5.0.0 and are
**not** part of what is left here:

- Every upload the sweeper ends is logged at `Info` with its upload id, bucket,
  key, the idle time measured and the configured timeout, and the message names
  `optimizations.multipart_session_idle_timeout` as the knob. Pinned by
  `TestOrcMgrSweptUploadIsLoggedWithWhatAnOperatorNeeds`, which was proven to
  fail when the line drops below `Info`.
- `README.md` and `docs/developer/multipart.md` say that the timeout bounds the
  duration of one part as well as the gap between parts, with the 5 GiB / 1.5 MB/s
  figure an operator can size against.

So the failure is now diagnosable from a default-level log and recoverable by
configuration. What is left is only the real fix.

## Work

1. **Move the clock during a part.** A reader wrapped around the part body that
   touches the session as bytes arrive.
   **It must not take the session mutex.** `sync.Mutex` in Go is not reentrant,
   so a reader that locks per `Read` self-deadlocks the moment it is ever read
   from inside a region that already holds the lock — a hang, not a panic. It
   would also contend with the sweeper and `ListParts` on the hottest path,
   per 64 KiB.
   Make `lastTouched` an `atomic.Int64` of Unix nanoseconds instead, the way
   `shutdownStart` in `main.go` is. `touch` becomes a store and `idleFor` a load,
   no lock on either side, and the sweeper stops taking the session mutex to
   measure. Store only when the last store is more than a second old: the clock's
   resolution is hours, and that turns the common case into a load and a branch.
2. **Test it** with a part fed slower than a short idle timeout, asserting the
   upload survives and completes.

## Done when

- [x] A swept upload is visible in a default-level log, with the three things an
      `AbortMultipartUpload` needs and the reason. **Done 2026-09-12.**
- [x] The timeout's real meaning is documented where an operator reads it.
      **Done 2026-09-12.**
- [ ] A slow part does not expire, `go test -race` is clean, and the sweeper no
      longer takes the session mutex to measure.
- [ ] Deleted, and `git grep` shows nothing outside `docs/tickets/`.
