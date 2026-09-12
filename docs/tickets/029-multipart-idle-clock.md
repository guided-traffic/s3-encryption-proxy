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

## Work

1. **Make the sweep visible.** One `Info` line per upload the sweeper ends,
   carrying the upload id, the bucket, the key and the idle time measured, and
   naming `multipart_session_idle_timeout` as what governs it. A few lines, no
   design decision, and it is what makes the operator's own workaround usable.
   **This is the half worth doing whether or not item 2 ever happens.**
2. **Name the knob where it is needed.** `README.md` and
   `docs/developer/multipart.md` should say that the timeout bounds the gap
   between parts *and* the duration of one part, and that a slow link with large
   parts is the case that needs it raised.
3. **Move the clock during a part.** A reader wrapped around the part body that
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
4. **Test it** with a part fed slower than a short idle timeout, asserting the
   upload survives and completes.

## Done when

- [ ] A swept upload is visible in a default-level log, with the three things an
      `AbortMultipartUpload` needs and the reason.
- [ ] The timeout's real meaning is documented where an operator reads it.
- [ ] If item 3 lands: a slow part does not expire, `go test -race` is clean, and
      the sweeper no longer takes the session mutex to measure.
- [ ] Deleted, and `git grep` shows nothing outside `docs/tickets/`.
