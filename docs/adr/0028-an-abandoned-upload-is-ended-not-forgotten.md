# ADR 0028: An abandoned upload is ended, not forgotten

## Status

**Accepted.** Date: 2026-09-12. **Implemented on the 5.0.0 branch the same day.**

A client-driven multipart upload that has received no part for
`optimizations.multipart_session_idle_timeout` seconds is aborted at the backend and then
forgotten. The key it replaces, `optimizations.multipart_session_max_age`, refuses the start by
name.

## Context

The proxy keeps one in-memory session per client-driven multipart upload: the object's data key,
the part table Complete is built from, and the one short part a session may hold (ADR 0011). A
background sweeper drops sessions a client never finished, so an abandoned upload does not hold
key material for the life of the process.

Two things about that sweeper were wrong, and each made the other worse.

**It measured the wrong clock.** Expiry was measured from the moment the upload was created,
against `optimizations.multipart_session_max_age`, which defaulted to one hour. The time of the
last part was recorded per part and read only by `ListParts`.
So an upload that was still transferring was dropped one hour after it began — 10 000 parts of
8 MiB is 78 GiB, which over a 20 Mbit/s link is about nine hours, and a backup of that shape over
a narrow link cannot finish. From then on the client is answered `NoSuchUpload` and cannot resume.

That is also a server wall clock on a transfer, which [ADR 0015](0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md)
rejects. Its D1 governs one request; nothing governed the sequence of requests that makes one
object.

**It abandoned data at the backend.** The sweep deleted the session and said nothing to the
backend. The multipart upload and every part already stored in it stayed there: invisible to
`ListObjects`, consuming space, reachable only by a client that still knows the upload id — and
that client has just been told the upload does not exist. `CompleteMultipartUpload` and
`AbortMultipartUpload` both clean up correctly; the sweeper was the one path that did not, and it
is the only place this proxy leaves data nobody can reach.

The order matters more than either fault. Aborting on the creation clock would have turned a leak
into destruction: the proxy would have deleted uploads that were still running. The clock has to
be right before the abort is built at all.

## Decision

**D1** Expiry is measured from the last part an upload received, never from when it was created. A
transfer that is still moving bytes is never abandoned for taking long, whatever its size or the
speed of the link.

**D2** Before the sweeper forgets a session it tells the backend the upload is over. A backend
that no longer knows the upload is the outcome asked for, so `NoSuchUpload` counts as success.

**D3** The backend call is made outside the session lock and under a context bounded by the sweep
interval, so a slow or unreachable backend cannot block an upload in progress and cannot stall the
sweeper past its next tick.

**D4** A session whose abort the backend refuses is kept for the next tick, and given up after
five attempts with an error naming the upload. Retrying for ever would keep an abandoned session's
data key and short part resident for the life of the process, which is the thing the sweeper
exists to prevent.

**D5** ~~Nothing is aborted at shutdown.~~ **Superseded 2026-09-12 by
[ADR 0029](0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md).** This
decision reasoned that a rollout must not destroy uploads in flight and that the client can abort
or restart. The second half is where it went wrong: the session holds the object's data key and
the part table, both process-local, so once this process exits *nobody* can finish the upload —
not the client, not another replica. There is no work left to protect, only storage nobody can
reach. The shutdown budget now ends those uploads.

**D6** The criterion gets a new configuration key, `optimizations.multipart_session_idle_timeout`,
and `optimizations.multipart_session_max_age` refuses the start naming it. The number an operator
already wrote means something else under the new rule, and a key that silently changes meaning is
what [ADR 0013](0013-a-configuration-key-exists-only-if-code-reads-it.md) forbids.

**D7** The proxy owns no S3 client in its orchestration layer, and this decision does not give it
one. The abort is handed in as a function by the layer that has the backend client. A manager
built without one — every unit test, and any future embedding — forgets as it did before.

## Consequences

* An abandoned upload costs one backend request per sweep instead of none. At the default interval
  of five minutes that is one request per abandoned upload, once.
* The proxy now issues a destructive backend call on its own initiative, for an upload a client
  began. That is new, it is what D2 is for, and an operator has to be able to reason about when:
  after the configured idle timeout, and — since the same day, under
  [ADR 0029](0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md) — at a
  signalled shutdown. Never for an upload this process does not itself hold.
* An upload lost to a crash or an OOM kill is **not** covered by any of this. A signalled
  shutdown is, since 2026-09-12 (ADR 0029); a process killed outright has no budget to spend, the
  session dies with it and nothing remains to abort the upload. A bucket lifecycle rule
  `AbortIncompleteMultipartUpload` is the answer to those, it works in days rather than minutes,
  and the proxy does not own the bucket configuration — so it belongs in the operator
  documentation, not here.
* Two sessions of the same upload cannot exist, so no second process can abort an upload this one
  is still feeding.

## Alternatives considered

**Leave it to a lifecycle rule alone.** It is the standard answer and it catches strictly more
cases, including the crash. It was rejected as the *only* answer because it works in days, the
proxy cannot set it, and an operator who does not set one gets no cleanup at all from a product
that knows exactly which uploads it has abandoned and when.

**Abort at shutdown as well.** Rejected here on the day and **taken the same day** by
[ADR 0029](0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md). The
rejection rested on calling it a data loss for anyone uploading at the time; it is not, because
nothing can finish those uploads once the process exits.

**Keep the age clock and simply raise the default.** Rejected: any finite age is a server wall
clock on a transfer, and there is no value that is right for both a 100 MiB upload and a 78 GiB
one. Inactivity is the property actually being tested for.

**Reuse `multipart_session_max_age` for the new meaning.** Rejected as D6. It is the cheaper
change and it is exactly the silent behaviour change ADR 0013 exists to prevent.

## Residual risks

* **Nothing bounds the number of live sessions.** The sweeper removes idle ones; a client that
  keeps many uploads alive by feeding each of them slowly holds one data key per upload, and
  nothing caps how many of those there may be. The buffered short parts are bounded — ADR 0011 D5
  caps them across all sessions at `optimizations.multipart_short_part_buffer_size`, a short part
  that does not fit beside what other uploads hold answers `SlowDown` and one larger than the whole
  budget `EntityTooLarge` — but the session count is not, and this decision does not change that.
* **The idle clock moves when a part arrives, never while one is arriving.** Recorded 2026-09-12.
  It is written when a part is handed to the session and again when a stored part is entered in the
  part table, so a single part that takes longer than `optimizations.multipart_session_idle_timeout`
  to transfer looks idle: the sweeper ends its upload at the backend while the body is still being
  written, and the client's next request is answered `NoSuchUpload`. D1 holds between parts and not
  within one. Every upload the sweeper ends is logged at Info with its upload id, bucket, key and
  how long it had been idle, and the line names `optimizations.multipart_session_idle_timeout`: the
  line is the only thing that says which knob to turn, and the only thing the client's unexplained
  `NoSuchUpload` can be correlated with.
* **The cleanup interval is not range-checked.** `multipart_session_cleanup_interval` takes any
  value, and 0 disables the sweeper altogether: for as long as the process runs, an idle upload is
  then neither ended nor forgotten (ADR 0013 records the same gap for other keys). A signalled
  shutdown still ends what the process is holding, whatever the interval says
  ([ADR 0029](0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md)).
  `multipart_session_idle_timeout` is no longer one of them: since 2026-09-12 a value below one
  second refuses the start by name, because 0 there means every upload is already idle rather than
  no timeout at all (ADR 0017 D8).
* **A backend that accepts an abort and keeps the parts** defeats D2 entirely. Verified against
  MinIO, which does not; not verified against anything else.

## References

* [ADR 0011](0011-the-proxy-owns-the-part-layout.md) — what a session holds and why
* [ADR 0013](0013-a-configuration-key-exists-only-if-code-reads-it.md) — a key may not change
  meaning in silence
* [ADR 0015](0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md) — no server wall clock
  on a transfer, which D1 extends from one request to one object
* [ADR 0024](0024-an-upload-forwards-while-it-receives.md) — the client-driven part path this
  session serves
