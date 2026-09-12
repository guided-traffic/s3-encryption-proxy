# ADR 0029: The shutdown budget finishes work, and sweeps what cannot be finished

## Status

**Accepted.** Date: 2026-09-12. **Implemented on the 5.0.0 branch the same day.**

The graceful shutdown period has four steps in a fixed order: readiness goes false, new work is
refused while the listener stays up, the transfers in flight are allowed to finish, and then every
multipart upload this process is holding is ended at the backend. The listener closes last, once
there is nothing left to serve.

This supersedes **D5 of [ADR 0028](0028-an-abandoned-upload-is-ended-not-forgotten.md)**, taken
the same day, which said nothing is aborted at shutdown.

## Context

A client-driven multipart upload lives in two places at once. The backend holds the upload and its
stored parts. The proxy holds the session: the object's data key, the part table
`CompleteMultipartUpload` is built from, and the one short part a session may buffer (ADR 0011).
**Only the pair can finish the object.** The backend cannot, because every part it holds is sealed
under a key it has never seen; the client cannot, because the part layout that makes the segment
chain line up is the proxy's, not the client's list.

The session is process-local. It is a map in memory, it is not shared between replicas, and
nothing persists it. So the moment this process exits, every upload it was holding becomes
unfinishable — not delayed, not resumable elsewhere, **unfinishable**. A second replica behind the
same Service cannot adopt it: it has no data key and no part table, and a client that sends the
next part there is answered `NoSuchUpload`.

ADR 0028 D5 nevertheless left those uploads alone at shutdown, reasoning that a rollout must not
destroy uploads in flight and that the client can restart. The first half is true of the *data* and
false of the *upload*: there is no upload left to destroy, only a record of one that can never be
completed. The second half is the error — the client can indeed start again, but nothing it or
anyone else does will ever finish the one that was in progress, and the parts already stored stay
at the backend, invisible to `ListObjects`, until a lifecycle rule removes them or an operator goes
looking.

Every deployment, every scale-down, every node drain, every crash-free restart therefore leaked
exactly as much storage as was in flight at the time. That is the common case, not the rare one.

A graceful shutdown period exists for precisely this: to spend a bounded amount of time putting
work into a state somebody can live with, instead of stopping wherever the signal landed.

## Decision

**D1** The shutdown budget runs in this order, and the order is the decision:

1. **Readiness goes false.** `/health` answers `503 shutting_down` from the first moment, so a
   readiness probe takes the instance out of rotation before anything else changes.
2. **No new work, and the listener stays up.** Every S3 request that arrives from now on is
   answered `503 ServiceUnavailable` with `Retry-After`. The door is not shut: a closed listener
   answers a client that arrives before a load balancer has taken this instance out of rotation
   with a connection refusal, which an SDK cannot tell apart from a backend that is down, while a
   `503` is a retry it makes against another replica on its own. The refusal sits in front of
   authentication, so it costs no signature check, and in front of the request tracker, so it is
   not counted as work step 3 has to wait for. The health and version routes keep answering, or a
   readiness probe would have nothing to read.
3. **Transfers in flight finish.** Uploads and downloads already running are given the budget to
   complete. This is the half that was already there, and ADR 0015 D4 is what bounds it.
4. **What cannot be finished is swept.** Every multipart session still held is ended at the
   backend.

Only then is the listener closed. Steps 2 and 3 are what the graceful period is *for*; taking the
socket down at the start would spend it refusing connections instead of finishing work.

Draining before sweeping is what keeps an upload from being ended while its own part is still
being written.

**D2** Every multipart session still held after the drain is aborted at the backend. An upload
this process was holding is unfinishable once it exits, so ending it is not destroying work — it
is releasing storage that would otherwise be unreachable. A transfer that finished during step 3
has already closed its own upload and is not in the map by then.

**D3** The second phase is bounded by **what is left** of the operator's shutdown timeout, not by
a fresh copy of it. The chart derives the pod's termination grace period from the same value, so a
second full budget is how a shutdown gets killed halfway through cleaning up. A drain that used
the whole budget leaves the uploads and says so.

**D4** Uploads are ended one at a time and the walk stops when the budget expires. What could not
be ended is reported with its upload id, bucket and key, so an operator has the three things an
`AbortMultipartUpload` needs.

**D5** Nothing is *completed* at shutdown, only ended. The proxy has no authority to finish an
object whose client has not finished sending it, and an object assembled from whatever happened to
have arrived is a corrupted backup that reads cleanly.

**D7** The budget is a **ceiling, not a duration**. The proxy exits as soon as the four steps are
done: there is nothing left to serve, nothing left to sweep, and a replacement instance is already
taking the traffic. The drain ends at the moment the last in-flight request finishes rather than on
the next tick of a poll, and an instance with nothing in flight when the signal arrives does not
wait at all.

**D6** This does not replace a bucket lifecycle rule. A crash, an OOM kill or a SIGKILL leaves no
shutdown period at all, and the session dies with the process. `AbortIncompleteMultipartUpload` is
the only thing that catches those, and the operator documentation says so.

## Consequences

* A rollout with uploads in flight now costs one `AbortMultipartUpload` per upload, inside the
  grace period the operator already configured, and leaves nothing behind.
* A client that reaches a draining instance gets a retryable `503` rather than a refused
  connection. Measured on 2026-09-12: `/health` and every S3 route answered `503` with
  `Retry-After: 1` for the whole drain, and the listener closed only after it.
* Shutdown takes as long as the work does and no longer. Measured on 2026-09-12 with an 8-second
  budget: **769 µs** with nothing in flight and one multipart upload to end, and **2.78 s** when a
  1 GiB download was mid-transfer — which is what was left of that download. The same run under
  the previous poll-every-second drain took 1.0027 s to do nothing.
* An in-flight transfer is not sacrificed to the exit. The 1 GiB download above delivered all
  1073741824 bytes after its instance had been told to stop.
* A client whose upload was in flight during a shutdown learns about it sooner: its next
  `UploadPart` is answered `NoSuchUpload` either way, but now the storage is gone too rather than
  waiting for a lifecycle rule.
* The shutdown path makes network calls to the backend for the first time. A backend that is
  already gone — the usual case when a whole stack is being torn down — costs one failed call per
  upload against the remaining budget, and each failure is logged with what an operator needs to
  finish the job by hand.
* Shutdown stays within one `shutdown_timeout`, which it did not before: the manager's stop phase
  used to get a fresh full budget on top of the drain.

## Alternatives considered

**Leave it to the lifecycle rule.** The position of ADR 0028 D5. Rejected because it treats the
one case the proxy can handle — a clean, signalled shutdown, where it knows every upload id — as
if it were the crash case it genuinely cannot handle. It also requires a bucket configuration the
proxy does not own and cannot check.

**Persist sessions so another process can adopt them.** This would make the uploads genuinely
resumable rather than merely not-cleaned-up, and it is the only alternative that would make D2
wrong. It means persisting data keys outside the process, which is a much larger decision about
where key material may live (ADR 0002), and it buys resumability for a case measured in seconds.
Not taken, and not closed.

**Complete what has arrived.** Rejected as D5: it produces an object the client never asked for,
and the segment chain would authenticate it perfectly.

## Residual risks

* **The clean-refusal window is exactly as long as the drain, and D7 makes it shorter.** An idle
  instance now exits in under a millisecond, so there is effectively no window in which a late
  request gets a `503` instead of a refused connection; a busy one keeps the window for as long as
  its transfers run. That is the right trade for the instance — it is the load balancer's job to
  have stopped sending — but it does mean the `503` is a courtesy for slow rotation, not a
  guarantee. A `preStop` sleep in the chart is what puts a floor under it, and it is not built:
  the deployment template has no `lifecycle` block.
* **A shutdown that overruns its drain cleans up nothing.** D3 chooses the pod's grace period over
  the cleanup, deliberately: being killed mid-abort is worse than not starting. An operator whose
  drains routinely fill the budget gets no cleanup and one warning line.
* **The backend is often gone first.** In a `docker compose down` or a namespace deletion the
  backend may already be unreachable, and every abort then fails. The uploads stay, and the
  lifecycle rule of D6 is what removes them.
* **Nothing is verified against a backend other than MinIO.** The abort call is ordinary S3, but
  the claim that ending an upload releases its parts is checked against MinIO only.

## References

* [ADR 0011](0011-the-proxy-owns-the-part-layout.md) — what a session holds, and why only the
  proxy can complete the object
* [ADR 0015](0015-a-transfer-is-bounded-by-the-client-and-by-shutdown.md) — shutdown is one of the
  two things that may bound a transfer
* [ADR 0028](0028-an-abandoned-upload-is-ended-not-forgotten.md) — the same cleanup for an upload
  that goes idle while the proxy keeps running; its D5 is superseded here
