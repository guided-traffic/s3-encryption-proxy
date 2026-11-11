# ADR 0015: A transfer is bounded by the client and by shutdown, not by a server wall clock

## Status

Accepted. Date: 2026-09-15.

**Built**, shipped in 5.0.0 (D7). The listener sets no wall-clock budget on reading a request body or on
writing a response body (D1); the header phase and the idle keep-alive phase have 30 and 60
seconds by default and refuse 0 (D2, D3, D8); `read_timeout` and `write_timeout` default to 0
(D8); `shutdown_timeout` is the one budget for the whole shutdown (D4); and the chart derives
`terminationGracePeriodSeconds` from it (D5). Two integration tests move a small object slowly in
each direction for longer than 30 seconds and assert the bytes by digest afterwards.

Not built: D4's "no other fixed shutdown deadline" holds for the request path and not for the
whole process. The metrics listener and the profiling listener each close on a fixed ten seconds
of their own, which nothing waits for — the process exits without them.

D1 holds at any speed the backend tolerates, which is not every speed: the backend has a
tolerance of its own, measured under Residual risks.

## Context

The data-plane listener carried two fixed 30-second budgets: one for reading a request, one for
writing a response. Neither was configurable. Both were wall-clock budgets for an *entire*
transfer, not for a stalled one — the clock ran while bytes were moving at full speed.

That made the maximum object the proxy could serve a function of the client's link:
30 seconds × client bandwidth. Roughly 3.6 GB at 1 Gbit/s, roughly 375 MB at 100 Mbit/s, less on
anything slower. Above that the connection was reset mid-stream, on a healthy transfer, with no
error the client could act on.

The concrete failures that forced the decision, both from a backup client in normal use:

* A restore streams one large archive over whatever link the operator has. The response budget
  reset the connection mid-download at exactly that size threshold.
* An upload agent on a slow link that moves less than one part per 30 seconds died on the read
  budget instead.

The bug survived every benchmark because the test suites run on loopback with parts in the
low tens of megabytes, which finish in well under a second. Relative-throughput measurement over
a real network was blocked by the same wall clock: a single-response leg of one gigabyte failed
outright below roughly 35 MB/s rather than reporting a poor number.

The same 30-second disconnect had a second, silent effect — it cancelled the attachment of
encryption metadata after a multipart completion, leaving a committed object in the bucket that
the proxy could no longer decrypt. That half is closed independently of this decision:
post-completion cleanup runs on a context detached from the request. The killed transfer is what
this record answers.

The reasoning against a whole-response budget was already accepted one listener over: the
profiling listener sets no response budget at all, because a profile that streams for 30 seconds
would otherwise be cut in half.

What a server *does* have to bound is the phase before a transfer exists: a connection that is
opened and then sends no complete set of request headers costs a goroutine and a file descriptor
for nothing. That is the classic slow-header attack, and it is the one thing the removal must not
take with it.

## Decision

**D1.** The proxy sets no wall-clock budget on reading a request body or on writing a response
body. A transfer lasts as long as the client and the backend keep it going, whatever the object
size and whatever the link speed.

**D2.** The request line and headers get a 30-second budget by default (D8). A connection that
has not delivered a complete header set within it is closed. This is the only bound the proxy
places on an inbound connection before a transfer starts, and it may not be switched off.

**D3.** An idle keep-alive connection is closed after 60 seconds by default (D8). A connection
between requests is not a transfer, and this bound may not be switched off either.

**D4.** `shutdown_timeout` (seconds; 30 is used when it is unset or zero) is the single
documented budget for the whole shutdown, and so the budget an in-flight transfer gets when the
process is asked to stop. The proxy stops accepting new requests, waits for the running ones,
ends the multipart uploads it is holding, and closes the listener last
([ADR 0029](0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md)). The
sweep and the close each get what is left of the budget, never a fresh copy of it, so all three
phases together stay inside the one budget the platform grace period is derived from; what is
still running when it is spent is closed by the exit. No other fixed shutdown deadline exists
anywhere in the process.

**D5.** The Kubernetes chart derives the platform's termination grace period from the proxy's
own budget rather than letting the two be configured apart. The platform does not kill the
process before that budget has expired. The derivation is the sum of the `preStop` hold,
`shutdown_timeout` and five seconds (ADR 0034 D11): the hold runs in front of the drain and is
part of the same window. An explicit override below the sum fails the render instead of winning
silently. The shipped compose environment stops its containers with a fixed 45-second grace
period, which covers the default budget; it is not derived and an operator who raises
`shutdown_timeout` past 40 seconds raises it too.

**D6.** Bounding a client that occupies a connection without making useful progress is the
ingress's job, not the proxy's. The proxy ships no rate limit, no connection cap and no
per-transfer progress deadline.

**D7.** Removing a bound that a deployment may have been relying on is a behaviour change and
ships in a major release with the other behaviour changes of that release, not as a patch.

**D8.** The four listener budgets are configuration keys, in seconds: `read_timeout` and
`write_timeout` for the two body phases, `read_header_timeout` and `idle_timeout` for the two that
are not transfers. The body budgets default to **0**, meaning no deadline, so a deployment that
configures nothing gets D1 exactly; an operator who knows their workload may set a ceiling, and
the key is an escape hatch for that and nothing more. The other two default to 30 and 60 and may
not be 0, and startup refuses it: with every budget at zero, a connection that never completes
its headers and a keep-alive connection that never sends another request would both be held
forever, and these two are the only bound on a connection that is occupying the server without
transferring anything. `shutdown_timeout` is the budget for the shutdown and the source of the
platform grace period derived from it.

**D9.** A layer that wraps the response on its way to the client preserves the capabilities the
layers beneath it expose — flushing a partial response, taking over the connection, and reaching
the writer underneath. A wrapper that silently removes one of them changes how a long transfer
behaves and disables the very mechanism a per-transfer deadline would need. This was found the
hard way: an observability wrapper removed the fast copy path and the streaming capabilities
together, and the loss was invisible because everything still worked, only differently.

## Consequences

* Object size stops being a function of client bandwidth. Any S3 client can move any object the
  backend accepts, over any link, at any speed **the backend itself tolerates** — which is not
  unlimited, and the measured floor is under Residual risks.
* A slow or malicious client can hold a connection — and the goroutine behind it — for an
  unbounded time as long as it keeps the body or the response moving at any rate at all. The
  proxy will not cut it. An operator who needs that bound sets it in the ingress.
* Pod termination now waits for the slowest in-flight transfer, up to `shutdown_timeout`. Rolling
  restarts get slower, and one long transfer delays a restart by the full budget. An operator who
  raises the budget to protect large transfers pays for it in rollout time on every deploy.
* A transfer longer than `shutdown_timeout` is still cut at shutdown. There is no per-transfer
  exemption and no "wait for this one" mechanism. The budget is a promise about the process, not
  about any individual request.
* Throughput measured over a real network is meaningful: a long single-response leg is no longer
  cut at a fixed wall clock, so a slow link reports a poor number rather than a failure.
* `shutdown_timeout` is the transfer budget on exit, not merely a shutdown nicety — with the body
  budgets at their default of 0 it is the only server-side limit on a running transfer, and the
  configuration reference says so beside the key.
* The outbound hop carries the SDK's dial, TLS-handshake, expect-continue and connection-pool
  budgets on both backend paths. The path that skips certificate verification builds on the SDK's
  client and overrides nothing but the TLS configuration, so the two differ in certificate
  verification and in nothing else.

## Alternatives Considered

**Give the read and write budgets a finite default.** Rejected. Any correct finite value is
"long enough for the largest object over the slowest client link", which the proxy cannot know
and the operator would have to recompute after every change in object size or connectivity. It
moves an availability bug into an operator's arithmetic. The objection is to the finite default,
not to the key: D8 ships the keys at 0.

**Raise the budgets to a large fixed number instead of removing them.** Rejected. The failure
mode is unchanged, only rarer — and rarer means harder to diagnose, because it then only bites
the largest object over the worst link, months after the deployment was declared healthy.

**Ship the removal as a patch.** It is an availability fix and no client knowingly depends on
the bound. Rejected under D7: the owner keeps every behaviour change of a cycle in one set of
release notes, so the removal rides a major release.

**Removal plus per-connection progress deadlines that are refreshed on every copy iteration, on
both the body read and the response write.** Rejected for now. It bounds a client that makes no
progress without bounding one that is merely slow, which is the right shape — but it adds
deadline handling to every copy loop in the data path and still needs a documented ceiling, and
the same protection is available in the ingress that operators already run. Kept as the option to
revisit if connection pinning turns out to be a real problem rather than a theoretical one.

## Residual risks

* **Accepted: no progress detection on an in-flight transfer.** A client that sends one byte per
  minute keeps a connection and a goroutine indefinitely. Only the header phase is bounded. The
  mitigation is external, and this ADR does not claim the proxy provides it.
* **Accepted: shutdown is a hard cut.** Transfers still running when `shutdown_timeout` expires
  are closed by process exit. Whether the client retries is the client's business.
* **Open, measured 2026-09-11: the backend has a tolerance of its own and the proxy amplifies
  it.** The proxy opens the backend request and then sends nothing until it has a whole segment
  of the stored format to seal, so a slow client turns into a silent backend request. MinIO
  refuses one it has heard nothing on for roughly 25 seconds, with `503` and a resource-lock
  timeout; the same body sent straight to the backend at the same rate is accepted, because the
  backend then receives bytes continuously. The practical floor is about one segment of client
  bytes per 25 seconds, roughly 2.6 KiB/s, and for an object below one segment it is the whole
  object inside that window; below that rate an upload is refused by the backend. Closing the gap
  is a design question: the write path would have to either delay the backend request until it
  has bytes, or keep the request alive some other way. Not decided.
* **Not verified beyond the shipped chart.** Only the Kubernetes chart derives a grace period
  from `shutdown_timeout`; the shipped compose environment carries a fixed one that happens to
  cover the default budget. Any other orchestrator, init system or service mesh may kill the
  process earlier, and the proxy has no way to detect that it was.
* **Open: the call budget for a remote key provider.** A key encryption key held in an external
  KMS needs its own bounded call, and the usual phrasing — "shorter than the request timeout" —
  now has nothing to refer to, because there is no request timeout. What bounds that call is
  decided with that provider, not here.

## References

* ADR 0005 — A KMS-backed key encryption key is a provider, not a mode
* ADR 0006 — The proxy serves any S3 client
* ADR 0013 — A configuration key exists only if code reads it, and an unworkable configuration
  refuses to start
* ADR 0014 — Authentication is SigV4 on both forms; there is no rate limiting and no IP blocking
* ADR 0018 — A major release is declared by a label, never discovered at merge
* ADR 0019 — Integration and end-to-end tests are the product; they are never skipped
* ADR 0020 — Performance is measured before and after, never asserted
* [README.md](../../README.md) — `shutdown_timeout` and the rest of the server configuration
* [docs/security/threat-model.md](../security/threat-model.md) — trust boundaries and what the
  proxy deliberately does not defend against
