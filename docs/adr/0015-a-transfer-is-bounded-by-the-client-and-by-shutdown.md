# ADR 0015: A transfer is bounded by the client and by shutdown, not by a server wall clock

## Status

Accepted. Date: 2026-09-07.

**Decided and specified; still not implemented**, and outstanding work for 5.0.0 rather than a
future release. The proxy still enforces a 30-second wall clock on the whole request body read
and on the whole response body write, and the shipped Kubernetes chart still sets no termination
grace period, so the platform kills the process 30 seconds after the stop signal regardless of
what `shutdown_timeout` says.

**Two claims this block used to make are wrong, and one of them hides a defect.**

The graceful drain does *not* honour the configured `shutdown_timeout` end to end. The wait loop
for active requests does, but the server drain it wraps runs under a **hard-coded 30-second
context** of its own. An operator who sets `shutdown_timeout: 120` gets a 120-second wait around
a 30-second drain, so the configured value cannot do what it says. D4 states that no other fixed
shutdown deadline exists anywhere in the process; one does, and removing it is part of D4.

And the metrics listener does not run without a response budget: it sets a 30-second write
timeout unconditionally, and reads nothing about profiling. The listener with no budget is the
separate pprof listener, and its absence of one is unconditional rather than gated on a setting.

Also unstated: `ReadHeaderTimeout` is set nowhere, so the header budget D2 asks for does not
exist even in the weak form. D1 and D2 therefore cannot be one change — removing the read
timeout without first adding a header timeout would delete the only bound there is.

## Context

The data-plane listener carries two fixed 30-second budgets: one for reading a request, one for
writing a response. Neither is configurable. Both are wall-clock budgets for an *entire*
transfer, not for a stalled one — the clock runs while bytes are moving at full speed.

That makes the maximum object the proxy can serve a function of the client's link:
30 seconds × client bandwidth. Roughly 3.6 GB at 1 Gbit/s, roughly 375 MB at 100 Mbit/s, less on
anything slower. Above that the connection is reset mid-stream, on a healthy transfer, with no
error the client can act on.

The concrete failures that forced the decision, both from a backup client in normal use:

* A restore streams one large archive over whatever link the operator has. The response budget
  resets the connection mid-download at exactly that size threshold.
* An upload agent on a slow link that moves less than one part per 30 seconds dies on the read
  budget instead.

The bug survived every benchmark because the test suites run on loopback with parts in the
low tens of megabytes, which finish in well under a second. Relative-throughput measurement over
a real network is blocked by the same wall clock: a single-response leg of one gigabyte fails
outright below roughly 35 MB/s rather than reporting a poor number.

The same 30-second disconnect once had a second, silent effect — it cancelled the attachment of
encryption metadata after a multipart completion, leaving a committed object in the bucket that
the proxy could no longer decrypt. That half is already closed: post-completion cleanup runs on a
context detached from the request. The killed transfer is what remains.

The reasoning against a whole-response budget was already accepted one listener over: the metrics
listener drops its response budget whenever profiling is enabled, because a profile that streams
for 30 seconds would otherwise be cut in half. It never reached the data plane.

What a server *does* have to bound is the phase before a transfer exists: a connection that is
opened and then sends no complete set of request headers costs a goroutine and a file descriptor
for nothing. That is the classic slow-header attack, and it is the one thing the removal must not
take with it.

## Decision

**D1.** The proxy sets no wall-clock budget on reading a request body or on writing a response
body. A transfer lasts as long as the client and the backend keep it going, whatever the object
size and whatever the link speed.

**D2.** The request line and headers get a 30-second budget. A connection that has not delivered
a complete header set within it is closed. This is the only bound the proxy places on an inbound
connection before a transfer starts.

**D3.** An idle keep-alive connection is closed after 60 seconds. A connection between requests
is not a transfer.

**D4.** `shutdown_timeout` (seconds; 30 is used when it is unset or zero) is the single
documented budget an in-flight transfer gets when the process is asked to stop. The proxy stops
accepting new requests, waits for the running ones up to that budget, and closes what is left by
exiting. No other fixed
shutdown deadline exists anywhere in the process.

**D5.** The Kubernetes chart derives the platform's termination grace period from the proxy's
own budget: `terminationGracePeriodSeconds` is `shutdown_timeout` plus five seconds. The
platform does not kill the process before that budget has expired. The shipped compose
environment already stops its containers with a fixed 45-second grace period, which covers the
default budget; it is not derived and an operator who raises `shutdown_timeout` past 40 seconds
raises it too.

**D6.** Bounding a client that occupies a connection without making useful progress is the
ingress's job, not the proxy's. The proxy ships no rate limit, no connection cap and no
per-transfer progress deadline.

**D7.** Removing a bound that a deployment may have been relying on is a behaviour change and
ships in a major release with the other behaviour changes of that release, not as a patch.

**D8.** No new configuration key is introduced for any of these budgets. `shutdown_timeout` is
the one knob, and it governs both the drain and the platform grace period derived from it.

**D9.** A layer that wraps the response on its way to the client preserves the capabilities the
layers beneath it expose — flushing a partial response, taking over the connection, and reaching
the writer underneath. A wrapper that silently removes one of them changes how a long transfer
behaves and disables the very mechanism a per-transfer deadline would need. This was found the
hard way: an observability wrapper removed the fast copy path and the streaming capabilities
together, and the loss was invisible because everything still worked, only differently.

## Consequences

* Object size stops being a function of client bandwidth. Any S3 client can move any object the
  backend accepts, over any link, at any speed.
* A slow or malicious client can hold a connection — and the goroutine behind it — for an
  unbounded time as long as it keeps the body or the response moving at any rate at all. The
  proxy will not cut it. An operator who needs that bound sets it in the ingress.
* Pod termination now waits for the slowest in-flight transfer, up to `shutdown_timeout`. Rolling
  restarts get slower, and one long transfer delays a restart by the full budget. An operator who
  raises the budget to protect large transfers pays for it in rollout time on every deploy.
* A transfer longer than `shutdown_timeout` is still cut at shutdown. There is no per-transfer
  exemption and no "wait for this one" mechanism. The budget is a promise about the process, not
  about any individual request.
* Until 5.0.0 ships, every transfer above the 30-second wall clock keeps failing, and no
  throughput number measured over a real network can be trusted. Loopback measurement is
  unaffected, which is exactly why the defect stayed invisible for so long.
* Documentation owes operators an explicit statement that `shutdown_timeout` is the transfer
  budget on exit, not merely a shutdown nicety — it is now the only server-side limit on a
  running transfer.

## Alternatives Considered

**Make the read and write budgets configurable keys.** Rejected. Any correct value is "long
enough for the largest object over the slowest client link", which the proxy cannot know and the
operator would have to recompute after every change in object size or connectivity. It moves an
availability bug into an operator's arithmetic and adds a key whose only correct setting is
effectively infinite.

**Raise the budgets to a large fixed number instead of removing them.** Rejected. The failure
mode is unchanged, only rarer — and rarer means harder to diagnose, because it then only bites
the largest object over the worst link, months after the deployment was declared healthy.

**Ship the removal immediately as a patch on the main line.** Rejected, though it was the
recommended option when the decision was put to the owner: it is an availability fix and no
client knowingly depends on the old behaviour. The owner keeps every behaviour change of this
cycle in one set of release notes, so it rides the major instead. The cost is explicit and
accepted: slow transfers keep dying until that release.

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
* **Not verified: that a transfer exceeding the old budget completes end to end.** No test in the
  suite runs a transfer longer than 30 seconds — that is precisely why the defect shipped. A
  rate-limited slow-transfer case belongs with the implementation; it does not exist yet.
* **Not verified beyond the shipped chart.** Only the Kubernetes chart derives a grace period
  from `shutdown_timeout`; the shipped compose environment carries a fixed one that happens to
  cover the default budget. Any other orchestrator, init system or service mesh may kill the
  process earlier, and the proxy has no way to detect that it was.
* **Untouched: the outbound hop.** The audit reports that the connection the proxy makes to the
  backend has no dial or TLS-handshake budget on the path that skips certificate verification.
  That is an outbound gap, it is not verified here, and this decision does not address it.
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
* [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md) — trust boundaries and the hardening
  checklist, including what the proxy deliberately does not defend against
