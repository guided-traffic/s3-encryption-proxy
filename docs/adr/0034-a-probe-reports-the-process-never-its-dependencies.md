# ADR 0034: A probe reports the process, never its dependencies

## Status

**Accepted.** Date: 2026-09-15. Decided with the owner while refining the high-availability
work, out of a defect that needed neither: one endpoint served both Kubernetes probes and
reported the drain, so a pod that was shutting down failed its own liveness probe by design.

**Built 2026-09-15.** The serving listener answers `/livez` and `/readyz`; the monitoring
listener answers `/livez`, `/metrics` and `/status`. The endpoints `/health`, `/version` and
`/info` are gone from both listeners. The chart points each probe at the endpoint that answers
its question, declares a `preStop` hold, and derives the termination grace period from the hold
plus the shutdown budget.

## Context

Kubernetes has exactly one reaction to a failing liveness probe: kill the container and restart
it. It has exactly one reaction to a failing readiness probe: take the pod out of the Service's
endpoints. Neither reaction is a diagnosis, and neither can be softened — so the only question
worth asking of a probe is which of those two reactions its answer should trigger.

Until this record the proxy had one unsigned endpoint, `/health`, and the chart pointed **both**
probes at it. That endpoint reported the drain: from the moment the process received `SIGTERM`
it answered `503`. Readiness wanted exactly that answer. Liveness got it too, and a draining pod
therefore spent the whole of its shutdown failing the probe whose only remedy is a kill.

What sits inside that window is the part of the shutdown that cannot be repeated: the proxy
holds its own multipart uploads (ADR 0033) and ends them in the shutdown tail (ADR 0028,
ADR 0029). A kill there leaves every open upload at the backend as an orphan — the precise
failure the sweep exists to prevent, triggered by the mechanism meant to protect the pod.

The same few lines carried a second defect. There was no `preStop` hold, so the listener stopped
accepting connections in the same moment the EndpointSlice withdrawal began propagating to
kube-proxy on every node. Those two are not ordered against each other, so for the length of that
propagation the pod refused connections the cluster was still sending it. An SDK retries; a
client that does not, fails.

## Decision

**D1. Three endpoints, each named for what it answers.** One liveness endpoint, one readiness
endpoint, one status document. The serving listener answers `/livez` and `/readyz`. The
monitoring listener answers `/livez` beside `/metrics` and `/status`. Nothing in the platform ever
acts on the status document automatically.

**D2. Liveness is a constant success on the serving listener, and covers nothing else.** Not
backend reachability, not the configuration, not the licence, not any other precondition. A
liveness probe answers one question — *would a restart repair this?* — and for every precondition
the answer is no:

* **A backend outage is not repaired by a restart.** Every instance would fail at once, restart at
  once, and back off exponentially, so the proxy would recover *later* than the backend it was
  waiting for: a foreign outage converted into one of our own. It is worse here than elsewhere,
  because a restart is not a drain — a backend hiccup of thirty seconds would strand exactly the
  uploads D2 exists to protect.
* **The configuration cannot be false at run time.** The loader decodes strictly and an unknown
  key refuses the start (ADR 0013), so a process that answers at all has a configuration that
  parsed. That is a startup fact, not a runtime signal.
* **The licence already ends the process itself on expiry** (ADR 0016). A restart would find the
  same expired token, so a probe would only convert a clean stop into a crash loop.

What is left is the single case a liveness probe is for: the process is alive but can no longer
answer HTTP — a wedged accept path, a deadlock. A constant-success handler on the *serving*
listener detects exactly that, and nothing finer.

**D3. Readiness says whether this instance wants and can take traffic, and the drain is what makes
it false.** It answers success normally and a refusal carrying the shutdown time from the moment
the drain starts. It stays reachable throughout the drain, because the listener closes last
(ADR 0029): a probe arriving during the sweep reads a refusal rather than a connection error, and
a load balancer cannot tell a connection error from a dead backend.

**D4. Readiness is a lifecycle signal, never a load signal.** No pressure measurement makes it
false. A full short-part budget answers `SlowDown` in a response and nothing more (ADR 0011). A
readiness probe that reported load would take the pod out of rotation, move its share onto the
remaining pods, and take those out too.

**D5. No probe depends on anything outside the process, and none depends on a load quantity.**
This is the general rule behind D2 and D4, and it binds every probe added later. Anything outside
the process is shared: a dependency that fails takes every instance out at the same moment, so a
probe that reads it converts a partial outage into a total one.

**D6. Dependency health is a fourth category: reported, never acted on.** Backend reachability,
the active provider with its type and key fingerprint, and the licence time remaining are what an
operator wants to see and to alert on, and no automatic actor may act on them. They are the
status document and the metrics.

**A backend transport failure is reported three ways, and each answers a different question.**
The status document says *what state the backend is in now*. A last-seen timestamp says *when it
last broke*. Neither can express a rate, so the thing an alert is written against is a **counter
of failed round trips by class, beside a counter of answered ones** — the share that failed is the
signal, and without the denominator the numerator cannot be read at all, because the SDK retries
and an ordinary network produces some. And every failure is a **warning-level log line** naming
the class, the host, the method and the error: that line is the only record of a round trip that
failed and then succeeded on a retry, which reaches no handler and appears in no other log. A
failure under an already-cancelled request is none of the three — it is a client that hung up or a
shutdown, and it says nothing about the backend. Nor is a failure the proxy's **own request body**
raised: the body handed to the backend is this proxy's reader chain, so an upload checksum that
did not verify or a segment that could not be sealed comes back as the error of the round trip.
Counting it would let any credentialed client drive the backend alert by sending one wrong digest.

**The alerting rules ship with the chart, off by default.** A rule is where a threshold belongs —
not in a page an operator retypes — and shipping them is what makes the counters above a contract
rather than a suggestion. They are off by default because a threshold nobody tuned pages somebody
at three in the morning, and every one of them tells a human: none is read by anything that acts.

**D7. The status document reports what the real traffic showed; it never probes on its own.** It
carries the time of the last HTTP response from the backend, the time and class of the last
transport failure — DNS, connect, TLS, timeout — and says `no request since start` when there has
been neither. **Any** HTTP response counts as reachability, a `403` included: the question is
whether the backend answered, not whether it agreed. A proxy that has served nothing says so and
never claims health it has not observed.

**D8. Operational data lives on the monitoring listener, not on the S3 surface.** The status
document is the same boundary `/metrics` already draws: it sits on the port whose reachability the
administrator controls (ADR 0030), not on the port every S3 client reaches. The deciding field is
the active provider — an `exit` provider means the backend holds plaintext (ADR 0025), which is
exactly what must not be readable without authentication from the data path. Build information
goes with it: the serving listener answers two probe paths with constant answers and no
operational data at all.

**D9. No startup probe while the startup path does no network I/O.** Configuration, licence and
providers are all resolved in process before the listener binds, and every failure on that path is
fatal — there is no "started but not yet usable" window for a startup probe to cover. What the
liveness probe gets instead is a small initial delay rather than a blind half-minute. Work that
makes the start depend on the backend reopens this, and a startup probe is the right instrument
then.

**D10. The platform holds the pod still while its endpoints are withdrawn.** A `preStop` hold runs
before `SIGTERM`, long enough for the EndpointSlice withdrawal to reach kube-proxy on every node,
so the process stops accepting connections only once the cluster has stopped sending them. Its
duration is a deployment value, not a proxy configuration key: the propagation time is a property
of the cluster. The hold has **no opt-out**, and a duration of zero is refused for the same
reason: an opt-out switch and a zero hold are the same thing, one wearing a flag and the other a
number, and both install everywhere while leaving the drain racing the withdrawal exactly as
before. The chart declares the Kubernetes floor the native hold needs rather than rendering it
conditionally, so a cluster too old for the hold fails the install instead of running without it.

**D11. The termination grace period is the sum of the hold, the shutdown budget and a fixed
margin, and an override below that sum fails the render.** The three phases are sequential, so a
grace period shorter than their sum is a kill somewhere inside the sweep. An operator who wants
less moves one of the two numbers that mean something — the hold or `shutdown_timeout` — and the
sum follows; the sum itself is a consequence, not a knob. A render that fails names all three
numbers, which is what a pod killed mid-transfer cannot do.

## Consequences

* **`/health`, `/version` and `/info` are gone from both listeners**, with no alias and no
  deprecation period. Anything probing the old paths — an ingress, a load balancer, a monitoring
  check — has to move. The removal ships without a major-release declaration: the owner weighed
  ADR 0018 deliberately and judged the declaration not worth a major for endpoints no known
  deployment probes.
* **The running build is no longer readable over HTTP on a default install**, because the
  monitoring listener is off by default. It stays in the image tag, in the release, and in the
  first log line of the start. The default is not flipped, because flipping it would switch on an
  unauthenticated metrics port with it.
* **The status document is absent unless monitoring is switched on.** Any troubleshooting
  procedure that reads it opens with switching it on.
* **Every rollout costs the hold per pod**, paid in wall-clock on every upgrade. The default is
  small, and it buys the ordering the cluster does not otherwise guarantee.
* **A grace period that used to render now fails the render.** That is the intended direction:
  the value that silently lost was the shutdown budget, and the thing it lost was the sweep.
* **An alert exists for what a probe may not act on.** The rules the chart ships are the other
  half of D5: taking an instance out of rotation because a dependency failed is refused, telling a
  human that it failed is the answer. An operator who switches the rules off has neither, and that
  is their call to make.
* **A liveness probe that is a constant success detects less than one that checks something.** A
  process that is alive, answering, and useless — every backend request failing — stays in
  rotation. That is deliberate under D5: the alternative takes down every instance at once, and
  the useless-but-answering case is what D6's metrics are for.

## Alternatives Considered

**Keep one endpoint and point both probes at it.** The state before this record. Rejected: the two
probes ask different questions and have different remedies, so one answer is necessarily wrong for
one of them. Here it was wrong for the one whose remedy is a kill.

**Make liveness check the backend.** Rejected under D2. It is the single most common way a
deployment turns a dependency's outage into its own, and this proxy pays more for it than most
because a restart discards multipart sessions the process alone can finish.

**Make readiness check the backend.** Rejected under D5. It is less violent than a liveness check
— no restart, no backoff — but it still takes every instance out of rotation simultaneously, and
reads and single-request writes that would have worked are refused with it.

**Make readiness report load.** Rejected under D4, as a cascade: shedding a pod moves its share to
the rest, which then shed too.

**Add a startup probe.** Rejected under D9: there is nothing for it to cover while the startup
path does no network I/O, and its cost is a third probe to keep correct.

**A synthetic backend check behind the status endpoint** — on every request, on an interval, or
both behind a query parameter. All three rejected under D7. There is no S3 call that is
universally permitted: a policy may deny listing buckets, and the proxy owns no bucket of its own
to head, so a synthetic check can report a failure the real path does not have. They also make a
read of the document trigger backend traffic, and the interval variant costs a configuration key
and permanent I/O with no reader. The real path has the right credentials, the right target and
the right timeout by construction.

**Put the status document on the serving listener.** Rejected under D8: the active provider is on
it, and an `exit` provider is a statement about where plaintext lives.

**An alias or a deprecation period for the old paths.** Put to the owner and declined: two names
for one endpoint is the ambiguity this record removes, held open for a release.

**Render the hold conditionally on the cluster version, or give it an `enabled` switch.** Rejected
under D10. Both install everywhere and leave an older or opted-out cluster running with exactly
the broken drain this record closes, silently. A declared version floor fails at install time, in
front of the person who can act on it.

## Residual risks

* **Measured 2026-09-15 on kubelet v1.36.1: kubelet does not act on a liveness failure for a pod
  that is already terminating — it stops probing it altogether.** A pod deleted with a
  permanently failing liveness endpoint was left alone for the whole of its 123-second grace
  period, with no unhealthy event and no restart, where the identical pod not terminating was
  marked for restart within two seconds. So the defect that produced this record was the probe
  semantics alone: the shutdown budget was not in fact being cut short. That is measured kubelet
  behaviour on one version, **not a guarantee read out of the API contract** — a kubelet that
  changed its mind would make the old design dangerous again, which is one more reason the
  liveness endpoint does not report the drain.
* **The hold's duration is a guess about the cluster, not a measurement of it.** Propagation is
  well under a second in a small cluster and a few seconds in a large one; nothing in the chart
  measures it, and a cluster slower than the configured hold still has the race this record
  closes, only narrower.
* **A useless-but-answering process stays in rotation** (D2, D5). Detecting it is an alerting
  problem, on metrics an operator has to have switched on.
* **Nothing enforces D5 on a probe added later.** It is a rule in this record, not a check in the
  tree: a future probe that reads a shared dependency would render, install and pass every suite
  this project runs, because they all run one instance against one backend.

## References

* [ADR 0028](0028-an-abandoned-upload-is-ended-not-forgotten.md) — the sweep that a kill inside
  the shutdown window destroys.
* [ADR 0029](0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md) — the
  order of the shutdown and why the listener closes last, which is what keeps the readiness
  endpoint answering during the sweep.
* [ADR 0033](0033-a-proxy-instance-holds-its-uploads.md) — why the state a restart discards cannot
  be recovered by another instance.
* [ADR 0030](0030-the-network-boundary-belongs-to-the-administrator.md) — the boundary the status
  document sits behind.
* [ADR 0025](0025-leaving-is-a-supported-mode.md) — why the active provider is a sensitive field.
* [ADR 0016](0016-the-license-is-a-startup-gate.md) and
  [ADR 0013](0013-a-configuration-key-exists-only-if-code-reads-it.md) — the two preconditions D2 rules
  out, and why each is already answered without a probe.
* [ADR 0018](0018-a-major-release-is-declared-by-a-label.md) — weighed and not observed for the
  endpoint removal, by the owner's decision.
* [README.md](../../README.md) — the endpoints as an operator meets them.
* [SECURITY_ARCHITECTURE.md](../../SECURITY_ARCHITECTURE.md) — the unauthenticated surface these
  endpoints form.
