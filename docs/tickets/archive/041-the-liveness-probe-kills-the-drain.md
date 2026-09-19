# 041 — The liveness probe kills the drain, and nothing holds the pod while its endpoints go away

Raised 2026-09-15 while refining [036](../036-high-availability.md). Two defects in
the same few lines, both reachable on every `helm upgrade` today, neither
depending on high availability or on anything in 036.

**Refined 2026-09-15. Nothing is open; the work list below is buildable as
written.** The decisions are P1 to P13 under *Refining round*; one unknown is
left to measure rather than decide, and it is work item 11.

**Built 2026-09-15, and item 11 measured the same day.** All eleven work items are
done — see *What was built* at the end of this file, and *The kubelet question,
answered* for the measurement. The decisions P1 to P12 now live in
[ADR 0034](../../adr/0034-a-probe-reports-the-process-never-its-dependencies.md).
Nothing durable is left in this file, so it is ready to archive.

## The shape after this work

| Listener | Path | Answers |
|---|---|---|
| S3 (`bind_address`, `:8080`) | `/livez` | Constant `200`. Never reports the drain |
| S3 | `/readyz` | `200`, and `503` with the shutdown time from the moment the drain starts |
| S3 | — | `/health` and `/version` are gone |
| Monitoring (`monitoring.bind_address`, `:9090`) | `/livez` | Constant `200`, the same handler |
| Monitoring | `/metrics` | Unchanged, plus the gauges the status document is built from |
| Monitoring | `/status` | The one descriptive document; replaces the `/info` stub |

Both probe paths on the S3 listener keep the `isProbeRequest` matcher `/health`
carries today: a request is a probe only when it is unsigned and carries no query
string. A signed request to `/livez`, or one carrying S3 parameters, is an S3
request for a bucket of that name and goes through authentication like any other
— the exemption covers the probe, not the name (ADR 0014 D14).

The status document carries: version, commit and build time; the active
provider's alias, type and key fingerprint; the backend observation — time of the
last HTTP response, time and class of the last transport failure, or
`no request since start`; and the licence time remaining. Every field is also a
Prometheus gauge or label on the same listener; the document is the reading of
them for a human with no Prometheus, never their replacement.

## What is wrong

**One endpoint serves both probes, and it reports the drain.**
[router.go:71](../../../internal/proxy/router.go) registers `/health` and nothing
else; [handler.go:69-85](../../../internal/proxy/handlers/health/handler.go) knows
exactly one state — `shutdownInitiated` — and answers `503 shutting_down` from
the moment SIGTERM arrives. The chart points **both** probes at it
([values.yaml:134-150](../../../deploy/helm/s3-encryption-proxy/values.yaml)):
`livenessProbe` with `periodSeconds: 10` and `failureThreshold: 3`,
`readinessProbe` with `periodSeconds: 5`.

So a draining pod fails its liveness probe by design. Against a grace period of
`shutdown_timeout + 5` — 35 s at the defaults
([_helpers.tpl:110-118](../../../deploy/helm/s3-encryption-proxy/templates/_helpers.tpl)) —
roughly 30 s of failing liveness sits inside the window the shutdown needs. A
SIGKILL there skips `runShutdownTail` entirely
([main.go:407-431](../../../cmd/s3-encryption-proxy/main.go)), which is where the
multipart sweep of ADR 0028 and ADR 0029 lives: every open upload is then left at
the backend as an orphan rather than ended.

**How bad this is turns on one fact, measured 2026-09-15: kubelet does not act.**
It stops liveness-probing a pod the moment termination begins, so the failing
probe never shortened the shutdown budget. The defect was the probe semantics
alone. See *The kubelet question, answered* below.

**There is no `preStop` hook.** `grep -rn "preStop\|lifecycle"` over
`deploy/helm/` finds nothing. SIGTERM therefore starts `http.Server.Shutdown` —
which stops accepting new connections — in the same moment the EndpointSlice
update begins propagating to kube-proxy on every node. Those two are not ordered,
so for the length of that propagation the pod refuses connections the cluster is
still sending it. The client sees a connection error. An SDK retries; a client
that does not, fails.

## Refining round, 2026-09-15 — what a probe is allowed to say

Worked through with the owner. **What is written as decided is decided**; the
open questions below say that they are open.

### The decisions

**P1. Three endpoints, each with the name that matches what it answers.** One
liveness, one readiness, one status. The third is not a probe and nothing in the
platform ever acts on it automatically.

**P2. Liveness is a constant 200 on the serving listener and covers nothing
else.** Not backend reachability, not the configuration, not the licence, not
any other precondition. The reason is the only reaction kubelet has to a failing
liveness probe: kill the container and restart it. So the question a liveness
probe answers is *"would a restart repair this?"*, and for every precondition the
answer is no:

* **Backend unreachable** — a restart does not reach it either. Every pod would
  fail at once, restart at once, and land in `CrashLoopBackOff` with exponential
  backoff, so the proxy recovers *later* than the backend it was waiting for. A
  foreign outage becomes an outage of our own. Worse here than elsewhere: a
  restart is not a drain. A process holds its own multipart sessions (ADR 0033)
  and ends them in the shutdown tail (ADR 0028), so a backend hiccup of thirty
  seconds would strand exactly the uploads this ticket exists to protect.
* **Configuration** — cannot be false at runtime. The loader decodes strictly and
  an unknown key refuses the start (ADR 0013 D11), so a process that answers at
  all has a configuration that parsed. A startup fact, not a runtime signal.
* **Licence** — the one precondition that does expire while the process runs, and
  the process already answers it by ending itself: the validator shuts down
  gracefully on expiry (ADR 0016 D4). A restart would find the same expired
  token, so a probe would only convert a clean stop into a crash loop.

What is left is the single case a liveness probe is for: the process is alive but
can no longer answer HTTP — a wedged accept path, a deadlock. A constant-200
handler on the serving listener detects exactly that and nothing finer, and the
endpoint documents itself as such.

**P3. Readiness says whether this instance wants and can take traffic, and the
drain is what makes it false.** That is the behaviour `/health` has today, wired
to the wrong probe. It stays reachable while draining — the health routes carry
no drain guard, and the listener closes last (ADR 0029 D1) — so a probe during
the sweep reads a refusal rather than a connection error.

**P4. Readiness is a lifecycle signal, never a load signal.** No pressure
measurement makes it false: a full short-part budget answers `SlowDown` in a
response and nothing more. A readiness probe that reports load takes the pod out
of rotation, moves its share onto the remaining pods, and takes those out too.

**P5. Dependency health is a fourth category and belongs on neither probe.**
Backend reachability, the active provider and its fingerprint, licence time
remaining: an operator wants to see it and alert on it, and no automatic actor
may act on it. That is what the status endpoint and the metrics are for. This
generalises the rule 036 needs: **no probe depends on anything outside the
process, and none depends on a load quantity.** 036 will want a session store
behind readiness, and reads and single-request PUTs need no store — so a store
outage that takes every pod out of rotation would make the majority of the
traffic less available than the single instance it replaces.

**P6. The paths are `/livez`, `/readyz` and the status endpoint, and `/health`
is removed from the S3 listener in the same change.** Decided by the owner on
2026-09-15 after the additive variants were put and declined: no alias, no
deprecation period, no two-stage removal at the next major. It ships as an
ordinary `feat:` — **no breaking marker, no breaking note, no `release:major`
label**. The concern was raised and overruled deliberately: ADR 0018 D5 would
call a removed endpoint a client-visible answer, no load balancer or ingress in
any known deployment probes it, and the owner judged the declaration not worth a
major. ADR 0018 itself is not amended and its guard is untouched — it reads
commit markers, so nothing in CI has an opinion about a removed route.

Ten call sites inside the repository move with it in the same change, all of them
waiting for "does it answer yet", which is liveness: the demo compose health
check, three in the demo start script, the performance script, two integration
helpers, both client e2e up-scripts, the Velero values file, and the chart's own
two probe defaults. The monitoring listener's own constant-200 `/health` and its
`/info` stub move with them — that listener is off by default and has no
consumer, so leaving `/health` there under a third meaning would reintroduce the
confusion this decision removes.

**P7. No startup probe.** The startup path is local and cannot be slow: the
configuration is loaded, the licence is verified from a JWT in process, the
providers are built, and only then is the server created — no backend round trip
anywhere, and every failure on that path is fatal, so the process dies rather
than lingering half-started. There is no "started but not yet usable" window for
a startup probe to cover. What replaces it is smaller: `initialDelaySeconds: 30`
on the liveness probe becomes a small value, because a constant-200 handler needs
no warm-up and the 30 seconds are a blind window — a process that wedges early is
noticed after 60 s today and after roughly 17 s at `initialDelaySeconds: 2`,
`periodSeconds: 5`, `failureThreshold: 3`.

**The one thing that reopens P7:** any work that does network I/O before the
listener binds. The startup readability verdict sketched in
[040](../040-managed-buckets.md) would do exactly that and would make the start time
depend on the backend; a startup probe is the right instrument then and is not
built before then.

**P8. The status endpoint is `/status` on the monitoring listener, and the
`/info` stub goes with it.** Decided 2026-09-15. It is the same boundary `/metrics` already
draws: operational data sits on the port whose reachability the operator
controls (ADR 0030), not on the port every S3 client reaches. The deciding field
is the active provider — an `exit` provider means the backend holds plaintext
(ADR 0025 D10), and an operator has to be able to see that, which is precisely
what must not be readable without authentication on the S3 surface.

Two consequences. The document is absent on a default install, because
`monitoring.enabled` is `false`; the default is **not** flipped, since that would
switch on an unauthenticated metrics port with it, so the chart declares the
container port without a Service entry and the troubleshooting documentation
opens with "turn `monitoring.enabled` on". And the metrics carry the same facts
as gauges — the endpoint is the ad-hoc reading of them for a human with no
Prometheus, never their replacement.

**P9. The status endpoint reports what the real traffic showed; it never probes
on its own.** Decided 2026-09-15. The backend HTTP client is built in one place,
so one `RoundTripper` wrapper sees every backend round trip and can tell a
transport failure from an answer — and for reachability **any** HTTP response
counts, a `403` included. It keeps the time of the last backend response, the
time and class of the last transport failure (DNS, connect, TLS, timeout), and
whether anything has been observed at all since the process started; the document
prints them with their timestamps.

Rejected with it: a check on every request, a background check on an interval,
and the two combined behind a query parameter. All three share a defect that has
no clean answer — there is no S3 call that is universally permitted, since a
policy may deny `ListBuckets` and the proxy owns no bucket of its own to head, so
a synthetic check can report a failure that the real path does not have. They
also make the endpoint trigger backend traffic, and the interval variant would
cost a configuration key and permanent I/O with no reader. The real path has the
right credentials, the right target and the right timeout by construction.

A proxy that has served nothing says so — `no request since start`, never `ok`.
The same counters feed the Prometheus gauges: one measurement, two renderings.

**P10. `/version` goes with `/health`, and everything descriptive is one status
document.** Decided 2026-09-15. After this work the S3 listener answers exactly
two unsigned paths, `/livez` and `/readyz`, both with a constant answer and
neither carrying operational data. Version, commit, build time, the active
provider and its fingerprint, the backend observation and the licence remaining
are one document on the monitoring listener.

Two things this buys beyond tidiness. The subrouter that sits ahead of the
authentication middleware becomes describable in one sentence instead of the
paragraph of exceptions it needs today, and an exception nobody has to explain is
one nobody extends by mistake. And the exact release stops being readable from
the data path by an unsigned request — it does not become secret, it moves behind
the same door as `s3ep_server_info`, which has always carried those three labels
on the monitoring listener.

What it costs: with `monitoring.enabled` off, the running build is not readable
over HTTP at all. It stays in the image tag, in the Helm release and in the first
log line of the start. Its consumers in the tree are one echo line in the demo
start script, two tests and three documentation passages.

**P11. The chart declares `kubeVersion: ">=1.34.0-0"` and the hook has no
opt-out.** Decided 2026-09-15. The owner runs 1.34.11 and everything older is end
of life; old clusters get no consideration. 1.34 is also where the sleep action
graduated to stable, so the beta feature gate that a cluster administrator could
switch off between 1.30 and 1.33 is not a residual risk at all.

The `-0` suffix is load-bearing rather than cosmetic: without it Helm's semver
reads a distribution version such as `1.34.4-gke.1` as a prerelease and refuses a
cluster that meets the requirement.

Rejected with it: leaving the floor undeclared, which fails at apply time with
`lifecycle.preStop: Required value: must specify a handler type` — a message that
sends the reader looking for a typo in the chart; and rendering the hook
conditionally on `.Capabilities.KubeVersion`, which installs everywhere and
leaves the older cluster running with exactly the broken drain this ticket
closes, silently. For the same reason there is no `preStop.enabled: false`: an
opt-out switch is the conditional render in values form. The duration is
configurable, the hook's existence is not.

**P12. The hook's duration is a values key, and the grace period stops being
overridable below the sum.** Decided 2026-09-15. `preStopSleepSeconds` defaults
to 5 and enters the derivation, which becomes `preStop + shutdown_timeout + 5` —
40 seconds at the defaults where it is 35 today. The duration belongs in values
rather than in the proxy's own configuration file: no Go code would ever read it,
and ADR 0013 D11 says a configuration key exists only if code reads it. It is not
a template constant either, because the time an EndpointSlice needs to reach
every node is a property of the cluster, not of the proxy.

The important half is the override. `.Values.terminationGracePeriodSeconds` wins
outright over the derivation today, so a value below the sum leaves the sweep
without a budget and says nothing. **The template fails at render time when the
override is smaller than `preStop + shutdown_timeout + 5`, naming all three
numbers and the sum.** That is the pattern the chart already follows — a
configuration that does not parse is a render-time failure rather than a pod
killed mid-transfer. An operator who deliberately wants less moves one of the two
numbers that mean something; the sum is only their consequence.

Five seconds is the default because propagation is well under a second in a small
cluster and a few in a large one, and because every extra second is paid per pod
on every rollout. The trailing `+ 5` stays as it is: it covers the listener close
and the process exit, and the hook changes nothing about either.

**P13. Proven by a chart unit test and one integration suite that owns the stack;
no Velero case.** Decided 2026-09-15. What is already pinned needs no second
proof: five unit tests fix the order of the shutdown tail and its budget
arithmetic, and `helm unittest` covers the chart's wiring — which probe points
where, that the hook exists, that the grace period is the sum — in seconds.

What is unproven is that a real process inside a container survives a real signal
to the end of its sweep. A new integration package opens a multipart upload,
sends SIGTERM to the proxy container, and asserts at the backend that no upload
is left. It owns the demo stack rather than sharing it, the way the performance
package already does for a weaker reason — that one only competes for the
backend, this one destroys the proxy — so it stays out of `INTEGRATION_PKGS` and
gets a target of its own. It has to bring the stack back up itself; a run that
aborts must not leave the next one a broken stack.

A Velero case is deliberately not added. What it would prove beyond the above is
that Kubernetes behaves as documented — preStop before SIGTERM, kubelet against a
terminating pod — and that does not regress from our commits, while our own half
is fully covered by the chart test. Paying minutes on every release gate to
re-measure a Kubernetes property is the wrong trade. The kubelet question stays
what it is: a one-off fact, answered once against `make e2e-up` and written into
this file.

Under ADR 0031 the new suite is red until the work lands. That is correct and it
is committed that way.

### What was verified while refining

In the tree:

* **The runtime image is `gcr.io/distroless/static-debian12:nonroot`**
  ([Containerfile:54](../../../Containerfile)). No shell and no `sleep` binary, so
  an `exec` preStop hook is not an option at all — the native
  `lifecycle.preStop.sleep` is the only shape.
* **The monitoring listener already serves a constant-200 `/health`** and an
  `/info` stub answering `{"service":"s3-encryption-proxy","monitoring":"enabled"}`
  ([server.go:37-53](../../../internal/monitoring/server.go)). The first is the
  liveness handler this ticket describes, already written; the second is the
  route the status document takes over. Neither has a consumer.
* **Ten places in the tree probe `/health` on the S3 listener**, and every one of
  them waits for "does it answer yet", which is liveness: the demo compose health
  check, three in the demo start script, the performance script, two integration
  helpers, both client e2e up-scripts, and the Velero values file, which pins it
  for *both* probes. `/version` has no machine consumer at all — one echo line in
  the demo start script, two tests, three documentation passages.
* **The startup path is local and fatal on error.** Configuration, then the
  licence verified from a JWT in process, then the providers, then the server
  ([main.go:120-136](../../../cmd/s3-encryption-proxy/main.go)) — no backend round
  trip, and every failure is a `Fatal`. There is no half-started state, which is
  what P7 rests on.
* **The backend HTTP client is built in exactly one place**
  ([server.go:211](../../../internal/proxy/server.go)), so one `RoundTripper`
  wrapper sees every backend round trip and can tell a transport failure from an
  answer. That is what makes P9 cheap.
* **The shutdown tail is already pinned by five unit tests**
  ([shutdown_test.go](../../../cmd/s3-encryption-proxy/shutdown_test.go)): the sweep
  before the listener close, the remaining budget rather than a second full one,
  an exhausted budget that still sweeps, a failing sweep that still closes, and
  the deadline as the single anchor. What they cannot show is a real process
  under a real signal, which is what P13 adds.
* **The chart already has a unit-test harness** — `helm unittest` through
  `make helm-test` ([Makefile:479](../../../Makefile)) with pinned assertions in
  `tests/deployment_test.yaml`.
* **The health routes carry no middleware and the drain guard is on the S3
  subrouter only** ([middleware_setup.go:69-93](../../../internal/proxy/middleware_setup.go)),
  so a probe keeps being answered throughout the drain. Nothing in P3 needs to
  change that.
* **The licence ends the process itself on expiry**
  ([validator.go:191-196](../../../internal/license/validator.go), ADR 0016 D4), and
  an unknown configuration key refuses the start (ADR 0013 D11). Those two are
  why neither can be a liveness condition (P2).

Upstream:

* **The `preStop` sleep action is alpha in 1.29 and enabled by default from
  1.30.** Its graduation to stable was reverted once and targets 1.34, so between
  1.30 and 1.33 it is a beta gate a cluster administrator can switch off. Zero
  duration is a separate gate, alpha in 1.32 and beta in 1.33 — not needed here.
  P11 puts the floor at 1.34, where the action is stable.
  ([KEP-3960](https://github.com/kubernetes/enhancements/issues/3960),
  [Kubernetes v1.33 container lifecycle](https://kubernetes.io/blog/2025/05/14/kubernetes-v1-33-updates-to-container-lifecycle/),
  [kubernetes#122488](https://github.com/kubernetes/kubernetes/issues/122488) for
  the message an install below the floor produces.)
* **The Velero suite's cluster is `kindest/node:v1.36.1`**
  ([versions.env:21](../../../test/e2e/velero/versions.env)), so the hook is
  exercisable there when the kubelet question of work item 11 is answered.

### The kubelet question, answered

**Measured 2026-09-15 against kubelet v1.36.1 in the Velero e2e kind cluster.
kubelet does not act on a liveness failure for a pod that is already
terminating — it stops probing it altogether.**

The experiment, in its own namespace, twice with the identical pod spec:

* A container serving a file over `httpd`, with a liveness probe on that file at
  `periodSeconds: 1`, `failureThreshold: 1`. It ignores `SIGTERM` and loops
  forever, so it cannot exit on its own inside the grace period — that is what
  makes any restart attributable to kubelet and to nothing else. A `preStop` hook
  removes the file, so the probe target is gone before `SIGTERM` and stays gone.
  `terminationGracePeriodSeconds: 120`.
* **Control, not terminating.** The file is removed by hand. Two seconds later:
  `Unhealthy: Liveness probe failed: HTTP probe failed with statuscode: 404` and
  `Killing: Container app failed liveness probe, will be restarted`.
* **Measurement, terminating.** `kubectl delete pod`. `Killing: Stopping
  container app` at once, then **nothing for the whole 123 seconds** until the
  pod went away at grace expiry: no `Unhealthy`, no restart event,
  `restartCount` 0, `started` still true. The probe target was confirmed to be
  returning 404 from inside the container 64 seconds into that window, so the
  probe would have failed on every one of its 120 attempts had kubelet made
  them.

**What this changes:** the *severity* of what preceded this work, not the work.
The shutdown budget was never actually cut short by the failing liveness probe on
this kubelet, so no upload was stranded by that mechanism. A liveness probe that
reports the drain is still wrong — it says the process should be killed while the
process is doing the one thing a kill must not interrupt — and the `preStop`
defect beside it was real and unconditional.

**What it does not establish:** this is measured kubelet behaviour on one
version, not a guarantee read out of the Kubernetes API contract. A kubelet that
changed its mind would make the old design dangerous again, which is one more
reason the liveness endpoint does not report the drain.

## What it must not break

* [ADR 0029](../../adr/0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md)
  D1 — the listener closes **last**, so that a probe arriving during the sweep
  reads `503 shutting_down` rather than a connection refusal. That is the
  behaviour of the endpoint that keeps reporting the drain, whichever name it
  ends up with.
* [ADR 0028](../../adr/0028-an-abandoned-upload-is-ended-not-forgotten.md) — the
  sweep has to run at all, which is the point of the fix.
* [ADR 0018](../../adr/0018-a-major-release-is-declared-by-a-label.md) D5 — not
  observed here, deliberately and by the owner's decision (P6). The ADR is not
  amended and its guard is not touched; the removal of `/health` and `/version`
  simply ships without a marker.
* [ADR 0030](../../adr/0030-the-network-boundary-belongs-to-the-administrator.md) —
  nothing here adds anything the chart has to defend.

## Open questions

**None.** The refining round of 2026-09-15 answered all eight, as P6 to P13
above. One unknown is left, and it is a fact to be measured rather than a
decision to be taken: whether kubelet acts on a liveness failure for a pod that
is already terminating. It is work item 11.

## Work

1. **Router.** Add `/livez` and `/readyz` to the S3 listener behind the same
   `isProbeRequest` matcher `/health` carries today, and remove `/health` and
   `/version` from it. Ships as a `feat:` with no breaking marker (P6, P10).
2. **Health handler.** Split into a constant-200 liveness handler and a
   readiness handler that answers 503 from the moment the drain starts (P2, P3).
   The version handler leaves the S3 listener with its route.
3. **Monitoring listener.** `/health` becomes `/livez`; the `/info` stub becomes
   the status document — build information, the active provider with its type and
   fingerprint, the backend observation, the licence remaining (P8, P10).
4. **Backend observation.** Wrap the backend client's transport, built in one
   place, in a `RoundTripper` that records the time of the last HTTP response,
   the time and class of the last transport failure, and whether anything has
   been observed since the start. It feeds both the status document and the
   Prometheus gauges (P9).
5. **Chart.** Probes to `/livez` and `/readyz`; `initialDelaySeconds` down to a
   small value and no startup probe (P7); `preStopSleepSeconds` with a default of
   5 and a `lifecycle.preStop.sleep` hook; the grace period derived as
   `preStop + shutdown_timeout + 5` with a render-time failure when the override
   undercuts it (P12); `kubeVersion: ">=1.34.0-0"` and no opt-out for the hook
   (P11).
6. **Call sites.** Move the ten in-repo users of `/health` to `/livez` — the demo
   compose health check, three in the demo start script, the performance script,
   two integration helpers, both client e2e up-scripts and the Velero values file
   — plus the `/version` echo line and the tests that name either path. After
   this step nothing in the tree names `/health` or `/version` on the proxy.
7. **Shutdown suite.** A new integration package that owns the demo stack: open a
   multipart upload, SIGTERM the proxy container, assert no upload is left at the
   backend, bring the stack back. Out of `INTEGRATION_PKGS`, its own Make target
   (P13).
8. **Chart tests.** `helm unittest` cases pinning which probe points where, the
   hook, the grace-period arithmetic and the render-time refusal; recompute the
   pinned ConfigMap and probe assertions in `tests/deployment_test.yaml`.
9. **ADR.** P2, P4 and P5 — what a liveness probe may say, that readiness is a
   lifecycle signal and never a load signal, and that no probe depends on
   anything outside the process. 036 depends on these and a ticket is not a
   source of a rule (ADR 0022).
10. **Documentation.** The chart README's probe rows,
    [README.md](../../../README.md), [docs/security/](../../security/)
    — the probe paragraph and the monitoring-listener paragraph both name
    `/health` — and [docs/developer/](../../developer/).
11. **Measure the one unknown.** Whether kubelet acts on a liveness failure for a
    pod that is already terminating, answered once against `make e2e-up` and
    written into this file before it is archived. **Done 2026-09-15: it does
    not.**

## Done when

- [x] `/livez`, `/readyz` and the status endpoint exist; `/health` and `/version`
      are gone from both listeners, and `git grep` finds only MinIO's and
      Vault's.
- [x] The liveness endpoint does not report the drain, the readiness one does,
      and the status one is acted on by nobody.
- [x] The status document reports the backend from observed traffic and says
      `no request since start` when there has been none.
- [x] A `preStop` hook holds the pod while its endpoints are withdrawn, and the
      grace period covers hook plus drain plus sweep. An override below the sum
      fails the render.
- [x] `make helm-test` pins the probe wiring, the hook and the arithmetic.
- [x] The shutdown suite shows a SIGTERMed container finishing its sweep — no
      multipart upload left at the backend — and leaves the stack usable.
- [x] The kubelet question is answered against a real cluster and written down
      here.
- [x] P2, P4 and P5 are in an ADR.

## What was built, 2026-09-15

Items 1 to 10, in one change. What is worth knowing beyond the work list:

- **The endpoint bodies.** `/livez` answers `{"status":"alive"}`, `/readyz`
  answers `{"status":"ready"}` and, while draining, the `shutting_down` document
  it answered on `/health` before. Nothing machine-reads a body — a probe reads
  the status code — so the strings are documentation, not an interface.
- **The backend observer sees what a handler never does.** It wraps the backend
  HTTP client, so it records transport failures the SDK retried away. The first
  live run against the demo stack produced exactly one, class `other`, with
  nothing in the proxy log — the retry had succeeded. A failure is therefore
  reported three ways: `warn` with the class, host, method and error, because
  that line is its only record; `s3ep_backend_transport_failures_total{class}`
  beside `s3ep_backend_responses_total`, because an alert needs a rate and the
  numerator alone cannot be read; and the status document, for the current
  state. A failure under an already-cancelled request is none of the three.
- **The observer had to learn which end failed.** The request body handed to the
  backend is the proxy's own reader chain — the upload checksum verifier in front
  of the segment sealer — and net/http reports an error it raises as the error of
  the round trip. So one client sending a wrong `Content-MD5` counted as a
  backend transport failure, logged a warning naming the backend host, and
  flipped the status document to `failing` while the backend behaved perfectly;
  any credentialed client could have driven the alert at will. The observer now
  tags the body it hands over and exempts a failure that came from it, the way it
  already exempted a request whose context was done. Found by review, reproduced
  against the real SDK, pinned by two tests.
- **The alerting rules are a `PrometheusRule` in the chart**, off by default,
  with four alerts: object integrity, the backend failure *share*, and the two
  licence ones. The backend rule reads a share and never a count, because the SDK
  retries. A unit test holds the rules to the same contract as the dashboard — an
  alert naming a series no scrape exports can never fire and, unlike an empty
  dashboard panel, nobody ever opens it.
- **A `terminationGracePeriodSeconds` of 0 was silently ignored.** The override
  branch was a Go-template truthiness test, and 0 reads as false — so the
  smallest override there is fell through to the derived sum with no message.
- **A `preStopSleepSeconds` of 0 now fails the render.** It was not in the work
  list. A zero hold is the opt-out P11 refuses, wearing a values key: it renders,
  installs, and leaves the drain racing the withdrawal exactly as before the hook
  existed. Two chart tests pin the refusal.
- **Two probe call sites were found beyond the ten.** `scripts/conformance-run.sh`
  and `performance.sh` both waited on `/health`, and four probes in
  `.github/workflows/test-pipeline.yml` did too. All moved.
- **A defect that predates this work.** The demo compose health check used
  `wget --spider`, which sends `HEAD`, and the probe route has always been `GET`
  only — so `proxy-healthcheck` was in a restart loop against `/health` before
  any of this. It now sends a `GET`. The probe routes were deliberately left
  `GET`-only: that is what Kubernetes sends and what every other call site sends.
- **`log_health_requests` no longer reaches the S3 logging middleware.** That
  middleware skipped `/health` and `/version` by path, which is dead now that the
  probes never reach it — and worse than dead: it would have hidden S3 traffic
  for buckets of those names. The special case is gone and the key governs the
  probe handlers alone.
- **Three ADRs, not one.** ADR 0034 carries P1 to P12. ADR 0014 D11 and D14 named
  `/health` and `/version` in the rule itself, and ADR 0029 D1 step 1 said
  `/health` was what goes false on a drain — both are amended in place, because
  an ADR that states a removed path as current is the defect the ground rules
  name.

**Verified on this branch:** `make test-unit` green; `make test-integration` and
`make test-integration-tls` green (450 tests each); `make test-integration-shutdown`
green — the process exited 268 ms after `SIGTERM` and the backend held no
multipart upload; `make helm-test` 48/48; `make e2e-rclone` and `make e2e-s3cmd`
green; `make helm-test` 57/57 across two chart suites; `make gosec` 0 issues;
`go vet` over all build tags clean; `make e2e-velero` 13 of 13 in 589 s against a
kind cluster that installed the changed chart — the API server accepted
`lifecycle.preStop.sleep`, the rendered grace period was 40, and the two probes
pointed at different endpoints. **Not verified locally:** `golangci-lint` is not
installed on the machine this was built on.
