# 041 — The liveness probe kills the drain, and nothing holds the pod while its endpoints go away

Raised 2026-09-15 while refining [036](036-high-availability.md). Two defects in
the same few lines, both reachable on every `helm upgrade` today, neither
depending on high availability or on anything in 036.

## What is wrong

**One endpoint serves both probes, and it reports the drain.**
[router.go:71](../../internal/proxy/router.go) registers `/health` and nothing
else; [handler.go:69-85](../../internal/proxy/handlers/health/handler.go) knows
exactly one state — `shutdownInitiated` — and answers `503 shutting_down` from
the moment SIGTERM arrives. The chart points **both** probes at it
([values.yaml:134-150](../../deploy/helm/s3-encryption-proxy/values.yaml)):
`livenessProbe` with `periodSeconds: 10` and `failureThreshold: 3`,
`readinessProbe` with `periodSeconds: 5`.

So a draining pod fails its liveness probe by design. Against a grace period of
`shutdown_timeout + 5` — 35 s at the defaults
([_helpers.tpl:110-118](../../deploy/helm/s3-encryption-proxy/templates/_helpers.tpl)) —
roughly 30 s of failing liveness sits inside the window the shutdown needs. A
SIGKILL there skips `runShutdownTail` entirely
([main.go:407-431](../../cmd/s3-encryption-proxy/main.go)), which is where the
multipart sweep of ADR 0028 and ADR 0029 lives: every open upload is then left at
the backend as an orphan rather than ended.

**Not verified, and it decides how bad this is:** whether kubelet acts on a
liveness failure for a pod that is already terminating. The answer needs a real
cluster, not this repository. If it does not act, the defect is the dead probe
semantics alone; if it does, the shutdown budget is a fiction.

**There is no `preStop` hook.** `grep -rn "preStop\|lifecycle"` over
`deploy/helm/` finds nothing. SIGTERM therefore starts `http.Server.Shutdown` —
which stops accepting new connections — in the same moment the EndpointSlice
update begins propagating to kube-proxy on every node. Those two are not ordered,
so for the length of that propagation the pod refuses connections the cluster is
still sending it. The client sees a connection error. An SDK retries; a client
that does not, fails.

## What it must not break

* [ADR 0029](../adr/0029-the-shutdown-budget-finishes-work-and-sweeps-what-cannot-be-finished.md)
  D1 — the listener closes **last**, so that a probe arriving during the sweep
  reads `503 shutting_down` rather than a connection refusal. That is the
  behaviour of the endpoint that keeps reporting the drain, whichever name it
  ends up with.
* [ADR 0028](../adr/0028-an-abandoned-upload-is-ended-not-forgotten.md) — the
  sweep has to run at all, which is the point of the fix.
* [ADR 0018](../adr/0018-a-major-release-is-declared-by-a-label.md) D5 — see the
  open question; one of the two shapes changes an existing answer and the other
  does not.
* [ADR 0030](../adr/0030-the-network-boundary-belongs-to-the-administrator.md) —
  nothing here adds anything the chart has to defend.

## Open question

**Which shape does the split take?**

**A — additive.** `/health` keeps its behaviour exactly (503 once the drain
starts) and is the readiness endpoint; a **new** path answers 200 for as long as
the process serves and becomes the liveness endpoint. Nothing existing changes
its answer, so no breaking marker and no release label.
Cost: `/health` is a slightly misleading name for a readiness probe, forever.

**B — rename the semantics.** `/health` becomes liveness (200 during the drain)
and a new `/ready` carries the 503.
Cost: an external load balancer or ingress that probes `/health` today loses the
drain signal at the upgrade and keeps routing to a pod that is about to close its
listener — a silent regression, discovered as connection resets. Under ADR 0018
D5 it is arguable whether a probe endpoint is a "client-visible answer" at all:
the router keeps probes off the S3 surface deliberately (`isProbeRequest`,
unsigned, ahead of the middleware), so the three categories D5 names do not
obviously cover it. Arguable is not the same as free.

Owner leaning at the time of writing was B; the refining round then set the
constraint that no work may produce a breaking commit, which makes A the shape
that needs no interpretation of D5.

## Work

1. Split the two probes into two endpoints, in the shape the open question
   settles. Both stay off the S3 surface and unauthenticated, as `/health` is
   today.
2. State what the liveness endpoint actually covers: that the listener still
   answers, not that the proxy works. It is a constant-200 handler; it catches a
   wedged process and nothing finer.
3. Add a `preStop` hook so the pod serves normally while its endpoints are
   withdrawn, and only then receives SIGTERM. Kubernetes 1.30 and later can do
   this natively (`lifecycle.preStop.sleep.seconds`) with no binary in the image;
   an `exec` hook needs a `sleep` in the runtime image, which has not been
   checked. Pick one and say which Kubernetes versions the chart then requires.
4. Recompute `terminationGracePeriodSeconds`: it derives
   `shutdown_timeout + 5` today and has to become `preStop + shutdown_timeout +
   margin`, or the hook eats the shutdown budget it was added to protect.
5. Record the rule that **neither probe ever depends on anything outside the
   process.** It is written down here because 036 will want to put a session
   store behind readiness, and reads and single-request PUTs need no store — so a
   store outage that takes every pod out of rotation would make the majority of
   the traffic less available than the single instance it replaces.
6. Update the chart README's probe rows and
   [docs/developer/](../developer/) wherever the endpoint is described.

## Done when

- [ ] Two endpoints exist, the liveness one does not report the drain, and the
      readiness one does.
- [ ] A `preStop` hook holds the pod while its endpoints are withdrawn, and the
      grace period covers hook plus drain plus sweep.
- [ ] A chart unit test pins which probe points where, and the pinned ConfigMap
      and probe assertions in `tests/deployment_test.yaml` are recomputed.
- [ ] An integration or e2e assertion shows that a terminating pod finishes its
      shutdown tail — the multipart sweep of ADR 0028 runs — rather than being
      killed mid-drain.
- [ ] The question of whether kubelet kills a terminating pod on liveness failure
      is answered against a real cluster, and the answer is written down here
      before this file is archived.
