# 043 — A backend the proxy cannot use is named before the first client request, and a backend fault is not called a client disconnect

Split out of the backend-trust refining session on 2026-09-18. Two findings that
belong together: both are about a backend failure being attributed to the wrong
thing, one before traffic and one during a response.

## Part one: nothing says the backend is unusable until a client asks

Verified 2026-09-18: there is no backend probe at startup and none behind the
health endpoints. So a backend the proxy cannot verify or cannot reach produces
a pod that starts, goes Ready, passes every probe, and answers
`500 InternalError` to every client request. The operator learns about it from a
user.

**Most of the answer is already written, and it is a refusal.** ADR 0034 D6 puts
dependency health in a category that is reported and never acted on, which rules
out a readiness endpoint that talks to the backend: readiness would then couple
this pod's health to the backend's availability, and a backend blip would
withdraw a proxy that is working. ADR 0034 D9 refuses a startup probe as well,
but conditionally — *while the startup path does no network I/O* — and it names
the condition that reopens it: work that makes the start depend on the backend.

So the open question is narrow and it is not about probes:

- **Should the start itself touch the backend?** One round trip before the
  listener binds, failing the start when it fails, would turn "the proxy cannot
  use its backend" into a deployment-time event with a named error instead of a
  runtime surprise. It also makes the proxy unable to start while its backend is
  down, which is a different availability posture than the one the product has
  today, and the restart loop that follows is its own behaviour to design.
- **Or should it be reported and not acted on**, consistent with ADR 0034 D6 —
  the status document and the counters already carry it, and what is missing is
  that nobody is looking at a fresh deployment's metrics in the first minute.
- **If the start does touch the backend, ADR 0034 D9 has to be amended** rather
  than worked around: it says there is no "started but not yet usable" window,
  and this would create one.

## Part two: a backend fault mid-response is logged as a client disconnect

`reportStreamFault` splits on the integrity sentinels; everything else becomes
`Warn("The response body stopped before the object ended")` and increments
nothing. A whole-object read makes two backend requests, so a backend fault can
land there — and it is then reported as a client that went away, which is the
wrong subject.

It is not urgent: the backend observer logs the same failure with its class and
host, so an operator is not blind, and for the certificate case specifically it
is unreachable in practice — roots load once per process, so if the first request
verified the second does too. It is reachable for a reset, a timeout, or a
backend that goes away mid-object.

**What to decide:** whether the handler asks the observer's classification who
ended the stream, or whether the two lines are simply allowed to stand side by
side with the observer's being the accurate one. The second is free and the first
is a small amount of plumbing for a line that is read after the fact either way.

## Done when

Both parts are decided; whichever is built has a test, and whichever is not is
recorded with its reason — including any amendment ADR 0034 needs.
