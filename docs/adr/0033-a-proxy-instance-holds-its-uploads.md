# ADR 0033: A proxy instance holds its uploads, so the chart installs one

## Status

**Accepted.** Date: 2026-09-14. Decided with the owner the same day, out of a review of what
three announced features — high availability, several backends kept in sync, and a Kubernetes
operator — would need the 5.0.0 configuration to look like. The review found the chart shipping
a production profile that could not work.

**Built 2026-09-14.** The chart refuses `replicaCount` above 1 and refuses
`autoscaling.enabled`, both with a message naming the reason. The shipped production and
monitoring profiles install one instance, autoscaling is off, and production's pod disruption
budget is off with it. Two chart tests pin the refusals and one pins that the rendered replica
count is 1.

## Context

A client-driven multipart upload is not stateless. The proxy owns the part layout (ADR 0011):
it holds the upload's part table and the object's data key for the lifetime of the upload, in
the process that answered `CreateMultipartUpload` and nowhere else. An `UploadPart` that reaches
a different process names an upload that process has never heard of, and is answered
`404 NoSuchUpload`. `CompleteMultipartUpload` and `ListParts` answer the same way.

Nothing in the chart makes a client reach the same pod twice. The Service sets no session
affinity and the default Ingress annotations carry none, so a second replica does not take a
share of the work — it takes requests belonging to an upload the first replica is holding.

Until this record the chart shipped `replicaCount: 3` in its production profile and autoscaling
from three to twenty pods beside it, and both rendered. A deployment following the profile the
project ships would fail every client-driven multipart upload that happened to be balanced
across pods, intermittently, with an S3 error code that says the upload does not exist. The
proxy's own suites never saw it: they run one instance.

The exit provider is the exception that proves where the state is. It keeps no session and
forwards `CreateMultipartUpload`, `UploadPart` and `CompleteMultipartUpload` to the backend, so
it is already indifferent to which instance answers. Every encrypting provider is not, because
an encrypting provider is the one that has a data key to hold.

## Decision

**D1. One proxy process serves a deployment of this chart, and the chart refuses to render a
second.** `replicaCount` above 1 fails the render; `autoscaling.enabled` fails it as well,
because a horizontal autoscaler is a second replica with a delay in front of it. The refusal
names what breaks and what to set instead.

**D2. It refuses rather than documents.** A warning in a values file is read by whoever is
already worried; a render that fails is read by whoever set the value. The failure mode this
prevents is intermittent, blames the client, and reports an S3 error code that means something
else — the worst kind to leave to a paragraph.

**D3. Running several proxies that cooperate is a different product.** It needs a shared
session table, an owner for the sweeper, and a bound on held short-part bytes that means
something across processes — none of which this chart can supply. It is the
`s3-encryption-operator`, with a chart of its own, and this chart stays the single-instance
one. The two are installed separately and neither is a mode of the other.

**D4. Availability at one replica is what a rollout gives it, and no more.** A pod disruption
budget over one pod blocks the drain instead of protecting the service, so the production
profile ships none. An upgrade is a restart, bounded by `shutdown_timeout` (ADR 0029), during
which the drain answers `503` with `Retry-After` rather than refusing connections.

## Consequences

* **A deployment on the shipped production profile changes shape on upgrade**: from three pods
  to one. That is a capacity change an operator must plan for, and it is stated in the chart's
  upgrade notes. What they lose was never working for client-driven multipart uploads.
* **Throughput is one process's.** The proxy is not the bottleneck at these rates — the link is
  — but a deployment that needs more than one process has no answer in this chart today.
* **A single instance is a single point of failure**, and this record accepts that for this
  chart. The operator is where that is answered.
* **The refusal will have to be lifted, not loosened**, when instances can hand work over. It is
  a values check, so it moves with the chart rather than with the binary.

## Alternatives Considered

**Ship session affinity and keep several replicas.** Rejected. It narrows the window and does
not close it: affinity is best-effort on both the Service and an Ingress, it does not survive a
pod restart, and an upload already open when the client's affinity moves is lost exactly as it
is today. A control that works most of the time against a failure that is already intermittent
is worse than none, because it makes the residue harder to reproduce.

**Document the limitation in the values file and leave the switches.** Rejected for the reason
in D2, and because the project had already done it: the production profile carried a comment
about drains and replica counts while shipping three of them.

**Hold the session in the backend, so any instance can pick it up.** Rejected here as out of
scope rather than wrong — it is one of the designs the high-availability work has to weigh, and
it has a security consequence this record will not decide in passing: the data key would have to
live somewhere every instance can read.

## Residual risks

* **Nothing detects a second instance at run time.** The refusal is in the chart, so a
  deployment that does not use this chart — a hand-written manifest, or a different chart — can
  still run several and will meet the same `404 NoSuchUpload`. The proxy itself neither knows
  nor says how many of it are running.
* **The failure is invisible to every suite this project runs.** Integration, conformance and
  all three end-to-end suites run one instance, so a regression that made a second instance
  necessary would not turn a test red. The chart tests are the whole guard.
